//! Language packs and scrub walk for pattern-based detectors.
//!
//! Universal detectors always run. Locale packs add national IDs / phones /
//! street addresses / NL and UK postcodes. Counts always include every
//! [`PiiType`] key (0 when unused); `person` is filled only by the `ner`
//! feature.

use crate::detectors::{detectors_for, PiiCategory};
use std::borrow::Cow;
use std::collections::BTreeMap;
use thiserror::Error;

pub const MAX_SCRUB_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DEPTH: usize = 200;

pub const PII_TYPES: &[&str] = &[
    "email",
    "iban",
    "credit_card",
    "bic",
    "mac",
    "imei",
    "ip",
    "location",
    "bsn",
    "ssn",
    "tax_id",
    "vat_id",
    "passport",
    "phone",
    "person",
    "address",
    "license_plate",
];

pub type PiiType = &'static str;
pub type PiiCounts = BTreeMap<String, u32>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageCode {
    En,
    Nl,
    De,
}

impl LanguageCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Nl => "nl",
            Self::De => "de",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "en" => Ok(Self::En),
            "nl" => Ok(Self::Nl),
            "de" => Ok(Self::De),
            _ => Err(format!(
                "unknown language {raw:?}; supported: [\"de\", \"en\", \"nl\"]"
            )),
        }
    }
}

pub const DEFAULT_LANGUAGES: &[LanguageCode] = &[LanguageCode::En, LanguageCode::Nl];

#[derive(Debug, Error)]
pub enum PiiScrubError {
    #[error("{0}")]
    Message(String),
}

impl PiiScrubError {
    pub fn new(message: impl Into<String>) -> Self {
        Self::Message(message.into())
    }
}

#[derive(Debug, Clone)]
pub struct ScrubResult {
    pub text: String,
    pub found: bool,
    pub counts: PiiCounts,
}

pub fn empty_pii_counts() -> PiiCounts {
    PII_TYPES.iter().map(|t| ((*t).to_string(), 0u32)).collect()
}

pub fn total_pii_count(counts: &PiiCounts) -> u32 {
    PII_TYPES
        .iter()
        .map(|t| counts.get(*t).copied().unwrap_or(0))
        .sum()
}

/// Normalize language list. `None` → default `en`+`nl`; empty → no locale packs.
pub fn normalize_languages(
    languages: Option<&[String]>,
) -> Result<Vec<LanguageCode>, PiiScrubError> {
    match languages {
        None => Ok(DEFAULT_LANGUAGES.to_vec()),
        Some(list) if list.is_empty() => Ok(Vec::new()),
        Some(list) => {
            let mut out = Vec::new();
            let mut seen = Vec::new();
            for raw in list {
                let code = LanguageCode::parse(raw).map_err(PiiScrubError::new)?;
                if !seen.contains(&code) {
                    seen.push(code);
                    out.push(code);
                }
            }
            Ok(out)
        }
    }
}

fn bump_count(counts: &mut PiiCounts, cat: PiiCategory, n: u32) {
    if n == 0 {
        return;
    }
    // Keys are pre-seeded by [`empty_pii_counts`]; avoid re-allocating the key.
    if let Some(slot) = counts.get_mut(cat.as_str()) {
        *slot += n;
    }
}

/// Fail unless the NER pass can run: built with the `ner` feature and a
/// loadable model.
fn require_ner() -> Result<(), PiiScrubError> {
    #[cfg(feature = "ner")]
    return crate::ner::ensure_loaded();
    #[cfg(not(feature = "ner"))]
    Err(PiiScrubError::new(
        "NER needs a native build with the `ner` feature \
         (maturin develop --release --features ner, or \
         npm run build:native -- --features ner)",
    ))
}

/// Mask pattern-detectable PII in a string using an already-normalized language pack.
///
/// With `ner`, a person-name pass runs last, on the already-masked text
/// (see the `ner` module).
pub fn scrub_text_langs(
    text: &str,
    langs: &[LanguageCode],
    check_size: bool,
    ner: bool,
) -> Result<ScrubResult, PiiScrubError> {
    if check_size && text.len() > MAX_SCRUB_BYTES {
        return Err(PiiScrubError::new(format!(
            "scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
        )));
    }

    let mut counts = empty_pii_counts();
    let mut out: Cow<'_, str> = Cow::Borrowed(text);
    for detector in detectors_for(langs) {
        let (next, n) = (detector.scrub)(out.as_ref());
        bump_count(&mut counts, detector.category, n);
        if let Some(s) = next {
            out = Cow::Owned(s);
        }
    }
    #[cfg(feature = "ner")]
    if ner {
        let (next, n) = crate::ner::scrub_persons(out.as_ref())?;
        bump_count(&mut counts, PiiCategory::Person, n);
        if let Some(s) = next {
            out = Cow::Owned(s);
        }
    }
    #[cfg(not(feature = "ner"))]
    if ner {
        require_ner()?;
    }
    Ok(ScrubResult {
        found: total_pii_count(&counts) > 0,
        text: out.into_owned(),
        counts,
    })
}

/// Mask pattern-detectable PII in a string. `ner` adds the person-name pass.
pub fn scrub_text(
    text: &str,
    languages: Option<&[String]>,
    check_size: bool,
    ner: bool,
) -> Result<ScrubResult, PiiScrubError> {
    let langs = normalize_languages(languages)?;
    if ner {
        require_ner()?;
    }
    scrub_text_langs(text, &langs, check_size, ner)
}

#[cfg(feature = "payload")]
mod payload {
    use super::*;
    use serde_json::Value;

    fn payload_string_bytes(value: &Value, depth: usize) -> Result<usize, PiiScrubError> {
        if depth > MAX_DEPTH {
            return Err(PiiScrubError::new(format!(
                "payload nests past the {MAX_DEPTH}-level scrub limit"
            )));
        }
        match value {
            Value::String(s) => Ok(s.len()),
            Value::Array(items) => {
                let mut total = 0usize;
                for item in items {
                    total += payload_string_bytes(item, depth + 1)?;
                }
                Ok(total)
            }
            Value::Object(map) => {
                let mut total = 0usize;
                for item in map.values() {
                    total += payload_string_bytes(item, depth + 1)?;
                }
                Ok(total)
            }
            _ => Ok(0),
        }
    }

    fn scrub_walk(
        value: Value,
        counts: &mut PiiCounts,
        depth: usize,
        langs: &[LanguageCode],
        ner: bool,
    ) -> Result<Value, PiiScrubError> {
        if depth > MAX_DEPTH {
            return Err(PiiScrubError::new(format!(
                "payload nests past the {MAX_DEPTH}-level scrub limit"
            )));
        }
        match value {
            Value::String(s) => {
                let result = scrub_text_langs(&s, langs, false, ner)?;
                for t in PII_TYPES {
                    if let Some(slot) = counts.get_mut(*t) {
                        *slot += result.counts.get(*t).copied().unwrap_or(0);
                    }
                }
                Ok(Value::String(result.text))
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(scrub_walk(item, counts, depth + 1, langs, ner)?);
                }
                Ok(Value::Array(out))
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, item) in map {
                    out.insert(key, scrub_walk(item, counts, depth + 1, langs, ner)?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other),
        }
    }

    #[derive(Debug, Clone)]
    pub struct PayloadScrubResult {
        pub payload: Value,
        pub found: bool,
        pub counts: PiiCounts,
    }

    /// Walk a JSON value and mask string leaves. `ner` adds the person-name pass.
    pub fn scrub_payload(
        payload: Value,
        languages: Option<&[String]>,
        ner: bool,
    ) -> Result<PayloadScrubResult, PiiScrubError> {
        if payload_string_bytes(&payload, 0)? > MAX_SCRUB_BYTES {
            return Err(PiiScrubError::new(format!(
                "scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
            )));
        }
        let langs = normalize_languages(languages)?;
        if ner {
            require_ner()?;
        }
        let mut counts = empty_pii_counts();
        let scrubbed = scrub_walk(payload, &mut counts, 0, &langs, ner)?;
        Ok(PayloadScrubResult {
            found: total_pii_count(&counts) > 0,
            payload: scrubbed,
            counts,
        })
    }
}

#[cfg(feature = "payload")]
pub use payload::{scrub_payload, PayloadScrubResult};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_uk_nino_as_ssn_in_en_pack() {
        let en = [LanguageCode::En];
        for value in [
            "AB123456C",
            "AB 12 34 56 C",
            "ab 12 34 56 d",
            "jg103759a",
            "AB 12 34 56",
            "AB 123456 C",
            "AB123456 C",
            "AB 12 34 56C",
            "AB\u{a0}12\u{a0}34\u{a0}56\u{a0}C",
        ] {
            let r = scrub_text_langs(&format!("NINO {value} on file"), &en, true, false).unwrap();
            assert_eq!(r.text, "NINO [SSN] on file", "{value}");
            assert_eq!(r.counts["ssn"], 1);
        }
        let r = scrub_text_langs(r#"{"ni": "JG103759A"}"#, &en, true, false).unwrap();
        assert_eq!(r.text, r#"{"ni": "[SSN]"}"#);
        let r = scrub_text_langs("a,JG 10 37 59 A,b", &en, true, false).unwrap();
        assert_eq!(r.text, "a,[SSN],b");
        let nl = [LanguageCode::Nl];
        let r = scrub_text_langs("NINO AB123456C", &nl, true, false).unwrap();
        assert_eq!(r.counts["ssn"], 0);
        let r = scrub_text_langs("AB 12 34 56 Cat", &en, true, false).unwrap();
        assert_eq!(r.text, "[SSN] Cat");
        let r = scrub_text_langs("AB 12 34 56 C 7 days", &en, true, false).unwrap();
        assert_eq!(r.text, "[SSN] 7 days");
        let r = scrub_text_langs("nino=AB123456C", &en, true, false).unwrap();
        assert_eq!(r.text, "nino=[SSN]");
        let r = scrub_text_langs("NINO AB 12 34 56 C/JG 10 37 59 A", &en, true, false).unwrap();
        assert_eq!(r.text, "NINO [SSN]/[SSN]");
        let r = scrub_text_langs("AB 12 34 56 C-2024", &en, true, false).unwrap();
        assert_eq!(r.text, "[SSN]-2024");
        for (text, expected) in [
            ("GET /api/claimants/AB123456C HTTP/1.1", "GET /api/claimants/[SSN] HTTP/1.1"),
            ("https://x.gov.uk/ni/AB123456C", "https://x.gov.uk/ni/[SSN]"),
            ("NINO:AB123456C/2", "NINO:[SSN]/2"),
        ] {
            let r = scrub_text_langs(text, &en, true, false).unwrap();
            assert_eq!(r.text, expected, "{text}");
        }
        for value in [
            "QQ123456C",
            "QQ 12 34 56 C",
            "GB123456A",
            "ZZ 12 34 56 A",
            "DA123456A",
            "AO123456A",
            "AB123456E",
            "AB123456",
            "AB 123456",
            "ab 12 34 56",
            "meet at 10 15 20",
            "rose by 100000 a year",
            "at 123456 b",
            "AB 12 34 56 78",
            "xAB123456C",
            "AB123456Cx",
            "sku_AB123456C",
            "ORD-AB123456C",
            "AB123456C-2",
            "aGVsbG8AB123456Cd29ybGQ=",
            "AB123456C=",
        ] {
            let text = format!("ref {value}");
            let r = scrub_text_langs(&text, &en, true, false).unwrap();
            assert_eq!(r.text, text, "{value}");
        }
    }

    #[test]
    fn rejects_every_unissued_nino_prefix_and_masks_thin_space_forms() {
        let en = [LanguageCode::En];
        let mut bad: Vec<String> = "DFIQUV".chars().map(|c| format!("{c}A")).collect();
        bad.extend("DFIOQUV".chars().map(|c| format!("A{c}")));
        bad.extend(["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"].map(String::from));
        for prefix in bad {
            let value = format!("{prefix}123456A");
            let r = scrub_text_langs(&value, &en, true, false).unwrap();
            assert_eq!(r.text, value, "{prefix}");
        }
        for value in [
            "AB\u{2009}12\u{2009}34\u{2009}56\u{2009}C",
            "AB\u{202f}12\u{202f}34\u{202f}56",
            "AB12 34 56 C",
        ] {
            let r = scrub_text_langs(value, &en, true, false).unwrap();
            assert_eq!(r.text, "[SSN]", "{value}");
        }
    }

    #[test]
    fn masks_grouped_nhs_numbers_as_ssn_in_en_pack() {
        let en = [LanguageCode::En];
        for value in ["943 476 5919", "943-476-5919", "943\u{a0}476\u{a0}5919"] {
            let r = scrub_text_langs(&format!("NHS {value} on file"), &en, true, false).unwrap();
            assert_eq!(r.text, "NHS [SSN] on file");
            assert_eq!(r.counts["ssn"], 1);
            assert_eq!(r.counts["phone"], 0);
        }
        let r = scrub_text_langs(r#"{"nhs": "943-476-5919"}"#, &en, true, false).unwrap();
        assert_eq!(r.text, r#"{"nhs": "[SSN]"}"#);
        for value in [
            "943 476 5918",
            "111 111 1111",
            "1-943-476-5919",
            "1 943 476 5919",
            "943-476 5919",
        ] {
            let r = scrub_text_langs(value, &en, true, false).unwrap();
            assert_eq!(r.text, "[PHONE]", "{value}");
            assert_eq!(r.counts["ssn"], 0, "{value}");
        }
        let r = scrub_text_langs("ts 9434765919", &en, true, false).unwrap();
        assert_eq!(r.text, "ts 9434765919");
        for (text, expected) in [
            ("943 476 5919 943 476 5919", "[SSN] [SSN]"),
            ("401-023-2137 401-023-2137", "[SSN] [SSN]"),
            ("Patient 2 943 476 5919", "Patient 2 [SSN]"),
            ("NHS 401 023 2137 2 visits", "NHS [SSN] 2 visits"),
            ("ward 11 943 476 5919", "ward 11 [SSN]"),
        ] {
            let r = scrub_text_langs(text, &en, true, false).unwrap();
            assert_eq!(r.text, expected, "{text}");
            assert_eq!(r.counts["phone"], 0, "{text}");
        }
        for (text, expected) in [
            ("401-023-2137 401-023-2137", "[SSN] [SSN]"),
            ("401 023 2137 943 476 5919", "[SSN] [SSN]"),
            ("NHS 401 023 2137 049", "NHS [SSN] 049"),
        ] {
            let r = scrub_text(text, None, true, false).unwrap();
            assert_eq!(r.text, expected, "{text}");
        }
        let r = scrub_text("bel 020 794 6095", None, true, false).unwrap();
        assert_eq!(r.text, "bel [PHONE]");
        assert_eq!(r.counts["ssn"], 0);
    }

    #[test]
    fn masks_only_valid_german_vat_ids_in_de_pack() {
        let de = [LanguageCode::De];
        for value in ["DE136695976", "DE 136 695 976", "DE.136.695.976"] {
            let r = scrub_text_langs(&format!("VAT {value} on file"), &de, true, false).unwrap();
            assert_eq!(r.text, "VAT [VAT_ID] on file");
            assert_eq!(r.counts["vat_id"], 1);
        }
        for value in [
            "DE136695977",
            "DE036695976",
            "de136695976",
            "xDE136695976",
            "DE136695976x",
        ] {
            let r = scrub_text_langs(value, &de, true, false).unwrap();
            assert_eq!(r.text, value);
            assert_eq!(r.counts["vat_id"], 0);
        }
        let r = scrub_text("DE136695976", None, true, false).unwrap();
        assert_eq!(r.text, "DE136695976");
    }

    #[test]
    fn ipv6_embedded_in_unicode_word_stays_outside_the_word() {
        let text = "Hauptstraße64:ff9b::142.227.134.185";
        let r = scrub_text(text, None, true, false).unwrap();
        assert_eq!(r.text, "Hauptstraße64:ff9b::[IP]");
    }

    #[test]
    fn decimal_location_backtracks_its_optional_tails() {
        // Python's order: drop the E/W group, then the degree sign.
        let r = scrub_text("52.3676, 4.9041°Ex", None, true, false).unwrap();
        assert_eq!(r.text, "[LOCATION]°Ex");
        let r = scrub_text("52.3676, 4.904152°22", None, true, false).unwrap();
        assert_eq!(r.text, "[LOCATION]°22");
        // Only two cuts: a long space run before the tail stays linear
        // (400k spaces: milliseconds, where a full walk-back takes minutes).
        let spaces = " ".repeat(400_000);
        let text = format!("52.3676, 4.9041{spaces}Ex");
        let started = std::time::Instant::now();
        let r = scrub_text(&text, None, true, false).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(r.text, format!("[LOCATION]{spaces}Ex"));
    }

    #[test]
    fn dms_seconds_glued_to_a_word_fall_back_to_minutes() {
        // Python's lookahead backtracks past the optional seconds; the
        // linear engine walks the end back instead.
        let r = scrub_text("N 52°22' E 4°54' 12\"x", None, true, false).unwrap();
        assert_eq!(r.text, "[LOCATION] 12\"x");
        for sep in ['\u{3000}', '\u{0c}', '\u{0b}', '\u{85}', '\u{2028}', '\u{2029}'] {
            let r = scrub_text(&format!("52°22'N{sep}4°54'E"), None, true, false).unwrap();
            assert_eq!(r.text, "[LOCATION]", "separator {sep:?}");
        }
    }

    #[test]
    fn email_before_at_backtracks_like_python() {
        // ``(?!@)`` emulation: the span Python's backtracking picks, even when
        // it lies past the shortening walk's cap.
        let text = format!("a@ex.com.{}.{}.xx@y", "1".repeat(63), "1".repeat(63));
        let r = scrub_text(&text, None, true, false).unwrap();
        assert_eq!(r.text, format!("[EMAIL]{}", &text["a@ex.com".len()..]));
        // No quadratic re-walk when a long domain runs into ``@``.
        let text = format!("{}@{}cc@", "a".repeat(64), "b.".repeat(2000));
        assert_eq!(scrub_text(&text, None, true, false).unwrap().text, text);
        // Capped walk: a long domain with a glued TLD is masked as found.
        let text = format!("a@{}{}", "b.".repeat(2000), "c".repeat(30));
        assert_eq!(scrub_text(&text, None, true, false).unwrap().text, "[EMAIL]cccccc");
    }

    #[test]
    fn masks_email() {
        let r = scrub_text("Contact ada@example.com for help", None, true, false).unwrap();
        assert_eq!(r.text, "Contact [EMAIL] for help");
        assert!(r.found);
        assert_eq!(r.counts["email"], 1);
    }

    #[test]
    fn masks_glued_emails() {
        let r = scrub_text("a@b.comc@d.com", None, true, false).unwrap();
        assert_eq!(r.text, "[EMAIL][EMAIL]");
        assert_eq!(r.counts["email"], 2);
    }

    #[test]
    fn email_tld_does_not_eat_iban() {
        let r = scrub_text("ada@example.comNL91ABNA0417164300", None, true, false).unwrap();
        assert_eq!(r.text, "[EMAIL][IBAN]");
        assert_eq!(r.counts["email"], 1);
        assert_eq!(r.counts["iban"], 1);
    }

    #[test]
    fn iban_inside_a_rejected_candidate_is_still_masked() {
        // The compact pattern starts at the hex digit before ``NL`` and yields
        // ``bc4545667033NL09BSLW5753882578``, whose country code is not in the
        // registry; the real IBAN starts eight characters inside that span.
        let r = scrub_text(
            "18:c0:50:92:da:be4+4bc4545667033NL09BSLW5753882578",
            None,
            true,
            false,
        )
        .unwrap();
        assert_eq!(r.text, "18:c0:50:92:da:be4+4bc4545667033[IBAN]");
        assert_eq!(r.counts["iban"], 1);
    }

    #[test]
    fn iban_after_a_pseudo_country_code_is_masked() {
        let r = scrub_text("ac@LG180UU07GB89IWQY91132044634700", None, true, false).unwrap();
        assert_eq!(r.text, "ac@[PASSPORT][IBAN]");
        assert_eq!(r.counts["iban"], 1);
    }

    #[test]
    fn location_masks_the_first_valid_pair_not_the_leftmost() {
        // ``0.5741, -0.9633`` is leftmost but both components are within 1.0,
        // so it is rejected. The scan resumes after it, as Python does, so the
        // overlapping window ``-0.9633,-37.45816`` is never considered.
        let r = scrub_text("scale 0.5741, -0.9633,-37.45816,41.605875", None, true, false).unwrap();
        assert_eq!(r.text, "scale 0.5741, -0.9633,[LOCATION]");
        assert_eq!(r.counts["location"], 1);
    }

    #[test]
    fn masks_iban_and_card() {
        let r = scrub_text("Pay NL91ABNA0417164300 with 4111111111111111", None, true, false).unwrap();
        assert_eq!(r.text, "Pay [IBAN] with [CREDIT_CARD]");
    }

    #[test]
    fn masks_dashed_and_mixed_case_iban() {
        let dashed = scrub_text("Pay NL91-ABNA-0417-1643-00 please", None, true, false).unwrap();
        assert_eq!(dashed.text, "Pay [IBAN] please");
        assert_eq!(dashed.counts["iban"], 1);
        assert_eq!(dashed.counts["phone"], 0);

        let mixed = scrub_text("Pay Nl91 AbNa 0417 1643 00 please", None, true, false).unwrap();
        assert_eq!(mixed.text, "Pay [IBAN] please");
        assert_eq!(mixed.counts["iban"], 1);

        let slash = scrub_text("Pay NL91/ABNA/0417/1643/00 please", None, true, false).unwrap();
        assert_eq!(slash.text, "Pay [IBAN] please");
        assert_eq!(slash.counts["iban"], 1);
    }

    #[test]
    fn masks_grouped_card_separators_and_mapped_ip() {
        let card = scrub_text("card 4111.1111.1111.1111", None, true, false).unwrap();
        assert_eq!(card.text, "card [CREDIT_CARD]");
        assert_eq!(card.counts["credit_card"], 1);

        let mapped = scrub_text("peer ::ffff:192.0.2.1 ok", None, true, false).unwrap();
        assert_eq!(mapped.text, "peer [IP] ok");
        assert_eq!(mapped.counts["ip"], 1);
    }

    #[test]
    fn masks_card_iban_glue_email_ssn_degree_nanp_double_spaced_iban() {
        let glue = scrub_text("4111111111111111NL91ABNA0417164300", None, true, false).unwrap();
        assert_eq!(glue.text, "[CREDIT_CARD][IBAN]");

        let langs = vec!["en".to_string()];
        let email_ssn =
            scrub_text("ada@example.com078-05-1120", Some(&langs), true, false).unwrap();
        assert_eq!(email_ssn.text, "[EMAIL][SSN]");

        let loc = scrub_text("52.3676°, 4.9041°", None, true, false).unwrap();
        assert_eq!(loc.text, "[LOCATION]");

        let phone = scrub_text("(415)555-0132", Some(&langs), true, false).unwrap();
        assert_eq!(phone.text, "[PHONE]");

        let iban = scrub_text("NL91  ABNA  0417  1643  00", None, true, false).unwrap();
        assert_eq!(iban.text, "[IBAN]");
    }

    #[test]
    fn masks_email_ip_mac_location_slash_ssn_padded_ip() {
        assert_eq!(
            scrub_text("ada@example.com192.0.2.1", None, true, false)
                .unwrap()
                .text,
            "[EMAIL][IP]"
        );
        assert_eq!(
            scrub_text("ada@example.comaa:bb:cc:dd:ee:ff", None, true, false)
                .unwrap()
                .text,
            "[EMAIL][MAC]"
        );
        assert_eq!(
            scrub_text("ada@example.com52.3676,4.9041", None, true, false)
                .unwrap()
                .text,
            "[EMAIL][LOCATION]"
        );
        let en = vec!["en".to_string()];
        assert_eq!(
            scrub_text("078/05/1120", Some(&en), true, false).unwrap().text,
            "[SSN]"
        );
        assert_eq!(
            scrub_text("192.168.001.001", None, true, false).unwrap().text,
            "[IP]"
        );
        assert_eq!(
            scrub_text("52.3676 N, 4.9041 E", None, true, false)
                .unwrap()
                .text,
            "[LOCATION]"
        );
        assert_eq!(
            scrub_text("NL91\u{200b}ABNA0417164300", None, true, false)
                .unwrap()
                .text,
            "[IBAN]"
        );
    }

    #[test]
    fn language_gate_bsn() {
        let langs = vec!["en".to_string()];
        let r = scrub_text("BSN 100000009 on file", Some(&langs), true, false).unwrap();
        assert_eq!(r.counts["bsn"], 0);
    }

    #[test]
    fn masks_grouped_itin_as_tax_id() {
        let langs = vec!["en".to_string()];
        for value in ["912-70-1234", "900 50 1234", "999\u{2013}94\u{2013}0001"] {
            let r = scrub_text(&format!("itin {value} on file"), Some(&langs), true, false).unwrap();
            assert_eq!(r.text, "itin [TAX_ID] on file", "{value}");
            assert_eq!(r.counts["tax_id"], 1, "{value}");
            assert_eq!(r.counts["ssn"], 0, "{value}");
        }
        for value in ["912-89-1234", "912-93-1234", "912701234", "912.70.1234"] {
            let text = format!("ref {value}");
            let r = scrub_text(&text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, text, "{value}");
        }
    }

    #[test]
    fn masks_uk_postcode_in_every_outward_shape() {
        let langs = vec!["en".to_string()];
        for value in [
            "M1 1AE", "B33 8TH", "W1A 0AX", "SW1A 1AA", "NW1 6XE", "GU30 7RS", "E1W 1AA",
            "JE2 3AA", "GY1 1AA", "ZE1 0AA", "NR1 3PS", "EC1A 1BB",
        ] {
            let r = scrub_text(&format!("postcode {value}"), Some(&langs), true, false).unwrap();
            assert_eq!(r.text, "postcode [ADDRESS]", "{value}");
            assert_eq!(r.counts["address"], 1, "{value}");
        }
    }

    #[test]
    fn masks_uk_postcode_across_whitespace_runs() {
        let langs = vec!["en".to_string()];
        for separator in [" ", "  ", "\t", "\u{a0}", "\u{202f}"] {
            let text = format!("postcode NW1{separator}6XE");
            let r = scrub_text(&text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, "postcode [ADDRESS]", "{separator:?}");
            assert_eq!(r.counts["address"], 1, "{separator:?}");
        }
    }

    #[test]
    fn masks_uk_postcode_after_a_street_address() {
        let langs = vec!["en".to_string()];
        let r = scrub_text(
            "Ship to 221B Baker Street, London NW1 6XE",
            Some(&langs),
            true,
            false,
        )
        .unwrap();
        assert_eq!(r.text, "Ship to [ADDRESS], London [ADDRESS]");
        assert_eq!(r.counts["address"], 2);
    }

    #[test]
    fn rejects_uk_postcode_areas_that_do_not_exist() {
        let langs = vec!["en".to_string()];
        for value in ["A4 2PK", "PS5 1TB", "A1 2PK"] {
            let text = format!("part {value} in stock");
            let r = scrub_text(&text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, text, "{value}");
            assert_eq!(r.counts["address"], 0, "{value}");
        }
    }

    #[test]
    fn rejects_uk_outward_shapes_that_do_not_exist() {
        let langs = vec!["en".to_string()];
        for value in ["AB12C 3DE", "M12C 3DE", "LA23J 2DX", "SW123 4AB"] {
            let text = format!("order {value} shipped");
            let r = scrub_text(&text, Some(&langs), true, false).unwrap();
            assert_eq!(r.counts["address"], 0, "{value}");
        }
    }

    #[test]
    fn uk_postcode_needs_the_en_pack() {
        let langs = vec!["nl".to_string()];
        let r = scrub_text("postcode NW1 6XE", Some(&langs), true, false).unwrap();
        assert_eq!(r.text, "postcode NW1 6XE");
        assert_eq!(r.counts["address"], 0);
    }

    #[test]
    fn uk_postcode_boundaries_are_ascii_alphanumeric_only() {
        // Python's ``(?<![A-Za-z0-9])…(?![A-Za-z0-9])``, not a Unicode ``\b``.
        let langs = vec!["en".to_string()];
        for (text, expected) in [
            ("_NW1 6XE", "_[ADDRESS]"),
            ("NW1 6XE_", "[ADDRESS]_"),
            ("__NW1 6XE__", "__[ADDRESS]__"),
            ("\u{e9}NW1 6XE", "\u{e9}[ADDRESS]"),
            ("NW1 6XE\u{e9}", "[ADDRESS]\u{e9}"),
            ("\u{416}NW1 6XE", "\u{416}[ADDRESS]"),
            ("NW1 6XE\u{663}", "[ADDRESS]\u{663}"),
            ("aNW1 6XE", "aNW1 6XE"),
            ("1NW1 6XE", "1NW1 6XE"),
            ("NW1 6XEa", "NW1 6XEa"),
        ] {
            let r = scrub_text(text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, expected, "{text:?}");
        }
    }

    #[test]
    fn masks_street_with_a_comma_before_the_house_number() {
        for (text, lang, expected) in [
            ("Birkhahnstraße, 676", "de", "[ADDRESS]"),
            ("Adresse: Kerkstraat, 12", "nl", "Adresse: [ADDRESS]"),
            ("518, Hollywater Road, Liphook", "en", "[ADDRESS], Liphook"),
            (
                "474, Lexington Drive, Colorado Springs",
                "en",
                "[ADDRESS], Colorado Springs",
            ),
            ("Kerkstraat,\u{a0}12", "nl", "[ADDRESS]"),
            ("Kerkstraat,  12", "nl", "[ADDRESS]"),
            ("Hauptstr., 12", "de", "[ADDRESS]"),
            ("Berliner Straße, 17", "de", "[ADDRESS]"),
            ("Laan van Meerdervoort, 52", "nl", "[ADDRESS]"),
            ("Kerkstraat, nr. 12", "nl", "[ADDRESS]"),
            ("221B, Baker Street", "en", "[ADDRESS]"),
        ] {
            let langs = vec![lang.to_string()];
            let r = scrub_text(text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, expected, "{text:?}");
            assert_eq!(r.counts["address"], 1, "{text:?}");
        }
    }

    #[test]
    fn street_comma_needs_a_street_word() {
        for (text, lang) in [("Foo, 12", "nl"), ("Foo, 12", "de"), ("12, Foo", "en")] {
            let langs = vec![lang.to_string()];
            let r = scrub_text(text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, text, "{text:?}");
            assert_eq!(r.counts["address"], 0, "{text:?}");
        }
    }

    /// A comma needs a space behind it, so CSV columns are not house numbers.
    #[test]
    fn csv_comma_is_a_field_separator() {
        for (text, lang) in [
            ("id,Kerkstraat,2024-01-15,active", "nl"),
            ("Kerkstraat,12", "nl"),
            ("Birkhahnstraße,676", "de"),
            ("id,518,Hollywater Road,x", "en"),
        ] {
            let langs = vec![lang.to_string()];
            let r = scrub_text(text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, text, "{text:?}");
            assert_eq!(r.counts["address"], 0, "{text:?}");
        }
    }

    #[test]
    fn street_comma_over_masks_like_the_comma_less_form() {
        for (text, lang, expected) in [
            ("Chapter 12, Main Street", "en", "Chapter [ADDRESS]"),
            ("Sections 3, Park Lane and 4", "en", "Sections [ADDRESS] and 4"),
            ("Kerkstraat, 2024", "nl", "[ADDRESS]"),
        ] {
            let langs = vec![lang.to_string()];
            let without = scrub_text(&text.replace(',', ""), Some(&langs), true, false).unwrap();
            assert_eq!(without.counts["address"], 1, "{text:?}");
            let r = scrub_text(text, Some(&langs), true, false).unwrap();
            assert_eq!(r.text, expected, "{text:?}");
        }
    }

    #[cfg(not(feature = "ner"))]
    #[test]
    fn ner_without_feature_is_an_error() {
        let err = scrub_text("Ada Lovelace", None, true, true).unwrap_err();
        assert!(err.to_string().contains("`ner` feature"));
    }

    #[cfg(all(feature = "payload", not(feature = "ner")))]
    #[test]
    fn ner_payload_without_feature_is_an_error() {
        let err = scrub_payload(serde_json::json!([]), None, true).unwrap_err();
        assert!(err.to_string().contains("`ner` feature"));
    }

    #[test]
    fn unknown_language() {
        let langs = vec!["fr".to_string()];
        let err = scrub_text("hi", Some(&langs), true, false).unwrap_err();
        assert!(err.to_string().contains("unknown language"));
    }

    #[test]
    fn clean_text_unchanged() {
        let t = "The server exposes a search tool and a fetch tool.";
        let r = scrub_text(t, None, true, false).unwrap();
        assert_eq!(r.text, t);
        assert!(!r.found);
    }
}
