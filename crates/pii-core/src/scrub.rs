//! Language packs and scrub walk for pattern-based detectors.
//!
//! Universal detectors always run. Locale packs add national IDs / phones /
//! NL postcodes. Counts always include every [`PiiType`] key (0 when unused),
//! including reserved `person` (unused until NER is added).

use crate::detectors::{detectors_for, PiiCategory};
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
    "ip",
    "location",
    "bsn",
    "ssn",
    "tax_id",
    "vat_id",
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
    PII_TYPES
        .iter()
        .map(|t| ((*t).to_string(), 0u32))
        .collect()
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

fn category_key(cat: PiiCategory) -> &'static str {
    cat.as_str()
}

/// Mask pattern-detectable PII in a string.
pub fn scrub_text(
    text: &str,
    languages: Option<&[String]>,
    check_size: bool,
) -> Result<ScrubResult, PiiScrubError> {
    if check_size && text.len() > MAX_SCRUB_BYTES {
        return Err(PiiScrubError::new(format!(
            "scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
        )));
    }

    let langs = normalize_languages(languages)?;
    let mut counts = empty_pii_counts();
    let mut out = text.to_string();
    for detector in detectors_for(&langs) {
        let (next, n) = (detector.scrub)(&out);
        out = next;
        let key = category_key(detector.category);
        *counts.entry(key.to_string()).or_insert(0) += n;
    }
    Ok(ScrubResult {
        found: total_pii_count(&counts) > 0,
        text: out,
        counts,
    })
}

#[cfg(feature = "payload")]
mod payload {
    use super::*;
    use serde_json::Value;

    fn utf8_size(text: &str) -> usize {
        text.len()
    }

    fn payload_string_bytes(value: &Value, depth: usize) -> Result<usize, PiiScrubError> {
        if depth > MAX_DEPTH {
            return Err(PiiScrubError::new(format!(
                "payload nests past the {MAX_DEPTH}-level scrub limit"
            )));
        }
        match value {
            Value::String(s) => Ok(utf8_size(s)),
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
        languages: Option<&[String]>,
    ) -> Result<Value, PiiScrubError> {
        if depth > MAX_DEPTH {
            return Err(PiiScrubError::new(format!(
                "payload nests past the {MAX_DEPTH}-level scrub limit"
            )));
        }
        match value {
            Value::String(s) => {
                let result = scrub_text(&s, languages, false)?;
                for t in PII_TYPES {
                    *counts.entry((*t).to_string()).or_insert(0) +=
                        result.counts.get(*t).copied().unwrap_or(0);
                }
                Ok(Value::String(result.text))
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(scrub_walk(item, counts, depth + 1, languages)?);
                }
                Ok(Value::Array(out))
            }
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (key, item) in map {
                    out.insert(key, scrub_walk(item, counts, depth + 1, languages)?);
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

    /// Walk a JSON value and mask string leaves.
    pub fn scrub_payload(
        payload: Value,
        languages: Option<&[String]>,
    ) -> Result<PayloadScrubResult, PiiScrubError> {
        if payload_string_bytes(&payload, 0)? > MAX_SCRUB_BYTES {
            return Err(PiiScrubError::new(format!(
                "scrub input exceeds the {MAX_SCRUB_BYTES}-byte size cap"
            )));
        }
        let mut counts = empty_pii_counts();
        let scrubbed = scrub_walk(payload, &mut counts, 0, languages)?;
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
    fn masks_email() {
        let r = scrub_text("Contact ada@example.com for help", None, true).unwrap();
        assert_eq!(r.text, "Contact [EMAIL] for help");
        assert!(r.found);
        assert_eq!(r.counts["email"], 1);
    }

    #[test]
    fn masks_iban_and_card() {
        let r = scrub_text(
            "Pay NL91ABNA0417164300 with 4111111111111111",
            None,
            true,
        )
        .unwrap();
        assert_eq!(r.text, "Pay [IBAN] with [CREDIT_CARD]");
    }

    #[test]
    fn language_gate_bsn() {
        let langs = vec!["en".to_string()];
        let r = scrub_text("BSN 100000009 on file", Some(&langs), true).unwrap();
        assert_eq!(r.counts["bsn"], 0);
    }

    #[test]
    fn unknown_language() {
        let langs = vec!["fr".to_string()];
        let err = scrub_text("hi", Some(&langs), true).unwrap_err();
        assert!(err.to_string().contains("unknown language"));
    }
}
