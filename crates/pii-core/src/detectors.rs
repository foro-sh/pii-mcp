//! Pattern detectors: regex + checksum where one exists.
//!
//! Patterns mirror `pii_mcp.detectors`. Python lookarounds are enforced with
//! explicit boundary checks so matching stays on the linear-time `regex` crate.

use crate::checksum::{
    bsn_valid, iban_valid, luhn_valid, nl_postcode_valid, ssn_valid, tax_id_valid,
};
use regex::Regex;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PiiCategory {
    Email,
    Iban,
    CreditCard,
    Bic,
    Mac,
    Ip,
    Location,
    Bsn,
    Ssn,
    TaxId,
    VatId,
    Phone,
    Address,
    LicensePlate,
}

impl PiiCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Iban => "iban",
            Self::CreditCard => "credit_card",
            Self::Bic => "bic",
            Self::Mac => "mac",
            Self::Ip => "ip",
            Self::Location => "location",
            Self::Bsn => "bsn",
            Self::Ssn => "ssn",
            Self::TaxId => "tax_id",
            Self::VatId => "vat_id",
            Self::Phone => "phone",
            Self::Address => "address",
            Self::LicensePlate => "license_plate",
        }
    }
}

/// `(Some(rewritten), n)` on hits; `(None, 0)` when the text is unchanged.
pub type ScrubFn = fn(&str) -> (Option<String>, u32);

#[derive(Clone, Copy)]
pub struct Detector {
    pub category: PiiCategory,
    pub scrub: ScrubFn,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Replace accepted matches. Allocates only when at least one match is kept.
fn replace_matches<F>(
    text: &str,
    pattern: &Regex,
    placeholder: &str,
    mut accept: F,
    retry_on_reject: bool,
) -> (Option<String>, u32)
where
    F: FnMut(&str, usize, usize) -> bool,
{
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        if !accept(m.as_str(), m.start(), m.end()) {
            // Lookaround-emulated patterns may need +1 to retry a longer match;
            // checksum rejects match Python ``re.sub`` and resume at ``m.end()``.
            pos = if retry_on_reject {
                m.start() + 1
            } else {
                m.end().max(m.start() + 1)
            };
            continue;
        }
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..m.start()]);
        buf.push_str(placeholder);
        last = m.end();
        pos = m.end();
        count += 1;
    }
    match out {
        None => (None, 0),
        Some(mut buf) => {
            buf.push_str(&text[last..]);
            (Some(buf), count)
        }
    }
}

/// Apply several patterns in order, allocating only when something changes.
fn scrub_patterns<F>(
    text: &str,
    patterns: &[Regex],
    placeholder: &str,
    mut accept: F,
    retry_on_reject: bool,
) -> (Option<String>, u32)
where
    F: FnMut(&str, usize, usize) -> bool,
{
    let mut current: Option<String> = None;
    let mut count = 0u32;
    for pattern in patterns {
        let src = current.as_deref().unwrap_or(text);
        let (next, n) = replace_matches(src, pattern, placeholder, &mut accept, retry_on_reject);
        count += n;
        if let Some(s) = next {
            current = Some(s);
        }
    }
    (current, count)
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}",
        )
        .unwrap()
    })
}

fn scrub_email(text: &str) -> (Option<String>, u32) {
    replace_matches(text, email_re(), "[EMAIL]", |_, _, _| true, false)
}

fn iban_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\b[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}\b").unwrap(),
            Regex::new(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){3,8}\b").unwrap(),
            Regex::new(r"\b[a-z]{2}\d{2}(?:[ ]?[a-z0-9]{1,4}){3,8}\b").unwrap(),
        ]
    })
}

fn scrub_iban(text: &str) -> (Option<String>, u32) {
    scrub_patterns(
        text,
        iban_res(),
        "[IBAN]",
        |v, _, _| iban_valid(v),
        false,
    )
}

fn credit_card_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}\b").unwrap(),
            Regex::new(r"\b\d{4}[ -]\d{6}[ -]\d{5}\b").unwrap(),
            Regex::new(r"\b\d{13,19}\b").unwrap(),
        ]
    })
}

fn credit_card_valid(value: &str) -> bool {
    let mut digits = [0u8; 19];
    let mut len = 0usize;
    for b in value.bytes() {
        if b == b' ' || b == b'-' {
            continue;
        }
        if !b.is_ascii_digit() || len >= digits.len() {
            return false;
        }
        digits[len] = b;
        len += 1;
    }
    // SAFETY: len <= 19; digits[..len] are ASCII digits.
    luhn_valid(std::str::from_utf8(&digits[..len]).unwrap())
}

fn scrub_credit_card(text: &str) -> (Option<String>, u32) {
    scrub_patterns(
        text,
        credit_card_res(),
        "[CREDIT_CARD]",
        |v, _, _| credit_card_valid(v),
        false,
    )
}

// Sorted for binary_search.
const ISO_3166_1_ALPHA2: &[&str] = &[
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
    "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
    "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
    "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
    "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
    "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
    "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
    "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
    "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
    "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
];

fn bic_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap()
    })
}

fn bic_valid(value: &str) -> bool {
    let len = value.len();
    if len != 8 && len != 11 {
        return false;
    }
    ISO_3166_1_ALPHA2.binary_search(&&value[4..6]).is_ok()
}

fn scrub_bic(text: &str) -> (Option<String>, u32) {
    replace_matches(text, bic_re(), "[BIC]", |v, _, _| bic_valid(v), false)
}

fn mac_colon_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}").unwrap())
}

fn mac_cisco_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}").unwrap())
}

fn mac_colon_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == ':' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == ':' {
            return false;
        }
    }
    true
}

fn mac_cisco_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '.' {
            return false;
        }
    }
    true
}

fn scrub_mac(text: &str) -> (Option<String>, u32) {
    let (first, mut count) = replace_matches(
        text,
        mac_colon_re(),
        "[MAC]",
        |_, s, e| mac_colon_boundary_ok(text, s, e),
        true,
    );
    let (second, n) = {
        let src = first.as_deref().unwrap_or(text);
        replace_matches(
            src,
            mac_cisco_re(),
            "[MAC]",
            |_, s, e| mac_cisco_boundary_ok(src, s, e),
            true,
        )
    };
    count += n;
    (second.or(first), count)
}

fn location_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[-+]?\d{1,3}\.\d{3,8}\s*,\s*[-+]?\d{1,3}\.\d{3,8}").unwrap()
    })
}

fn location_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if prev.is_ascii_digit() || prev == '.' || prev == '+' || prev == '-' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if next.is_ascii_digit() || next == '.' {
            return false;
        }
    }
    true
}

fn location_valid(value: &str) -> bool {
    let trimmed = value.trim();
    let mut parts = trimmed.split(',');
    let Some(lat_s) = parts.next() else {
        return false;
    };
    let Some(lon_s) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    let Ok(lat) = lat_s.trim().parse::<f64>() else {
        return false;
    };
    let Ok(lon) = lon_s.trim().parse::<f64>() else {
        return false;
    };
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

fn scrub_location(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        location_re(),
        "[LOCATION]",
        |v, s, e| location_boundary_ok(text, s, e) && location_valid(v),
        true,
    )
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
        )
        .unwrap()
    })
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Candidate shapes; ``ip_valid`` drops non-addresses. Alternatives that end
    // with a hextet are listed before those that end with a bare ``:`` so the
    // linear-time regex crate prefers complete addresses (Python SRE relies on
    // a trailing lookahead to reject incomplete matches).
    RE.get_or_init(|| {
        Regex::new(
            r"(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::)",
        )
        .unwrap()
    })
}

fn ip_valid(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn ipv4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w.]) ... (?![\w.])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '.' {
            return false;
        }
    }
    true
}

fn ipv6_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w:]) ... (?![\w:])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == ':' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == ':' {
            return false;
        }
    }
    true
}

fn scrub_ip(text: &str) -> (Option<String>, u32) {
    let (first, mut count) = replace_matches(
        text,
        ipv4_re(),
        "[IP]",
        |v, s, e| ipv4_boundary_ok(text, s, e) && ip_valid(v),
        true,
    );
    let (second, n) = {
        let src = first.as_deref().unwrap_or(text);
        replace_matches(
            src,
            ipv6_re(),
            "[IP]",
            |v, s, e| ipv6_boundary_ok(src, s, e) && ip_valid(v),
            true,
        )
    };
    count += n;
    (second.or(first), count)
}

fn bsn_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{8,9}\b").unwrap())
}

fn scrub_bsn(text: &str) -> (Option<String>, u32) {
    replace_matches(text, bsn_re(), "[BSN]", |v, _, _| bsn_valid(v), false)
}

fn ssn_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            Regex::new(r"\b\d{9}\b").unwrap(),
        ]
    })
}

fn scrub_ssn(text: &str) -> (Option<String>, u32) {
    scrub_patterns(text, ssn_res(), "[SSN]", |v, _, _| ssn_valid(v), false)
}

fn tax_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{11}\b").unwrap())
}

fn scrub_tax_id(text: &str) -> (Option<String>, u32) {
    replace_matches(text, tax_id_re(), "[TAX_ID]", |v, _, _| tax_id_valid(v), false)
}

fn digit_count(text: &str) -> usize {
    text.bytes().filter(|b| b.is_ascii_digit()).count()
}

fn digits_only_starts_with_06(text: &str) -> bool {
    let mut digits = text.bytes().filter(|b| b.is_ascii_digit());
    matches!((digits.next(), digits.next()), (Some(b'0'), Some(b'6')))
}

fn phone_left_ok(text: &str, start: usize) -> bool {
    // (?<![\w+])
    if start == 0 {
        return true;
    }
    let prev = text[..start].chars().next_back().unwrap();
    !(is_word_char(prev) || prev == '+')
}

fn phone_international_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:\+|00)\d[\d .()\-]{6,16}\d").unwrap())
}

fn phone_international_valid(m: &str) -> bool {
    let n = digit_count(m);
    (8..=15).contains(&n)
}

fn phone_nl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"0\d(?:[ .\-]?\d){8}").unwrap())
}

fn phone_nl_valid(m: &str) -> bool {
    digit_count(m) == 10
}

fn phone_en_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}").unwrap())
}

fn phone_en_valid(m: &str) -> bool {
    digit_count(m) == 10
}

fn phone_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"0\d(?:[ .\-]?\d){8,10}").unwrap())
}

fn phone_de_valid(m: &str) -> bool {
    let n = digit_count(m);
    if !(10..=12).contains(&n) {
        return false;
    }
    !(n == 10 && digits_only_starts_with_06(m))
}

fn no_trailing_digit(text: &str, end: usize) -> bool {
    // (?!\d)
    if end >= text.len() {
        return true;
    }
    !text.as_bytes()[end].is_ascii_digit()
}

fn scrub_phone_international(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        phone_international_re(),
        "[PHONE]",
        |v, s, _| phone_left_ok(text, s) && phone_international_valid(v),
        true,
    )
}

fn scrub_phone_nl(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        phone_nl_re(),
        "[PHONE]",
        |v, s, e| phone_left_ok(text, s) && no_trailing_digit(text, e) && phone_nl_valid(v),
        true,
    )
}

fn scrub_phone_en(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        phone_en_re(),
        "[PHONE]",
        |v, s, e| phone_left_ok(text, s) && no_trailing_digit(text, e) && phone_en_valid(v),
        true,
    )
}

fn scrub_phone_de(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        phone_de_re(),
        "[PHONE]",
        |v, s, e| phone_left_ok(text, s) && no_trailing_digit(text, e) && phone_de_valid(v),
        true,
    )
}

fn nl_postcode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[1-9]\d{3}\s?[A-Z]{2}\b").unwrap())
}

fn scrub_nl_postcode(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        nl_postcode_re(),
        "[ADDRESS]",
        |v, _, _| nl_postcode_valid(v),
        false,
    )
}

fn nl_vat_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[Nn][Ll]\d{9}[Bb]\d{2}\b").unwrap())
}

fn scrub_nl_vat(text: &str) -> (Option<String>, u32) {
    replace_matches(text, nl_vat_re(), "[VAT_ID]", |_, _, _| true, false)
}

fn nl_license_plate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:[A-Z]{2}-\d{2}-\d{2}|\d{2}-\d{2}-[A-Z]{2}|\d{2}-[A-Z]{2}-\d{2}|[A-Z]{2}-\d{2}-[A-Z]{2}|[A-Z]{2}-[A-Z]{2}-\d{2}|\d{2}-[A-Z]{2}-[A-Z]{2}|\d{2}-[A-Z]{3}-\d|\d-[A-Z]{3}-\d{2}|[A-Z]{2}-\d{3}-[A-Z]|[A-Z]-\d{3}-[A-Z]{2}|[A-Z]{3}-\d{2}-[A-Z]|[A-Z]-\d{2}-[A-Z]{3}|\d-[A-Z]{2}-\d{3}|\d{3}-[A-Z]{2}-\d)",
        )
        .unwrap()
    })
}

const NL_PLATE_LETTER_REJECTS: &[&str] = &["SA", "SD", "SS"];

fn nl_plate_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '-' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '-' {
            return false;
        }
    }
    true
}

fn nl_license_plate_valid(value: &str) -> bool {
    let mut letters = [0u8; 16];
    let mut len = 0usize;
    for b in value.bytes() {
        if b.is_ascii_alphabetic() {
            if len >= letters.len() {
                break;
            }
            letters[len] = b.to_ascii_uppercase();
            len += 1;
        }
    }
    for i in 0..len.saturating_sub(1) {
        let pair = std::str::from_utf8(&letters[i..i + 2]).unwrap();
        if NL_PLATE_LETTER_REJECTS.contains(&pair) {
            return false;
        }
    }
    true
}

fn scrub_nl_license_plate(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        nl_license_plate_re(),
        "[LICENSE_PLATE]",
        |v, s, e| nl_plate_boundary_ok(text, s, e) && nl_license_plate_valid(v),
        true,
    )
}

const UNIVERSAL: &[Detector] = &[
    Detector {
        category: PiiCategory::Email,
        scrub: scrub_email,
    },
    Detector {
        category: PiiCategory::Iban,
        scrub: scrub_iban,
    },
    Detector {
        category: PiiCategory::CreditCard,
        scrub: scrub_credit_card,
    },
    Detector {
        category: PiiCategory::Bic,
        scrub: scrub_bic,
    },
    Detector {
        category: PiiCategory::Mac,
        scrub: scrub_mac,
    },
    Detector {
        category: PiiCategory::Ip,
        scrub: scrub_ip,
    },
    Detector {
        category: PiiCategory::Location,
        scrub: scrub_location,
    },
];

fn language_mask(languages: &[crate::LanguageCode]) -> u8 {
    let mut mask = 0u8;
    for &code in languages {
        mask |= match code {
            crate::LanguageCode::En => 0b001,
            crate::LanguageCode::Nl => 0b010,
            crate::LanguageCode::De => 0b100,
        };
    }
    mask
}

fn build_detectors(mask: u8) -> Vec<Detector> {
    let has_en = mask & 0b001 != 0;
    let has_nl = mask & 0b010 != 0;
    let has_de = mask & 0b100 != 0;
    let mut pack = UNIVERSAL.to_vec();

    if has_nl {
        pack.push(Detector {
            category: PiiCategory::Bsn,
            scrub: scrub_bsn,
        });
        pack.push(Detector {
            category: PiiCategory::VatId,
            scrub: scrub_nl_vat,
        });
    }
    if has_de {
        pack.push(Detector {
            category: PiiCategory::TaxId,
            scrub: scrub_tax_id,
        });
    }
    if has_en {
        pack.push(Detector {
            category: PiiCategory::Ssn,
            scrub: scrub_ssn,
        });
    }
    if has_nl {
        pack.push(Detector {
            category: PiiCategory::Address,
            scrub: scrub_nl_postcode,
        });
        pack.push(Detector {
            category: PiiCategory::LicensePlate,
            scrub: scrub_nl_license_plate,
        });
    }
    if mask != 0 {
        pack.push(Detector {
            category: PiiCategory::Phone,
            scrub: scrub_phone_international,
        });
    }
    if has_nl {
        pack.push(Detector {
            category: PiiCategory::Phone,
            scrub: scrub_phone_nl,
        });
    }
    if has_en {
        pack.push(Detector {
            category: PiiCategory::Phone,
            scrub: scrub_phone_en,
        });
    }
    if has_de {
        pack.push(Detector {
            category: PiiCategory::Phone,
            scrub: scrub_phone_de,
        });
    }
    pack
}

/// Ordered detector pack for language codes (`en` / `nl` / `de`).
///
/// Packs are cached by language bitmask (8 combinations).
pub fn detectors_for(languages: &[crate::LanguageCode]) -> &'static [Detector] {
    let mask = language_mask(languages) as usize;
    static CACHE: [OnceLock<Vec<Detector>>; 8] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    CACHE[mask]
        .get_or_init(|| build_detectors(mask as u8))
        .as_slice()
}
