//! Pattern detectors: regex + checksum where one exists.
//!
//! Patterns mirror `pii_mcp.detectors`. Python lookarounds are enforced with
//! explicit boundary checks so matching stays on the linear-time `regex` crate.

use crate::checksum::{
    bsn_valid, iban_valid, imei_valid, luhn_valid, nl_passport_valid, nl_postcode_valid, ssn_valid,
    tax_id_valid,
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
    Imei,
    Ip,
    Location,
    Bsn,
    Ssn,
    TaxId,
    VatId,
    Passport,
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
            Self::Imei => "imei",
            Self::Ip => "ip",
            Self::Location => "location",
            Self::Bsn => "bsn",
            Self::Ssn => "ssn",
            Self::TaxId => "tax_id",
            Self::VatId => "vat_id",
            Self::Passport => "passport",
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

/// Python/JS shorten when ``(?!@)`` is not enough — TLD may also absorb a
/// following IBAN/card/SSN/phone. The linear ``regex`` crate has no lookaround;
/// digit-bounded BSN/phone tails are checked in ``email_next_pii``.
fn email_next_pii_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"^(?:[A-Za-z]{2}\d{2}[A-Za-z0-9]|\d{13,19}|\d{3}[- ./]?\d{2}[- ./]?\d{4}|\d{3}[ .]\d{3}[ .]\d{3}|(?:\d{1,3}\.){3}\d{1,3}|\d{1,3}\.\d{3,8}|[0-9A-Fa-f]{2}([-:/.])[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{3,4}:|::)|[A-Za-z0-9._%+-]{1,64}@|[+0]\d)",
        )
        .unwrap()
    })
}

fn email_next_pii(text: &str, end: usize) -> bool {
    let rest = &text[end..];
    if email_next_pii_re().is_match(rest) {
        return true;
    }
    // ``\d{8,9}(?!\d)`` — BSN / short national id without lookaround.
    let bytes = rest.as_bytes();
    let mut n = 0usize;
    while n < bytes.len() && bytes[n].is_ascii_digit() {
        n += 1;
    }
    (8..=9).contains(&n)
}

fn email_end_ok(text: &str, end: usize) -> bool {
    if end >= text.len() {
        return true;
    }
    let next = text[end..].chars().next().unwrap();
    if next == '@' {
        return false;
    }
    if !next.is_ascii_alphanumeric() {
        return true;
    }
    email_next_pii(text, end)
}

fn email_should_peel(text: &str, start: usize, end: usize) -> bool {
    let pattern = email_re();
    let mut try_end = end;
    while try_end > start {
        try_end -= 1;
        while try_end > start && !text.is_char_boundary(try_end) {
            try_end -= 1;
        }
        let ch = text[try_end..].chars().next().unwrap();
        if !ch.is_ascii_alphabetic() {
            break;
        }
        let cand = &text[start..try_end];
        if let Some(mm) = pattern.find(cand) {
            if mm.start() == 0 && mm.end() == cand.len() && email_next_pii(text, try_end) {
                return true;
            }
        }
    }
    false
}

fn scrub_email(text: &str) -> (Option<String>, u32) {
    let pattern = email_re();
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        let start = m.start();
        let mut end = m.end();
        if !email_end_ok(text, end) || email_should_peel(text, start, end) {
            let mut shortened = None;
            for try_end in (start + 1..end).rev() {
                if !text.is_char_boundary(try_end) {
                    continue;
                }
                let cand = &text[start..try_end];
                if let Some(mm) = pattern.find(cand) {
                    if mm.start() == 0 && mm.end() == cand.len() && email_end_ok(text, try_end)
                    {
                        shortened = Some(try_end);
                        break;
                    }
                }
            }
            match shortened {
                Some(e) => end = e,
                None => {
                    pos = start + 1;
                    continue;
                }
            }
        }
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..start]);
        buf.push_str("[EMAIL]");
        last = end;
        pos = end;
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

fn iban_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        // Unicode Zs separators commonly used in OCR / rich text.
        let sep = r"[ \t\r\n\u{00a0}\u{2000}-\u{200a}\u{202f}\u{3000}]";
        vec![
            // Compact: boundary emulated in ``iban_glue_boundary_ok``.
            Regex::new(r"[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}").unwrap(),
            Regex::new(&format!(
                r"\b[A-Z]{{2}}\d{{2}}(?:{sep}?[A-Z0-9]{{1,4}}){{3,8}}\b"
            ))
            .unwrap(),
            Regex::new(&format!(
                r"\b[a-z]{{2}}\d{{2}}(?:{sep}?[a-z0-9]{{1,4}}){{3,8}}\b"
            ))
            .unwrap(),
            // Mixed case / hyphen|slash|dot|whitespace groups (one or more seps).
            Regex::new(&format!(
                r"[A-Za-z]{{2}}\d{{2}}(?:(?:{sep}|[\-/.])+[A-Za-z0-9]{{1,4}}){{3,8}}"
            ))
            .unwrap(),
            // Single hyphen after check digits, compact BBAN.
            Regex::new(r"[A-Za-z]{2}\d{2}-[A-Za-z0-9]{11,30}").unwrap(),
        ]
    })
}

/// ``(?<![A-Za-z])…(?![A-Za-z0-9])`` — allow after digits (card|IBAN glue).
fn iban_glue_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if prev.is_ascii_alphabetic() {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if next.is_ascii_alphanumeric() {
            return false;
        }
    }
    true
}

/// Emulate ``(?![A-Za-z0-9])`` backtracking: greedy sep-groups may swallow the
/// next word (``…00 please`` → ``…00 plea``); walk the end left until the
/// candidate is a full pattern match, boundary-ok, and checksum-valid.
fn iban_glue_accept(text: &str, pattern: &Regex, start: usize, end: usize) -> Option<usize> {
    let mut try_end = end;
    while try_end > start {
        if iban_glue_boundary_ok(text, start, try_end) {
            let cand = &text[start..try_end];
            if let Some(m) = pattern.find(cand) {
                if m.start() == 0 && m.end() == cand.len() && iban_valid(cand) {
                    return Some(try_end);
                }
            }
        }
        try_end -= 1;
        while try_end > start && !text.is_char_boundary(try_end) {
            try_end -= 1;
        }
    }
    None
}

fn strip_invisible(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{00ad}' | '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}'
            )
        })
        .collect()
}

fn scrub_iban(text: &str) -> (Option<String>, u32) {
    let cleaned = strip_invisible(text);
    let patterns = iban_res();
    let mut current: Option<String> = None;
    let mut count = 0u32;
    for (i, pattern) in patterns.iter().enumerate() {
        let need_glue = i == 0 || i == 3 || i == 4;
        let src = current.as_deref().unwrap_or(cleaned.as_str());
        if need_glue {
            let (next, n) = replace_iban_glue(src, pattern);
            count += n;
            if let Some(s) = next {
                current = Some(s);
            }
        } else {
            let (next, n) = replace_matches(src, pattern, "[IBAN]", |v, _, _| iban_valid(v), false);
            count += n;
            if let Some(s) = next {
                current = Some(s);
            }
        }
    }
    match current {
        Some(s) => (Some(s), count),
        None if cleaned.as_str() != text => (Some(cleaned), count),
        None => (None, count),
    }
}

fn replace_iban_glue(text: &str, pattern: &Regex) -> (Option<String>, u32) {
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        let start = m.start();
        let end = m.end();
        let Some(ok_end) = iban_glue_accept(text, pattern, start, end) else {
            pos = start + 1;
            continue;
        };
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..start]);
        buf.push_str("[IBAN]");
        last = ok_end;
        pos = ok_end;
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

fn credit_card_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        // One or more whitespace / dash / punct separators between digit groups.
        let sep_space = r"[ \t\r\n\u{00a0}\u{2000}-\u{200a}\u{202f}\u{3000}]";
        let sep = format!(r"(?:{sep_space}|[./\-\u{{2010}}-\u{{2015}}])+");
        vec![
            // 17–19 digit PANs (UnionPay, Maestro, Visa) group as 4-4-4-4-x.
            Regex::new(&format!(
                r"\d{{4}}{sep}\d{{4}}{sep}\d{{4}}{sep}\d{{4}}{sep}\d{{1,3}}"
            ))
            .unwrap(),
            Regex::new(&format!(r"\d{{4}}{sep}\d{{4}}{sep}\d{{4}}{sep}\d{{1,4}}")).unwrap(),
            Regex::new(&format!(r"\d{{4}}{sep}\d{{6}}{sep}\d{{5}}")).unwrap(),
            // Diners Club 14-digit 4-6-4.
            Regex::new(&format!(r"\d{{4}}{sep}\d{{6}}{sep}\d{{4}}")).unwrap(),
            // Digit/letter glue: \b does not split 1N.
            Regex::new(r"\d{13,19}").unwrap(),
        ]
    })
}

/// ``(?<!\d)…(?!\d)`` emulation for compact / grouped cards.
fn digit_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 && text.as_bytes()[start - 1].is_ascii_digit() {
        return false;
    }
    if end < text.len() && text.as_bytes()[end].is_ascii_digit() {
        return false;
    }
    true
}

fn credit_card_valid(value: &str) -> bool {
    let mut digits = [0u8; 19];
    let mut len = 0usize;
    for c in value.chars() {
        if !c.is_ascii_digit() {
            continue;
        }
        if len >= digits.len() {
            return false;
        }
        digits[len] = c as u8;
        len += 1;
    }
    // SAFETY: len <= 19; digits[..len] are ASCII digits.
    let digits = std::str::from_utf8(&digits[..len]).unwrap();
    // Issuer prefix (see Python ``_card_valid``): 2–6, 15 digits, or 16-digit
    // RuPay 81/82 / Troy 9792.
    let prefix_ok = matches!(digits.as_bytes().first(), Some(b'2'..=b'6'))
        || len == 15
        || (len == 16
            && (digits.starts_with("81")
                || digits.starts_with("82")
                || digits.starts_with("9792")));
    prefix_ok && luhn_valid(digits)
}

fn scrub_credit_card(text: &str) -> (Option<String>, u32) {
    let cleaned = strip_invisible(text);
    let mut current: Option<String> = None;
    let mut count = 0u32;
    for pattern in credit_card_res() {
        let (next, n) = {
            let src = current.as_deref().unwrap_or(cleaned.as_str());
            replace_matches(
                src,
                pattern,
                "[CREDIT_CARD]",
                |v, s, e| digit_boundary_ok(src, s, e) && credit_card_valid(v),
                true,
            )
        };
        count += n;
        if let Some(s) = next {
            current = Some(s);
        }
    }
    (current, count)
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
    RE.get_or_init(|| Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").unwrap())
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

fn mac_dot_ieee_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[0-9A-Fa-f]{2}\.){5}[0-9A-Fa-f]{2}").unwrap())
}

fn mac_cisco_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}").unwrap())
}

/// Allow ``label:<hit>``; reject when the ``:`` continues a colon-hex run
/// (the token before it is empty or a 1–4 digit hex group).
fn colon_label_ok(text: &str, start: usize) -> bool {
    let Some(before) = text[..start].strip_suffix(':') else {
        return true;
    };
    let token_start = before
        .char_indices()
        .rev()
        .take_while(|(_, c)| is_word_char(*c))
        .last()
        .map_or(before.len(), |(i, _)| i);
    let token = &before[token_start..];
    !(token.len() <= 4 && token.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn mac_colon_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || !colon_label_ok(text, start) {
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

fn mac_dot_boundary_ok(text: &str, start: usize, end: usize) -> bool {
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
            mac_dot_ieee_re(),
            "[MAC]",
            |_, s, e| mac_dot_boundary_ok(src, s, e),
            true,
        )
    };
    count += n;
    let (third, n) = {
        let src = second.as_deref().or(first.as_deref()).unwrap_or(text);
        replace_matches(
            src,
            mac_cisco_re(),
            "[MAC]",
            |_, s, e| mac_dot_boundary_ok(src, s, e),
            true,
        )
    };
    count += n;
    (third.or(second).or(first), count)
}

// Grouped only — compact 15-digit Luhn values collide with Amex credit cards.
fn imei_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\d{2}[- ./]\d{6}[- ./]\d{6}[- ./]\d").unwrap(),
            Regex::new(r"\d{8}[- ./]\d{6}[- ./]\d").unwrap(),
            Regex::new(r"\d{2}[- ./]\d{6}[- ./]\d{7}").unwrap(),
        ]
    })
}

fn imei_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w.-]) … (?![\w.-])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '-' || prev == '.' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '-' || next == '.' {
            return false;
        }
    }
    true
}

fn scrub_imei(text: &str) -> (Option<String>, u32) {
    let mut current: Option<String> = None;
    let mut count = 0u32;
    for pattern in imei_res() {
        let (next, n) = {
            let src = current.as_deref().unwrap_or(text);
            replace_matches(
                src,
                pattern,
                "[IMEI]",
                |v, s, e| imei_boundary_ok(src, s, e) && imei_valid(v),
                true,
            )
        };
        count += n;
        if let Some(s) = next {
            current = Some(s);
        }
    }
    (current, count)
}

fn location_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[NnSs])?\s*,\s*[-+]?\d{1,3}\.\d{3,8}°?(?:\s*[EeWw])?",
        )
        .unwrap()
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
        if next.is_ascii_digit() || next == '.' || next.is_ascii_alphabetic() {
            return false;
        }
    }
    true
}

fn coord_component(part: &str) -> Option<f64> {
    let cleaned: String = part
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '+' || *c == '-')
        .collect();
    cleaned.parse().ok()
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
    let Some(lat) = coord_component(lat_s) else {
        return false;
    };
    let Some(lon) = coord_component(lon_s) else {
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
        Regex::new(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)")
            .unwrap()
    })
}

/// IPv6 with a trailing dotted quad (``::ffff:a.b.c.d``, NAT64 ``64:ff9b::a.b.c.d``).
fn ipv6_v4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)",
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

fn normalize_ipv4_octets(value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut nums = [0u32; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        nums[i] = n;
    }
    Some(format!("{}.{}.{}.{}", nums[0], nums[1], nums[2], nums[3]))
}

fn ip_valid(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((head, tail)) = value.rsplit_once(':') {
        return normalize_ipv4_octets(tail)
            .is_some_and(|norm| format!("{head}:{norm}").parse::<std::net::IpAddr>().is_ok());
    }
    normalize_ipv4_octets(value).is_some()
}

fn ipv4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w.]) ... (?![\w.]) — IPv6-embedded forms are consumed first.
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

fn ipv6_v4_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w:.]) ... (?![\w.])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == ':' || prev == '.' {
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

/// Linear regex prefers a short ``X:X:X::X`` prefix of a longer address; extend
/// by trailing ``:hextet`` so ``2001:db8:85a3::8a2e:370:7334`` still matches.
fn extend_ipv6_end(text: &str, mut end: usize) -> usize {
    loop {
        let Some(rest) = text.get(end..) else {
            break;
        };
        if !rest.starts_with(':') || rest.starts_with("::") {
            break;
        }
        let after = &rest[1..];
        let hextet_len = after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .count();
        if !(1..=4).contains(&hextet_len) {
            break;
        }
        let new_end = end + 1 + hextet_len;
        if new_end < text.len() {
            let n = text[new_end..].chars().next().unwrap();
            if n.is_ascii_hexdigit() {
                break;
            }
        }
        end = new_end;
    }
    end
}

fn scrub_ipv6(text: &str) -> (Option<String>, u32) {
    let pattern = ipv6_re();
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        let start = m.start();
        let end = extend_ipv6_end(text, m.end());
        let value = &text[start..end];
        if !(ipv6_boundary_ok(text, start, end) && ip_valid(value)) {
            pos = start + 1;
            continue;
        }
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..start]);
        buf.push_str("[IP]");
        last = end;
        pos = end;
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

fn scrub_ip(text: &str) -> (Option<String>, u32) {
    let (mapped, mut count) = replace_matches(
        text,
        ipv6_v4_re(),
        "[IP]",
        |v, s, e| ipv6_v4_boundary_ok(text, s, e) && ip_valid(v),
        true,
    );
    let (first, n) = {
        let src = mapped.as_deref().unwrap_or(text);
        replace_matches(
            src,
            ipv4_re(),
            "[IP]",
            |v, s, e| ipv4_boundary_ok(src, s, e) && ip_valid(v),
            true,
        )
    };
    count += n;
    let (second, n) = {
        let src = first
            .as_deref()
            .or(mapped.as_deref())
            .unwrap_or(text);
        scrub_ipv6(src)
    };
    count += n;
    (second.or(first).or(mapped), count)
}

fn bsn_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\b\d{8,9}\b").unwrap(),
            Regex::new(r"\b\d{3}[ .\-]\d{3}[ .\-]\d{3}\b").unwrap(),
        ]
    })
}

fn scrub_bsn(text: &str) -> (Option<String>, u32) {
    scrub_patterns(text, bsn_res(), "[BSN]", |v, _, _| bsn_valid(v), false)
}

fn ssn_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            Regex::new(r"\b\d{3}/\d{2}/\d{4}\b").unwrap(),
            Regex::new(r"\b\d{3}[ .]\d{2}[ .]\d{4}\b").unwrap(),
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
    replace_matches(
        text,
        tax_id_re(),
        "[TAX_ID]",
        |v, _, _| tax_id_valid(v),
        false,
    )
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
    RE.get_or_init(|| Regex::new(r"\(?0\d\)?(?:[ .\-/()]?\d){8}").unwrap())
}

fn phone_nl_valid(m: &str) -> bool {
    digit_count(m) == 10
}

fn phone_en_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]\d{4}").unwrap()
    })
}

fn phone_en_valid(m: &str) -> bool {
    let n = digit_count(m);
    if n == 10 {
        return true;
    }
    if n != 11 {
        return false;
    }
    m.bytes().find(|b| b.is_ascii_digit()) == Some(b'1')
}

fn phone_de_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\(?0\d\)?(?:[ .\-/()]?\d){8,10}").unwrap())
}

fn phone_de_valid(m: &str) -> bool {
    let n = digit_count(m);
    if !(10..=12).contains(&n) {
        return false;
    }
    if n == 10 && digits_only_starts_with_06(m) {
        return false;
    }
    // Separator-free 12-digit runs collide with UPC-A barcodes.
    if n == 12 && m.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    true
}

fn no_trailing_digit(text: &str, end: usize) -> bool {
    // (?!\d)
    if end >= text.len() {
        return true;
    }
    !text.as_bytes()[end].is_ascii_digit()
}

fn no_trailing_hex_letters(text: &str, end: usize) -> bool {
    // (?![A-Fa-f]{2}) — hex digest glue after a digit run (sha256:0123…abcd).
    let bytes = text.as_bytes();
    if end + 1 >= bytes.len() {
        return true;
    }
    let a = bytes[end];
    let b = bytes[end + 1];
    !(a.is_ascii_hexdigit() && a.is_ascii_alphabetic() && b.is_ascii_hexdigit() && b.is_ascii_alphabetic())
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
        |v, s, e| {
            phone_left_ok(text, s)
                && no_trailing_digit(text, e)
                && no_trailing_hex_letters(text, e)
                && phone_nl_valid(v)
        },
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
        |v, s, e| {
            phone_left_ok(text, s)
                && no_trailing_digit(text, e)
                && no_trailing_hex_letters(text, e)
                && phone_de_valid(v)
        },
        true,
    )
}

fn nl_postcode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[1-9]\d{3}\s+[A-Z]{2}\b|\b[1-9]\d{3}[A-Z]{2}\b").unwrap()
    })
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
    RE.get_or_init(|| Regex::new(r"\b[Nn][Ll][.\s]*\d{9}[.\s]*[Bb][.\s]*\d{2}\b").unwrap())
}

fn scrub_nl_vat(text: &str) -> (Option<String>, u32) {
    replace_matches(text, nl_vat_re(), "[VAT_ID]", |_, _, _| true, false)
}

fn nl_passport_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b[A-Z]{2}[0-9A-Z]{6}\d\b").unwrap())
}

fn scrub_nl_passport(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        nl_passport_re(),
        "[PASSPORT]",
        |v, _, _| nl_passport_valid(v),
        false,
    )
}

fn nl_license_plate_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:[A-Z]{2}-\d{2}-\d{2}|\d{2}-\d{2}-[A-Z]{2}|\d{2}-[A-Z]{2}-\d{2}|[A-Z]{2}-\d{2}-[A-Z]{2}|[A-Z]{2}-[A-Z]{2}-\d{2}|\d{2}-[A-Z]{2}-[A-Z]{2}|\d{2}-[A-Z]{3}-\d|\d-[A-Z]{3}-\d{2}|[A-Z]{2}-\d{3}-[A-Z]|[A-Z]-\d{3}-[A-Z]{2}|[A-Z]{3}-\d{2}-[A-Z]|[A-Z]-\d{2}-[A-Z]{3}|\d-[A-Z]{2}-\d{3}|\d{3}-[A-Z]{2}-\d)",
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
        category: PiiCategory::Imei,
        scrub: scrub_imei,
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

    if mask != 0 {
        pack.push(Detector {
            category: PiiCategory::Phone,
            scrub: scrub_phone_international,
        });
    }
    if has_nl {
        pack.push(Detector {
            category: PiiCategory::Bsn,
            scrub: scrub_bsn,
        });
        pack.push(Detector {
            category: PiiCategory::VatId,
            scrub: scrub_nl_vat,
        });
        pack.push(Detector {
            category: PiiCategory::Passport,
            scrub: scrub_nl_passport,
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
