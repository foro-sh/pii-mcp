//! Pattern detectors: regex + checksum where one exists.
//!
//! Patterns mirror `pii_mcp.detectors`. Python lookarounds are enforced with
//! explicit boundary checks so matching stays on the linear-time `regex` crate.

use crate::checksum::{
    bsn_valid, iban_valid, imei_valid, is_group_sep, luhn_valid, nl_passport_valid,
    nl_postcode_valid, ssn_valid, tax_id_valid, GROUP_DASHES, GROUP_SPACES,
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
    replace_matches_end(
        text,
        pattern,
        placeholder,
        |s, e| if accept(&text[s..e], s, e) { e } else { s },
        retry_on_reject,
    )
}

/// Like ``replace_matches``, but ``accept_end(start, end)`` returns where the
/// replacement ends (``start`` rejects), so a hit can be cut back or
/// re-measured against the surrounding text.
fn replace_matches_end<F>(
    text: &str,
    pattern: &Regex,
    placeholder: &str,
    mut accept_end: F,
    retry_on_reject: bool,
) -> (Option<String>, u32)
where
    F: FnMut(usize, usize) -> usize,
{
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        let end = accept_end(m.start(), m.end());
        if end == m.start() {
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

/// Scripts written without spaces (Thai, Lao, Tibetan, Myanmar, Khmer, kana,
/// Bopomofo, CJK, Hangul, fullwidth forms) glue prose straight onto an
/// address (``请发送至ada@example.com以便``), so a TLD is either all such
/// script or free of it, and one such letter after the TLD ends the address.
/// The local part may mix scripts (``田中123@``): glued prose before it is
/// over-masked rather than a name part leaked.
const UNSPACED_SCRIPTS: &str = r"[\u{0e00}-\u{0eff}\u{0f00}-\u{0fff}\u{1000}-\u{109f}\u{1100}-\u{11ff}\u{1780}-\u{17ff}\u{3000}-\u{31ff}\u{3400}-\u{4dbf}\u{4e00}-\u{9fff}\u{a960}-\u{a97f}\u{ac00}-\u{d7ff}\u{f900}-\u{faff}\u{ff00}-\u{ffef}\u{20000}-\u{3ffff}]";
/// Email local part (1–64 chars): Unicode letters / digits plus ``_.%+-``.
const EMAIL_LOCAL: &str = r"[\p{L}\p{N}_.%+\-]{1,64}";

fn is_unspaced_script(c: char) -> bool {
    matches!(
        c,
        '\u{0e00}'..='\u{0eff}'
            | '\u{0f00}'..='\u{0fff}'
            | '\u{1000}'..='\u{109f}'
            | '\u{1100}'..='\u{11ff}'
            | '\u{1780}'..='\u{17ff}'
            | '\u{3000}'..='\u{31ff}'
            | '\u{3400}'..='\u{4dbf}'
            | '\u{4e00}'..='\u{9fff}'
            | '\u{a960}'..='\u{a97f}'
            | '\u{ac00}'..='\u{d7ff}'
            | '\u{f900}'..='\u{faff}'
            | '\u{ff00}'..='\u{ffef}'
            | '\u{20000}'..='\u{3ffff}'
    )
}

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Letters and digits are Unicode (EAI / IDN: ``josé@example.com``,
        // ``ada@münchen.de``), matching Python's ``\w`` / ``[^\W_]``, except
        // that a TLD may not mix unspaced scripts with others (see
        // ``UNSPACED_SCRIPTS``). Bounded Unicode classes need a larger
        // lazy-DFA cache than the 2 MiB default, or big inputs fall back to
        // the ~30x slower NFA engine.
        regex::RegexBuilder::new(&format!(
            r"{EMAIL_LOCAL}@[\p{{L}}\p{{N}}-]{{1,63}}(?:\.[\p{{L}}\p{{N}}-]{{1,63}})*\.(?:[\p{{L}}--{UNSPACED_SCRIPTS}]{{2,24}}|[\p{{L}}&&{UNSPACED_SCRIPTS}]{{2,24}})"
        ))
        .dfa_size_limit(16 << 20)
        .build()
        .unwrap()
    })
}

/// Python/JS shorten when ``(?!@)`` is not enough — TLD may also absorb a
/// following IBAN/card/SSN/phone. The linear ``regex`` crate has no lookaround;
/// digit-bounded BSN/phone tails are checked in ``email_next_pii``.
fn email_next_pii_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r"^(?:[A-Za-z]{{2}}\d{{2}}[A-Za-z0-9]|\d{{13,19}}|\d{{3}}[- ./]?\d{{2}}[- ./]?\d{{4}}|\d{{3}}[ .]\d{{3}}[ .]\d{{3}}|(?:\d{{1,3}}\.){{3}}\d{{1,3}}|\d{{1,3}}\.\d{{3,8}}|[0-9A-Fa-f]{{2}}([-:/.])[0-9A-Fa-f]{{2}}|(?:[0-9A-Fa-f]{{3,4}}:|::)|{EMAIL_LOCAL}@|[+0]\d)",
        ))
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
    if !next.is_alphanumeric() || is_unspaced_script(next) {
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
        if !ch.is_alphabetic() {
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
                // Python's ``(?!@)`` never yields a match right before ``@``.
                None if text[end..].starts_with('@') => {
                    pos = start + 1;
                    continue;
                }
                // No clean shorter end (letters glued after the TLD): mask the
                // match as found rather than leak the address.
                None => {}
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
            let (next, n) = replace_iban_cut(src, pattern);
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

fn is_iban_sep(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\r' | '\n' | '\u{00a0}' | '\u{2000}'
            ..='\u{200a}' | '\u{202f}' | '\u{3000}' | '-' | '/' | '.'
    )
}

/// Length of the longest prefix, cut at a group separator, that passes the
/// IBAN check (``GB82 BIWD … 25 role`` swallowed a word); 0 rejects.
fn iban_accept_len(value: &str) -> usize {
    if iban_valid(value) {
        return value.len();
    }
    let mut prev_sep = false;
    let mut cuts = Vec::new();
    for (i, c) in value.char_indices() {
        let sep = is_iban_sep(c);
        if sep && !prev_sep {
            cuts.push(i);
        }
        prev_sep = sep;
    }
    cuts.into_iter()
        .rev()
        .find(|&i| iban_valid(&value[..i]))
        .unwrap_or(0)
}

/// ``\b``-bounded patterns: replace the valid prefix; a reject resumes at the
/// match end like Python ``re``.
fn replace_iban_cut(text: &str, pattern: &Regex) -> (Option<String>, u32) {
    replace_matches_end(
        text,
        pattern,
        "[IBAN]",
        |s, e| s + iban_accept_len(&text[s..e]),
        false,
    )
}

fn replace_iban_glue(text: &str, pattern: &Regex) -> (Option<String>, u32) {
    replace_matches_end(
        text,
        pattern,
        "[IBAN]",
        |s, e| iban_glue_accept(text, pattern, s, e).unwrap_or(s),
        true,
    )
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
    // 13-digit PANs were only ever issued by Visa (4); other runs are EANs.
    if len == 13 && !digits.starts_with('4') {
        return false;
    }
    // 17–19 digits: only Visa, Maestro, Discover/UnionPay (6), JCB 35 and Mir
    // 2200–2204 issue long PANs; 2/3-led snowflake ids are not cards.
    if len >= 17
        && !["4", "5", "6", "35", "2200", "2201", "2202", "2203", "2204"]
            .iter()
            .any(|p| digits.starts_with(p))
    {
        return false;
    }
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

/// Huawei / H3C ``aabb-ccdd-eeff``; ``mac_dash_valid`` needs a hex letter.
fn mac_dash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:[0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4}").unwrap())
}

/// A 4-4-4 dash run of digits only is a part / order number, not a MAC.
fn mac_dash_valid(value: &str) -> bool {
    value.bytes().any(|b| b.is_ascii_hexdigit() && b.is_ascii_alphabetic())
}

fn mac_dash_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![\w.-]) … (?![\w.-])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' || prev == '-' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '.' || next == '-' {
            return false;
        }
    }
    true
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
    let (fourth, n) = {
        let src = third
            .as_deref()
            .or(second.as_deref())
            .or(first.as_deref())
            .unwrap_or(text);
        replace_matches(
            src,
            mac_dash_re(),
            "[MAC]",
            |v, s, e| mac_dash_boundary_ok(src, s, e) && mac_dash_valid(v),
            true,
        )
    };
    count += n;
    (fourth.or(third).or(second).or(first), count)
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
    // |lat|,|lon| <= 1 is open ocean (Gulf of Guinea): embedding / weight vectors.
    if lat.abs() <= 1.0 && lon.abs() <= 1.0 {
        return false;
    }
    (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon)
}

/// Degrees-minutes(-seconds) as maps, EXIF, and GPS units print them
/// (``52°22'3.4"N 4°54'14.8"E``, ``N 52° 22.057' E 4° 54.246'``). Each half
/// needs a degree sign, a minute mark, and a hemisphere letter before or after
/// (Dutch / German ``Z`` / ``O`` for south / east); prime and double-prime
/// glyphs stand in for ``'`` / ``"``.
fn location_dms_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let body = r#"\d{1,3}\s?[°º]\s?\d{1,2}(?:[.,]\d{1,4})?\s?['′’](?:\s?\d{1,2}(?:[.,]\d{1,4})?\s?(?:["″”]|''|′′))?"#;
        Regex::new(&format!(
            r"(?:[NSZ]\s?{body}|{body}\s?[NSZ])\s{{0,3}}[,;/]?\s{{0,3}}(?:[EOW]\s?{body}|{body}\s?[EOW])"
        ))
        .unwrap()
    })
}

fn location_dms_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    // (?<![A-Za-z0-9_.]) … (?![A-Za-z0-9_])
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) {
            return false;
        }
    }
    true
}

/// Numbers (``3`` / ``3.4`` / ``3,4``) in a DMS fragment.
fn dms_numbers(part: &str) -> Vec<f64> {
    let mut out = Vec::new();
    let mut chars = part.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if !c.is_ascii_digit() {
            continue;
        }
        let mut end = i + 1;
        let mut seen_sep = false;
        while let Some(&(j, d)) = chars.peek() {
            if d.is_ascii_digit() {
                end = j + 1;
                chars.next();
            } else if (d == '.' || d == ',')
                && !seen_sep
                && part[j + 1..].starts_with(|n: char| n.is_ascii_digit())
            {
                seen_sep = true;
                chars.next();
            } else {
                break;
            }
        }
        if let Ok(n) = part[i..end].replace(',', ".").parse() {
            out.push(n);
        }
    }
    out
}

/// Degrees within ±90 / ±180, minutes and seconds below 60. The two degree
/// signs split the hit: the number before the first is the latitude degrees,
/// the one before the second the longitude degrees.
fn location_dms_valid(value: &str) -> bool {
    let parts: Vec<&str> = value.split(['°', 'º']).collect();
    if parts.len() != 3 {
        return false;
    }
    let lat = dms_numbers(parts[0]);
    let mid = dms_numbers(parts[1]);
    let (Some(&lat_deg), Some((&lon_deg, lat_ms))) = (lat.last(), mid.split_last()) else {
        return false;
    };
    lat_deg <= 90.0
        && lon_deg <= 180.0
        && lat_ms
            .iter()
            .chain(dms_numbers(parts[2]).iter())
            .all(|&n| n < 60.0)
}

fn scrub_location(text: &str) -> (Option<String>, u32) {
    let (dms, dms_count) = replace_matches(
        text,
        location_dms_re(),
        "[LOCATION]",
        |v, s, e| location_dms_boundary_ok(text, s, e) && location_dms_valid(v),
        true,
    );
    let src = dms.as_deref().unwrap_or(text);
    let (decimal, count) = scrub_location_decimal(src);
    (decimal.or(dms), dms_count + count)
}

fn scrub_location_decimal(text: &str) -> (Option<String>, u32) {
    let accept =
        |s: usize, e: usize| location_boundary_ok(text, s, e) && location_valid(&text[s..e]);
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = location_re().find_at(text, pos) {
        let start = m.start();
        let mut end = m.end();
        if !accept(start, end) {
            // Python backtracks the optional E/W letter (``4.9041 exactly``);
            // the linear regex keeps it, so retry without it.
            let shorter = m
                .as_str()
                .strip_suffix(['E', 'e', 'W', 'w'])
                .map(|v| start + v.trim_end().len())
                .filter(|&e| accept(start, e));
            let Some(e) = shorter else {
                pos = start + 1;
                continue;
            };
            end = e;
        }
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..start]);
        buf.push_str("[LOCATION]");
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
    // (?<![\w.]) ... (?![\w.]); a label colon is left to ``colon_label_ok``.
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' || !colon_label_ok(text, start) {
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
    // (?<!\w) ... (?![\w:]); a label colon (``user:2001:db8::1``) is left to
    // ``colon_label_ok``.
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

/// Regex class body for ``chars`` (``checksum::GROUP_SPACES`` /
/// ``GROUP_DASHES``), so the patterns and the separator checks share one list.
fn group_class(chars: &[char]) -> String {
    chars
        .iter()
        .map(|&c| format!(r"\u{{{:04x}}}", u32::from(c)))
        .collect()
}

/// National-id group separators: space or ``GROUP_SPACES``.
fn id_space() -> String {
    format!("[ {}]", group_class(&GROUP_SPACES))
}

/// National-id group separators: hyphen or ``GROUP_DASHES``.
fn id_dash() -> String {
    format!(r"[\-{}]", group_class(&GROUP_DASHES))
}

fn bsn_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        let id_space = id_space();
        let id_dash = id_dash();
        let sep = format!(r"(?:{id_space}|{id_dash}|\.)");
        vec![
            Regex::new(r"\b\d{8,9}\b").unwrap(),
            Regex::new(&format!(r"\b\d{{3}}{sep}\d{{3}}{sep}\d{{3}}\b")).unwrap(),
        ]
    })
}

/// ``(?<!\d\.)``: the fractional part of a decimal (``0.12345678``) is not an id.
fn not_decimal_fraction(text: &str, start: usize) -> bool {
    let b = text.as_bytes();
    !(start >= 2 && b[start - 1] == b'.' && b[start - 2].is_ascii_digit())
}

fn scrub_bsn(text: &str) -> (Option<String>, u32) {
    let res = bsn_res();
    let (first, mut count) = replace_matches(
        text,
        &res[0],
        "[BSN]",
        |v, s, _| not_decimal_fraction(text, s) && bsn_valid(v),
        false,
    );
    let src = first.as_deref().unwrap_or(text);
    let (second, n) = replace_matches(src, &res[1], "[BSN]", |v, _, _| bsn_valid(v), false);
    count += n;
    (second.or(first), count)
}

fn ssn_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        let id_space = id_space();
        let id_dash = id_dash();
        vec![
            Regex::new(&format!(r"\b\d{{3}}{id_dash}\d{{2}}{id_dash}\d{{4}}\b")).unwrap(),
            Regex::new(r"\b\d{3}/\d{2}/\d{4}\b").unwrap(),
            Regex::new(&format!(
                r"\b\d{{3}}(?:{id_space}|\.)\d{{2}}(?:{id_space}|\.)\d{{4}}\b"
            ))
            .unwrap(),
            Regex::new(r"\b\d{9}\b").unwrap(),
        ]
    })
}

fn scrub_ssn(text: &str) -> (Option<String>, u32) {
    let res = ssn_res();
    let (grouped, mut count) =
        scrub_patterns(text, &res[..3], "[SSN]", |v, _, _| ssn_valid(v), false);
    let src = grouped.as_deref().unwrap_or(text);
    let (compact, n) = replace_matches(
        src,
        &res[3],
        "[SSN]",
        |v, s, _| not_decimal_fraction(src, s) && ssn_valid(v),
        false,
    );
    count += n;
    (compact.or(grouped), count)
}

/// Compact, or the ``12 345 678 901`` grouping printed on Steuerbescheide and
/// payslips (single space / nbsp between groups).
fn tax_id_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        let id_space = id_space();
        vec![
            Regex::new(r"\b\d{11}\b").unwrap(),
            Regex::new(&format!(
                r"\b\d{{2}}{id_space}\d{{3}}{id_space}\d{{3}}{id_space}\d{{3}}\b"
            ))
            .unwrap(),
        ]
    })
}

fn scrub_tax_id(text: &str) -> (Option<String>, u32) {
    scrub_patterns(
        text,
        tax_id_res(),
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

/// An opening ``(`` belongs to the number only when it wraps the area code
/// (``(06)…``); ``(06-1234…)`` is retried from the ``0``.
fn phone_paren_ok(m: &str) -> bool {
    !m.starts_with('(') || m.contains(')')
}

fn phone_left_ok(text: &str, start: usize) -> bool {
    // (?<![\w+])
    if start == 0 {
        return true;
    }
    let prev = text[..start].chars().next_back().unwrap();
    !(is_word_char(prev) || prev == '+')
}

/// Rich text / PDFs put nbsp, thin / narrow nbsp, or a unicode dash between
/// phone groups; every phone pattern accepts them alongside the ASCII seps.
fn phone_sep_extra() -> String {
    group_class(&GROUP_SPACES) + &group_class(&GROUP_DASHES)
}

/// The span allows more than 15 digits so a ``(0)`` trunk between spaced
/// groups (``+44 (0) 20 7946 0958``) fits; ``phone_international_end``
/// re-measures the run.
fn phone_international_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let phone_sep_extra = phone_sep_extra();
        Regex::new(&format!(
            r"(?:\+|00)\d[\d .()\-{phone_sep_extra}]{{6,20}}\d"
        ))
        .unwrap()
    })
}

fn is_phone_international_sep(c: char) -> bool {
    matches!(c, ' ' | '.' | '(' | ')' | '-') || is_group_sep(c)
}

/// Unicode decimal digit (``\d`` / Python ``str.isdecimal``). The regex only
/// runs for non-ASCII numerics, so separators never reach it.
fn is_decimal(c: char) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    c.is_ascii_digit()
        || (!c.is_ascii()
            && c.is_numeric()
            && RE
                .get_or_init(|| Regex::new(r"^\d$").unwrap())
                .is_match(c.encode_utf8(&mut [0u8; 4])))
}

/// End of the run of digit groups starting at ``start`` (``start`` rejects).
///
/// The run is rescanned from ``start`` (64 chars of groups and separators,
/// whole groups only) so a group the regex span cut in half never counts. It
/// needs 8+ digits, not counting a ``00`` prefix or a ``(0)`` trunk. Past 15
/// digits it holds more than one number (``… 1234567 (06) 12345678``,
/// ``… 0958 - 020 7946 …``); no split point is reliable, and any tail left out
/// could be a subscriber part, so the whole run is masked.
fn phone_international_end(text: &str, start: usize) -> usize {
    // The 64-char window plus one char to see whether a group goes on.
    let mut chars = [(0usize, '\0'); 65];
    let mut n = 0usize;
    for (i, c) in text[start..].char_indices().take(chars.len()) {
        chars[n] = (start + i, c);
        n += 1;
    }
    let at = |k: usize| (k < n).then(|| chars[k].1);
    let end_of = |k: usize| if k < n { chars[k].0 } else { text.len() };
    let limit = n.min(64);
    let mut end = start;
    let mut digits = 0usize;
    let mut k = if at(0) == Some('0') && at(1) == Some('0') {
        2
    } else {
        usize::from(at(0) == Some('+'))
    };
    while k < limit {
        let c = chars[k].1;
        if is_phone_international_sep(c) {
            k += 1;
            continue;
        }
        if !is_decimal(c) {
            break;
        }
        if k > 0 && at(k - 1) == Some('(') && c == '0' && at(k + 1) == Some(')') {
            k += 1;
            continue;
        }
        let run = k;
        while k < limit && is_decimal(chars[k].1) {
            k += 1;
        }
        if at(k).is_some_and(is_decimal) {
            break; // the group runs past the window
        }
        digits += k - run;
        end = end_of(k);
    }
    if digits >= 8 {
        end
    } else {
        start
    }
}

fn phone_nl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let phone_sep_extra = phone_sep_extra();
        Regex::new(&format!(r"\(?0\d\)?(?:[ .\-/(){phone_sep_extra}]?\d){{8}}")).unwrap()
    })
}

fn phone_nl_valid(m: &str) -> bool {
    digit_count(m) == 10
}

fn phone_en_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let phone_sep_extra = phone_sep_extra();
        let sep = format!(r"[ .\-{phone_sep_extra}]");
        Regex::new(&format!(
            r"(?:1{sep}?)?\(?\d{{3}}\)?{sep}?\d{{3}}{sep}\d{{4}}"
        ))
        .unwrap()
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
    RE.get_or_init(|| {
        let phone_sep_extra = phone_sep_extra();
        Regex::new(&format!(r"\(?0\d\)?(?:[ .\-/(){phone_sep_extra}]?\d){{8,10}}")).unwrap()
    })
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
    replace_matches_end(
        text,
        phone_international_re(),
        "[PHONE]",
        |s, _| {
            if phone_left_ok(text, s) {
                phone_international_end(text, s)
            } else {
                s
            }
        },
        true,
    )
}

/// National phone forms: emulate Python backtracking on the trailing
/// ``(?!\d)`` / ``(?![A-Fa-f]{2})`` lookaheads. The greedy ``{8,10}`` run may
/// take one digit group too many (``030/86872539 26``); walk the end left to
/// the longest prefix that is a full pattern match with a clean right edge,
/// then validate it. A reject resumes at ``start + 1``.
fn replace_national_phone(
    text: &str,
    pattern: &Regex,
    hex_guard: bool,
    valid: fn(&str) -> bool,
) -> (Option<String>, u32) {
    let right_ok =
        |e: usize| no_trailing_digit(text, e) && (!hex_guard || no_trailing_hex_letters(text, e));
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some(m) = pattern.find_at(text, pos) {
        let start = m.start();
        let mut end = m.end();
        let mut found = None;
        while phone_left_ok(text, start) && end > start {
            let cand = &text[start..end];
            let full = pattern
                .find(cand)
                .is_some_and(|mm| mm.start() == 0 && mm.end() == cand.len());
            if full && right_ok(end) {
                found = Some(end);
                break;
            }
            end -= 1;
            while end > start && !text.is_char_boundary(end) {
                end -= 1;
            }
        }
        let Some(end) = found.filter(|&e| {
            let v = &text[start..e];
            phone_paren_ok(v) && valid(v)
        }) else {
            pos = start + 1;
            continue;
        };
        let buf = out.get_or_insert_with(|| String::with_capacity(text.len()));
        buf.push_str(&text[last..start]);
        buf.push_str("[PHONE]");
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

fn scrub_phone_nl(text: &str) -> (Option<String>, u32) {
    replace_national_phone(text, phone_nl_re(), true, phone_nl_valid)
}

fn scrub_phone_en(text: &str) -> (Option<String>, u32) {
    replace_national_phone(text, phone_en_re(), false, phone_en_valid)
}

fn scrub_phone_de(text: &str) -> (Option<String>, u32) {
    replace_national_phone(text, phone_de_re(), true, phone_de_valid)
}

fn nl_postcode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[1-9]\d{3}\s+[A-Z]{2}\b|\b[1-9]\d{3}[A-Z]{2}\b").unwrap())
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

/// Reject RDW-forbidden SA/SD/SS pairs inside one letter group; letters split
/// by a hyphen (``KS-234-S``) are not a combination.
fn nl_license_plate_valid(value: &str) -> bool {
    !value.split('-').any(|group| {
        let upper = group.to_ascii_uppercase();
        NL_PLATE_LETTER_REJECTS
            .iter()
            .any(|pair| upper.contains(pair))
    })
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
    // National phone forms (trunk ``0`` + area code) before bare-digit IDs, so
    // BSN does not take the subscriber part of ``040 78703244``.
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
    if has_de {
        // Before BSN: the last three groups of ``12 345 678 901`` are a
        // spaced 9-digit BSN candidate.
        pack.push(Detector {
            category: PiiCategory::TaxId,
            scrub: scrub_tax_id,
        });
    }
    if has_nl {
        // BTW-id first: its 9-digit body can itself pass the BSN elfproef.
        pack.push(Detector {
            category: PiiCategory::VatId,
            scrub: scrub_nl_vat,
        });
        pack.push(Detector {
            category: PiiCategory::Bsn,
            scrub: scrub_bsn,
        });
        pack.push(Detector {
            category: PiiCategory::Passport,
            scrub: scrub_nl_passport,
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
