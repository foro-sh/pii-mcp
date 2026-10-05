//! Pattern detectors: regex + checksum where one exists.
//!
//! Patterns mirror `pii_mcp.detectors`. Python lookarounds are enforced with
//! explicit boundary checks so matching stays on the linear-time `regex` crate.

use crate::checksum::{
    bsn_valid_grouped, iban_valid, imei_valid, is_group_sep, itin_valid_grouped, luhn_valid,
    nl_passport_valid, nl_postcode_valid, ssn_valid_grouped, tax_id_valid_grouped,
    uk_postcode_valid, GROUP_DASHES, GROUP_SPACES,
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
    Person,
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
            Self::Person => "person",
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
const UNSPACED_RANGES: [(char, char); 13] = [
    ('\u{0e00}', '\u{0eff}'),
    ('\u{0f00}', '\u{0fff}'),
    ('\u{1000}', '\u{109f}'),
    ('\u{1100}', '\u{11ff}'),
    ('\u{1780}', '\u{17ff}'),
    ('\u{3000}', '\u{31ff}'),
    ('\u{3400}', '\u{4dbf}'),
    ('\u{4e00}', '\u{9fff}'),
    ('\u{a960}', '\u{a97f}'),
    ('\u{ac00}', '\u{d7ff}'),
    ('\u{f900}', '\u{faff}'),
    ('\u{ff00}', '\u{ffef}'),
    ('\u{20000}', '\u{3ffff}'),
];
/// Email local part (1–64 chars): Unicode letters / digits plus ``_.%+-``.
const EMAIL_LOCAL: &str = r"[\p{L}\p{N}_.%+\-]{1,64}";

pub(crate) fn is_unspaced_script(c: char) -> bool {
    UNSPACED_RANGES.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// ``UNSPACED_RANGES`` as a regex class, so the TLD split and
/// ``is_unspaced_script`` read one list.
fn unspaced_class() -> String {
    let ranges: String = UNSPACED_RANGES
        .iter()
        .map(|&(lo, hi)| format!(r"\u{{{:x}}}-\u{{{:x}}}", u32::from(lo), u32::from(hi)))
        .collect();
    format!("[{ranges}]")
}

/// Letters and digits are Unicode (EAI / IDN: ``josé@example.com``,
/// ``ada@münchen.de``), matching Python's ``\w`` / ``[^\W_]``, except that a
/// TLD may not mix unspaced scripts with others. TLD chars are ``[^\W\d_]``
/// as in Python: letters plus letter-like / other numerics (``Ⅻ``, ``²``).
fn email_pattern() -> String {
    let unspaced = unspaced_class();
    format!(
        r"{EMAIL_LOCAL}@[\p{{L}}\p{{N}}-]{{1,63}}(?:\.[\p{{L}}\p{{N}}-]{{1,63}})*\.(?:[[\p{{L}}\p{{Nl}}\p{{No}}]--{unspaced}]{{2,24}}|[[\p{{L}}\p{{Nl}}\p{{No}}]&&{unspaced}]{{2,24}})"
    )
}

/// Bounded Unicode classes need a larger lazy-DFA cache than the 2 MiB
/// default, or big inputs fall back to the ~30x slower NFA engine.
fn build_email_regex(pattern: &str) -> Regex {
    regex::RegexBuilder::new(pattern)
        .dfa_size_limit(16 << 20)
        .build()
        .unwrap()
}

/// ``cand`` is one whole address (Python ``EMAIL_RE.fullmatch``). Each call
/// scans the whole candidate, and the domain has no length bound, so this
/// anchored copy needs the same DFA cache as ``email_re``.
fn is_full_email(cand: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| build_email_regex(&format!("^(?:{})$", email_pattern())))
        .is_match(cand)
}

/// ``EMAIL_RE`` with Python's trailing ``(?!@)``: the linear engine has no
/// lookahead, so the address is group 1 and a following non-``@`` char (or
/// the end of text) must match too. Leftmost-first then picks the span
/// Python's backtracking does (a shorter TLD / domain when the greedy one
/// runs into ``@``).
fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| build_email_regex(&format!(r"({})(?:[^@]|\z)", email_pattern())))
}

/// Span of the leftmost address at or after ``pos`` (group 1 of ``email_re``).
fn find_email_at(text: &str, pos: usize) -> Option<(usize, usize)> {
    let m = email_re().find_at(text, pos)?;
    if m.end() < text.len() {
        // ``\z`` only matches at the end of text, so the match ends with the
        // one ``[^@]`` char after the address: drop it, no captures needed.
        let last = m.as_str().chars().next_back()?;
        return Some((m.start(), m.end() - last.len_utf8()));
    }
    // At the end of text the tail may be ``\z`` or a last char; ask group 1.
    let address = email_re().captures_at(text, m.start())?.get(1)?;
    Some((address.start(), address.end()))
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

/// ``c`` is in the regex ``class`` (compiled once into ``re``); std has no
/// Unicode general-category predicates matching Python's.
fn char_in_class(re: &'static OnceLock<Regex>, class: &str, c: char) -> bool {
    re.get_or_init(|| Regex::new(&format!("^{class}$")).unwrap())
        .is_match(c.encode_utf8(&mut [0u8; 4]))
}

/// ``\p{L}`` (Python ``str.isalpha``): ``char::is_alphabetic`` also takes
/// letter numbers (``Ⅻ``) and some combining marks.
fn is_letter(c: char) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    c.is_ascii_alphabetic() || (!c.is_ascii() && char_in_class(&RE, r"\p{L}", c))
}

/// ``[\p{L}\p{N}]`` (Python ``str.isalnum``).
fn is_letter_or_number(c: char) -> bool {
    is_letter(c) || c.is_numeric()
}

fn email_end_ok(text: &str, end: usize) -> bool {
    if end >= text.len() {
        return true;
    }
    let next = text[end..].chars().next().unwrap();
    if next == '@' {
        return false;
    }
    if !is_letter_or_number(next) || is_unspaced_script(next) {
        return true;
    }
    email_next_pii(text, end)
}

/// How far back from a greedy email end to look for a clean shorter one
/// (24-char TLD + 63-char label, with room); bounds the per-end full match.
const EMAIL_SHORTEN_SPAN: usize = 128;

fn email_should_peel(text: &str, start: usize, end: usize) -> bool {
    let mut try_end = end;
    while try_end > start {
        try_end -= 1;
        while try_end > start && !text.is_char_boundary(try_end) {
            try_end -= 1;
        }
        let ch = text[try_end..].chars().next().unwrap();
        if !is_letter(ch) {
            break;
        }
        if email_next_pii(text, try_end) && is_full_email(&text[start..try_end]) {
            return true;
        }
    }
    false
}

fn scrub_email(text: &str) -> (Option<String>, u32) {
    let mut count = 0u32;
    let mut out: Option<String> = None;
    let mut last = 0usize;
    let mut pos = 0usize;
    while let Some((start, mut end)) = find_email_at(text, pos) {
        if !email_end_ok(text, end) || email_should_peel(text, start, end) {
            // Only ends before the greedy one (it already failed the checks),
            // and within ``EMAIL_SHORTEN_SPAN`` chars of it: a clean shorter
            // end sits within a TLD and a label; past that, the fallback
            // below masks the match as found.
            let mut back = text[start..end].char_indices().rev().map(|(i, _)| start + i);
            let before_end = back.next().unwrap_or(start);
            let floor = back.nth(EMAIL_SHORTEN_SPAN - 2).unwrap_or(start);
            let shortened = longest_end(text, floor, before_end, |e| {
                is_full_email(&text[start..e]) && email_end_ok(text, e)
            });
            // No clean shorter end (letters glued after the TLD): mask the
            // match as found rather than leak the address.
            if let Some(e) = shortened {
                end = e;
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

/// Spacing between groups: space, tab, CR / LF, and the Unicode Zs spaces
/// OCR and rich text use (nbsp, thin / figure / ideographic …). Shared by the
/// IBAN, card, and DMS patterns.
macro_rules! sep_space_chars {
    () => {
        r" \t\r\n\u{00a0}\u{2000}-\u{200a}\u{202f}\u{3000}"
    };
}
const SEP_SPACE: &str = concat!("[", sep_space_chars!(), "]");

fn iban_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        vec![
            // Compact: boundary emulated in ``iban_glue_boundary_ok``.
            Regex::new(r"[A-Za-z]{2}\d{2}[A-Za-z0-9]{11,30}").unwrap(),
            Regex::new(&format!(
                r"\b[A-Z]{{2}}\d{{2}}(?:{SEP_SPACE}?[A-Z0-9]{{1,4}}){{3,8}}\b"
            ))
            .unwrap(),
            Regex::new(&format!(
                r"\b[a-z]{{2}}\d{{2}}(?:{SEP_SPACE}?[a-z0-9]{{1,4}}){{3,8}}\b"
            ))
            .unwrap(),
            // Mixed case / hyphen|slash|dot|whitespace groups (one or more seps).
            Regex::new(&format!(
                r"[A-Za-z]{{2}}\d{{2}}(?:(?:{SEP_SPACE}|[\-/.])+[A-Za-z0-9]{{1,4}}){{3,8}}"
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
    longest_end(text, start, end, |e| {
        let cand = &text[start..e];
        iban_glue_boundary_ok(text, start, e)
            && pattern
                .find(cand)
                .is_some_and(|m| m.start() == 0 && m.end() == cand.len())
            && iban_valid(cand)
    })
}

/// Largest char-boundary end in ``(start, end]`` that ``accept`` takes: the
/// linear engine keeps the greedy match, so a failed Python lookahead is
/// emulated by walking the end back.
fn longest_end(
    text: &str,
    start: usize,
    end: usize,
    mut accept: impl FnMut(usize) -> bool,
) -> Option<usize> {
    let mut try_end = end;
    while try_end > start {
        if accept(try_end) {
            return Some(try_end);
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
        let sep = format!(r"(?:{SEP_SPACE}|[./\-\u{{2010}}-\u{{2015}}])+");
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
    // (?<![\w.-]) … (?![\w-])(?!\.\w): a sentence-ending ``.`` may follow.
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if is_word_char(prev) || prev == '.' || prev == '-' {
            return false;
        }
    }
    if end < text.len() {
        let next = text[end..].chars().next().unwrap();
        if is_word_char(next) || next == '-' {
            return false;
        }
        if next == '.' && text[end + 1..].chars().next().is_some_and(is_word_char) {
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
/// Spacing: the shared separator spaces plus line / page breaks, spelled out
/// (not ``\s``) and with ASCII digits so every backend reads a pair alike.
fn location_dms_pattern() -> String {
    let sep = concat!("[", sep_space_chars!(), r"\f\v\x85\u{2028}\u{2029}]");
    let body = format!(
        r#"[0-9]{{1,3}}{sep}?[°º]{sep}?[0-9]{{1,2}}(?:[.,][0-9]{{1,4}})?{sep}?['′’](?:{sep}?[0-9]{{1,2}}(?:[.,][0-9]{{1,4}})?{sep}?(?:["″”]|''|′′))?"#
    );
    format!(
        r"(?:[NSZ]{sep}?{body}|{body}{sep}?[NSZ]){sep}{{0,3}}[,;/]?{sep}{{0,3}}(?:[EOW]{sep}?{body}|{body}{sep}?[EOW])"
    )
}

fn location_dms_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&location_dms_pattern()).unwrap())
}

fn location_dms_full_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(&format!("^(?:{})$", location_dms_pattern())).unwrap())
}

/// Emulate Python's ``(?![A-Za-z0-9_])`` backtracking: when the greedy hit
/// runs into a word (``… 4°54' 12"x``), the pattern falls back to a shorter
/// hit (without the optional seconds, or the spacing before them). Take the
/// longest prefix that is a whole match with a clean right edge, then
/// validate it; ``start`` rejects. ``end`` must be the end of a
/// ``location_dms_re`` match at ``start`` (it is not re-matched).
fn location_dms_end(text: &str, start: usize, end: usize) -> usize {
    if !location_dms_left_ok(text, start) {
        return start;
    }
    // ``find_at`` already proved the greedy span is a whole match.
    let found = longest_end(text, start, end, |e| {
        location_dms_right_ok(text, e)
            && (e == end || location_dms_full_re().is_match(&text[start..e]))
    });
    match found {
        Some(e) if location_dms_valid(&text[start..e]) => e,
        _ => start,
    }
}

/// ``(?<![A-Za-z0-9_.])`` before a DMS hit.
fn location_dms_left_ok(text: &str, start: usize) -> bool {
    text[..start]
        .chars()
        .next_back()
        .is_none_or(|prev| !(is_word_char(prev) || prev == '.'))
}

/// ``(?![A-Za-z0-9_])`` after a DMS hit.
fn location_dms_right_ok(text: &str, end: usize) -> bool {
    text[end..].chars().next().is_none_or(|next| !is_word_char(next))
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
    let (dms, dms_count) = replace_matches_end(
        text,
        location_dms_re(),
        "[LOCATION]",
        |s, e| location_dms_end(text, s, e),
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
            // Python's ``(?![A-Za-z\d.])`` backtracks the optional tails in
            // order: the ``\s*[EeWw]`` group (``4.9041 exactly``), then the
            // ``°`` (``4.904152°22``); the linear regex keeps them. Only a
            // failed right edge backtracks: the tails never change a number,
            // so a validity reject stays a reject.
            let right_edge_ok = location_boundary_ok(text, start, end);
            let shorter = if right_edge_ok {
                None
            } else {
                let mut value = m.as_str();
                let mut cuts = [None, None];
                if let Some(v) = value.strip_suffix(['E', 'e', 'W', 'w']) {
                    value = v.trim_end();
                    cuts[0] = Some(start + value.len());
                }
                if let Some(v) = value.strip_suffix('°') {
                    cuts[1] = Some(start + v.len());
                }
                cuts.into_iter()
                    .flatten()
                    .find(|&e| location_boundary_ok(text, start, e))
                    .filter(|&e| location_valid(&text[start..e]))
            };
            let Some(e) = shorter else {
                // A validity reject resumes at the match end, as Python does.
                pos = if right_edge_ok { end.max(start + 1) } else { start + 1 };
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
        |v, s, _| not_decimal_fraction(text, s) && bsn_valid_grouped(v),
        false,
    );
    let src = first.as_deref().unwrap_or(text);
    let (second, n) =
        replace_matches(src, &res[1], "[BSN]", |v, _, _| bsn_valid_grouped(v), false);
    count += n;
    (second.or(first), count)
}

fn itin_res() -> &'static [Regex] {
    static RES: OnceLock<Vec<Regex>> = OnceLock::new();
    RES.get_or_init(|| {
        let id_space = id_space();
        let id_dash = id_dash();
        vec![
            Regex::new(&format!(r"\b9\d{{2}}{id_dash}\d{{2}}{id_dash}\d{{4}}\b")).unwrap(),
            Regex::new(&format!(r"\b9\d{{2}}{id_space}\d{{2}}{id_space}\d{{4}}\b")).unwrap(),
        ]
    })
}

fn scrub_itin(text: &str) -> (Option<String>, u32) {
    scrub_patterns(text, itin_res(), "[TAX_ID]", |v, _, _| itin_valid_grouped(v), false)
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
        scrub_patterns(text, &res[..3], "[SSN]", |v, _, _| ssn_valid_grouped(v), false);
    let src = grouped.as_deref().unwrap_or(text);
    let (compact, n) = replace_matches(
        src,
        &res[3],
        "[SSN]",
        |v, s, _| not_decimal_fraction(src, s) && ssn_valid_grouped(v),
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
        |v, _, _| tax_id_valid_grouped(v),
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
        let ascii: String = PHONE_INTERNATIONAL_ASCII_SEPS
            .iter()
            .map(|c| regex::escape(&c.to_string()))
            .collect();
        let phone_sep_extra = phone_sep_extra();
        Regex::new(&format!(
            r"(?:\+|00)\d[\d{ascii}{phone_sep_extra}]{{6,20}}\d"
        ))
        .unwrap()
    })
}

/// ASCII separators the international pattern and its rescan both accept.
const PHONE_INTERNATIONAL_ASCII_SEPS: [char; 5] = [' ', '.', '(', ')', '-'];

fn is_phone_international_sep(c: char) -> bool {
    PHONE_INTERNATIONAL_ASCII_SEPS.contains(&c) || is_group_sep(c)
}

/// Unicode decimal digit (``\d`` / Python ``str.isdecimal``). The regex only
/// runs for non-ASCII numerics, so separators never reach it.
fn is_decimal(c: char) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    c.is_ascii_digit() || (!c.is_ascii() && c.is_numeric() && char_in_class(&RE, r"\d", c))
}

/// End of the run of digit groups starting at ``start`` (``start`` rejects).
///
/// The run is rescanned from ``start`` to its end, so neither the regex span
/// nor a scan window can stop inside it and leave a group out. It needs 8+
/// digits, not counting a ``00`` prefix or a ``(0)`` trunk. Past 15 digits it
/// holds more than one number (``… 1234567 (06) 12345678``,
/// ``… 0958 - 020 7946 …``); no split point is reliable, and any tail left out
/// could be a subscriber part, so the whole run is masked.
fn phone_international_end(text: &str, start: usize) -> usize {
    let rest = &text[start..];
    let mut i = if rest.starts_with("00") {
        2
    } else {
        usize::from(rest.starts_with('+'))
    };
    let mut end = start;
    let mut digits = 0usize;
    let mut prev = '\0';
    while let Some(c) = rest[i..].chars().next() {
        if is_phone_international_sep(c) {
            prev = c;
            i += c.len_utf8();
            continue;
        }
        if !is_decimal(c) {
            break;
        }
        if prev == '(' && c == '0' && rest[i + 1..].starts_with(')') {
            prev = c;
            i += 1;
            continue;
        }
        while let Some(d) = rest[i..].chars().next().filter(|&d| is_decimal(d)) {
            digits += 1;
            prev = d;
            i += d.len_utf8();
        }
        end = start + i;
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

/// Outward shapes A9, A99, A9A, AA9, AA99, AA9A, or `GIR`; inward 9AA.
fn uk_postcode_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?:[A-Z]{1,2}[0-9][A-Z0-9]?|GIR)[ \t\u{a0}\u{202f}]+[0-9][ABD-HJLNP-UW-Z]{2}")
            .unwrap()
    })
}

/// ``(?<![A-Za-z0-9])…(?![A-Za-z0-9])``; unlike ``\b``, `_` and non-ASCII
/// letters are boundaries.
fn uk_postcode_boundary_ok(text: &str, start: usize, end: usize) -> bool {
    if start > 0 {
        let prev = text[..start].chars().next_back().unwrap();
        if prev.is_ascii_alphanumeric() {
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

fn scrub_uk_postcode(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        uk_postcode_re(),
        "[ADDRESS]",
        |v, s, e| uk_postcode_boundary_ok(text, s, e) && uk_postcode_valid(v),
        false,
    )
}

const STREET_UP: &str = r"A-Z\u00c0-\u00d6\u00d8-\u00de";
const STREET_LOW: &str = r"a-z\u00df-\u00f6\u00f8-\u017f";
const HOUSE_NUMBER: &str = r"[1-9][0-9]{0,4}[A-Za-z]{0,3}(?:[-/][0-9]{1,4}[A-Za-z]?)?(?-u:\b)";
const NL_ADJECTIVES: &str =
    "(?:Grote|Kleine|Oude|Nieuwe|Korte|Lange|Hoge|Lage|Brede|Verlengde)";
const DE_STREET_WORDS: &str =
    r"(?:Straße|Strasse|Str(?-u:\b)\.?|Weg|Allee|Platz|Gasse|Damm|Ufer|Ring)";

/// Street + house number, mirroring Python ``STREET_*_RE``. ``\b`` is ASCII
/// there (``re.ASCII``) and in JS, so it is ``(?-u:\b)`` here.
///
/// `nr_sep` joins the street and the number: up to three spaces, tabs, or
/// no-break spaces, or a comma plus one to three of them
/// (`Birkhahnstraße, 676`, `518, Hollywater Road`). A comma with no space
/// after it is a CSV field separator, so `id,Kerkstraat,2024-01-15` keeps the
/// bare street name clean. The comma form inherits the same recall-first
/// over-masking as the comma-less one, so `Chapter 12, Main Street` masks
/// exactly as `Chapter 12 Main Street` already does.
fn street_res() -> &'static [Regex; 3] {
    static RES: OnceLock<[Regex; 3]> = OnceLock::new();
    RES.get_or_init(|| {
        let word = format!("[{STREET_UP}][{STREET_LOW}]+");
        let sep_chars = r" \t\u00a0\u202f";
        let sep = format!("[{sep_chars}]{{1,3}}");
        let gap = format!("(?:{sep}|-)");
        let nr_sep = format!("(?:,[{sep_chars}]{{1,3}}|{sep})");
        let house = format!(r"(?:(?:[Nn]r|[Nn]o)\.?{sep})?{HOUSE_NUMBER}");
        let nl_words =
            "(?:Straat|Laan|Weg|Plein|Gracht|Kade|Singel|Dijk|Dreef|Steeg|Hof|Markt|Wal|Haven|Park)";
        let particle = "(?:van|der|de|den|het|ten|ter|op|aan)";
        let nl = format!(
            r"(?:{word}{gap}){{0,3}}(?:[{STREET_UP}][{STREET_LOW}]*(?:straat|str(?-u:\b)\.?|laan|weg|plein|gracht|kade|singel|dijk|dreef|steeg|pad|hof|markt|plantsoen|wal)|{NL_ADJECTIVES}{sep}{nl_words}|{nl_words}(?:{sep}{particle}){{1,2}}{sep}{word}(?:{gap}{word}){{0,3}}){nr_sep}{house}"
        );
        let de = format!(
            r"(?:{word}{gap}){{0,3}}(?:(?:[{STREET_UP}][{STREET_LOW}]*(?:straße|strasse|str(?-u:\b)\.?|weg|allee|platz|gasse|damm|ufer)|[{STREET_UP}][{STREET_LOW}]{{2,}}ring|[{STREET_UP}][{STREET_LOW}]*er{sep}{DE_STREET_WORDS}|[{STREET_UP}][{STREET_LOW}]+-{DE_STREET_WORDS}){nr_sep}|[{STREET_UP}][{STREET_LOW}]*str\.){house}"
        );
        let en = format!(
            r"(?-u:\b)[1-9][0-9]{{0,4}}(?:[-/][0-9]{{1,4}})?[A-Za-z]?{nr_sep}(?:{word}{sep}){{1,3}}(?:(?:Street|Road|Avenue|Lane|Drive|Boulevard|Court|Place|Way|Close|Crescent|Terrace|Square|Highway|Parkway|Row|Loop)(?-u:\b)|(?:St|Rd|Ave|Ln|Blvd|Dr|Ct|Pl|Hwy|Pkwy)(?-u:\b)\.?)"
        );
        [nl, de, en].map(|p| Regex::new(&p).unwrap())
    })
}

const DE_FUNCTION_WORDS: &[&str] = &[
    "Der", "Hier", "Oder", "Aber", "Wieder", "Jeder", "Jener", "Einer", "Keiner", "Immer",
    "Unser", "Euer", "Weder", "Außer",
];

fn de_street_valid(value: &str) -> bool {
    let first = value
        .split(|c: char| c.is_whitespace() || c == '-')
        .next()
        .unwrap_or("");
    !DE_FUNCTION_WORDS.contains(&first)
}

fn scrub_street(text: &str, pattern: &Regex) -> (Option<String>, u32) {
    replace_matches(text, pattern, "[ADDRESS]", |_, _, _| true, false)
}

fn scrub_street_nl(text: &str) -> (Option<String>, u32) {
    scrub_street(text, &street_res()[0])
}

fn scrub_street_de(text: &str) -> (Option<String>, u32) {
    replace_matches(
        text,
        &street_res()[1],
        "[ADDRESS]",
        |v, _, _| de_street_valid(v),
        true,
    )
}

fn scrub_street_en(text: &str) -> (Option<String>, u32) {
    scrub_street(text, &street_res()[2])
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
            category: PiiCategory::TaxId,
            scrub: scrub_itin,
        });
        pack.push(Detector {
            category: PiiCategory::Ssn,
            scrub: scrub_ssn,
        });
        pack.push(Detector {
            category: PiiCategory::Address,
            scrub: scrub_street_en,
        });
        pack.push(Detector {
            category: PiiCategory::Address,
            scrub: scrub_uk_postcode,
        });
    }
    if has_de {
        pack.push(Detector {
            category: PiiCategory::Address,
            scrub: scrub_street_de,
        });
    }
    if has_nl {
        pack.push(Detector {
            category: PiiCategory::Address,
            scrub: scrub_street_nl,
        });
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
