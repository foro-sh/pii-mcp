//! Checksum / structure validators for pattern detectors.

use regex::Regex;
use std::sync::OnceLock;

fn compact_iban_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$").unwrap())
}

fn nl_postcode_compact_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[1-9]\d{3}[A-Z]{2}$").unwrap())
}

fn fold_iban_mod97(chars: impl Iterator<Item = char>, mut remainder: u32) -> u32 {
    for ch in chars {
        if ch.is_ascii_alphabetic() {
            remainder = (remainder * 100 + (ch as u32 - 55)) % 97;
        } else {
            remainder = (remainder * 10 + (ch as u32 - 48)) % 97;
        }
    }
    remainder
}

/// IBAN mod-97 after compacting whitespace/hyphens/slashes/soft-hyphens and uppercasing.
pub fn iban_valid(value: &str) -> bool {
    // Max IBAN length is 34; keep a stack buffer for the ASCII path.
    let mut compact = [0u8; 34];
    let mut len = 0usize;
    for c in value.chars() {
        if c.is_whitespace() || c == '-' || c == '/' || c == '\u{00ad}' {
            continue;
        }
        if !c.is_ascii() || len >= compact.len() {
            return false;
        }
        compact[len] = (c as u8).to_ascii_uppercase();
        len += 1;
    }
    let compact = std::str::from_utf8(&compact[..len]).unwrap();
    if !compact_iban_re().is_match(compact) {
        return false;
    }
    // Rearrange without allocating: body then first 4 chars.
    let remainder = fold_iban_mod97(compact[4..].chars(), 0);
    let remainder = fold_iban_mod97(compact[..4].chars(), remainder);
    remainder == 1
}

/// Luhn check for digit strings of length 13–19.
pub fn luhn_valid(digits: &str) -> bool {
    let len = digits.len();
    if !(13..=19).contains(&len) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut total = 0u32;
    let mut double = false;
    for b in digits.bytes().rev() {
        let mut d = (b - b'0') as u32;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        total += d;
        double = !double;
    }
    total % 10 == 0
}

/// IMEI: exactly 15 digits after stripping spaces/hyphens, Luhn-valid.
pub fn imei_valid(value: &str) -> bool {
    let mut digits = [0u8; 15];
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
    if len != 15 {
        return false;
    }
    luhn_valid(std::str::from_utf8(&digits).unwrap())
}

/// Dutch passport / NIK document number (RvIG): 9 chars, no letter O.
/// Case-insensitive: candidates are uppercased before structure checks.
pub fn nl_passport_valid(value: &str) -> bool {
    let mut buf = [0u8; 9];
    let bytes = value.as_bytes();
    if bytes.len() != 9 {
        return false;
    }
    for (i, &b) in bytes.iter().enumerate() {
        buf[i] = b.to_ascii_uppercase();
    }
    if !buf[0].is_ascii_uppercase() || !buf[1].is_ascii_uppercase() {
        return false;
    }
    if !buf[8].is_ascii_digit() {
        return false;
    }
    for &b in &buf {
        if b == b'O' {
            return false;
        }
        if !(b.is_ascii_uppercase() || b.is_ascii_digit()) {
            return false;
        }
    }
    true
}

/// Dutch BSN 11-check (8–9 digits, zero-padded to 9).
pub fn bsn_valid(digits: &str) -> bool {
    let len = digits.len();
    if !(8..=9).contains(&len) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut padded = [b'0'; 9];
    padded[9 - len..].copy_from_slice(digits.as_bytes());
    if padded == *b"000000000" {
        return false;
    }
    let weights: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let total: i32 = padded
        .iter()
        .enumerate()
        .map(|(i, &b)| (b - b'0') as i32 * weights[i])
        .sum();
    total % 11 == 0
}

/// SSA rejects: area 000/666/9xx, group 00, serial 0000.
pub fn ssn_valid(value: &str) -> bool {
    let mut digits = [0u8; 9];
    let mut len = 0usize;
    for b in value.bytes() {
        if b == b'-' {
            continue;
        }
        if !b.is_ascii_digit() || len >= 9 {
            return false;
        }
        digits[len] = b;
        len += 1;
    }
    if len != 9 {
        return false;
    }
    let area = (digits[0] - b'0') as u32 * 100
        + (digits[1] - b'0') as u32 * 10
        + (digits[2] - b'0') as u32;
    let group = (digits[3] - b'0') as u32 * 10 + (digits[4] - b'0') as u32;
    let serial = (digits[5] - b'0') as u32 * 1000
        + (digits[6] - b'0') as u32 * 100
        + (digits[7] - b'0') as u32 * 10
        + (digits[8] - b'0') as u32;
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }
    if group == 0 || serial == 0 {
        return false;
    }
    true
}

/// German Steuer-IdNr: structure + mod-11/10 check digit.
pub fn tax_id_valid(digits: &str) -> bool {
    if digits.len() != 11 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if digits.as_bytes()[0] == b'0' {
        return false;
    }
    let body = &digits.as_bytes()[..10];
    let mut counts = [0u8; 10];
    for &b in body {
        counts[(b - b'0') as usize] += 1;
    }
    let mut repeat_kind = 0u8;
    let mut repeat_slots = 0u8;
    for &n in &counts {
        if n > 1 {
            repeat_slots += 1;
            repeat_kind = n;
        }
    }
    if repeat_slots != 1 || (repeat_kind != 2 && repeat_kind != 3) {
        return false;
    }
    let mut product: u32 = 10;
    for &b in body {
        let mut total = ((b - b'0') as u32 + product) % 10;
        if total == 0 {
            total = 10;
        }
        product = (2 * total) % 11;
    }
    let mut check = 11 - product;
    if check == 10 {
        check = 0;
    }
    check == (digits.as_bytes()[10] - b'0') as u32
}

const NL_POSTCODE_REJECTS: &[&str] = &["SA", "SD", "SS"];

/// NL postcode `1234AB` / `1234 AB` with SA/SD/SS letter rejects.
pub fn nl_postcode_valid(value: &str) -> bool {
    let mut compact = [0u8; 6];
    let mut len = 0usize;
    for c in value.chars() {
        // Match Python/`\s`: strip any Unicode whitespace the detector may keep.
        if c.is_whitespace() {
            continue;
        }
        if !c.is_ascii() || len >= compact.len() {
            return false;
        }
        compact[len] = (c as u8).to_ascii_uppercase();
        len += 1;
    }
    if len != 6 {
        return false;
    }
    let compact = std::str::from_utf8(&compact).unwrap();
    if !nl_postcode_compact_re().is_match(compact) {
        return false;
    }
    !NL_POSTCODE_REJECTS.contains(&&compact[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iban_nl_valid() {
        assert!(iban_valid("NL91ABNA0417164300"));
        assert!(iban_valid("NL91 ABNA 0417 1643 00"));
        assert!(iban_valid("NL91-ABNA-0417-1643-00"));
        assert!(iban_valid("Nl91 AbNa 0417 1643 00"));
        assert!(!iban_valid("NL91ABNA0417164301"));
    }

    #[test]
    fn luhn_visa_test() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("1234567812345678"));
    }

    #[test]
    fn imei_grouped() {
        assert!(imei_valid("49-015420-323751-8"));
        assert!(imei_valid("49 015420 323751 8"));
        assert!(imei_valid("490154203237518"));
        assert!(!imei_valid("49-015420-323751-9"));
    }

    #[test]
    fn nl_passport_format() {
        assert!(nl_passport_valid("XR1001R58"));
        assert!(nl_passport_valid("xr1001r58"));
        assert!(!nl_passport_valid("XR1O01R58"));
        assert!(!nl_passport_valid("581001RXR"));
    }

    #[test]
    fn bsn_known() {
        assert!(bsn_valid("111222333"));
        assert!(!bsn_valid("123456789"));
    }

    #[test]
    fn ssn_rejects() {
        assert!(ssn_valid("078-05-1120"));
        assert!(!ssn_valid("000-12-3456"));
        assert!(!ssn_valid("123-00-1234"));
    }

    #[test]
    fn tax_id_known() {
        assert!(tax_id_valid("36574261809"));
        assert!(!tax_id_valid("36574261890"));
    }

    #[test]
    fn nl_postcode() {
        assert!(nl_postcode_valid("1012 AB"));
        assert!(nl_postcode_valid("2511VA"));
        assert!(!nl_postcode_valid("1234 SA"));
        // Detector `\s` can match NBSP; validator must still accept.
        assert!(nl_postcode_valid("1012\u{00a0}AB"));
    }

    #[test]
    fn iban_unicode_space() {
        assert!(iban_valid("NL91\u{00a0}ABNA0417164300"));
    }
}
