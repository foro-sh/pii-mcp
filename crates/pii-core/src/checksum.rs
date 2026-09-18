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

/// IBAN mod-97 after compacting whitespace and uppercasing.
pub fn iban_valid(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !compact_iban_re().is_match(&compact) {
        return false;
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut remainder: u32 = 0;
    for ch in rearranged.chars() {
        if ch.is_ascii_alphabetic() {
            remainder = (remainder * 100 + (ch as u32 - 55)) % 97;
        } else {
            remainder = (remainder * 10 + (ch as u32 - 48)) % 97;
        }
    }
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

/// Dutch BSN 11-check (8–9 digits, zero-padded to 9).
pub fn bsn_valid(digits: &str) -> bool {
    let len = digits.len();
    if !(8..=9).contains(&len) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let padded = format!("{:0>9}", digits);
    if padded == "000000000" {
        return false;
    }
    let weights: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];
    let total: i32 = padded
        .bytes()
        .enumerate()
        .map(|(i, b)| (b - b'0') as i32 * weights[i])
        .sum();
    total % 11 == 0
}

/// SSA rejects: area 000/666/9xx, group 00, serial 0000.
pub fn ssn_valid(value: &str) -> bool {
    let digits: String = value.chars().filter(|c| *c != '-').collect();
    if digits.len() != 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let area: u32 = digits[..3].parse().unwrap();
    let group: u32 = digits[3..5].parse().unwrap();
    let serial: u32 = digits[5..].parse().unwrap();
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
    let body = &digits[..10];
    let mut counts = [0u8; 10];
    for b in body.bytes() {
        counts[(b - b'0') as usize] += 1;
    }
    let repeats: Vec<u8> = counts.iter().copied().filter(|&n| n > 1).collect();
    if repeats.len() != 1 || (repeats[0] != 2 && repeats[0] != 3) {
        return false;
    }
    let mut product: u32 = 10;
    for b in body.bytes() {
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
    let compact: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if !nl_postcode_compact_re().is_match(&compact) {
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
        assert!(!iban_valid("NL91ABNA0417164301"));
    }

    #[test]
    fn luhn_visa_test() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("1234567812345678"));
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
    }
}
