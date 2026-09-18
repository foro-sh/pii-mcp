//! Shared PII core: regex detectors, checksum validators, and scrub walk.
//!
//! Detector order matches the Python `pii_mcp` pack: universal → national IDs →
//! NL postcode → phones. Earlier matches become digit-free placeholders before
//! looser numeric detectors run.

mod checksum;
mod detectors;
mod scrub;

pub use checksum::{bsn_valid, iban_valid, luhn_valid, nl_postcode_valid, ssn_valid, tax_id_valid};
pub use detectors::{detectors_for, PiiCategory};
pub use scrub::{
    empty_pii_counts, normalize_languages, scrub_text, scrub_text_langs, total_pii_count,
    LanguageCode, PiiCounts, PiiScrubError, PiiType, ScrubResult, DEFAULT_LANGUAGES, MAX_DEPTH,
    MAX_SCRUB_BYTES, PII_TYPES,
};

#[cfg(feature = "payload")]
pub use scrub::{scrub_payload, PayloadScrubResult};
