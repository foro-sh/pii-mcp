//! Thin N-API binding over `pii-core` (`scrubText` / `scrubPayload`).

use std::collections::HashMap;

use napi::bindgen_prelude::*;
use napi_derive::napi;
use pii_core::{scrub_payload_with, scrub_text_with, PiiScrubError, ScrubOptions, PII_TYPES};
use serde_json::Value;

fn scrub_error(err: PiiScrubError) -> Error {
    let msg = err.to_string();
    if msg.starts_with("unknown language") || msg.starts_with("unknown type") {
        Error::from_reason(msg)
    } else {
        // Prefixed so TypeScript can remap to ``PiiScrubError``.
        Error::from_reason(format!("PiiScrubError:{msg}"))
    }
}

fn counts_to_map(counts: &pii_core::PiiCounts) -> HashMap<String, u32> {
    let mut out = HashMap::with_capacity(PII_TYPES.len());
    for key in PII_TYPES {
        out.insert((*key).to_string(), counts.get(*key).copied().unwrap_or(0));
    }
    out
}

#[napi(object)]
pub struct ScrubTextResult {
    pub text: String,
    pub found: bool,
    pub counts: HashMap<String, u32>,
}

#[napi(object)]
pub struct ScrubPayloadResult {
    pub payload: Value,
    pub found: bool,
    pub counts: HashMap<String, u32>,
}

fn options(
    languages: Option<Vec<String>>,
    types: Option<Vec<String>>,
    allow: Option<Vec<String>>,
) -> ScrubOptions {
    ScrubOptions {
        languages,
        types,
        allow: allow.unwrap_or_default(),
    }
}

/// Mask pattern-detectable PII in a string. Returns ``{text, found, counts}``.
#[napi]
pub fn scrub_text(
    text: String,
    languages: Option<Vec<String>>,
    types: Option<Vec<String>>,
    allow: Option<Vec<String>>,
) -> Result<ScrubTextResult> {
    let result = scrub_text_with(&text, &options(languages, types, allow), true)
        .map_err(scrub_error)?;
    Ok(ScrubTextResult {
        text: result.text,
        found: result.found,
        counts: counts_to_map(&result.counts),
    })
}

/// Walk a JSON-like payload and mask string leaves.
#[napi]
pub fn scrub_payload(
    payload: Value,
    languages: Option<Vec<String>>,
    types: Option<Vec<String>>,
    allow: Option<Vec<String>>,
) -> Result<ScrubPayloadResult> {
    let result =
        scrub_payload_with(payload, &options(languages, types, allow)).map_err(scrub_error)?;
    Ok(ScrubPayloadResult {
        payload: result.payload,
        found: result.found,
        counts: counts_to_map(&result.counts),
    })
}
