//! Thin PyO3 binding over `pii-core` (`scrub_text` / `scrub_payload`).

use pii_core::{scrub_payload as core_scrub_payload, scrub_text as core_scrub_text, PiiScrubError};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;
use serde_json::Value;

fn scrub_error(err: PiiScrubError) -> PyErr {
    let msg = err.to_string();
    if msg.starts_with("unknown language") {
        PyValueError::new_err(msg)
    } else {
        // Prefixed so Python can remap to ``PiiScrubError``.
        PyRuntimeError::new_err(format!("PiiScrubError:{msg}"))
    }
}

fn counts_to_py<'py>(py: Python<'py>, counts: &pii_core::PiiCounts) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for key in pii_core::PII_TYPES {
        let n = counts.get(*key).copied().unwrap_or(0);
        dict.set_item(*key, n)?;
    }
    Ok(dict)
}

/// Mask pattern-detectable PII in a string. Returns ``{text, found, counts}``.
#[pyfunction]
#[pyo3(signature = (text, *, languages=None))]
fn scrub_text<'py>(
    py: Python<'py>,
    text: &str,
    languages: Option<Vec<String>>,
) -> PyResult<Bound<'py, PyDict>> {
    let result = core_scrub_text(text, languages.as_deref(), true).map_err(scrub_error)?;
    let out = PyDict::new(py);
    out.set_item("text", result.text)?;
    out.set_item("found", result.found)?;
    out.set_item("counts", counts_to_py(py, &result.counts)?)?;
    Ok(out)
}

fn py_to_value(obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > pii_core::MAX_DEPTH {
        return Err(PyRuntimeError::new_err(format!(
            "PiiScrubError:payload nests past the {}-level scrub limit",
            pii_core::MAX_DEPTH
        )));
    }
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if obj.is_instance_of::<pyo3::types::PyBool>() {
        return Ok(Value::Bool(obj.extract::<bool>()?));
    }
    if let Ok(i) = obj.extract::<i64>() {
        return Ok(Value::Number(i.into()));
    }
    if let Ok(f) = obj.extract::<f64>() {
        return Ok(serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(s));
    }
    if let Ok(list) = obj.downcast::<PyList>() {
        let mut items = Vec::with_capacity(list.len());
        for item in list.iter() {
            items.push(py_to_value(&item, depth + 1)?);
        }
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (key, value) in dict.iter() {
            let k: String = key.extract()?;
            map.insert(k, py_to_value(&value, depth + 1)?);
        }
        return Ok(Value::Object(map));
    }
    Err(PyRuntimeError::new_err(
        "PiiScrubError:payload contains a non-plain object that cannot be safely scrubbed",
    ))
}

fn value_to_py(py: Python<'_>, value: Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.into_py_any(py)?),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_py_any(py)?)
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_py_any(py)?)
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_py_any(py)?)
            } else {
                Ok(py.None())
            }
        }
        Value::String(s) => Ok(s.into_py_any(py)?),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(value_to_py(py, item)?)?;
            }
            Ok(list.into_any().unbind())
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, value_to_py(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
}

/// Walk a JSON-like payload and mask string leaves.
#[pyfunction]
#[pyo3(signature = (payload, *, languages=None))]
fn scrub_payload<'py>(
    py: Python<'py>,
    payload: Bound<'_, PyAny>,
    languages: Option<Vec<String>>,
) -> PyResult<Bound<'py, PyDict>> {
    let value = py_to_value(&payload, 0)?;
    let result = core_scrub_payload(value, languages.as_deref()).map_err(scrub_error)?;
    let out = PyDict::new(py);
    out.set_item("payload", value_to_py(py, result.payload)?)?;
    out.set_item("found", result.found)?;
    out.set_item("counts", counts_to_py(py, &result.counts)?)?;
    Ok(out)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scrub_text, m)?)?;
    m.add_function(wrap_pyfunction!(scrub_payload, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
