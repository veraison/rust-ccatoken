// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::Error;
use ciborium::de::from_reader;
use ciborium::Value;

const EAT_PROFILE_LABEL: i128 = 265;

// Among the admissible values in
// https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
// we only support sha-256, sha-384 and sha-512 as per RMM specification
pub fn is_valid_hash(value: &str) -> bool {
    matches!(value, "sha-256" | "sha-384" | "sha-512")
}

pub fn is_valid_measurement(value: &[u8]) -> bool {
    matches!(value.len(), 32 | 48 | 64)
}

pub fn is_valid_lifecycle(value: i128) -> bool {
    matches!(
        value,
        0x0000..=0x00ff
            | 0x1000..=0x10ff
            | 0x2000..=0x20ff
            | 0x3000..=0x30ff
            | 0x4000..=0x40ff
            | 0x5000..=0x50ff
            | 0x6000..=0x60ff
    )
}

pub fn to_tstr(v: &Value, n: &str) -> Result<String, Error> {
    let x = v.as_text();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{n} MUST be tstr")));
    }

    Ok(x.unwrap().to_string())
}

pub fn to_bstr(v: &Value, n: &str) -> Result<Vec<u8>, Error> {
    let x = v.as_bytes();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{n} MUST be bstr")));
    }

    Ok(x.unwrap().clone())
}

pub fn to_int(v: &Value, n: &str) -> Result<i128, Error> {
    let x = v.as_integer();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{n} MUST be int")));
    }

    Ok(x.unwrap().into())
}

pub fn to_bool(v: &Value, n: &str) -> Result<bool, Error> {
    let x = v.as_bool();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{n} MUST be bool")));
    }

    Ok(x.unwrap())
}

pub fn to_measurement(v: &Value, n: &str) -> Result<Vec<u8>, Error> {
    let x = to_bstr(v, n)?;

    if !is_valid_measurement(&x) {
        return Err(Error::Sema(format!(
            "{n}: expecting 32, 48 or 64 bytes, got {}",
            x.len()
        )));
    }

    Ok(x)
}

pub fn to_hash_alg(v: &Value, n: &str) -> Result<String, Error> {
    let x = to_tstr(v, n)?;

    if !is_valid_hash(&x) {
        return Err(Error::Sema(format!("unknown {n} {x}")));
    }

    Ok(x)
}

/// Decode the profile name from a CBOR-encoded Platform or Realm token.
pub fn decode_profile_name(buf: &Vec<u8>) -> Result<Option<String>, Error> {
    let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

    if let Value::Map(contents) = v {
        for (k, v) in contents.iter() {
            if let Value::Integer(k_int) = k {
                match (*k_int).into() {
                    EAT_PROFILE_LABEL => {
                        let profile_name = v.as_text().ok_or(Error::Syntax(
                            "expecting text value for profile claim".to_string(),
                        ))?;
                        return Ok(Some(profile_name.to_string()));
                    }
                    _ => continue,
                }
            }
        }
    } else {
        return Err(Error::Syntax("expecting map type".to_string()));
    }

    Ok(None)
}
