// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::Error;
use ciborium::Value;

// See https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
pub fn is_valid_hash(value: &str) -> bool {
    matches!(
        value,
        "md2"
            | "md5"
            | "sha-1"
            | "sha-224"
            | "sha-256"
            | "sha-384"
            | "sha-512"
            | "shake128"
            | "shake256"
    )
}

pub fn is_valid_measurement(value: &Vec<u8>) -> bool {
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
        return Err(Error::TypeMismatch(format!("{} MUST be tstr", n)));
    }

    Ok(x.unwrap().to_string())
}

pub fn to_bstr(v: &Value, n: &str) -> Result<Vec<u8>, Error> {
    let x = v.as_bytes();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{} MUST be bstr", n)));
    }

    Ok(x.unwrap().clone())
}

pub fn to_int(v: &Value, n: &str) -> Result<i128, Error> {
    let x = v.as_integer();

    if x.is_none() {
        return Err(Error::TypeMismatch(format!("{} MUST be int", n)));
    }

    Ok(x.unwrap().into())
}

pub fn to_measurement(v: &Value, n: &str) -> Result<Vec<u8>, Error> {
    let x = to_bstr(v, n)?;

    if !is_valid_measurement(&x) {
        return Err(Error::Sema(format!(
            "{}: expecting 32, 48 or 64 bytes, got {}",
            n,
            x.len()
        )));
    }

    Ok(x)
}

pub fn to_hash_alg(v: &Value, n: &str) -> Result<String, Error> {
    let x = to_tstr(v, n)?;

    if !is_valid_hash(&x) {
        return Err(Error::Sema(format!("unknown {} {}", n, x)));
    }

    Ok(x)
}
