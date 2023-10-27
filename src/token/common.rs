// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

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
