// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate ccatoken;

use ccatoken::store::{IRefValueStore, MemoRefValueStore};
use hex_literal::hex;

fn main() {
    let j: &str = r#"{
        "platform": [
            {
                "implementation-id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "platform-configuration": "CFCFCFCF",
                "sw-components": [
                    {
                        "component-type": "BL",
                        "measurement-value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "signer-id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "version": "1.0.2rc5"
                    }
                ]
            }
        ]
    }"#;

    let mut s: MemoRefValueStore = Default::default();

    s.load_json(j).unwrap();

    println!(
        "{:#?}",
        s.lookup_platform(&hex!(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ))
    );
}
