// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate ccatoken;

use ccatoken::store::RefValueStore;

fn main() {
    let j: &str = r#"{
        "platform": [
            {
                "implementation-id": "/BASE64+ENCODED+VAL/",
                "platform-configuration": "/BASE64+ENCODED+VAL/",
                "sw-components": [
                    {
                        "component-type": "[OPTIONAL] e.g., BL",
                        "measurement-value": "/BASE64+ENCODED+VAL/",
                        "signer-id": "/BASE64+ENCODED+VAL/",
                        "version": "[OPTIONAL] e.g., 1.0.2rc5"
                    }
                ]
            }
        ]
    }"#;

    let mut s: RefValueStore = Default::default();

    s.load_json(j).unwrap();

    println!("{:#?}", s.lookup_platform("/BASE64+ENCODED+VAL/"));
}
