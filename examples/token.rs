// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

extern crate ccatoken;

use ccatoken::token::Realm;
use std::fs;

fn main() {
    realm_tokens_decode();
}

fn realm_tokens_decode() {
    let files = vec!["testdata/realm-claims.cbor"];

    for f in files {
        let buf = fs::read(f).unwrap_or_else(|_| panic!("loading file {}", f));

        let rc = Realm::decode(&buf).unwrap();

        println!("{:?}", rc);
    }
}
