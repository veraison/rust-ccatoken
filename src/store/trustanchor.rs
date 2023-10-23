// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;
use serde_json::Error;
use std::collections::HashMap;

/// A CCA platform attestation key and associated metadata
#[derive(Clone, Deserialize, Debug)]
pub struct Cpak {
    /// The CPAK (a raw public key) wrapped in a Subject Public Key Info and
    /// serialised using the textual encoding described in §13 of RFC7468
    #[serde(rename(deserialize = "pkey"))]
    pkey: String,

    /// The CCA platform Implementation ID claim uniquely identifies the
    /// implementation of the CCA platform.  The semantics of the CCA platform
    /// Implementation ID value are defined by the manufacturer or a particular
    /// certification scheme.  For example, the ID could take the form of a
    /// product serial number, database ID, or other appropriate identifier.
    /// It is a fixed-size, 32 bytes binary blob, base64 encoded.
    #[serde(rename(deserialize = "implementation-id"))]
    impl_id: String,

    /// The CCA platform Instance ID claim represents the unique identifier of
    /// the CPAK
    /// It is a fixed-size, 33 bytes binary blob (a EAT UEID), base64 encoded.
    /// The first byte MUST be 0x01 (i.e., RAND UEID).
    #[serde(rename(deserialize = "instance-id"))]
    inst_id: String,
}

/// The store where the active CPAKs are stashed.  CPAKs are indexed by their
/// instance-id.
#[derive(Debug)]
pub struct TrustAnchorStore {
    p: HashMap<String, Cpak>,
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustAnchorStore {
    /// Returns a new empty TrustAnchorStore
    pub fn new() -> Self {
        Self { p: HashMap::new() }
    }

    /// Add to an existing (and possibly empty) TrustAnchorStore the trust
    /// anchors loaded from the given JSON file
    pub fn load_json(&mut self, j: &str) -> Result<(), Error> {
        let tas: Vec<Cpak> = serde_json::from_str(j)?;

        for ta in tas.iter() {
            self.p.insert(ta.inst_id.clone(), ta.clone());
        }

        Ok(())
    }

    /// Lookup a trust anchor from the store given the corresponding Instance ID
    pub fn lookup(&self, inst_id: &str) -> Option<&Cpak> {
        return self.p.get(inst_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_JSON_TA_OK_0: &str = r#"[
        {
            "instance-id": "/BASE64+ENCODED+VAL/",
            "implementation-id": "/BASE64+ENCODED+VAL/",
            "pkey": "/BASE64+ENCODED+VAL/"
        }
    ]"#;
    const TEST_B64: &str = "/BASE64+ENCODED+VAL/";
    const TEST_INST_ID_0: &str = TEST_B64;
    const TEST_IMPL_ID_0: &str = TEST_B64;
    const TEST_PKEY_0: &str = TEST_B64;

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s: TrustAnchorStore = Default::default();

        // load store from JSON
        s.load_json(TEST_JSON_TA_OK_0).unwrap();

        // lookup a known platform reference value
        let ta = s.lookup(TEST_INST_ID_0);
        assert!(ta.is_some());

        let res = ta.unwrap();

        assert_eq!(res.inst_id, TEST_IMPL_ID_0);
        assert_eq!(res.impl_id, TEST_IMPL_ID_0);
        assert_eq!(res.pkey, TEST_PKEY_0);
    }
}
