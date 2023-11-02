// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::errors::Error;
use hex_literal::hex;
use jsonwebkey as jwk;
use jwk::JsonWebKey;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::HashMap;
use std::sync::RwLock;

/// A CCA platform attestation key and associated metadata
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct Cpak {
    /// The CPAK (a raw public key) wrapped in a Subject Public Key Info and
    /// serialised using the textual encoding described in §13 of RFC7468
    #[serde(rename(deserialize = "pkey"))]
    raw_pkey: Box<RawValue>,

    #[serde(skip)]
    pkey: Option<jwk::JsonWebKey>,

    /// The CCA platform Implementation ID claim uniquely identifies the
    /// implementation of the CCA platform.  The semantics of the CCA platform
    /// Implementation ID value are defined by the manufacturer or a particular
    /// certification scheme.  For example, the ID could take the form of a
    /// product serial number, database ID, or other appropriate identifier.
    /// It is a fixed-size, 32 bytes binary blob, base64 encoded.
    #[serde(rename(deserialize = "implementation-id"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    impl_id: [u8; 32],

    /// The CCA platform Instance ID claim represents the unique identifier of
    /// the CPAK
    /// It is a fixed-size, 33 bytes binary blob (a EAT UEID), base64 encoded.
    /// The first byte MUST be 0x01 (i.e., RAND UEID).
    #[serde(rename(deserialize = "instance-id"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    inst_id: [u8; 33],
}

impl Cpak {
    pub fn parse_pkey(&mut self) -> Result<(), Error> {
        let s = self.raw_pkey.get();

        let pkey = serde_json::from_str::<JsonWebKey>(s)
            .map_err(|e| Error::Syntax(e.to_string()))?
            .clone();

        self.pkey = Some(pkey);

        Ok(())
    }
}

/// The store where the active CPAKs are stashed.  CPAKs are indexed by their
/// instance-id.
#[derive(Debug)]
pub struct TrustAnchorStore {
    p: RwLock<HashMap<[u8; 33], Cpak>>,
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustAnchorStore {
    /// Returns a new empty TrustAnchorStore
    pub fn new() -> Self {
        Self {
            p: Default::default(),
        }
    }

    /// Add to an existing (and possibly empty) TrustAnchorStore the trust
    /// anchors loaded from the given JSON file
    pub fn load_json(&mut self, j: &str) -> Result<(), Error> {
        let mut tas: Vec<Cpak> =
            serde_json::from_str(j).map_err(|e| Error::Syntax(e.to_string()))?;

        for ta in tas.iter_mut() {
            ta.parse_pkey()?;
            self.p.write().unwrap().insert(ta.inst_id, ta.clone());
        }

        Ok(())
    }

    /// Lookup a trust anchor from the store given the corresponding Instance ID
    pub fn lookup(&self, inst_id: &[u8; 33]) -> Option<Cpak> {
        return self.p.read().unwrap().get(inst_id).cloned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_JSON_TA_OK_0: &str = include_str!("../../testdata/ta.json");
    const TEST_INST_ID_0: &[u8; 33] = include_bytes!("../../testdata/inst-id.bin");
    const TEST_IMPL_ID_0: &[u8; 32] = include_bytes!("../../testdata/impl-id.bin");
    const TEST_PKEY_0: &str = include_str!("../../testdata/pkey.json");

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s: TrustAnchorStore = Default::default();

        // load store from JSON
        s.load_json(TEST_JSON_TA_OK_0).unwrap();

        // lookup a known platform reference value
        let ta = s.lookup(TEST_INST_ID_0);
        assert!(ta.is_some());

        let res = ta.unwrap();

        assert_eq!(res.inst_id, *TEST_INST_ID_0);
        assert_eq!(res.impl_id, *TEST_IMPL_ID_0);

        let pkey = serde_json::from_str::<JsonWebKey>(TEST_PKEY_0).unwrap();
        assert_eq!(res.pkey, Some(pkey));
    }
}
