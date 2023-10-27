// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use hex_literal::hex;
use serde::Deserialize;
use serde_json::Error;
use std::collections::HashMap;
use std::sync::RwLock;

/// A CCA platform attestation key and associated metadata
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct Cpak {
    /// The CPAK (a raw public key) wrapped in a Subject Public Key Info and
    /// serialised using the textual encoding described in §13 of RFC7468
    #[serde(rename(deserialize = "pkey"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    pkey: [u8; 97],

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
        let tas: Vec<Cpak> = serde_json::from_str(j)?;

        for ta in tas.iter() {
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
    const TEST_JSON_TA_OK_0: &str = r#"[
        {
            "instance-id": "01AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "implementation-id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "pkey": "0476F988091BE585ED41801AECFAB858548C63057E16B0E676120BBD0D2F9C29E056C5D41A0130EB9C21517899DC23146B28E1B062BD3EA4B315FD219F1CBB528CB6E74CA49BE16773734F61A1CA61031B2BBF3D918F2F94FFC4228E50919544AE"
        }
    ]"#;
    const TEST_INST_ID_0: [u8; 33] = hex!(
        "01
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    const TEST_IMPL_ID_0: [u8; 32] = hex!(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );
    const TEST_PKEY_0: [u8; 97] = hex!(
        "0476F988091BE585ED41801AECFAB858
         548C63057E16B0E676120BBD0D2F9C29
         E056C5D41A0130EB9C21517899DC2314
         6B28E1B062BD3EA4B315FD219F1CBB52
         8CB6E74CA49BE16773734F61A1CA6103
         1B2BBF3D918F2F94FFC4228E50919544
         AE"
    );

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s: TrustAnchorStore = Default::default();

        // load store from JSON
        s.load_json(TEST_JSON_TA_OK_0).unwrap();

        // lookup a known platform reference value
        let ta = s.lookup(&TEST_INST_ID_0);
        assert!(ta.is_some());

        let res = ta.unwrap();

        assert_eq!(res.inst_id, TEST_INST_ID_0);
        assert_eq!(res.impl_id, TEST_IMPL_ID_0);
        assert_eq!(res.pkey, TEST_PKEY_0);
    }
}
