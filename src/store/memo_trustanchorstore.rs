// Copyright 2023-2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::cpak::Cpak;
use super::errors::Error;
use super::ITrustAnchorStore;
use std::collections::HashMap;
use std::sync::RwLock;

/// The store where the active CPAKs are stashed.  CPAKs are indexed by their
/// instance-id.
#[derive(Debug)]
pub struct MemoTrustAnchorStore {
    p: RwLock<HashMap<[u8; 33], Cpak>>,
}

impl Default for MemoTrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoTrustAnchorStore {
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
}

impl ITrustAnchorStore for MemoTrustAnchorStore {
    /// Lookup a trust anchor from the store given the corresponding Instance ID
    fn lookup(&self, inst_id: &[u8; 33]) -> Option<Cpak> {
        return self.p.read().unwrap().get(inst_id).cloned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk;

    const TEST_JSON_TA_OK_0: &str = include_str!("../../testdata/ta.json");
    const TEST_INST_ID_0: &[u8; 33] = include_bytes!("../../testdata/inst-id.bin");
    const TEST_IMPL_ID_0: &[u8; 32] = include_bytes!("../../testdata/impl-id.bin");
    const TEST_PKEY_0: &str = include_str!("../../testdata/pkey.json");

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s: MemoTrustAnchorStore = Default::default();

        // load store from JSON
        s.load_json(TEST_JSON_TA_OK_0).unwrap();

        // lookup a known platform reference value
        let ta = s.lookup(TEST_INST_ID_0);
        assert!(ta.is_some());

        let res = ta.unwrap();

        assert_eq!(res.inst_id, *TEST_INST_ID_0);
        assert_eq!(res.impl_id, *TEST_IMPL_ID_0);

        let pkey = serde_json::from_str::<jwk::Jwk>(TEST_PKEY_0).unwrap();
        assert_eq!(res.pkey, Some(pkey));
    }
}
