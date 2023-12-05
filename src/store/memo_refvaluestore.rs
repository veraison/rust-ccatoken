// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::platformrefvalue::PlatformRefValue;
use super::realmrefvalue::RealmRefValue;
use super::refvalues::RefValues;
use super::IRefValueStore;
use multimap::MultiMap;
use serde_json::Error;
use std::sync::RwLock;

/// The store where platform and realm reference values are stashed
#[derive(Debug, Default)]
pub struct MemoRefValueStore {
    /// platform reference values, indexed by implementation-id
    p: RwLock<MultiMap<[u8; 32], PlatformRefValue>>,

    /// realm reference values, indexed by RIM
    r: RwLock<MultiMap<Vec<u8>, RealmRefValue>>,
}

impl MemoRefValueStore {
    pub fn new() -> Self {
        Self {
            p: Default::default(),
            r: Default::default(),
        }
    }

    /// Add to an existing (and possibly empty) RefValueStore the platform and
    /// realm reference values loaded from the given JSON file
    pub fn load_json(&mut self, j: &str) -> Result<(), Error> {
        let v = RefValues::parse(j)?;

        if v.platform.is_some() {
            let p = v.platform.as_ref().unwrap();

            for prv in p.iter() {
                self.p.write().unwrap().insert(prv.impl_id, prv.clone());
            }
        }

        if v.realm.is_some() {
            let p = v.realm.as_ref().unwrap();

            for prv in p.iter() {
                self.r.write().unwrap().insert(prv.rim.clone(), prv.clone());
            }
        }

        Ok(())
    }
}

impl IRefValueStore for MemoRefValueStore {
    /// Lookup all platform reference values matching the given implementation identifier
    fn lookup_platform(&self, impl_id: &[u8; 32]) -> Option<Vec<PlatformRefValue>> {
        return self.p.read().unwrap().get_vec(impl_id).cloned();
    }

    /// Lookup all realm reference values matching the given RIM
    fn lookup_realm(&self, rim: &[u8]) -> Option<Vec<RealmRefValue>> {
        return self.r.read().unwrap().get_vec(rim).cloned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const TEST_CCA_RVS_OK: &str = include_str!("../../testdata/rv.json");
    const TEST_HEX: [u8; 32] =
        hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const TEST_IMPL_ID_0: [u8; 32] = TEST_HEX;
    const TEST_MVAL_0_0: [u8; 32] = TEST_HEX;
    const TEST_SID_0_0: [u8; 32] = TEST_HEX;
    const TEST_CONFIG_0: [u8; 4] = hex!("CFCFCFCF");
    const TEST_RIM_UNKNOWN: [u8; 4] = hex!("DEADBEEF");

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s = MemoRefValueStore::new();

        // load store from JSON
        s.load_json(TEST_CCA_RVS_OK).unwrap();

        // lookup a known platform reference value
        let prv = s.lookup_platform(&TEST_IMPL_ID_0);
        assert!(prv.is_some());

        let res = prv.unwrap();
        assert_eq!(res.len(), 1);

        let res0 = &res[0];
        assert_eq!(res0.impl_id, TEST_IMPL_ID_0);
        assert_eq!(res0.config, TEST_CONFIG_0);
        assert_eq!(res0.sw_components.len(), 1);

        let swcomp = &res0.sw_components[0];
        assert!(swcomp.mtyp.is_some());
        assert_eq!(swcomp.mtyp.as_ref().unwrap(), "BL");
        assert_eq!(swcomp.mval, TEST_MVAL_0_0);
        assert_eq!(swcomp.signer_id, TEST_SID_0_0);
        assert!(swcomp.version.is_some());
        assert_eq!(swcomp.version.as_ref().unwrap(), "1.0.2rc5");

        let rrv = s.lookup_realm(&TEST_RIM_UNKNOWN);
        assert!(rrv.is_none());
    }
}
