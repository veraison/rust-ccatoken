// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use hex_literal::hex;
use multimap::MultiMap;
use serde::Deserialize;
use serde_json::Error;
use std::sync::RwLock;

/// CCA measured firmware component descriptor
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct SWComponent {
    /// The measurement value
    #[serde(rename(deserialize = "measurement-value"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    mval: Vec<u8>,

    /// The identifier of the ROTPK that signs the firmware image
    #[serde(rename(deserialize = "signer-id"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    signer_id: Vec<u8>,

    /// (Optional) versionining information of the firmare release, e.g., using
    /// SemVer
    #[serde(rename(deserialize = "version"))]
    version: Option<String>,

    /// (Optional) human readable label describing the firwmare, e.g., "TF-A"
    #[serde(rename(deserialize = "component-type"))]
    mtyp: Option<String>,
}

/// A CCA platform reference value set, comprising all the firmware components
/// and platform configuration.  It describes an acceptable state for a certain
/// platform, identified by its implementation identifier.  There may be
/// multiple platform-rv records for the same platform at any point in time,
/// each describing one possible "good" state.
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct PlatformRefValue {
    /// The platform's implementation identifier
    #[serde(rename(deserialize = "implementation-id"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    impl_id: [u8; 32],

    /// The TCB firmare components
    #[serde(rename(deserialize = "sw-components"))]
    sw_components: Vec<SWComponent>,

    /// The CCA platform config contains the System Properties field which is
    /// present in the Root NVS public parameters
    #[serde(rename(deserialize = "platform-configuration"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    config: Vec<u8>,
}

/// A realm reference value set, including RIM, REM and the personalisation
/// value.  It describes an acceptable state for a given realm / CC workload.
/// There may be multiple such records for the same realm, each describing one
/// possible "good" state associated to the realm.
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct RealmRefValue {
    /// The value of the Realm Initial Measurement
    #[serde(rename(deserialize = "initial-measurement"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    rim: Vec<u8>,

    /// The Realm hash algorithm ID claim identifies the algorithm used to
    /// calculate all hash values which are present in the Realm token.  It is
    /// encoded as a human readable string with values from the IANA Hash
    /// Function Textual Names registry.  See:
    /// https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
    #[serde(rename(deserialize = "rak-hash-algorithm"))]
    rak_hash_alg: String,

    /// The Realm Extensible Measurements values
    #[serde(rename(deserialize = "extensible-measurements"))]
    rem: Option<Vec<String>>,

    /// The Realm Personalization Value contains the RPV which was provided at
    /// Realm creation
    #[serde(rename(deserialize = "personalization-value"))]
    perso: Option<String>,
}

/// JSON format for CCA reference values (both platform and realm).
#[derive(Deserialize, Debug)]
pub struct RefValues {
    #[serde(rename(deserialize = "platform"))]
    platform: Option<Vec<PlatformRefValue>>,

    #[serde(rename(deserialize = "realm"))]
    realm: Option<Vec<RealmRefValue>>,
}

impl RefValues {
    /// Parse CCA reference values from JSON
    pub fn parse(j: &str) -> Result<Self, Error> {
        let v: RefValues = serde_json::from_str(j)?;
        // TODO: add validation of variable length fields
        Ok(v)
    }
}

/// The store where platform and realm reference values are stashed
#[derive(Debug)]
pub struct RefValueStore {
    /// platform reference values, indexed by implementation-id
    p: RwLock<MultiMap<[u8; 32], PlatformRefValue>>,

    /// realm reference values, indexed by RIM
    r: RwLock<MultiMap<Vec<u8>, RealmRefValue>>,
}

impl Default for RefValueStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RefValueStore {
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

    /// Lookup all platform reference values matching the given implementation identifier
    pub fn lookup_platform(&self, impl_id: &[u8; 32]) -> Option<Vec<PlatformRefValue>> {
        return self.p.read().unwrap().get_vec(impl_id).cloned();
    }

    /// Lookup all realm reference values matching the given RIM
    pub fn lookup_realm(&self, rim: &Vec<u8>) -> Option<Vec<RealmRefValue>> {
        return self.r.read().unwrap().get_vec(rim).cloned();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_JSON_RV_OK_0: &str = r#"{
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
    const TEST_HEX: [u8; 32] =
        hex!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const TEST_IMPL_ID_0: [u8; 32] = TEST_HEX;
    const TEST_MVAL_0_0: [u8; 32] = TEST_HEX;
    const TEST_SID_0_0: [u8; 32] = TEST_HEX;
    const TEST_CONFIG_0: [u8; 4] = hex!("CFCFCFCF");
    const TEST_RIM_UNKNOWN: [u8; 4] = hex!("DEADBEEF");

    #[test]
    fn load_json_and_lookup_ok() {
        let mut s = RefValueStore::new();

        // load store from JSON
        s.load_json(TEST_JSON_RV_OK_0).unwrap();

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

        let rrv = s.lookup_realm(&TEST_RIM_UNKNOWN.into());
        assert!(rrv.is_none());
    }
}
