// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// A realm reference value set, including RIM, REM and the personalisation
/// value.  It describes an acceptable state for a given realm / CC workload.
/// There may be multiple such records for the same realm, each describing one
/// possible "good" state associated to the realm.
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct RealmRefValue {
    /// The value of the Realm Initial Measurement
    #[serde(rename = "initial-measurement")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub rim: Vec<u8>,

    /// The Realm hash algorithm ID claim identifies the algorithm used to
    /// calculate all hash values which are present in the Realm token.  It is
    /// encoded as a human readable string with values from the IANA Hash
    /// Function Textual Names registry.  See:
    /// https://www.iana.org/assignments/hash-function-text-names/hash-function-text-names.xhtml
    #[serde(rename = "rak-hash-algorithm")]
    pub rak_hash_alg: String,

    /// The Realm Extensible Measurements values
    #[serde(rename = "extensible-measurements")]
    pub rem: [RemEntry; 4],

    /// The Realm Personalization Value contains the RPV which was provided at
    /// Realm creation
    #[serde(rename = "personalization-value")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub perso: Vec<u8>,
}

#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Default)]
#[serde(transparent)]
pub struct RemEntry {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub value: Vec<u8>,
}

// Allow comparison for REM entries between evidence and reference values
impl PartialEq<Vec<u8>> for RemEntry {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.value.eq(other)
    }
}
