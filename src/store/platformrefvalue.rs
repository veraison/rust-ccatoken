// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::token;
use hex_literal::hex;
use multimap::MultiMap;
use serde::Deserialize;
use serde_json::Error;
use std::sync::RwLock;

/// CCA measured firmware component descriptor
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Debug)]
pub struct SwComponent {
    /// The measurement value
    #[serde(rename(deserialize = "measurement-value"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub mval: Vec<u8>,

    /// The identifier of the ROTPK that signs the firmware image
    #[serde(rename(deserialize = "signer-id"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signer_id: Vec<u8>,

    /// (Optional) versionining information of the firmare release, e.g., using
    /// SemVer
    #[serde(rename(deserialize = "version"))]
    pub version: Option<String>,

    /// (Optional) human readable label describing the firwmare, e.g., "TF-A"
    #[serde(rename(deserialize = "component-type"))]
    pub mtyp: Option<String>,
}

// Allow comparison between SwComponents in evidence and reference values
impl PartialEq<token::SwComponent> for SwComponent {
    fn eq(&self, other: &token::SwComponent) -> bool {
        if self.mval != other.mval {
            return false;
        }

        if self.signer_id != other.signer_id {
            return false;
        }

        if self.mtyp.is_some() && (other.mtyp.is_none() || Some(&self.mtyp) != Some(&other.mtyp)) {
            return false;
        }

        if self.version.is_some()
            && (other.version.is_none() || Some(&self.version) != Some(&other.version))
        {
            return false;
        }

        true
    }
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
    pub impl_id: [u8; 32],

    /// The TCB firmare components
    #[serde(rename(deserialize = "sw-components"))]
    pub sw_components: Vec<SwComponent>,

    /// The CCA platform config contains the System Properties field which is
    /// present in the Root NVS public parameters
    #[serde(rename(deserialize = "platform-configuration"))]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub config: Vec<u8>,
}
