// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::token;
use serde::{Deserialize, Serialize};

/// CCA measured firmware component descriptor
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct SwComponent {
    /// The measurement value
    #[serde(rename = "measurement-value")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub mval: Vec<u8>,

    /// The identifier of the ROTPK that signs the firmware image
    #[serde(rename = "signer-id")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub signer_id: Vec<u8>,

    /// (Optional) versionining information of the firmare release, e.g., using
    /// SemVer
    #[serde(rename = "version")]
    pub version: Option<String>,

    /// (Optional) human readable label describing the firwmare, e.g., "TF-A"
    #[serde(rename = "component-type")]
    pub mtyp: Option<String>,
}

impl SwComponent {
    pub fn new() -> Self {
        Self {
            mval: Default::default(),
            signer_id: Default::default(),
            version: Default::default(),
            mtyp: Default::default(),
        }
    }
}

impl Default for SwComponent {
    fn default() -> Self {
        Self::new()
    }
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
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub struct PlatformRefValue {
    /// The platform's implementation identifier
    #[serde(rename = "implementation-id")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub impl_id: [u8; 32],

    /// The TCB firmare components
    #[serde(rename = "sw-components")]
    pub sw_components: Vec<SwComponent>,

    /// The CCA platform config contains the System Properties field which is
    /// present in the Root NVS public parameters
    #[serde(rename = "platform-configuration")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub config: Vec<u8>,
}
