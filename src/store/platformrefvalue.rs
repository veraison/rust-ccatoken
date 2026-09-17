// Copyright 2023-2026 Contributors to the Veraison project.
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

/// A single item (public key identifier) in the OPTIONAL TBB ROTPK claim.
///
/// Where an implementation of the CCA platform follows the Trusted Board
/// Boot specification \[TBB\], the platform will include several
/// provisioned public key identifiers which are used to establish a
/// chain of trust. The CCA platform TBB ROTPK claim is used to provide
/// this information to a verifier.
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct TbbRotpkItem {
    /// e.g. "CM" or "DM"
    pub name: String,

    /// The active ROTPK array
    #[serde(rename = "active-array-index")]
    pub active_array_index: i128,

    /// The index in the active array
    pub index: i128,

    /// The hash object
    #[serde_as(as = "serde_with::hex::Hex")]
    pub hash: Vec<u8>,
}

impl TbbRotpkItem {
    pub fn new() -> Self {
        Self {
            name: Default::default(),
            active_array_index: Default::default(),
            index: Default::default(),
            hash: Default::default(),
        }
    }
}

impl Default for TbbRotpkItem {
    fn default() -> Self {
        Self::new()
    }
}

// Allow comparison between TBBRotpkItems in evidence and reference values.
impl PartialEq<token::TbbRotpkItem> for TbbRotpkItem {
    fn eq(&self, other: &token::TbbRotpkItem) -> bool {
        self.name == other.name
            && self.active_array_index == other.active_array_index
            && self.index == other.index
            && self.hash == other.hash
    }
}

/// A single platform extension device in the OPTIONAL extension claim.
///
/// The CCA platform extension claim identifies components which have
/// been added to the CCA platform at runtime and supplies verification
/// hashes for evidence obtained from those components.
/// An example of such a component is a coherent memory (CMEM) device.
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct ExtensionDevice {
    /// The hash algorithm used for the digest fields.
    #[serde(rename = "hash-algo-id", skip_serializing_if = "Option::is_none")]
    pub hash_algo_id: Option<String>,

    /// The device measurements exchange digest.
    #[serde(rename = "device-measurements-digest")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub device_measurements_digest: Vec<u8>,

    /// The certificate chain digest.
    #[serde(rename = "certificate-chain-digest")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub certificate_chain_digest: Vec<u8>,

    /// Indicates whether the device uses Integrity & Data Encryption.
    #[serde(rename = "uses-ide")]
    pub uses_ide: bool,

    /// The protocol used to communicate with the device.
    pub protocol: String,

    /// Required when this device's protocol is one of the protocols supporting VCA,
    /// otherwise no vca-digest field is expected.
    ///
    /// See EXTENSION_DEVICE_PROTOCOLS_SUPPORTING_VCA in token/extension.rs.
    #[serde(rename = "vca-digest", skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    pub vca_digest: Option<Vec<u8>>,

    /// The type of this extension device.
    #[serde(rename = "device-type")]
    pub device_type: String,

    /// Required when this device's device-type requires encryption,
    /// otherwise no encryption-type field is expected
    ///
    /// See EXTENSION_DEVICE_TYPES_WITH_ENCRYPTION_TYPE in token/extension.rs.
    #[serde(rename = "encryption-type", skip_serializing_if = "Option::is_none")]
    pub encryption_type: Option<i128>,
}

impl ExtensionDevice {
    pub fn new() -> Self {
        Self {
            hash_algo_id: Default::default(),
            device_measurements_digest: Default::default(),
            certificate_chain_digest: Default::default(),
            uses_ide: Default::default(),
            protocol: Default::default(),
            vca_digest: Default::default(),
            device_type: Default::default(),
            encryption_type: Default::default(),
        }
    }
}

impl Default for ExtensionDevice {
    fn default() -> Self {
        Self::new()
    }
}

// Allow comparison between extension devices in evidence and reference values.
impl PartialEq<token::ExtensionDevice> for ExtensionDevice {
    fn eq(&self, other: &token::ExtensionDevice) -> bool {
        if self.hash_algo_id != other.hash_algo_id
            || self.device_measurements_digest != other.device_measurements_digest
            || self.certificate_chain_digest != other.certificate_chain_digest
            || self.uses_ide != other.uses_ide
            || self.protocol != other.protocol
            || self.vca_digest != other.vca_digest
            || self.device_type != other.device_type
            || self.encryption_type != other.encryption_type
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

    /// The security domain from which the attestation token was requested.
    ///
    /// Added as a MANDATORY claim in Platform2024 for draft-ffm-03.
    #[serde(rename = "client-id", skip_serializing_if = "Option::is_none")]
    pub client_id: Option<i128>,

    /// Represents a record ofproduction phases and testing conducted
    /// during the manufacturing process for this instance.
    ///
    /// Added as an OPTIONAL claim in Platform2024 for draft-ffm-03.
    #[serde(
        rename = "manufacturing-config",
        skip_serializing_if = "Option::is_none"
    )]
    pub manufacturing_config: Option<Vec<u8>>,

    /// Identifies components which have been added to the CCA platform at runtime
    /// and supplies verification hashes for evidence obtained from those components.
    ///
    /// Added as an OPTIONAL claim in Platform2024 for draft-ffm-03.
    #[serde(rename = "extension", skip_serializing_if = "Option::is_none")]
    pub extension: Option<Vec<ExtensionDevice>>,

    /// Where an implementation of the CCA platform follows the
    /// Trusted Board Boot specification \[TBB\], the platform will include
    /// several provisioned public key identifiers which are used to
    /// establish a chain of trust. The CCA platform TBB ROTPK claim is used
    /// to provide this information to a verifier.
    ///
    /// Added as an OPTIONAL claim in Platform2024 for draft-ffm-03.
    #[serde(rename = "tbb-rotpk", skip_serializing_if = "Option::is_none")]
    pub tbb_rotpk: Option<Vec<TbbRotpkItem>>,

    /// In the event that the CCA platform consists of multiple peer RoTs
    /// which are unable to establish a single attestation signing entity at
    /// boot time, it is necessary for an attestation report produced by one
    /// of those RoTs to identify its peers where execution may be
    /// subsequently scheduled.  The CCA platform peer signers claim is used
    /// to provide this information to a verifier.
    ///
    /// Added as an OPTIONAL claim in Platform2024 for draft-ffm-03.
    #[serde(rename = "peer-signers", skip_serializing_if = "Option::is_none")]
    pub peer_signers: Option<Vec<u8>>,
}
