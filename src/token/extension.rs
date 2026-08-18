// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use crate::token::common::*;
use crate::token::errors::Error;
use bitflags::bitflags;
use ciborium::Value;

const EXTENSION_DEVICE_HASH_ALGORITHM: i128 = 1;
const EXTENSION_DEVICE_DEVICE_MEASUREMENTS_DIGEST: i128 = 2;
const EXTENSION_DEVICE_CERTIFICATE_CHAIN_DIGEST: i128 = 3;
const EXTENSION_DEVICE_USES_IDE: i128 = 4;
const EXTENSION_DEVICE_PROTOCOL: i128 = 5;
const EXTENSION_DEVICE_VCA_DIGEST: i128 = 6;
const EXTENSION_DEVICE_DEVICE_TYPE: i128 = 7;
const EXTENSION_DEVICE_ENCRYPTION_TYPE: i128 = 8;

const EXTENSION_DEVICE_PROTOCOLS_SUPPORTING_VCA: &[&str] = &[
    "spdm-1.2.0",
    "spdm-1.2.1",
    "spdm-1.2.2",
    "spdm-1.2.3",
    "spdm-1.3.0",
    "spdm-1.3.1",
    "spdm-1.3.2",
    "spdm-1.4.0",
];

const EXTENSION_DEVICE_TYPES_WITH_ENCRYPTION_TYPE: &[&str] = &["cxl-type-3"];

const ENCRYPTION_TYPE_HOST_SIDE_ENCRYPTION: i128 = 0;
const ENCRYPTION_TYPE_TARGET_SIDE_ENCRYPTION: i128 = 1;
const ENCRYPTION_TYPE_NO_ENCRYPTION: i128 = 2;

pub fn is_valid_encryption_type(value: i128) -> bool {
    matches!(
        value,
        ENCRYPTION_TYPE_HOST_SIDE_ENCRYPTION
            | ENCRYPTION_TYPE_TARGET_SIDE_ENCRYPTION
            | ENCRYPTION_TYPE_NO_ENCRYPTION
    )
}

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    struct ExtensionDeviceClaimsSet: u8 {
        const HASH_ALGORITHM        = 0x01;
        const DEVICE_MEASUREMENTS_DIGEST = 0x02;
        const CERTIFICATE_CHAIN_DIGEST = 0x04;
        const USES_IDE              = 0x08;
        const PROTOCOL              = 0x10;
        const VCA_DIGEST            = 0x20;
        const DEVICE_TYPE           = 0x40;
        const ENCRYPTION_TYPE       = 0x80;
    }
}

#[derive(Debug, PartialEq)]
pub struct ExtensionDevice {
    pub hash_algo_id: Option<String>,        // 1, text
    pub device_measurements_digest: Vec<u8>, // 2, bytes .size {32,48,64}
    pub certificate_chain_digest: Vec<u8>,   // 3, bytes .size {32,48,64}
    pub uses_ide: bool,                      // 4, bool
    pub protocol: String,                    // 5, text
    pub vca_digest: Option<Vec<u8>>,         // 6, bytes .size {32,48,64}
    pub device_type: String,                 // 7, text
    pub encryption_type: Option<i128>,       // 8, int (enum)

    claims_set: ExtensionDeviceClaimsSet,
}

impl Default for ExtensionDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionDevice {
    pub fn new() -> Self {
        Self {
            hash_algo_id: None,
            device_measurements_digest: Default::default(),
            certificate_chain_digest: Default::default(),
            uses_ide: false,
            protocol: String::from(""),
            vca_digest: None,
            device_type: String::from(""),
            encryption_type: None,

            claims_set: ExtensionDeviceClaimsSet::empty(),
        }
    }

    fn set_hash_algorithm(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::HASH_ALGORITHM)
        {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        let hash_algo_id = to_tstr(v, "hash-algo-id")?;

        if hash_algo_id.is_empty() {
            return Err(Error::Sema(
                "hash-algo-id should not be empty if set".to_string(),
            ));
        }

        self.hash_algo_id = Some(hash_algo_id);

        self.claims_set
            .set(ExtensionDeviceClaimsSet::HASH_ALGORITHM, true);

        Ok(())
    }

    fn set_device_measurements_digest(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::DEVICE_MEASUREMENTS_DIGEST)
        {
            return Err(Error::DuplicatedClaim(
                "device-measurements-digest".to_string(),
            ));
        }

        self.device_measurements_digest = to_measurement(v, "device-measurements-digest")?;

        self.claims_set
            .set(ExtensionDeviceClaimsSet::DEVICE_MEASUREMENTS_DIGEST, true);

        Ok(())
    }

    fn set_certificate_chain_digest(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::CERTIFICATE_CHAIN_DIGEST)
        {
            return Err(Error::DuplicatedClaim(
                "certificate-chain-digest".to_string(),
            ));
        }

        self.certificate_chain_digest = to_measurement(v, "certificate-chain-digest")?;

        self.claims_set
            .set(ExtensionDeviceClaimsSet::CERTIFICATE_CHAIN_DIGEST, true);

        Ok(())
    }

    fn set_uses_ide(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ExtensionDeviceClaimsSet::USES_IDE) {
            return Err(Error::DuplicatedClaim("uses-ide".to_string()));
        }

        self.uses_ide = to_bool(v, "uses-ide")?;

        self.claims_set
            .set(ExtensionDeviceClaimsSet::USES_IDE, true);

        Ok(())
    }

    fn set_protocol(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ExtensionDeviceClaimsSet::PROTOCOL) {
            return Err(Error::DuplicatedClaim("protocol".to_string()));
        }

        let protocol = to_tstr(v, "protocol")?;

        if protocol.is_empty() {
            return Err(Error::Sema("protocol should not be empty".to_string()));
        }

        self.protocol = protocol;

        self.claims_set
            .set(ExtensionDeviceClaimsSet::PROTOCOL, true);

        Ok(())
    }

    fn set_vca_digest(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::VCA_DIGEST)
        {
            return Err(Error::DuplicatedClaim("vca-digest".to_string()));
        }

        let vca_digest = to_measurement(v, "vca-digest")?;

        self.vca_digest = Some(vca_digest);

        self.claims_set
            .set(ExtensionDeviceClaimsSet::VCA_DIGEST, true);

        Ok(())
    }

    fn set_device_type(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::DEVICE_TYPE)
        {
            return Err(Error::DuplicatedClaim("device-type".to_string()));
        }

        let device_type = to_tstr(v, "device-type")?;

        if device_type.is_empty() {
            return Err(Error::Sema("device-type should not be empty".to_string()));
        }

        self.device_type = device_type;

        self.claims_set
            .set(ExtensionDeviceClaimsSet::DEVICE_TYPE, true);

        Ok(())
    }

    fn set_encryption_type(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(ExtensionDeviceClaimsSet::ENCRYPTION_TYPE)
        {
            return Err(Error::DuplicatedClaim("encryption-type".to_string()));
        }

        let encryption_type = to_int(v, "encryption-type")?;

        if !is_valid_encryption_type(encryption_type) {
            return Err(Error::Sema(format!(
                "unknown encryption type {encryption_type}"
            )));
        }

        self.encryption_type = Some(encryption_type);

        self.claims_set
            .set(ExtensionDeviceClaimsSet::ENCRYPTION_TYPE, true);

        Ok(())
    }

    pub(crate) fn parse(&mut self, contents: &[(Value, Value)]) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    EXTENSION_DEVICE_HASH_ALGORITHM => self.set_hash_algorithm(v)?,
                    EXTENSION_DEVICE_DEVICE_MEASUREMENTS_DIGEST => {
                        self.set_device_measurements_digest(v)?
                    }
                    EXTENSION_DEVICE_CERTIFICATE_CHAIN_DIGEST => {
                        self.set_certificate_chain_digest(v)?
                    }
                    EXTENSION_DEVICE_USES_IDE => self.set_uses_ide(v)?,
                    EXTENSION_DEVICE_PROTOCOL => self.set_protocol(v)?,
                    EXTENSION_DEVICE_VCA_DIGEST => self.set_vca_digest(v)?,
                    EXTENSION_DEVICE_DEVICE_TYPE => self.set_device_type(v)?,
                    EXTENSION_DEVICE_ENCRYPTION_TYPE => self.set_encryption_type(v)?,
                    unknown => {
                        return Err(Error::Syntax(format!(
                            "unknown key {unknown} in extension device"
                        )))
                    }
                }
            } else {
                return Err(Error::Syntax(
                    "non-integer key in extension device".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Validates correct shape of object.
    /// Field-level validation is done in the setters called by parse.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let mandatory_claims = [
            (
                ExtensionDeviceClaimsSet::DEVICE_MEASUREMENTS_DIGEST,
                "device-measurements-digest",
            ),
            (
                ExtensionDeviceClaimsSet::CERTIFICATE_CHAIN_DIGEST,
                "certificate-chain-digest",
            ),
            (ExtensionDeviceClaimsSet::USES_IDE, "uses-ide"),
            (ExtensionDeviceClaimsSet::PROTOCOL, "protocol"),
            (ExtensionDeviceClaimsSet::DEVICE_TYPE, "device-type"),
        ];

        for (claim, name) in mandatory_claims.iter() {
            if !self.claims_set.contains(*claim) {
                return Err(Error::MissingClaim(name.to_string()));
            }
        }

        if EXTENSION_DEVICE_PROTOCOLS_SUPPORTING_VCA.contains(&self.protocol.as_str()) {
            if !self
                .claims_set
                .contains(ExtensionDeviceClaimsSet::VCA_DIGEST)
            {
                return Err(Error::MissingClaim("vca-digest".to_string()));
            }
        } else {
            if self
                .claims_set
                .contains(ExtensionDeviceClaimsSet::VCA_DIGEST)
            {
                return Err(Error::Sema(format!(
                    "vca-digest is set but not expected for protocol {}",
                    self.protocol
                )));
            }
        }

        if EXTENSION_DEVICE_TYPES_WITH_ENCRYPTION_TYPE.contains(&self.device_type.as_str()) {
            if !self
                .claims_set
                .contains(ExtensionDeviceClaimsSet::ENCRYPTION_TYPE)
            {
                return Err(Error::MissingClaim("encryption-type".to_string()));
            }
        } else {
            if self
                .claims_set
                .contains(ExtensionDeviceClaimsSet::ENCRYPTION_TYPE)
            {
                return Err(Error::Sema(format!(
                    "encryption-type is set but not expected for device-type {}",
                    self.device_type
                )));
            }
        }

        Ok(())
    }
}
