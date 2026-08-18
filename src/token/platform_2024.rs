// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use super::common::*;
use super::errors::Error;
use super::ExtensionDevice;
use super::SwComponent;
use super::TbbRotpkItem;
use bitflags::bitflags;
use ciborium::de::from_reader;
use ciborium::Value;

const PLATFORM_PROFILE_2024: &str = "tag:arm.com,2024:cca_platform#2.0.0";
const PLATFORM_PROFILE_LABEL: i128 = 265;
const PLATFORM_CHALLENGE_LABEL: i128 = 10;
const PLATFORM_IMPL_ID_LABEL: i128 = 2396;
const PLATFORM_INST_ID_LABEL: i128 = 256;
const PLATFORM_CONFIG_LABEL: i128 = 2401;
const PLATFORM_LIFECYCLE_LABEL: i128 = 2395;
const PLATFORM_SW_COMPONENTS: i128 = 2399;
const PLATFORM_VERIFICATION_SERVICE: i128 = 2400;
const PLATFORM_HASH_ALG: i128 = 2402;
const PLATFORM_CLIENT_ID: i128 = 2394;
const PLATFORM_MANUFACTURING_CONFIG: i128 = 2403;
const PLATFORM_EXTENSION: i128 = 2404;
const PLATFORM_TBB_ROTPK: i128 = 2405;
const PLATFORM_PEER_SIGNERS: i128 = 2406;

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    struct ClaimsSet: u16 {
        const PROFILE      = 0x01;
        const CHALLENGE    = 0x02;
        const IMPL_ID      = 0x04;
        const INST_ID      = 0x08;
        const CONFIG       = 0x10;
        const LIFECYCLE    = 0x20;
        const SW_COMPONENTS = 0x40;
        const VSI          = 0x80;
        const HASH_ALG     = 0x100;
        const CLIENT_ID    = 0x200;
        const MANUFACTURING_CONFIG = 0x400;
        const EXTENSION    = 0x800;
        const TBB_ROTPK    = 0x1000;
        const PEER_SIGNERS = 0x2000;
    }
}

/// For syntax and semantics of the claims-set, see
/// https://datatracker.ietf.org/doc/draft-ffm-rats-cca-token/03/
#[derive(Debug)]
pub struct Platform2024 {
    pub profile: String,                 // 265, text ("http://arm.com/CCA-SSD/1.0.0")
    pub challenge: Vec<u8>,              // 10, bytes .size {32,48,64}
    pub impl_id: [u8; 32],               // 2396, bytes .size 32
    pub inst_id: [u8; 33],               // 256, bytes .size 33
    pub config: Vec<u8>,                 // 2401, bytes
    pub lifecycle: u16,                  // 2395, 0x0000..0x00ff ... 0x6000..0x60ff
    pub sw_components: Vec<SwComponent>, // 2399, cca-platform-sw-component
    pub verification_service: Option<String>, // 2400, text
    pub hash_alg: String,                // 2402, text
    pub client_id: i128,                 // 2394, int, must be 1
    pub manufacturing_config: Option<Vec<u8>>, // 2403, bytes
    pub extension: Option<Vec<ExtensionDevice>>, // 2404, platform-extension-device
    pub tbb_rotpk: Option<Vec<TbbRotpkItem>>, // 2405, platform-tbb-rotpk
    pub peer_signers: Option<Vec<u8>>,   // 2406, bytes
    claims_set: ClaimsSet,
}

impl Default for Platform2024 {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform2024 {
    pub fn new() -> Self {
        Self {
            profile: String::from(""),
            challenge: Default::default(),
            impl_id: [0; 32],
            inst_id: [0; 33],
            config: Default::default(),
            lifecycle: 0,
            sw_components: Default::default(),
            verification_service: None,
            hash_alg: String::from(""),
            client_id: 0,
            manufacturing_config: None,
            extension: None,
            tbb_rotpk: None,
            peer_signers: None,
            claims_set: ClaimsSet::empty(),
        }
    }

    /// Decode a CBOR encoded CCA platform claims-set
    pub fn decode(buf: &Vec<u8>) -> Result<Platform2024, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut platform_claims: Platform2024 = Default::default();

        if let Value::Map(contents) = v {
            platform_claims.parse(contents)?;
        } else {
            return Err(Error::Syntax("expecting map type".to_string()));
        }

        platform_claims.validate()?;

        Ok(platform_claims)
    }

    fn parse(&mut self, contents: Vec<(Value, Value)>) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            // Setters check validity of each claim
            if let Value::Integer(i) = k {
                match (*i).into() {
                    PLATFORM_PROFILE_LABEL => self.set_profile(v)?,
                    PLATFORM_CHALLENGE_LABEL => self.set_challenge(v)?,
                    PLATFORM_IMPL_ID_LABEL => self.set_impl_id(v)?,
                    PLATFORM_INST_ID_LABEL => self.set_inst_id(v)?,
                    PLATFORM_CONFIG_LABEL => self.set_config(v)?,
                    PLATFORM_LIFECYCLE_LABEL => self.set_lifecycle(v)?,
                    PLATFORM_SW_COMPONENTS => self.set_sw_components(v)?,
                    PLATFORM_VERIFICATION_SERVICE => self.set_vsi(v)?,
                    PLATFORM_HASH_ALG => self.set_hash_alg(v)?,
                    PLATFORM_CLIENT_ID => self.set_client_id(v)?,
                    PLATFORM_MANUFACTURING_CONFIG => self.set_manufacturing_config(v)?,
                    PLATFORM_EXTENSION => self.set_extension(v)?,
                    PLATFORM_TBB_ROTPK => self.set_tbb_rotpk(v)?,
                    PLATFORM_PEER_SIGNERS => self.set_peer_signers(v)?,
                    _ => continue,
                }
            } else {
                // CCA does not define any non-integer key
                continue;
            }
        }
        Ok(())
    }

    /// Validates correct shape of token.
    /// Claim-level validation is done in the setters called by parse.
    fn validate(&self) -> Result<(), Error> {
        let mandatory_claims = [
            (ClaimsSet::PROFILE, "profile"),
            (ClaimsSet::CHALLENGE, "challenge"),
            (ClaimsSet::IMPL_ID, "implementation-id"),
            (ClaimsSet::INST_ID, "instance-id"),
            (ClaimsSet::CONFIG, "config"),
            (ClaimsSet::LIFECYCLE, "lifecycle"),
            (ClaimsSet::SW_COMPONENTS, "sw-components"),
            (ClaimsSet::HASH_ALG, "hash-algo"),
            (ClaimsSet::CLIENT_ID, "client-id"),
        ];

        for (claim, name) in mandatory_claims.iter() {
            if !self.claims_set.contains(*claim) {
                return Err(Error::MissingClaim(name.to_string()));
            }
        }

        // TODO:
        // * hash-type'd measurements are compatible with hash-alg
        Ok(())
    }

    fn set_profile(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::PROFILE) {
            return Err(Error::DuplicatedClaim("profile".to_string()));
        }

        let profile = to_tstr(v, "profile")?;

        if profile != PLATFORM_PROFILE_2024 {
            return Err(Error::UnknownProfile(profile.to_string()));
        }

        self.profile = profile;

        self.claims_set.set(ClaimsSet::PROFILE, true);

        Ok(())
    }

    fn set_challenge(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::CHALLENGE) {
            return Err(Error::DuplicatedClaim("challenge".to_string()));
        }

        self.challenge = to_measurement(v, "challenge")?;

        self.claims_set.set(ClaimsSet::CHALLENGE, true);

        Ok(())
    }

    fn set_impl_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::IMPL_ID) {
            return Err(Error::DuplicatedClaim("implementation-id".to_string()));
        }

        let impl_id = to_bstr(v, "implementation-id")?;
        let impl_id_len = impl_id.len();

        if impl_id_len != 32 {
            return Err(Error::Sema(format!(
                "implementation-id: expecting 32 bytes, got {impl_id_len}"
            )));
        }

        self.impl_id[..].clone_from_slice(&impl_id);

        self.claims_set.set(ClaimsSet::IMPL_ID, true);

        Ok(())
    }

    fn set_inst_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::INST_ID) {
            return Err(Error::DuplicatedClaim("instance-id".to_string()));
        }

        let inst_id = to_bstr(v, "instance-id")?;
        let inst_id_len = inst_id.len();

        if inst_id_len != 33 {
            return Err(Error::Sema(format!(
                "instance-id: expecting 33 bytes, got {inst_id_len}"
            )));
        }

        if inst_id[0] != 0x01 {
            return Err(Error::Sema(format!(
                "instance-id: first byte MUST be 0x01 (RAND), got 0x{:02x}",
                inst_id[0]
            )));
        }

        self.inst_id[..].clone_from_slice(&inst_id);

        self.claims_set.set(ClaimsSet::INST_ID, true);

        Ok(())
    }

    fn set_config(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::CONFIG) {
            return Err(Error::DuplicatedClaim("config".to_string()));
        }

        let cfg = to_bstr(v, "config")?;

        if cfg.is_empty() {
            return Err(Error::Sema("config: should not be empty".to_string()));
        }

        self.config = cfg;

        self.claims_set.set(ClaimsSet::CONFIG, true);

        Ok(())
    }

    fn set_lifecycle(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::LIFECYCLE) {
            return Err(Error::DuplicatedClaim("lifecycle".to_string()));
        }

        let lc: i128 = to_int(v, "lifecycle")?;

        if !is_valid_lifecycle(lc) {
            return Err(Error::Sema(format!("unknown lifecycle {lc}")));
        }

        self.lifecycle = lc as u16;

        self.claims_set.set(ClaimsSet::LIFECYCLE, true);

        Ok(())
    }

    fn set_vsi(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::VSI) {
            return Err(Error::DuplicatedClaim("verification-service".to_string()));
        }

        let vsi = to_tstr(v, "verification-service")?;

        if vsi.is_empty() {
            return Err(Error::Sema(
                "verification-service: should not be empty if set".to_string(),
            ));
        }

        self.verification_service = Some(vsi);

        self.claims_set.set(ClaimsSet::VSI, true);

        Ok(())
    }

    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::HASH_ALG) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        self.hash_alg = to_hash_alg(v, "hash-algo-id")?;

        self.claims_set.set(ClaimsSet::HASH_ALG, true);

        Ok(())
    }

    fn set_sw_component(&mut self, swc: &Value) -> Result<(), Error> {
        let mut sw_component: SwComponent = Default::default();

        if let Value::Map(contents) = swc {
            sw_component.parse(contents)?;
        }

        sw_component.validate()?;

        self.sw_components.push(sw_component);

        Ok(())
    }

    fn set_sw_components(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::SW_COMPONENTS) {
            return Err(Error::DuplicatedClaim("software-components".to_string()));
        }

        let input_arr = v.as_array().ok_or(Error::TypeMismatch(
            "software-components MUST be array".to_string(),
        ))?;
        let input_arr_len = input_arr.len();

        if input_arr_len == 0 {
            return Err(Error::Sema(
                "software-measurements: expecting at least one slot".to_string(),
            ));
        }

        for (i, swc) in input_arr.iter().enumerate() {
            let _ = swc.as_map().ok_or(Error::TypeMismatch(format!(
                "sw-component[{i}] MUST be map"
            )))?;

            self.set_sw_component(swc)?;
        }

        self.claims_set.set(ClaimsSet::SW_COMPONENTS, true);

        Ok(())
    }

    fn set_client_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::CLIENT_ID) {
            return Err(Error::DuplicatedClaim("client-id".to_string()));
        }

        let client_id: i128 = to_int(v, "client-id")?;

        if client_id != 1 {
            return Err(Error::Sema(format!(
                "client-id: expecting 1, got {client_id}"
            )));
        }

        self.client_id = client_id;

        self.claims_set.set(ClaimsSet::CLIENT_ID, true);

        Ok(())
    }

    fn set_manufacturing_config(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::MANUFACTURING_CONFIG) {
            return Err(Error::DuplicatedClaim("manufacturing-config".to_string()));
        }

        let mfg_config = to_bstr(v, "manufacturing-config")?;

        if mfg_config.is_empty() {
            return Err(Error::Sema(
                "manufacturing-config: should not be empty if set".to_string(),
            ));
        }

        self.manufacturing_config = Some(mfg_config);

        self.claims_set.set(ClaimsSet::MANUFACTURING_CONFIG, true);

        Ok(())
    }

    fn set_tbb_rotpk(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::TBB_ROTPK) {
            return Err(Error::DuplicatedClaim("tbb-rotpk".to_string()));
        }

        let input_arr = v
            .as_array()
            .ok_or(Error::TypeMismatch("tbb-rotpk MUST be array".to_string()))?;

        let input_arr_len = input_arr.len();

        if input_arr_len == 0 {
            return Err(Error::Sema(
                "tbb-rotpk: expecting at least one item if set".to_string(),
            ));
        }

        let mut tbb_rotpk_items: Vec<TbbRotpkItem> = Vec::new();

        for (i, input_item) in input_arr.iter().enumerate() {
            let _ = input_item
                .as_map()
                .ok_or(Error::TypeMismatch(format!("tbb-rotpk[{i}] MUST be map")))?;

            let mut tbb_rotpk_item: TbbRotpkItem = Default::default();

            if let Value::Map(contents) = input_item {
                tbb_rotpk_item.parse(contents)?;
            }

            tbb_rotpk_item.validate()?;

            tbb_rotpk_items.push(tbb_rotpk_item);
        }
        self.tbb_rotpk = Some(tbb_rotpk_items);
        self.claims_set.set(ClaimsSet::TBB_ROTPK, true);

        Ok(())
    }

    fn set_extension(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::EXTENSION) {
            return Err(Error::DuplicatedClaim("extension".to_string()));
        }

        let input_arr = v
            .as_array()
            .ok_or(Error::TypeMismatch("extension MUST be array".to_string()))?;
        let input_arr_len = input_arr.len();

        if input_arr_len == 0 {
            return Err(Error::Sema(
                "extension: expecting at least one item if set".to_string(),
            ));
        }

        let mut extension_devices: Vec<ExtensionDevice> = Vec::new();

        for (i, input_item) in input_arr.iter().enumerate() {
            let _ = input_item
                .as_map()
                .ok_or(Error::TypeMismatch(format!("extension[{i}] MUST be map")))?;

            let mut device: ExtensionDevice = Default::default();

            if let Value::Map(contents) = input_item {
                device.parse(contents)?;
            }

            device.validate()?;

            extension_devices.push(device);
        }
        self.extension = Some(extension_devices);
        self.claims_set.set(ClaimsSet::EXTENSION, true);

        Ok(())
    }

    fn set_peer_signers(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::PEER_SIGNERS) {
            return Err(Error::DuplicatedClaim("peer-signers".to_string()));
        }

        let peer_signers = to_bstr(v, "peer-signers")?;

        if peer_signers.is_empty() {
            return Err(Error::Sema(
                "peer-signers: should not be empty if set".to_string(),
            ));
        }

        self.peer_signers = Some(peer_signers);

        self.claims_set.set(ClaimsSet::PEER_SIGNERS, true);

        Ok(())
    }

    pub fn get_challenge(&self) -> Result<&Vec<u8>, Error> {
        Ok(self.challenge.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn mandatory_claims_only_ok() {
        let buf = include_bytes!("../../testdata/platform-2024/valid-mandatory-only.cbor").to_vec();

        let _p = Platform2024::decode(&buf).unwrap();

        println!("{_p:#?}");
    }

    #[test]
    fn all_claims_ok() {
        let buf = include_bytes!("../../testdata/platform-2024/valid-all.cbor").to_vec();

        let _p = Platform2024::decode(&buf).unwrap();

        println!("{_p:#?}");
    }

    macro_rules! claims_nok {
        ($name:ident, $filename:literal, $error:ident) => {
            #[test]
            fn $name() {
                let buf =
                    include_bytes!(concat!("../../testdata/platform-2024/", $filename, ".cbor"))
                        .to_vec();

                assert!(matches!(Platform2024::decode(&buf), Err(Error::$error(_))));
            }
        };
    }

    claims_nok!(
        claims_missing_client_id_nok,
        "missing-client-id",
        MissingClaim
    );
    claims_nok!(
        claims_invalid_manufacturing_config_nok,
        "invalid-manufacturing-config",
        Sema
    );
    claims_nok!(
        claims_missing_extension_vca_digest_nok,
        "missing-extension-vca-digest",
        MissingClaim
    );
    claims_nok!(
        claims_invalid_extension_vca_digest_nok,
        "invalid-extension-vca-digest",
        Sema
    );
    claims_nok!(
        claims_invalid_extension_certificate_chain_digest_nok,
        "invalid-extension-certificate-chain-digest",
        Sema
    );
    claims_nok!(
        claims_missing_extension_encryption_type_nok,
        "missing-extension-encryption-type",
        MissingClaim
    );
    claims_nok!(
        claims_invalid_tbb_rotpk_hash_length_nok,
        "invalid-tbb-rotpk-hash-length",
        Sema
    );

    #[test]
    fn dup_claim() {
        let buf = hex!("a219096061781909606178").to_vec();

        assert!(Platform2024::decode(&buf).is_err());
    }
}
