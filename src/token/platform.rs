// Copyright 2023-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use super::common::*;
use super::errors::Error;
use bitflags::bitflags;
use ciborium::de::from_reader;
use ciborium::Value;

const SW_COMPONENT_MTYP: i128 = 1;
const SW_COMPONENT_MVAL: i128 = 2;
const SW_COMPONENT_VERSION: i128 = 4;
const SW_COMPONENT_SIGNER_ID: i128 = 5;
const SW_COMPONENT_HASH_ALGO: i128 = 6;

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    struct SwClaimsSet: u8 {
        const MTYP      = 0x01;
        const MVAL      = 0x02;
        const VERSION   = 0x04;
        const SIGNER_ID = 0x08;
        const CONFIG    = 0x10;
        const HASH_ALG  = 0x20;
    }
}

#[derive(Debug, PartialEq)]
pub struct SwComponent {
    pub mtyp: Option<String>, // 1, text

    pub mval: Vec<u8>,            // 2, bytes .size {32,48,64}
    pub version: Option<String>,  // 4, text
    pub signer_id: Vec<u8>,       // 5, bytes .size {32,48,64}
    pub hash_alg: Option<String>, // 6, text

    claims_set: SwClaimsSet,
}

impl Default for SwComponent {
    fn default() -> Self {
        Self::new()
    }
}

impl SwComponent {
    pub fn new() -> Self {
        Self {
            mtyp: None,
            mval: Default::default(),
            version: None,
            signer_id: Default::default(),
            hash_alg: None,

            claims_set: SwClaimsSet::empty(),
        }
    }

    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaimsSet::HASH_ALG) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        let x = to_hash_alg(v, "hash-algo-id")?;

        self.hash_alg = Some(x);

        self.claims_set.set(SwClaimsSet::HASH_ALG, true);

        Ok(())
    }

    fn set_signer_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaimsSet::SIGNER_ID) {
            return Err(Error::DuplicatedClaim("signer-id".to_string()));
        }

        self.signer_id = to_bstr(v, "signer-id")?;

        self.claims_set.set(SwClaimsSet::SIGNER_ID, true);

        Ok(())
    }

    fn set_version(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaimsSet::VERSION) {
            return Err(Error::DuplicatedClaim("version".to_string()));
        }

        let x = to_tstr(v, "version")?;

        self.version = Some(x);

        self.claims_set.set(SwClaimsSet::VERSION, true);

        Ok(())
    }

    fn set_mtyp(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaimsSet::MTYP) {
            return Err(Error::DuplicatedClaim("measurement-type".to_string()));
        }

        let x = to_tstr(v, "measurement-type")?;

        self.mtyp = Some(x);

        self.claims_set.set(SwClaimsSet::MTYP, true);

        Ok(())
    }

    fn set_mval(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(SwClaimsSet::MVAL) {
            return Err(Error::DuplicatedClaim("measurement-value".to_string()));
        }

        self.mval = to_measurement(v, "measurement-value")?;

        self.claims_set.set(SwClaimsSet::MVAL, true);

        Ok(())
    }

    pub(crate) fn parse(&mut self, contents: &[(Value, Value)]) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    SW_COMPONENT_MTYP => self.set_mtyp(v)?,
                    SW_COMPONENT_MVAL => self.set_mval(v)?,
                    SW_COMPONENT_VERSION => self.set_version(v)?,
                    SW_COMPONENT_SIGNER_ID => self.set_signer_id(v)?,
                    SW_COMPONENT_HASH_ALGO => self.set_hash_alg(v)?,
                    unknown => {
                        return Err(Error::Syntax(format!(
                            "unknown key {unknown} in sw-components"
                        )))
                    }
                }
            } else {
                return Err(Error::Syntax(
                    "non-integer key in sw-components".to_string(),
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        // only mval and signer-id are mandatory
        let mandatory_claims = [
            (SwClaimsSet::MVAL, "measurement-value"),
            (SwClaimsSet::SIGNER_ID, "signer-id"),
        ];

        for (c, n) in mandatory_claims.iter() {
            if !self.claims_set.contains(*c) {
                return Err(Error::MissingClaim(n.to_string()));
            }
        }

        // TODO: hash-type'd measurements are compatible with hash-alg

        Ok(())
    }
}

const PLATFORM_PROFILE_LEGACY: &str = "http://arm.com/CCA-SSD/1.0.0";
const PLATFORM_PROFILE: &str = "tag:arm.com,2023:cca_platform#1.0.0";

const PLATFORM_PROFILE_LABEL: i128 = 265;
const PLATFORM_CHALLENGE_LABEL: i128 = 10;
const PLATFORM_IMPL_ID_LABEL: i128 = 2396;
const PLATFORM_INST_ID_LABEL: i128 = 256;
const PLATFORM_CONFIG_LABEL: i128 = 2401; // XXX requested, unassigned
const PLATFORM_LIFECYCLE_LABEL: i128 = 2395;
const PLATFORM_SW_COMPONENTS: i128 = 2399;
const PLATFORM_VERIFICATION_SERVICE: i128 = 2400;
const PLATFORM_HASH_ALG: i128 = 2402; // XXX not requested, unassigned

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
    }
}

/// For syntax and semantics of the claims-set, see §A.7.2.3.2 of "Realm
/// Management Monitor (RMM) Specification" v.1.0-eac4
#[derive(Debug)]
pub struct Platform {
    pub profile: String,                 // 265, text ("http://arm.com/CCA-SSD/1.0.0")
    pub challenge: Vec<u8>,              // 10, bytes .size {32,48,64}
    pub impl_id: [u8; 32],               // 2396, bytes .size 32
    pub inst_id: [u8; 33],               // 256, bytes .size 33
    pub config: Vec<u8>,                 // 2401, bytes
    pub lifecycle: u16,                  // 2395, 0x0000..0x00ff ... 0x6000..0x60ff
    pub sw_components: Vec<SwComponent>, // 2399, cca-platform-sw-component
    pub verification_service: Option<String>, // 2400, text
    pub hash_alg: String,                // 2402, text

    claims_set: ClaimsSet,
}

impl Default for Platform {
    fn default() -> Self {
        Self::new()
    }
}

impl Platform {
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
            claims_set: ClaimsSet::empty(),
        }
    }

    /// Decode a CBOR encoded CCA platform claims-set
    pub fn decode(buf: &Vec<u8>) -> Result<Platform, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut pc: Platform = Default::default();

        if let Value::Map(contents) = v {
            pc.parse(contents)?;
        } else {
            return Err(Error::Syntax("expecting map type".to_string()));
        }

        pc.validate()?;

        Ok(pc)
    }

    fn parse(&mut self, contents: Vec<(Value, Value)>) -> Result<(), Error> {
        for (k, v) in contents.iter() {
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
                    _ => continue,
                }
            } else {
                // CCA does not define any non-integer key
                continue;
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        // all platform claims are mandatory except vsi
        let mandatory_claims = [
            (ClaimsSet::PROFILE, "profile"),
            (ClaimsSet::CHALLENGE, "challenge"),
            (ClaimsSet::IMPL_ID, "implementation-id"),
            (ClaimsSet::INST_ID, "instance-id"),
            (ClaimsSet::CONFIG, "config"),
            (ClaimsSet::LIFECYCLE, "lifecycle"),
            (ClaimsSet::SW_COMPONENTS, "sw-components"),
            (ClaimsSet::HASH_ALG, "hash-algo"),
        ];

        for (c, n) in mandatory_claims.iter() {
            if !self.claims_set.contains(*c) {
                return Err(Error::MissingClaim(n.to_string()));
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

        let p = to_tstr(v, "profile")?;

        // There is not material difference between the two profiles regarding
        // the platform claims-set arrangement.
        // However, if p == PLATFORM_PROFILE, then the realm token shall also
        // have a profile claim.
        if p != PLATFORM_PROFILE && p != PLATFORM_PROFILE_LEGACY {
            return Err(Error::UnknownProfile(p.to_string()));
        }

        self.profile = p;

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

        let x = to_bstr(v, "implementation-id")?;
        let x_len = x.len();

        if x_len != 32 {
            return Err(Error::Sema(format!(
                "implementation-id: expecting 32 bytes, got {x_len}"
            )));
        }

        self.impl_id[..].clone_from_slice(&x);

        self.claims_set.set(ClaimsSet::IMPL_ID, true);

        Ok(())
    }

    fn set_inst_id(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::INST_ID) {
            return Err(Error::DuplicatedClaim("instance-id".to_string()));
        }

        let x = to_bstr(v, "instance-id")?;
        let x_len = x.len();

        if x_len != 33 {
            return Err(Error::Sema(format!(
                "instance-id: expecting 33 bytes, got {x_len}"
            )));
        }

        self.inst_id[..].clone_from_slice(&x);

        self.claims_set.set(ClaimsSet::INST_ID, true);

        Ok(())
    }

    fn set_config(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::CONFIG) {
            return Err(Error::DuplicatedClaim("config".to_string()));
        }

        self.config = to_bstr(v, "config")?;

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

        let _x = to_tstr(v, "verification-service")?;

        // no specific validation is required: VSI could be a URL, but not
        // necessarily so.  We could maybe check for positive len() but I'm
        // not sure it's worth it.

        self.verification_service = Some(_x);

        self.claims_set.set(ClaimsSet::VSI, true);

        Ok(())
    }

    // XXX this is exactly the same as realm's
    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::HASH_ALG) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        self.hash_alg = to_hash_alg(v, "hash-algo-id")?;

        self.claims_set.set(ClaimsSet::HASH_ALG, true);

        Ok(())
    }

    fn set_sw_component(&mut self, swc: &Value) -> Result<(), Error> {
        let mut v: SwComponent = Default::default();

        if let Value::Map(contents) = swc {
            v.parse(contents)?;
        }

        v.validate()?;

        self.sw_components.push(v);

        Ok(())
    }

    fn set_sw_components(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::SW_COMPONENTS) {
            return Err(Error::DuplicatedClaim("software-components".to_string()));
        }

        let _x = v.as_array();

        if _x.is_none() {
            return Err(Error::TypeMismatch(
                "software-components MUST be array".to_string(),
            ));
        }

        let x = _x.unwrap();
        let x_len = x.len();

        if x_len == 0 {
            return Err(Error::Sema(
                "software-measurements: expecting at least one slot".to_string(),
            ));
        }

        for (i, xi) in x.iter().enumerate() {
            let _xi = xi.as_map();

            if _xi.is_none() {
                return Err(Error::TypeMismatch(format!(
                    "sw-component[{i}] MUST be map"
                )));
            }

            self.set_sw_component(xi)?;
        }

        self.claims_set.set(ClaimsSet::SW_COMPONENTS, true);

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
    fn platform_ok() {
        let buf = include_bytes!("../../testdata/platform-claims.cbor").to_vec();

        let _p = Platform::decode(&buf).unwrap();

        println!("{_p:#?}");
    }

    #[test]
    fn dup_claim() {
        let buf = hex!("a219096061781909606178").to_vec();

        assert!(Platform::decode(&buf).is_err());
    }
}
