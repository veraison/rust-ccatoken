// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use super::common::*;
use super::errors::Error;
use bitflags::bitflags;
use ciborium::de::from_reader;
use ciborium::Value;

pub const REALM_PROFILE_2024: &str = "tag:arm.com,2024:realm#2.0.0";
const REALM_CHALLENGE_LABEL: i128 = 10;
const REALM_PROFILE_LABEL: i128 = 265;
const REALM_PERSO_LABEL: i128 = 44235;
const REALM_RIM_LABEL: i128 = 44238;
const REALM_REM_LABEL: i128 = 44239;
const REALM_HASH_ALG_LABEL: i128 = 44236;
const REALM_RAK_LABEL: i128 = 44237;
const REALM_RAK_HASH_ALG_LABEL: i128 = 44240;
const REALM_MEC_POLICY_LABEL: i128 = 44243;

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    struct ClaimsSet: u16 {
        const CHALLENGE  = 0x01;
        const PERSO      = 0x02;
        const RIM        = 0x04;
        const REM        = 0x08;
        const HASH_ALG   = 0x10;
        const RAK        = 0x20;
        const RAK_HASH_ALG = 0x40;
        const PROFILE    = 0x80;
        const MEC_POLICY  = 0x100;
    }
}

/// For syntax and semantics of the claims-set, see
/// https://datatracker.ietf.org/doc/draft-ffm-rats-cca-token/03/
#[derive(Debug)]
pub struct Realm2024 {
    pub challenge: [u8; 64],  //    10 => bytes .size 64
    pub profile: String,      //   265 => text
    pub perso: [u8; 64],      // 44235 => bytes .size 64
    pub rim: Vec<u8>,         // 44238 => bytes .size {32,48,64}
    pub rem: [Vec<u8>; 4],    // 44239 => [ 4*4 bytes .size {32,48,64} ]
    pub hash_alg: String,     // 44236 => text
    pub cose_rak: Vec<u8>,    // 44237 => bytes .cbor COSE_Key (profile==REALM_PROFILE)
    pub rak_hash_alg: String, // 44240 => text
    pub mec_policy: String,   // 44243 => "private" | "shared"

    claims_set: ClaimsSet,
}

impl Default for Realm2024 {
    fn default() -> Self {
        Self::new()
    }
}

impl Realm2024 {
    pub fn new() -> Self {
        Self {
            challenge: [0; 64],
            profile: String::from(""),
            perso: [0; 64],
            rim: vec![0, 64],
            rem: Default::default(),
            hash_alg: String::from(""),
            cose_rak: Default::default(),
            rak_hash_alg: String::from(""),
            mec_policy: String::from(""),
            claims_set: ClaimsSet::empty(),
        }
    }

    /// Decode a CBOR encoded CCA realm claims-set
    pub fn decode(buf: &Vec<u8>) -> Result<Realm2024, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut realm_claims: Realm2024 = Default::default();

        if let Value::Map(contents) = v {
            realm_claims.parse(contents)?;
        } else {
            return Err(Error::TypeMismatch("expecting map type".to_string()));
        }

        realm_claims.validate()?;

        Ok(realm_claims)
    }

    fn parse(&mut self, contents: Vec<(Value, Value)>) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    REALM_PROFILE_LABEL => self.set_profile(v)?,
                    REALM_CHALLENGE_LABEL => self.set_challenge(v)?,
                    REALM_PERSO_LABEL => self.set_perso(v)?,
                    REALM_RIM_LABEL => self.set_rim(v)?,
                    REALM_REM_LABEL => self.set_rem(v)?,
                    REALM_HASH_ALG_LABEL => self.set_hash_alg(v)?,
                    REALM_RAK_LABEL => self.set_rak(v)?,
                    REALM_RAK_HASH_ALG_LABEL => self.set_rak_hash_alg(v)?,
                    REALM_MEC_POLICY_LABEL => self.set_mec_policy(v)?,
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
        // all realm claims are mandatory, except for profile.
        // Empty profile claim corresponds to the legacy profile,
        // which is supported through realm::Realm
        // and rejected here for realm_2024::Realm2024.
        let mandatory_claims = [
            (ClaimsSet::PROFILE, "profile"),
            (ClaimsSet::CHALLENGE, "challenge"),
            (ClaimsSet::PERSO, "personalization-value"),
            (ClaimsSet::RIM, "initial-measurement"),
            (ClaimsSet::REM, "extensible-measurements"),
            (ClaimsSet::HASH_ALG, "hash-algo-id"),
            (ClaimsSet::RAK, "public-key"),
            (ClaimsSet::RAK_HASH_ALG, "public-key-hash-algo-id"),
            (ClaimsSet::MEC_POLICY, "mec-policy"),
        ];

        for (claim, name) in mandatory_claims.iter() {
            if !self.claims_set.contains(*claim) {
                return Err(Error::MissingClaim(name.to_string()));
            }
        }
        // TODO: hash-type'd measurements are compatible with hash-alg

        Ok(())
    }

    fn set_profile(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::PROFILE) {
            return Err(Error::DuplicatedClaim("profile".to_string()));
        }

        let profile = to_tstr(v, "profile")?;

        if profile != REALM_PROFILE_2024 {
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

        let challenge = v
            .as_bytes()
            .ok_or(Error::TypeMismatch(("challenge MUST be bstr").to_string()))?
            .clone();

        let challenge_len = challenge.len();

        if challenge_len != 64 {
            return Err(Error::Sema(format!(
                "challenge: expecting 64 bytes, got {challenge_len}"
            )));
        }

        self.challenge[..].clone_from_slice(&challenge);

        self.claims_set.set(ClaimsSet::CHALLENGE, true);

        Ok(())
    }

    fn set_rak_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::RAK_HASH_ALG) {
            return Err(Error::DuplicatedClaim(
                "public-key-hash-algo-id".to_string(),
            ));
        }

        self.rak_hash_alg = to_hash_alg(v, "public-key-hash-algo-id")?;

        self.claims_set.set(ClaimsSet::RAK_HASH_ALG, true);

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

    fn set_rim(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::RIM) {
            return Err(Error::DuplicatedClaim("initial-measurement".to_string()));
        }

        self.rim = to_measurement(v, "initial-measurement")?;

        self.claims_set.set(ClaimsSet::RIM, true);

        Ok(())
    }

    fn set_rak(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::RAK) {
            return Err(Error::DuplicatedClaim("public-key".to_string()));
        }

        let cose_key = v
            .as_bytes()
            .ok_or(Error::TypeMismatch("public-key MUST be bstr".to_string()))?;

        if cose_key.is_empty() {
            return Err(Error::Sema("RAK COSE_Key should not be empty".to_string()));
        }

        self.cose_rak = cose_key.clone();

        self.claims_set.set(ClaimsSet::RAK, true);

        Ok(())
    }

    fn set_rem(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::REM) {
            return Err(Error::DuplicatedClaim(
                "extensible-measurements".to_string(),
            ));
        }

        let ext_meas_arr = v
            .as_array()
            .ok_or(Error::TypeMismatch(
                "extensible-measurements MUST be array".to_string(),
            ))?
            .clone();

        let ext_meas_arr_len = ext_meas_arr.len();

        if ext_meas_arr_len != 4 {
            return Err(Error::Sema(format!(
                "extensible-measurements: expecting 4 slots, got {ext_meas_arr_len}"
            )));
        }

        for (i, xi) in ext_meas_arr.iter().enumerate() {
            self.rem[i] = to_measurement(xi, format!("extensible-measurement[{i}]").as_str())?;
        }

        self.claims_set.set(ClaimsSet::REM, true);

        Ok(())
    }

    fn set_perso(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::PERSO) {
            return Err(Error::DuplicatedClaim("personalization-value".to_string()));
        }

        let perso = v
            .as_bytes()
            .ok_or(Error::TypeMismatch(
                "personalization-value MUST be bstr".to_string(),
            ))?
            .clone();

        let perso_len = perso.len();

        if perso_len != 64 {
            return Err(Error::Sema(format!(
                "personalization value: expecting 64 bytes, got {perso_len}"
            )));
        }

        self.perso[..].clone_from_slice(&perso);
        self.claims_set.set(ClaimsSet::PERSO, true);

        Ok(())
    }

    fn set_mec_policy(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(ClaimsSet::MEC_POLICY) {
            return Err(Error::DuplicatedClaim("mec-policy".to_string()));
        }

        let mec_policy = to_tstr(v, "mec-policy")?;

        if mec_policy != "private" && mec_policy != "shared" {
            return Err(Error::Sema(format!(
                "mec-policy: expecting 'private' or 'shared', got '{mec_policy}'"
            )));
        }

        self.mec_policy = mec_policy;

        self.claims_set.set(ClaimsSet::MEC_POLICY, true);

        Ok(())
    }

    pub fn get_realm_key(&self) -> Result<Vec<u8>, Error> {
        let rak = self.cose_rak.clone();

        if rak.is_empty() {
            return Err(Error::MissingClaim("No realm Key".to_string()));
        }

        Ok(rak)
    }

    pub fn get_rak_hash_alg(&self) -> Result<String, Error> {
        let rak_hash_alg = self.rak_hash_alg.clone();

        if rak_hash_alg.is_empty() {
            return Err(Error::MissingClaim("No realm hash alg".to_string()));
        }

        Ok(rak_hash_alg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_ok() {
        let buf = include_bytes!("../../testdata/realm-2024/valid-all.cbor").to_vec();

        let _p = Realm2024::decode(&buf).unwrap();

        println!("{_p:#?}");
    }

    macro_rules! claims_nok {
        ($name:ident, $filename:literal, $error:ident) => {
            #[test]
            fn $name() {
                let buf = include_bytes!(concat!("../../testdata/realm-2024/", $filename, ".cbor"))
                    .to_vec();

                assert!(matches!(Realm2024::decode(&buf), Err(Error::$error(_))));
            }
        };
    }

    claims_nok!(
        claims_missing_mec_policy_nok,
        "missing-mec-policy",
        MissingClaim
    );
    claims_nok!(claims_invalid_mec_policy_nok, "invalid-mec-policy", Sema);
}
