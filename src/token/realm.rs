// Copyright 2023-2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use super::common::*;
use super::errors::Error;
use bitmask::*;
use ciborium::de::from_reader;
use ciborium::Value;

pub const REALM_PROFILE: &str = "tag:arm.com,2023:realm#1.0.0";

const REALM_CHALLENGE_LABEL: i128 = 10;
const REALM_PROFILE_LABEL: i128 = 265;
const REALM_PERSO_LABEL: i128 = 44235;
const REALM_RIM_LABEL: i128 = 44238;
const REALM_REM_LABEL: i128 = 44239;
const REALM_HASH_ALG_LABEL: i128 = 44236;
const REALM_RAK_LABEL: i128 = 44237;
const REALM_RAK_HASH_ALG_LABEL: i128 = 44240;

bitmask! {
    #[derive(Debug)]
    mask ClaimsSet: u8 where flags Claims {
        Challenge  = 0x01,
        Perso      = 0x02,
        Rim        = 0x04,
        Rem        = 0x08,
        HashAlg    = 0x10,
        Rak        = 0x20,
        RakHashAlg = 0x40,
        Profile    = 0x80,
    }
}

/// For syntax and semantics of the claims-set, see §A.7.2.3.1 of "Realm
/// Management Monitor (RMM) Specification" v.1.0-eac4
#[derive(Debug)]
pub struct Realm {
    pub challenge: [u8; 64],  //    10 => bytes .size 64
    pub profile: String,      //   265 => text
    pub perso: [u8; 64],      // 44235 => bytes .size 64
    pub rim: Vec<u8>,         // 44238 => bytes .size {32,48,64}
    pub rem: [Vec<u8>; 4],    // 44239 => [ 4*4 bytes .size {32,48,64} ]
    pub hash_alg: String,     // 44236 => text
    pub raw_rak: [u8; 97],    // 44237 => bytes .size 97 (profile=="")
    pub cose_rak: Vec<u8>,    // 44237 => bytes .cbor COSE_Key (profile==REALM_PROFILE)
    pub rak_hash_alg: String, // 44240 => text

    claims_set: ClaimsSet,
}

impl Default for Realm {
    fn default() -> Self {
        Self::new()
    }
}

impl Realm {
    pub fn new() -> Self {
        Self {
            challenge: [0; 64],
            profile: String::from(""),
            perso: [0; 64],
            rim: vec![0, 64],
            rem: Default::default(),
            hash_alg: String::from(""),
            raw_rak: [0; 97],
            cose_rak: Default::default(),
            rak_hash_alg: String::from(""),
            claims_set: ClaimsSet::none(),
        }
    }

    /// Decode a CBOR encoded CCA realm claims-set
    pub fn decode(buf: &Vec<u8>) -> Result<Realm, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut rc: Realm = Default::default();

        if let Value::Map(contents) = v {
            rc.parse(contents)?;
        } else {
            return Err(Error::TypeMismatch("expecting map type".to_string()));
        }

        rc.validate()?;

        Ok(rc)
    }

    fn parse(&mut self, contents: Vec<(Value, Value)>) -> Result<(), Error> {
        // Extract the profile claim first.  This is because the RAK claim
        // (44237) has different encodings depending on the profile value.
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    REALM_PROFILE_LABEL => self.set_profile(v)?,
                    _ => continue,
                }
            }
        }

        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    REALM_CHALLENGE_LABEL => self.set_challenge(v)?,
                    REALM_PERSO_LABEL => self.set_perso(v)?,
                    REALM_RIM_LABEL => self.set_rim(v)?,
                    REALM_REM_LABEL => self.set_rem(v)?,
                    REALM_HASH_ALG_LABEL => self.set_hash_alg(v)?,
                    REALM_RAK_LABEL => self.set_rak(v)?,
                    REALM_RAK_HASH_ALG_LABEL => self.set_rak_hash_alg(v)?,
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
        // all realm claims are mandatory
        let mandatory_claims = [
            (Claims::Challenge, "challenge"),
            (Claims::Perso, "personalization-value"),
            (Claims::Rim, "initial-measurement"),
            (Claims::Rem, "extensible-measurements"),
            (Claims::HashAlg, "hash-algo-id"),
            (Claims::Rak, "public-key"),
            (Claims::RakHashAlg, "public-key-hash-algo-id"),
        ];

        for (c, n) in mandatory_claims.iter() {
            if !self.claims_set.contains(*c) {
                return Err(Error::MissingClaim(n.to_string()));
            }
        }

        // RAK format depends on the token profile
        if self.profile == REALM_PROFILE {
            if self.cose_rak.is_empty() {
                return Err(Error::Sema("RAK COSE_Key not set".to_string()));
            }
        } else if self.raw_rak == [0; 97] {
            return Err(Error::Sema("RAK raw public key not set".to_string()));
        }

        // TODO: hash-type'd measurements are compatible with hash-alg

        Ok(())
    }

    fn set_profile(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Profile) {
            return Err(Error::DuplicatedClaim("profile".to_string()));
        }

        let p = to_tstr(v, "profile")?;

        if p != REALM_PROFILE {
            return Err(Error::UnknownProfile(p.to_string()));
        }

        self.profile = p;

        self.claims_set.set(Claims::Profile);

        Ok(())
    }

    fn set_challenge(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Challenge) {
            return Err(Error::DuplicatedClaim("challenge".to_string()));
        }

        let _x = v.as_bytes();

        if _x.is_none() {
            return Err(Error::TypeMismatch("challenge MUST be bstr".to_string()));
        }

        let x = _x.unwrap().clone();
        let x_len = x.len();

        if x_len != 64 {
            return Err(Error::Sema(format!(
                "challenge: expecting 64 bytes, got {x_len}"
            )));
        }

        self.challenge[..].clone_from_slice(&x);

        self.claims_set.set(Claims::Challenge);

        Ok(())
    }

    fn set_rak_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::RakHashAlg) {
            return Err(Error::DuplicatedClaim(
                "public-key-hash-algo-id".to_string(),
            ));
        }

        self.rak_hash_alg = to_hash_alg(v, "public-key-hash-algo-id")?;

        self.claims_set.set(Claims::RakHashAlg);

        Ok(())
    }

    fn set_hash_alg(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::HashAlg) {
            return Err(Error::DuplicatedClaim("hash-algo-id".to_string()));
        }

        self.hash_alg = to_hash_alg(v, "hash-algo-id")?;

        self.claims_set.set(Claims::HashAlg);

        Ok(())
    }

    fn set_rim(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Rim) {
            return Err(Error::DuplicatedClaim("initial-measurement".to_string()));
        }

        self.rim = to_measurement(v, "initial-measurement")?;

        self.claims_set.set(Claims::Rim);

        Ok(())
    }

    fn set_rak(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Rak) {
            return Err(Error::DuplicatedClaim("public-key".to_string()));
        }

        let _x = v.as_bytes();

        if _x.is_none() {
            return Err(Error::TypeMismatch("public-key MUST be bstr".to_string()));
        }

        let x = v.as_bytes().unwrap().clone();
        let x_len = x.len();

        // Backwards compatibility with the previous "raw key" format.
        if self.profile.is_empty() {
            if x_len != 97 {
                return Err(Error::Sema(format!(
                    "public-key: expecting 97 bytes, got {}",
                    x_len
                )));
            }
            self.raw_rak[..].clone_from_slice(&x);
        } else {
            self.cose_rak = x
        }

        self.claims_set.set(Claims::Rak);

        Ok(())
    }

    fn set_rem(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Rem) {
            return Err(Error::DuplicatedClaim(
                "extensible-measurements".to_string(),
            ));
        }

        let _x = v.as_array();

        if _x.is_none() {
            return Err(Error::TypeMismatch(
                "extensible-measurements MUST be array".to_string(),
            ));
        }

        let x = _x.unwrap().clone();
        let x_len = x.len();

        if x_len != 4 {
            return Err(Error::Sema(format!(
                "extensible-measurements: expecting 4 slots, got {}",
                x_len
            )));
        }

        for (i, xi) in x.iter().enumerate() {
            self.rem[i] = to_measurement(xi, format!("extensible-measurement[{}]", i).as_str())?;
        }

        self.claims_set.set(Claims::Rem);

        Ok(())
    }

    fn set_perso(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(Claims::Perso) {
            return Err(Error::DuplicatedClaim("personalization-value".to_string()));
        }

        let _x = v.as_bytes();

        if _x.is_none() {
            return Err(Error::TypeMismatch(
                "personalization-value MUST be bstr".to_string(),
            ));
        }

        let x = _x.unwrap().clone();
        let x_len = x.len();

        if x_len != 64 {
            return Err(Error::Sema(format!(
                "personalization value: expecting 64 bytes, got {}",
                x_len
            )));
        }

        self.perso[..].clone_from_slice(&x);
        self.claims_set.set(Claims::Perso);

        Ok(())
    }

    pub fn get_realm_key(&self) -> Result<Vec<u8>, Error> {
        let rak = if self.profile == REALM_PROFILE {
            self.cose_rak.clone()
        } else {
            self.raw_rak.clone().to_vec()
        };

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
    use hex_literal::hex;

    const TEST_REALM_CLAIMS_OK: &[u8; 438] = include_bytes!("../../testdata/realm-claims.cbor");
    const TEST_REALM_CLAIMS_BAD_EXTRA_NUMERIC_KEY: &[u8; 457] =
        include_bytes!("../../testdata/realm-claims+spurious-numeric-key.cbor");
    const TEST_REALM_CLAIMS_BAD_EXTRA_TEXT_KEY: &[u8; 464] =
        include_bytes!("../../testdata/realm-claims+spurious-text-key.cbor");
    const TEST_REALM_CLAIMS_BAD_MISSING_NONCE: &[u8; 371] =
        include_bytes!("../../testdata/realm-claims-missing-challenge.cbor");

    #[test]
    fn realm_ok() {
        let _r = Realm::decode(&TEST_REALM_CLAIMS_OK.to_vec()).expect("successful decode");
    }

    #[test]
    fn realm_good_with_extra_claim_using_numeric_key() {
        let _r = Realm::decode(&TEST_REALM_CLAIMS_BAD_EXTRA_NUMERIC_KEY.to_vec())
            .expect("successful decode");
    }

    #[test]
    fn realm_good_with_extra_claim_using_text_key() {
        let _r = Realm::decode(&TEST_REALM_CLAIMS_BAD_EXTRA_TEXT_KEY.to_vec())
            .expect("successful decode");
    }

    #[test]
    fn realm_bad_missing_mandatory_claim() {
        assert!(Realm::decode(&TEST_REALM_CLAIMS_BAD_MISSING_NONCE.to_vec()).is_err());
    }

    #[test]
    fn realm_bad_empty_map() {
        let buf = hex!("a0").to_vec();

        assert!(Realm::decode(&buf).is_err());
    }

    #[test]
    fn realm_bad_unknown_eat() {
        let buf = hex!("a10a48deadbeefdeadbeef").to_vec();

        assert!(Realm::decode(&buf).is_err());
    }

    #[test]
    fn realm_bad_rubbish_cbor() {
        let buf = hex!("ffffffff").to_vec();

        assert!(Realm::decode(&buf).is_err());
    }

    #[test]
    fn realm_bad_challenge_type() {
        let buf = hex!("a10a0a").to_vec();

        assert!(Realm::decode(&buf).is_err());
    }
}
