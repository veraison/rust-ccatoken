// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::common::*;
use super::errors::Error;
use bitmask::*;
use ciborium::de::from_reader;
use ciborium::Value;
use hex_literal::hex;

const REALM_CHALLENGE_LABEL: i128 = 10;
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
    }
}

/// For syntax and semantics of the claims-set, see §A.7.2.3.1 of "Realm
/// Management Monitor (RMM) Specification" v.1.0-eac4
#[derive(Debug)]
pub struct Realm {
    challenge: [u8; 64],  //    10 => bytes .size 64
    perso: [u8; 64],      // 44235 => bytes .size 64
    rim: Vec<u8>,         // 44238 => bytes .size {32,48,64}
    rem: [Vec<u8>; 4],    // 44239 => [ 4*4 bytes .size {32,48,64} ]
    hash_alg: String,     // 44236 => text
    rak: [u8; 97],        // 44237 => bytes .size 97
    rak_hash_alg: String, // 44240 => text

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
            perso: [0; 64],
            rim: vec![0, 64],
            rem: Default::default(),
            hash_alg: String::from(""),
            rak: [0; 97],
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

        // TODO: hash-type'd measurements are compatible with hash-alg

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

        if x_len != 97 {
            return Err(Error::Sema(format!(
                "public-key: expecting 97 bytes, got {}",
                x_len
            )));
        }

        self.rak[..].clone_from_slice(&x);

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
}

mod tests {
    use super::*;

    #[test]
    fn realm_ok() {
        let buf = hex!(
            "a70a5840abababababababababababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "abababababababab19accb5840ababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "ababababababababababababababababab19acce58200000000000000000"
            "00000000000000000000000000000000000000000000000019accf845820"
            "000000000000000000000000000000000000000000000000000000000000"
            "000058200000000000000000000000000000000000000000000000000000"
            "000000000000582000000000000000000000000000000000000000000000"
            "000000000000000000005820000000000000000000000000000000000000"
            "000000000000000000000000000019accc677368612d32353619accd5861"
            "0476f988091be585ed41801aecfab858548c63057e16b0e676120bbd0d2f"
            "9c29e056c5d41a0130eb9c21517899dc23146b28e1b062bd3ea4b315fd21"
            "9f1cbb528cb6e74ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4"
            "228e50919544ae19acd0677368612d323536"
        )
        .to_vec();

        let _r = Realm::decode(&buf).unwrap();
    }

    #[test]
    fn realm_good_with_extra_claim_using_numeric_key() {
        let buf = hex!(
            "a80a5840abababababababababababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "abababababababab19accb5840ababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "ababababababababababababababababab19acce58200000000000000000"
            "00000000000000000000000000000000000000000000000019accf845820"
            "000000000000000000000000000000000000000000000000000000000000"
            "000058200000000000000000000000000000000000000000000000000000"
            "000000000000582000000000000000000000000000000000000000000000"
            "000000000000000000005820000000000000000000000000000000000000"
            "000000000000000000000000000019accc677368612d32353619accd5861"
            "0476f988091be585ed41801aecfab858548c63057e16b0e676120bbd0d2f"
            "9c29e056c5d41a0130eb9c21517899dc23146b28e1b062bd3ea4b315fd21"
            "9f1cbb528cb6e74ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4"
            "228e50919544ae19acd0677368612d3235361a0012d6876d756e6b6e6f77"
            "6e2d636c61696d"
        )
        .to_vec();

        let _r = Realm::decode(&buf).unwrap();
    }

    #[test]
    fn realm_good_with_extra_claim_using_text_key() {
        let buf = hex!(
            "a80a5840abababababababababababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "abababababababab19accb5840ababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "ababababababababababababababababab19acce58200000000000000000"
            "00000000000000000000000000000000000000000000000019accf845820"
            "000000000000000000000000000000000000000000000000000000000000"
            "000058200000000000000000000000000000000000000000000000000000"
            "000000000000582000000000000000000000000000000000000000000000"
            "000000000000000000005820000000000000000000000000000000000000"
            "000000000000000000000000000019accc677368612d32353619accd5861"
            "0476f988091be585ed41801aecfab858548c63057e16b0e676120bbd0d2f"
            "9c29e056c5d41a0130eb9c21517899dc23146b28e1b062bd3ea4b315fd21"
            "9f1cbb528cb6e74ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4"
            "228e50919544ae19acd0677368612d3235366b756e6b6e6f776e2d6b6579"
            "6d756e6b6e6f776e2d636c61696d"
        )
        .to_vec();

        let _r = Realm::decode(&buf).unwrap();
    }

    #[test]
    fn realm_bad_missing_mandatory_claim() {
        let buf = hex!(
            "a619accb5840abababababababababababababababababababababababab"
            "abababababababababababababababababababababababababababababab"
            "abababababababababab19acce5820000000000000000000000000000000"
            "000000000000000000000000000000000019accf84582000000000000000"
            "000000000000000000000000000000000000000000000000005820000000"
            "000000000000000000000000000000000000000000000000000000000058"
            "200000000000000000000000000000000000000000000000000000000000"
            "000000582000000000000000000000000000000000000000000000000000"
            "0000000000000019accc677368612d32353619accd58610476f988091be5"
            "85ed41801aecfab858548c63057e16b0e676120bbd0d2f9c29e056c5d41a"
            "0130eb9c21517899dc23146b28e1b062bd3ea4b315fd219f1cbb528cb6e7"
            "4ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4228e50919544ae"
            "19acd0677368612d323536"
        )
        .to_vec();

        assert!(Realm::decode(&buf).is_err());
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
