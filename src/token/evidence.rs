// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::base64;
use super::common::*;
use super::errors::Error;
use super::platform::Platform;
use super::realm::Realm;
use crate::store::PlatformRefValue;
use crate::store::RealmRefValue;
use crate::store::{Cpak, IRefValueStore, ITrustAnchorStore};
use ciborium::de::from_reader;
use ciborium::Value;
use cose::keys::CoseKey;
use cose::message::CoseMessage;
use ear::claim::*;
use ear::TrustVector;
use jsonwebtoken::jwk;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcPoint};
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use serde::Deserialize;
use std::fs;

const CBOR_TAG: u64 = 399;
const PLATFORM_LABEL: i128 = 44234;
const REALM_LABEL: i128 = 44241;

const SHA_224: &str = "sha-224";
const SHA_256: &str = "sha-256";
const SHA_384: &str = "sha-384";
const SHA_512: &str = "sha-512";

#[derive(Debug, Deserialize)]
struct CBORCollection {
    #[serde(rename = "44234")]
    raw_platform_token: Vec<u8>,
    #[serde(rename = "44241")]
    raw_realm_token: Vec<u8>,
}

impl CBORCollection {
    pub fn new() -> Self {
        Self {
            raw_platform_token: Default::default(),
            raw_realm_token: Default::default(),
        }
    }

    fn set_platform_token(&mut self, v: &Value) -> Result<(), Error> {
        self.raw_platform_token = to_bstr(v, "platform token")?;
        Ok(())
    }

    fn set_realm_token(&mut self, v: &Value) -> Result<(), Error> {
        self.raw_realm_token = to_bstr(v, "realm token")?;
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if self.raw_platform_token.is_empty() {
            return Err(Error::Syntax("missing platform token".to_string()));
        }

        if self.raw_realm_token.is_empty() {
            return Err(Error::Syntax("missing realm token".to_string()));
        }

        Ok(())
    }

    fn decode(buf: &Vec<u8>) -> Result<CBORCollection, Error> {
        let v: Value = from_reader(buf.as_slice()).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut collection = CBORCollection::new();

        if let Value::Tag(t, m) = v {
            if t != CBOR_TAG {
                return Err(Error::Syntax(format!(
                    "expecting tag {}, got {}",
                    CBOR_TAG, t
                )));
            }

            if let Value::Map(contents) = *m {
                collection.parse(contents)?;
            } else {
                return Err(Error::Syntax("expecting map type".to_string()));
            }
        } else {
            return Err(Error::Syntax("expecting tag type".to_string()));
        }

        collection.validate()?;

        Ok(collection)
    }

    fn parse(&mut self, contents: Vec<(Value, Value)>) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    PLATFORM_LABEL => self.set_platform_token(v)?,
                    REALM_LABEL => self.set_realm_token(v)?,
                    unknown => {
                        return Err(Error::Syntax(format!(
                            "unknown key {unknown} in collection"
                        )))
                    }
                }
            } else {
                return Err(Error::Syntax("expecting integer key".to_string()));
            }
        }
        Ok(())
    }
}

/// This structure collects all the structural aspects of the CCA token
pub struct Evidence {
    /// decoded platform claims-set
    pub platform_claims: Platform,
    /// decoded realm claims-set
    pub realm_claims: Realm,
    /// COSE Sign1 envelope for the platform claims-set
    pub platform: CoseMessage,
    /// COSE Sign1 envelope for the realm claims-set
    pub realm: CoseMessage,
    /// Platform appraisal trust vector
    platform_tvec: TrustVector,
    /// Realm appraisal trust vector
    realm_tvec: TrustVector,
}

impl Default for Evidence {
    fn default() -> Self {
        Self::new()
    }
}

impl Evidence {
    pub fn new() -> Self {
        Self {
            platform_claims: Default::default(),
            realm_claims: Default::default(),
            platform: CoseMessage::new_sign(),
            realm: CoseMessage::new_sign(),
            platform_tvec: TrustVector::default(),
            realm_tvec: TrustVector::default(),
        }
    }

    pub fn decode(buf: &Vec<u8>) -> Result<Evidence, Error> {
        let collection = CBORCollection::decode(buf)?;

        let mut t = Evidence::new();

        t.platform.bytes = collection.raw_platform_token;
        t.realm.bytes = collection.raw_realm_token;

        if t.platform.bytes.is_empty() {
            return Err(Error::MissingPlatformToken(
                "Missing Platform Token".to_string(),
            ));
        }

        t.platform
            .init_decoder(None)
            .map_err(|e| Error::Syntax(format!("platform token: {:?}", e)))?;

        t.realm
            .init_decoder(None)
            .map_err(|e| Error::Syntax(format!("realm token: {:?}", e)))?;

        t.platform_claims = Platform::decode(&t.platform.payload)?;
        t.realm_claims = Realm::decode(&t.realm.payload)?;

        Ok(t)
    }

    fn appraise_platform(&mut self, rvs: &[PlatformRefValue]) -> Result<(), Error> {
        let evidence = &self.platform_claims;

        for refval in rvs.iter() {
            if refval.config != evidence.config || refval.sw_components != evidence.sw_components {
                continue;
            }

            // if we survived the sieve, it means we've got a match.
            // we can set all the good properties in the platform TV
            self.platform_tvec
                .instance_identity
                .set(TRUSTWORTHY_INSTANCE);
            self.platform_tvec.hardware.set(GENUINE_HARDWARE);
            self.platform_tvec.executables.set(APPROVED_BOOT);
            self.platform_tvec.configuration.set(APPROVED_CONFIG);
            self.platform_tvec
                .runtime_opaque
                .set(ISOLATED_MEMORY_RUNTIME);

            return Ok(());
        }

        // just say that we couldn't recognize HW/FW
        self.platform_tvec.hardware.set(UNRECOGNIZED_HARDWARE);

        Ok(())
    }

    fn appraise_realm(&mut self, rvs: &[RealmRefValue]) -> Result<(), Error> {
        let evidence = &self.realm_claims;

        // if we are here is because we have a match on RIM, so we don't need to check
        // it again.
        for refval in rvs.iter() {
            // if the ref-val provider has stated that REM is expected to be
            // populated in a certain way, then we need to check for a match
            let must_match_rem = !refval.rem.is_empty();

            if must_match_rem {
                if refval.rem == evidence.rem {
                    self.realm_tvec.executables.set(APPROVED_RUNTIME);

                    return Ok(());
                }

                continue;
            }

            // if we are not asked to match REM, we are good to go
            self.realm_tvec.executables.set(APPROVED_BOOT);

            return Ok(());
        }

        // if we got here it means we were asked to match REM and we exhausted
        // the search without success.  Since we don't currently have a way to
        // specify known-bad values (which would allow us to declare
        // "contraindicated" or "unsafe"), we fall back to "approved boot-time"
        // which is OK since at least RIM has been matched
        self.realm_tvec.executables.set(CONTRAINDICATED_RUNTIME);

        Ok(())
    }

    pub fn appraise(&mut self, rvs: &impl IRefValueStore) -> Result<(), Error> {
        let impl_id = &self.platform_claims.impl_id;

        let r = rvs.lookup_platform(impl_id);

        // if platform is unknown, appraisal ends here because no further
        // trustworthiness deduction can be made about the supplied evidence
        if r.is_none() {
            self.platform_tvec.hardware.set(UNRECOGNIZED_INSTANCE);

            self.realm_tvec.set_all(NO_CLAIM);

            return Ok(());
        }

        self.appraise_platform(r.unwrap().as_ref())?;

        // realm appraisal is subordinate (and maybe optional?) to platform
        // appraisal so if platform appraisal wasn't successful, don't even
        // bother looking at the realm
        //
        // XXX(tho) this test assumes knowledge of appraise_platform inner
        // logics. we need to make it more general (e.g., all tiers in the
        // platform tvec are either no_claim or affirming)
        if self.platform_tvec.hardware.get() == UNRECOGNIZED_HARDWARE {
            // leave platform as-is and update realm

            self.realm_tvec.set_all(NO_CLAIM);

            return Ok(());
        }

        let rim = &self.realm_claims.rim;
        let r = rvs.lookup_realm(rim);

        if r.is_none() {
            // only update realm
            //
            // XXX(tho) using a custom contraindicated claim because there is no
            // standard "unrecognized boot" in AR4SI
            let unrecognized_boot = -97i8;
            self.realm_tvec.executables.set(unrecognized_boot);

            return Ok(());
        }

        self.appraise_realm(r.unwrap().as_ref())?;

        Ok(())
    }

    pub fn get_trust_vectors(&self) -> (TrustVector, TrustVector) {
        (self.platform_tvec, self.realm_tvec)
    }

    pub fn verify_platform_token(&mut self, cpak: Cpak) -> Result<(), Error> {
        if cpak.pkey.is_some() {
            let pkey = cpak.pkey.unwrap();
            let cose_key = compose_cose_key(&self.platform, pkey).map_err(|e| {
                self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);
                self.realm_tvec.set_all(NO_CLAIM);
                Error::ComposeCoseKey(e.to_string())
            })?;
            self.platform.key(&cose_key).map_err(|e| {
                self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);
                self.realm_tvec.set_all(NO_CLAIM);
                Error::Syntax(format!(
                    "Add cose-key to Platform Sign1 Message failed: {:?}",
                    e
                ))
            })?;
            self.platform.decode(None, None).map_err(|e| {
                self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);
                self.realm_tvec.set_all(NO_CLAIM);
                Error::Syntax(format!("Verify Platform Sign1 message failed: {:?}", e))
            })?;
        } else {
            self.platform_tvec
                .instance_identity
                .set(UNRECOGNIZED_INSTANCE);
            self.realm_tvec.set_all(NO_CLAIM);
            let inst_id = self.platform_claims.inst_id;
            return Err(Error::NotFoundTA(format!(
                "Not found the trust anchor for {inst_id:?}"
            )));
        }
        self.platform_tvec
            .instance_identity
            .set(TRUSTWORTHY_INSTANCE);
        Ok(())
    }

    fn abstract_cpak(&mut self, tas: &impl ITrustAnchorStore) -> Result<Cpak, Error> {
        let inst_id = self.platform_claims.inst_id;
        let platform_key = tas.lookup(&inst_id);

        // if platform is unknown, appraisal ends here because no further
        // trustworthiness deduction can be made
        if platform_key.is_none() {
            self.platform_tvec
                .instance_identity
                .set(UNRECOGNIZED_INSTANCE);
            self.realm_tvec.set_all(NO_CLAIM);
            return Err(Error::NotFoundTA(format!(
                "Parse platform token failed for {inst_id:?}"
            )));
        }
        Ok(platform_key.unwrap())
    }

    pub fn verify_realm_token(&mut self) -> Result<(), Error> {
        let realm_pub_key = self.realm_claims.get_realm_key()?;
        let mut cose_key = self
            .ecdsa_public_key_from_raw(&realm_pub_key)
            .map_err(|e| {
                self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
                Error::Syntax(format!("Verify Realm Sign1 message failed: {:?}", e))
            })?;

        let cose_alg = self.realm.header.alg;
        if cose_alg.is_none() {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
            return Err(Error::NoCoseAlgInHeader(
                "No Cose Alg in Header".to_string(),
            ));
        }
        cose_key.alg(cose_alg.unwrap());
        cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);
        self.realm.key(&cose_key).map_err(|e| {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
            Error::Syntax(format!(
                "Add cose-key to Realm Sign1 Message failed: {:?}",
                e
            ))
        })?;
        self.realm.decode(None, None).map_err(|e| {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
            Error::Syntax(format!("Verify Realm Sign1 message failed: {:?}", e))
        })?;
        Ok(())
    }

    pub fn verify(&mut self, tas: &impl ITrustAnchorStore) -> Result<(), Error> {
        assert!(
            !self.platform.bytes.is_empty(),
            "Platform Token is Mandatory"
        );
        let cpak = self.abstract_cpak(tas)?;
        self.verify_platform_token(cpak)?;
        assert!(!self.realm.bytes.is_empty(), "Realm Token is Mandatory");
        self.verify_realm_token()?;
        self.check_binding()?;
        self.realm_tvec.instance_identity.set(TRUSTWORTHY_INSTANCE);
        Ok(())
    }

    pub fn verify_with_cpak(&mut self, cpak: Cpak) -> Result<(), Error> {
        assert!(
            !self.platform.bytes.is_empty(),
            "Platform Token is Mandatory"
        );
        self.verify_platform_token(cpak)?;
        assert!(!self.realm.bytes.is_empty(), "Realm Token is Mandatory");
        self.verify_realm_token()?;
        self.check_binding()?;
        self.realm_tvec.instance_identity.set(TRUSTWORTHY_INSTANCE);
        Ok(())
    }

    fn ecdsa_public_key_from_raw(&self, data: &[u8]) -> Result<CoseKey, ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, data, &mut ctx)?;

        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        point.affine_coordinates(&group, &mut x, &mut y, &mut ctx)?;

        let mut cose_key = CoseKey::new();
        cose_key.kty(cose::keys::EC2);
        cose_key.crv(cose::keys::P_384);
        cose_key.x(x.to_vec());
        cose_key.y(y.to_vec());

        Ok(cose_key)
    }

    fn check_binding(&mut self) -> Result<(), Error> {
        let realm_pub_key = self.realm_claims.get_realm_key()?;
        let realm_pub_key_hash_alg = self.realm_claims.get_rak_hash_alg()?;
        let mut hasher = match realm_pub_key_hash_alg.as_str() {
            SHA_224 => Hasher::new(MessageDigest::sha224())
                .map_err(|e| Error::HasherCreationFail(format!("{:?}", e)))?,
            SHA_256 => Hasher::new(MessageDigest::sha256())
                .map_err(|e| Error::HasherCreationFail(format!("{:?}", e)))?,
            SHA_384 => Hasher::new(MessageDigest::sha384())
                .map_err(|e| Error::HasherCreationFail(format!("{:?}", e)))?,
            SHA_512 => Hasher::new(MessageDigest::sha512())
                .map_err(|e| Error::HasherCreationFail(format!("{:?}", e)))?,
            x => return Err(Error::UnknownHash(x.to_string())),
        };
        hasher
            .update(&realm_pub_key)
            .map_err(|e| Error::HashCalculateFail(format!("{:?}", e)))?;
        let sum = hasher
            .finish()
            .map_err(|e| Error::HashCalculateFail(format!("{:?}", e)))?;

        let p_nonce = self.platform_claims.get_challenge()?;
        if sum.to_vec() != *p_nonce {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
            return Err(Error::BindingMismatch(format!(
                "Platform Nonce: {p_nonce:?}"
            )));
        }
        Ok(())
    }
}

fn compose_cose_key(cose_message: &CoseMessage, pkey: jwk::Jwk) -> Result<CoseKey, Error> {
    let mut cose_key = CoseKey::new();
    let header_alg = cose_message.header.alg.ok_or(Error::NoCoseAlgInHeader(
        "Missing Alg In Header".to_string(),
    ));
    let cose_alg = header_alg.unwrap();
    cose_key.alg(match pkey.common.key_algorithm {
        Some(jwk::KeyAlgorithm::ES256) => cose::algs::ES256,
        Some(jwk::KeyAlgorithm::ES384) => cose::algs::ES384,
        Some(jwk::KeyAlgorithm::EdDSA) => cose::algs::EDDSA,
        Some(a) => return Err(Error::Key(format!("unsupported algorithm {a:?}"))),
        None => cose_alg,
    });
    cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);

    match pkey.algorithm {
        jwk::AlgorithmParameters::EllipticCurve(ec_params) => {
            cose_key.kty(cose::keys::EC2);
            cose_key.crv(match ec_params.curve {
                jwk::EllipticCurve::P256 => cose::keys::P_256,
                jwk::EllipticCurve::P384 => cose::keys::P_384,
                jwk::EllipticCurve::P521 => cose::keys::P_521,
                c => return Err(Error::Key(format!("invalid EC2 curve {c:?}"))),
            });
            cose_key.x(base64::decode_str(ec_params.x.as_str())?);
            cose_key.y(base64::decode_str(ec_params.y.as_str())?);
        }
        jwk::AlgorithmParameters::OctetKeyPair(okp_params) => {
            cose_key.kty(cose::keys::OKP);
            cose_key.crv(match okp_params.curve {
                jwk::EllipticCurve::Ed25519 => cose::keys::ED25519,
                c => return Err(Error::Key(format!("invalid OKP curve {c:?}"))),
            });
            cose_key.x(base64::decode_str(okp_params.x.as_str())?);
        }
        a => return Err(Error::Key(format!("unsupported algorithm params {a:?}"))),
    }
    Ok(cose_key)
}

mod tests {
    use super::*;
    use crate::store::MemoRefValueStore;

    #[test]
    fn test_file_path_creation() {
        let basedir: Path = Path::new(env!("CARGO_MANIFEST_DIR"));

        let cca_token_path: Path = basedir.join("testdata/cca-token.cbor");
        let cca_rv_path: Path = basedir.join("testdata/rv.json");
        let cbor_claims_path: Path = basedir.join("testdata/verification/cca_claims.cbor");
        let pkey_1_path: Path = basedir.join("testdata/verification/pkey-verify-success.json");
        let pkey_2_path: Path = basedir.join("testdata/verification/pkey-verify-fail.json");
    }
    #[test]
    fn decode_good_token() {
        let r = Evidence::decode(&TEST_CCA_TOKEN_OK.to_vec());

        assert!(r.is_ok());
    }

    #[test]
    fn appraise_ok() {
        let mut rvs = MemoRefValueStore::new();
        rvs.load_json(TEST_CCA_RVS_OK)
            .expect("loading TEST_CCA_RVS_OK");

        let mut e =
            Evidence::decode(&TEST_CCA_TOKEN_OK.to_vec()).expect("decoding TEST_CCA_TOKEN_OK");

        e.appraise(&rvs)
            .expect("validation successful for both platform and realm");

        println!("PTV = {:?}", e.platform_tvec);
        println!("RTV = {:?}", e.realm_tvec);
    }

    // TODO platform-specific tests
    // - unknown impl-id
    // - non-matching ref-vals
    // - bad security state?

    // TODO realm tests
    // - unknown rim
    // - non-matching rem
    // - non-matching personalisation value

    #[test]
    fn verify_platform_token_ok() {
        let cca_cbor = fs::read(TEST_CBOR_CLAIMS).expect("Open Cbor file failed");
        let mut evidence = Evidence::decode(&cca_cbor).expect("Decode Evidence Failed");
        let pkey = serde_json::from_str::<jwk::Jwk>(TEST_PKEY_1).expect("Abstract Pkey failed");
        let cose_key = compose_cose_key(&evidence.platform, pkey).expect("Compose the key failed");
        evidence.platform.key(&cose_key).unwrap();
        let r = evidence.platform.decode(None, None);
        assert!(r.is_ok())
    }

    #[test]
    fn verify_platform_token_error() {
        let cca_cbor = fs::read(TEST_CBOR_CLAIMS).expect("Open Cbor file failed");
        let mut evidence = Evidence::decode(&cca_cbor).expect("Decode Evidence Failed");
        let pkey = serde_json::from_str::<jwk::Jwk>(TEST_PKEY_2).expect("Abstract Pkey failed");

        let cose_key = compose_cose_key(&evidence.platform, pkey).expect("Compose the key failed");
        evidence.platform.key(&cose_key).unwrap();
        let r = evidence.platform.decode(None, None);
        assert!(r.is_err())
    }

    #[test]
    fn verify_realm_token_ok() {
        let cca_cbor = fs::read(TEST_CBOR_CLAIMS).expect("Open Cbor file failed");
        let mut evidence = Evidence::decode(&cca_cbor).expect("Decode Evidence Failed");
        let r = evidence.verify_realm_token();
        assert!(r.is_ok())
    }
    #[test]
    fn check_binding_ok() {
        let cca_cbor = fs::read(TEST_CBOR_CLAIMS).expect("Open Cbor file failed");
        let mut evidence = Evidence::decode(&cca_cbor).expect("Decode Evidence Failed");
        let r = evidence.check_binding();
        assert!(r.is_ok())
    }
}
