// Copyright 2023-2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::base64;
use super::common::*;
use super::errors::Error;
use super::platform::Platform;
use super::realm::Realm;
use super::realm::REALM_PROFILE;
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

const CBOR_TAG: u64 = 399;
const PLATFORM_LABEL: i128 = 44234;
const REALM_LABEL: i128 = 44241;

const SHA_256: &str = "sha-256";
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

    fn decode<R: std::io::Read>(buf: R) -> Result<CBORCollection, Error> {
        let v: Value = from_reader(buf).map_err(|e| Error::Syntax(e.to_string()))?;

        let mut collection = CBORCollection::new();

        if let Value::Tag(t, m) = v {
            if t != CBOR_TAG {
                return Err(Error::Syntax(format!("expecting tag {CBOR_TAG}, got {t}",)));
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

/// Collects all the components of a CCA token
pub struct Evidence {
    /// Decoded platform claims-set
    pub platform_claims: Platform,
    /// Decoded realm claims-set
    pub realm_claims: Realm,
    /// COSE Sign1 envelope for the platform claims-set
    pub platform: CoseMessage,
    /// COSE Sign1 envelope for the realm claims-set
    pub realm: CoseMessage,
    /// Platform appraisal AR4SI trust vector
    platform_tvec: TrustVector,
    /// Realm appraisal AR4SI trust vector
    realm_tvec: TrustVector,
}

impl Default for Evidence {
    fn default() -> Self {
        Self::new()
    }
}

impl Evidence {
    /// Return a new, default Evidence object
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

    /// Decode a CBOR-encoded CCA Token and instantiate an Evidence object.
    pub fn decode<R: std::io::Read>(buf: R) -> Result<Evidence, Error> {
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
            .map_err(|e| Error::Syntax(format!("platform token: {e:?}")))?;

        t.realm
            .init_decoder(None)
            .map_err(|e| Error::Syntax(format!("realm token: {e:?}")))?;

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

    /// Appraise the CCA Token's platform and realm claims-sets against the
    /// supplied reference values store.
    /// On success, the results of the appraisal are stored in the relevant
    /// AR4SI trust vectors, which can be accessed using
    /// [Evidence::get_trust_vectors()].
    /// A call to this method will fail only on an internal error, i.e., in
    /// general a failure to appraise is only reflected in the trust vectors'
    /// state.
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

    /// Return the current state of the AR4SI trust vectors associated with platform and realm
    pub fn get_trust_vectors(&self) -> (TrustVector, TrustVector) {
        (self.platform_tvec, self.realm_tvec)
    }

    /// If (for any reason) crypto verification fails, this method will return
    /// an error which tells the caller to stop verifying immediately: there's
    /// no need to waste resources on realm verification if the trust anchor is
    /// not verified.
    fn verify_platform_token(&mut self, cpak: Cpak) -> Result<(), Error> {
        let inst_id = self.platform_claims.inst_id;

        match cpak.pkey {
            None => {
                //  The trust anchor store is misconfigured, this is an internal error.
                self.platform_tvec
                    .instance_identity
                    .set(VERIFIER_MALFUNCTION);

                return Err(Error::BadInternalState(format!(
                    "no public key found in the CPAK entry for inst-id:{inst_id:?}"
                )));
            }
            Some(cpak) => {
                let cose_key = make_cose_key(&self.platform, cpak).map_err(|e| {
                    self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);

                    Error::ComposeCoseKey(e.to_string())
                })?;

                self.platform.key(&cose_key).map_err(|e| {
                    self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);

                    Error::Syntax(format!(
                        "Setting CPAK for platform token with inst-id:{inst_id:?} failed: {e:?}"
                    ))
                })?;

                self.platform.decode(None, None).map_err(|e| {
                    self.platform_tvec.set_all(CRYPTO_VALIDATION_FAILED);

                    Error::Syntax(format!(
                        "Verifying platform token with inst-id:{inst_id:?} failed: {e:?}"
                    ))
                })?;
            }
        }

        self.platform_tvec
            .instance_identity
            .set(TRUSTWORTHY_INSTANCE);

        Ok(())
    }

    pub fn verify_realm_token(&mut self) -> Result<(), Error> {
        let realm_pub_key = self.realm_claims.get_realm_key()?;

        let mut cose_key: CoseKey;

        if self.realm_claims.profile == REALM_PROFILE {
            // it is already a COSE_Key, it just need decoding
            cose_key = CoseKey::new();
            cose_key.bytes = realm_pub_key;
            cose_key.decode().map_err(|e| {
                // a failure to decode should happen only if the rak claim is malformed
                self.realm_tvec.set_all(UNEXPECTED_EVIDENCE);

                Error::Syntax(format!("decoding the rak claim as COSE_Key failed: {e:?}"))
            })?;
        } else {
            // re-format RAK into a COSE_Key
            cose_key = self
                .ecdsa_public_key_from_raw(&realm_pub_key)
                .map_err(|e| {
                    // a failure to reformat should happen only if the rak claim is malformed
                    self.realm_tvec.set_all(UNEXPECTED_EVIDENCE);

                    Error::Syntax(format!("formatting the rak claim into ECDSA failed: {e:?}"))
                })?;
        }

        // explicitly set key-ops to verify
        cose_key.key_ops(vec![cose::keys::KEY_OPS_VERIFY]);

        // set algorithm for verification
        match self.realm.header.alg {
            None => {
                // a failure to reformat should happen only if the rak claim is malformed
                self.realm_tvec.set_all(UNEXPECTED_EVIDENCE);

                return Err(Error::Syntax(
                    "alg header parameter not found in realm token".to_string(),
                ));
            }
            Some(alg) => cose_key.alg(alg),
        }

        // associate the verification to the message to verify
        self.realm.key(&cose_key).map_err(|e| {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);

            Error::Syntax(format!(
                "pairing COSE_Key to realm's COSE_Sign1 message failed: {e:?}"
            ))
        })?;

        // verify signature
        self.realm.decode(None, None).map_err(|e| {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);

            Error::Syntax(format!(
                "verifying realm's COSE_Sign1 message failed: {e:?}"
            ))
        })?;

        Ok(())
    }

    /// Cryptographically verify the integrity of the CCA Token using key
    /// material from the supplied trust anchors' store.  This entails verifying
    /// the two separate signatures over the realm and platform tokens as well
    /// as the integrity of their binding.  On success, the results of the
    /// verification are stored in the relevant AR4SI trust vectors, which can
    /// be accessed using [Evidence::get_trust_vectors()].
    pub fn verify(&mut self, tas: &impl ITrustAnchorStore) -> Result<(), Error> {
        assert!(
            !self.platform.bytes.is_empty(),
            "platform token is mandatory"
        );
        assert!(!self.realm.bytes.is_empty(), "realm token is mandatory");

        // verify platform evidence first
        let inst_id = self.platform_claims.inst_id;

        match tas.lookup(&inst_id) {
            None => {
                // if platform is unknown, appraisal ends here because no further
                // trustworthiness deduction can be made
                self.platform_tvec
                    .instance_identity
                    .set(UNRECOGNIZED_INSTANCE);

                self.realm_tvec.set_all(NO_CLAIM);

                return Ok(());
            }
            Some(cpak) => {
                match self.verify_platform_token(cpak) {
                    Err(_) => {
                        /* swallow error */

                        // Since the platform also attests the realm attestation
                        // key (RAK), if verification fails at this stage there
                        // is no point in continuing because the RAK delegation
                        // can't be trusted.

                        // platform's trust vector is set in verify_platform_token
                        self.realm_tvec.set_all(NO_CLAIM);

                        return Ok(());
                    }
                    _ => { /* continue with realm */ }
                }
            }
        }

        match self.verify_realm_token() {
            Err(_) => {
                /* swallow error */
                return Ok(());
            }
            _ => { /* continue with binding */ }
        }

        match self.check_binding() {
            Err(_) => {
                return Ok(());
            }
            _ => {
                // early return on binder errors
                if self.realm_tvec.instance_identity.get() == CRYPTO_VALIDATION_FAILED {
                    return Ok(());
                }
            }
        }

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
        // early return on binder errors
        if self.realm_tvec.instance_identity.get() == CRYPTO_VALIDATION_FAILED {
            return Ok(());
        }
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

    // this method fails only on an internal errors, which are forwarded as-is
    fn check_binding(&mut self) -> Result<(), Error> {
        // it is OK to unwrap() here because these three claims are mandatory
        // and we expect the caller to (indirectly) invoke this methon on
        // Evidence that has been successfully decoded (and therefore
        // successfully validated).
        let realm_pub_key = self.realm_claims.get_realm_key().unwrap();
        let realm_pub_key_hash_alg = self.realm_claims.get_rak_hash_alg().unwrap();
        let platform_nonce = self.platform_claims.get_challenge().unwrap();

        let mut hasher = hasher_from_alg(realm_pub_key_hash_alg.as_str())?;

        hasher.update(&realm_pub_key).map_err(|e| {
            self.realm_tvec.set_all(VERIFIER_MALFUNCTION);

            Error::HashCalculateFail(format!("{e:?}"))
        })?;

        let sum = hasher.finish().map_err(|e| {
            self.realm_tvec.set_all(VERIFIER_MALFUNCTION);

            Error::HashCalculateFail(format!("{e:?}"))
        })?;

        if sum.to_vec() != *platform_nonce {
            self.realm_tvec.set_all(CRYPTO_VALIDATION_FAILED);
        }

        Ok(())
    }
}

fn hasher_from_alg(alg: &str) -> Result<Hasher, Error> {
    let h = match alg {
        SHA_256 => Hasher::new(MessageDigest::sha256())
            .map_err(|e| Error::HasherCreationFail(format!("{e:?}")))?,
        SHA_512 => Hasher::new(MessageDigest::sha512())
            .map_err(|e| Error::HasherCreationFail(format!("{e:?}")))?,
        x => return Err(Error::UnknownHash(x.to_string())),
    };

    Ok(h)
}

fn make_cose_key(cose_message: &CoseMessage, pkey: jwk::Jwk) -> Result<CoseKey, Error> {
    let mut cose_key = CoseKey::new();
    let header_alg = cose_message.header.alg.ok_or(Error::NoCoseAlgInHeader(
        "missing 'alg' header parameter".to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{MemoRefValueStore, MemoTrustAnchorStore};

    const TEST_CCA_TOKEN_1_OK: &[u8; 1222] = include_bytes!("../../testdata/cca-token-01.cbor");
    const TEST_CCA_TOKEN_2_OK: &[u8; 1125] = include_bytes!("../../testdata/cca-token-02.cbor");
    const TEST_CCA_TOKEN_BUG_33: &[u8; 2507] = include_bytes!("../../testdata/bug-33-repro.cbor");
    const TEST_CCA_TOKEN_DRAFT_FFM_00: &[u8; 2124] =
        include_bytes!("../../testdata/cca-token-draft-ffm-00.cbor");
    const TEST_CCA_RVS_OK: &str = include_str!("../../testdata/rv.json");
    const TEST_TA_2_OK: &str = include_str!("../../testdata/ta-02-ok.json");
    const TEST_TA_2_BAD: &str = include_str!("../../testdata/ta-02-bad.json");
    const TEST_TA_TFA: &str = include_str!("../../testdata/ta-tfa.json");

    #[test]
    fn decode_good_token() {
        let r = Evidence::decode(TEST_CCA_TOKEN_1_OK.as_slice());

        assert!(r.is_ok());
    }

    #[test]
    fn appraise_ok() {
        let mut rvs = MemoRefValueStore::new();
        rvs.load_json(TEST_CCA_RVS_OK)
            .expect("loading TEST_CCA_RVS_OK");

        let mut e =
            Evidence::decode(TEST_CCA_TOKEN_1_OK.as_slice()).expect("decoding TEST_CCA_TOKEN_1_OK");

        e.appraise(&rvs)
            .expect("validation successful for both platform and realm");

        println!(
            "platform trust vector: {}",
            serde_json::to_string_pretty(&e.platform_tvec).unwrap()
        );
        println!(
            "realm trust vector: {}",
            serde_json::to_string_pretty(&e.realm_tvec).unwrap()
        );
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
    fn verify_legacy_token_ok() {
        let mut evidence =
            Evidence::decode(TEST_CCA_TOKEN_2_OK.as_slice()).expect("decoding TEST_CCA_TOKEN_2_OK");

        let mut tas = MemoTrustAnchorStore::new();
        tas.load_json(TEST_TA_2_OK).expect("loading trust anchors");

        let r = evidence.verify(&tas);

        assert!(r.is_ok());

        println!(
            "platform trust vector: {}",
            serde_json::to_string_pretty(&evidence.platform_tvec).unwrap()
        );
        println!(
            "realm trust vector: {}",
            serde_json::to_string_pretty(&evidence.realm_tvec).unwrap()
        );
    }

    #[test]
    fn verify_legacy_token_error() {
        let mut evidence =
            Evidence::decode(TEST_CCA_TOKEN_2_OK.as_slice()).expect("decoding TEST_CCA_TOKEN_2_OK");

        let mut tas = MemoTrustAnchorStore::new();
        tas.load_json(TEST_TA_2_BAD).expect("loading trust anchors");

        let r = evidence.verify(&tas);

        assert!(r.is_ok());

        assert_eq!(
            evidence.platform_tvec.instance_identity,
            ear::claim::CRYPTO_VALIDATION_FAILED
        );

        assert_eq!(evidence.realm_tvec.instance_identity, ear::claim::NO_CLAIM);

        println!(
            "platform trust vector: {}",
            serde_json::to_string_pretty(&evidence.platform_tvec).unwrap()
        );
        println!(
            "realm trust vector: {}",
            serde_json::to_string_pretty(&evidence.realm_tvec).unwrap()
        );
    }

    #[test]
    fn bug_33_regression() {
        let mut evidence = Evidence::decode(TEST_CCA_TOKEN_BUG_33.as_slice())
            .expect("decoding TEST_CCA_TOKEN_BUG_33");

        let mut tas = MemoTrustAnchorStore::new();
        tas.load_json(TEST_TA_TFA).expect("loading trust anchors");

        let r = evidence.verify(&tas);

        assert!(r.is_ok());

        assert!(evidence.realm_tvec.instance_identity.get() == CRYPTO_VALIDATION_FAILED);
        assert!(evidence.platform_tvec.instance_identity.get() == TRUSTWORTHY_INSTANCE);
    }

    #[test]
    fn verify_draft_ffm_00_token_ok() {
        let mut evidence = Evidence::decode(TEST_CCA_TOKEN_DRAFT_FFM_00.as_slice())
            .expect("decoding TEST_CCA_TOKEN_DRAFT_FFM_00");

        let mut tas = MemoTrustAnchorStore::new();
        tas.load_json(TEST_TA_TFA).expect("loading trust anchors");

        let r = evidence.verify(&tas);

        assert!(r.is_ok());

        assert!(evidence.realm_tvec.instance_identity.get() == TRUSTWORTHY_INSTANCE);
        assert!(evidence.platform_tvec.instance_identity.get() == TRUSTWORTHY_INSTANCE);

        println!(
            "platform trust vector: {}",
            serde_json::to_string_pretty(&evidence.platform_tvec).unwrap()
        );
        println!(
            "realm trust vector: {}",
            serde_json::to_string_pretty(&evidence.realm_tvec).unwrap()
        );
    }
}
