// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::store::IRefValueStore;
use crate::store::PlatformRefValue;
use crate::store::RealmRefValue;

use super::common::*;
use super::errors::Error;
use super::platform::Platform;
use super::realm::Realm;
use ciborium::de::from_reader;
use ciborium::Value;
use cose::message::CoseMessage;
use ear::claim::*;
use ear::TrustVector;
use serde::Deserialize;

const CBOR_TAG: u64 = 399;
const PLATFORM_LABEL: i128 = 44234;
const REALM_LABEL: i128 = 44241;

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
    platform: CoseMessage,
    /// COSE Sign1 envelope for the realm claims-set
    realm: CoseMessage,
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
}

mod tests {
    use super::*;
    use crate::store::MemoRefValueStore;

    const TEST_CCA_TOKEN_OK: &[u8; 1222] = include_bytes!("../../testdata/cca-token.cbor");
    const TEST_CCA_RVS_OK: &str = include_str!("../../testdata/rv.json");

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
}
