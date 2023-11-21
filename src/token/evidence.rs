// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::common::*;
use super::errors::Error;
use super::platform::Platform;
use super::realm::Realm;
use ciborium::de::from_reader;
use ciborium::Value;
use cose::message::CoseMessage;
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
                    x => return Err(Error::Syntax(format!("unknown key {x} in collection"))),
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
    platform_claims: Platform,
    /// decoded realm claims-set
    realm_claims: Realm,
    /// COSE Sign1 envelope for the platform claims-set
    platform: CoseMessage,
    /// COSE Sign1 envelope for the realm claims-set
    realm: CoseMessage,
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
        }
    }

    fn decode(buf: &Vec<u8>) -> Result<Evidence, Error> {
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
}

mod tests {
    use super::*;

    const TEST_CCA_TOKEN_OK: &[u8; 1222] = include_bytes!("../../testdata/cca-token.cbor");

    #[test]
    fn good_token() {
        let r = Evidence::decode(&TEST_CCA_TOKEN_OK.to_vec());

        assert!(r.is_ok());
    }
}
