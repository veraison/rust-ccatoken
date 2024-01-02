// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::errors::Error;
use jsonwebtoken::jwk;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

/// A CCA platform attestation key and associated metadata
#[serde_with::serde_as]
#[derive(Clone, Deserialize, Serialize, Debug)]
pub struct Cpak {
    /// The CPAK (a raw public key) wrapped in a Subject Public Key Info and
    /// serialised using the textual encoding described in §13 of RFC7468
    #[serde(rename = "pkey")]
    pub raw_pkey: Box<RawValue>,

    #[serde(skip)]
    pub pkey: Option<jwk::Jwk>,

    /// The CCA platform Implementation ID claim uniquely identifies the
    /// implementation of the CCA platform.  The semantics of the CCA platform
    /// Implementation ID value are defined by the manufacturer or a particular
    /// certification scheme.  For example, the ID could take the form of a
    /// product serial number, database ID, or other appropriate identifier.
    /// It is a fixed-size, 32 bytes binary blob, base64 encoded.
    #[serde(rename = "implementation-id")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub impl_id: [u8; 32],

    /// The CCA platform Instance ID claim represents the unique identifier of
    /// the CPAK
    /// It is a fixed-size, 33 bytes binary blob (a EAT UEID), base64 encoded.
    /// The first byte MUST be 0x01 (i.e., RAND UEID).
    #[serde(rename = "instance-id")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub inst_id: [u8; 33],
}

impl Default for Cpak {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpak {
    pub fn new() -> Self {
        Self {
            impl_id: Default::default(),
            inst_id: [0; 33],
            pkey: None,
            raw_pkey: Default::default(),
        }
    }

    pub fn parse_pkey(&mut self) -> Result<(), Error> {
        let s = self.raw_pkey.get();

        let pkey = serde_json::from_str::<jwk::Jwk>(s).map_err(|e| Error::Syntax(e.to_string()))?;

        self.pkey = Some(pkey);

        Ok(())
    }
    pub fn get_pkey(&mut self) -> Result<Option<&jwk::Jwk>, Error> {
        Ok(self.pkey.as_ref())
    }
}
