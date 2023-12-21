// SPDX-License-Identifier: Apache-2.0

use base64::{self, engine::general_purpose, Engine as _};
use serde::{
    de::{self, Deserialize, Visitor},
    ser::{Serialize, Serializer},
};

use super::errors::Error;

/// decodes bytes from a base64-encoded string
pub fn decode_str(v: &str) -> Result<Vec<u8>, Error> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(v)
        .map_err(|e| Error::Parse(e.to_string()))
}

/// a `Vec<u8>` encoded as base64 in human readable serialization
#[derive(Debug, PartialEq)]
pub struct Bytes(Vec<u8>);

impl Bytes {
    pub fn new() -> Self {
        Bytes(Vec::new())
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self::new()
    }
}

impl From<&[u8]> for Bytes {
    fn from(v: &[u8]) -> Self {
        Self(v.to_owned())
    }
}

impl TryFrom<&str> for Bytes {
    type Error = Error;

    fn try_from(v: &str) -> Result<Self, Error> {
        general_purpose::URL_SAFE_NO_PAD
            .decode(v)
            .map(Bytes)
            .map_err(|e| Error::Parse(e.to_string()))
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&base64::display::Base64Display::new(
                &self.0,
                &general_purpose::URL_SAFE_NO_PAD,
            ))
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(BytesVisitor {})
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a text string or a byte string")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Bytes::try_from(v).map_err(de::Error::custom)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Bytes::from(v))
    }
}
