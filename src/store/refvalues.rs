// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::platformrefvalue::PlatformRefValue;
use super::realmrefvalue::RealmRefValue;
use serde::{Deserialize, Serialize};
use serde_json::Error;

/// JSON format for CCA reference values (both platform and realm).
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct RefValues {
    pub platform: Option<Vec<PlatformRefValue>>,
    pub realm: Option<Vec<RealmRefValue>>,
}

impl RefValues {
    /// Parse CCA reference values from JSON
    pub fn parse(j: &str) -> Result<Self, Error> {
        let v: RefValues = serde_json::from_str(j)?;
        // TODO: add validation of variable length fields
        Ok(v)
    }
}
