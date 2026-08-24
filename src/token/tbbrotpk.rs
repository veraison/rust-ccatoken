// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0
#![allow(unexpected_cfgs)] // fixes warning from bitmask! macro

use crate::token::common::*;
use crate::token::errors::Error;
use bitflags::bitflags;
use ciborium::Value;

const TBB_ROTPK_NAME: i128 = 1;
const TBB_ROTPK_ACTIVE_ARRAY_INDEX: i128 = 2;
const TBB_ROTPK_INDEX: i128 = 3;
const TBB_ROTPK_HASH: i128 = 4;

bitflags! {
    #[derive(Debug, PartialEq, Copy, Clone)]
    struct TbbRotpkClaimsSet: u8 {
        const NAME                  = 0x01;
        const ACTIVE_ARRAY_INDEX    = 0x02;
        const INDEX                 = 0x04;
        const HASH                  = 0x08;
    }
}

#[derive(Debug, PartialEq)]
pub struct TbbRotpkItem {
    pub name: String,             // 1, text
    pub active_array_index: i128, // 2, int
    pub index: i128,              // 3, int
    pub hash: Vec<u8>,            // 4, bytes .size {32,48,64}

    claims_set: TbbRotpkClaimsSet,
}

impl Default for TbbRotpkItem {
    fn default() -> Self {
        Self::new()
    }
}

impl TbbRotpkItem {
    pub fn new() -> Self {
        Self {
            name: String::from(""),
            active_array_index: 0,
            index: 0,
            hash: Default::default(),

            claims_set: TbbRotpkClaimsSet::empty(),
        }
    }

    fn set_name(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(TbbRotpkClaimsSet::NAME) {
            return Err(Error::DuplicatedClaim("name".to_string()));
        }

        let name = to_tstr(v, "name")?;

        if name.is_empty() {
            return Err(Error::Sema(
                "tbb-rotpk item name should not be empty".to_string(),
            ));
        }

        self.name = name;

        self.claims_set.set(TbbRotpkClaimsSet::NAME, true);

        Ok(())
    }

    fn set_active_array_index(&mut self, v: &Value) -> Result<(), Error> {
        if self
            .claims_set
            .contains(TbbRotpkClaimsSet::ACTIVE_ARRAY_INDEX)
        {
            return Err(Error::DuplicatedClaim("active-array-index".to_string()));
        }

        self.active_array_index = to_int(v, "active-array-index")?;

        self.claims_set
            .set(TbbRotpkClaimsSet::ACTIVE_ARRAY_INDEX, true);

        Ok(())
    }

    fn set_index(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(TbbRotpkClaimsSet::INDEX) {
            return Err(Error::DuplicatedClaim("index".to_string()));
        }

        self.index = to_int(v, "index")?;

        self.claims_set.set(TbbRotpkClaimsSet::INDEX, true);

        Ok(())
    }

    fn set_hash(&mut self, v: &Value) -> Result<(), Error> {
        if self.claims_set.contains(TbbRotpkClaimsSet::HASH) {
            return Err(Error::DuplicatedClaim("hash".to_string()));
        }

        self.hash = to_measurement(v, "hash")?;

        self.claims_set.set(TbbRotpkClaimsSet::HASH, true);

        Ok(())
    }

    pub(crate) fn parse(&mut self, contents: &[(Value, Value)]) -> Result<(), Error> {
        for (k, v) in contents.iter() {
            if let Value::Integer(i) = k {
                match (*i).into() {
                    TBB_ROTPK_NAME => self.set_name(v)?,
                    TBB_ROTPK_ACTIVE_ARRAY_INDEX => self.set_active_array_index(v)?,
                    TBB_ROTPK_INDEX => self.set_index(v)?,
                    TBB_ROTPK_HASH => self.set_hash(v)?,
                    unknown => {
                        return Err(Error::Syntax(format!(
                            "unknown key {unknown} in tbb-rotpk item"
                        )))
                    }
                }
            } else {
                return Err(Error::Syntax(
                    "non-integer key in tbb-rotpk item".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Validates correct shape of item.
    /// Field-level validation is done in the setters called by parse.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        // Within each TBB RoTPK item, all claims are mandatory
        let mandatory_claims = [
            (TbbRotpkClaimsSet::NAME, "name"),
            (TbbRotpkClaimsSet::ACTIVE_ARRAY_INDEX, "active-array-index"),
            (TbbRotpkClaimsSet::INDEX, "index"),
            (TbbRotpkClaimsSet::HASH, "hash"),
        ];

        for (claim, name) in mandatory_claims.iter() {
            if !self.claims_set.contains(*claim) {
                return Err(Error::MissingClaim(name.to_string()));
            }
        }

        Ok(())
    }
}
