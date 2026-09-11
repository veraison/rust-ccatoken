// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::{
    common::decode_profile_name, realm::REALM_PROFILE, realm_2024::REALM_PROFILE_2024, Error,
    Realm, Realm2024,
};

#[non_exhaustive]
pub enum RealmClaims {
    Realm(Realm),
    Realm2024(Realm2024),
}

impl Default for RealmClaims {
    /// Return the latest version as the default
    fn default() -> Self {
        RealmClaims::Realm2024(Realm2024::default())
    }
}

impl RealmClaims {
    pub fn decode(buf: &Vec<u8>) -> Result<Self, Error> {
        let realm_profile = decode_profile_name(buf)?;
        match realm_profile {
            Some(profile) => {
                let p = profile.as_str();
                if p == REALM_PROFILE {
                    let realm_claims = Realm::decode(buf)?;
                    Ok(RealmClaims::Realm(realm_claims))
                } else if p == REALM_PROFILE_2024 {
                    let realm_claims = Realm2024::decode(buf)?;
                    Ok(RealmClaims::Realm2024(realm_claims))
                } else {
                    Err(Error::UnknownProfile(format!(
                        "unexpected realm profile: {profile}"
                    )))
                }
            }
            None => {
                // Missing realm profile claim is treated as legacy profile
                let realm_claims = Realm::decode(buf)?;
                Ok(RealmClaims::Realm(realm_claims))
            }
        }
    }

    pub fn profile(&self) -> &String {
        match self {
            // Realm represents either the legacy profile (without profile claim)
            // or the "tag:arm.com,2023:realm#1.0.0"; profile (with profile claim).
            // this matters as the legacy profile uses a raw RAK format for
            // the realm public key, but the 2023 profile uses a COSE_Key format.
            RealmClaims::Realm(r) => &r.profile,
            RealmClaims::Realm2024(r) => &r.profile,
        }
    }

    pub fn challenge(&self) -> &[u8; 64] {
        match self {
            RealmClaims::Realm(r) => &r.challenge,
            RealmClaims::Realm2024(r) => &r.challenge,
        }
    }

    pub fn perso(&self) -> &[u8] {
        match self {
            RealmClaims::Realm(r) => &r.perso,
            RealmClaims::Realm2024(r) => &r.perso,
        }
    }

    pub fn rim(&self) -> &Vec<u8> {
        match self {
            RealmClaims::Realm(r) => &r.rim,
            RealmClaims::Realm2024(r) => &r.rim,
        }
    }

    pub fn rem(&self) -> &[Vec<u8>; 4] {
        match self {
            RealmClaims::Realm(r) => &r.rem,
            RealmClaims::Realm2024(r) => &r.rem,
        }
    }

    pub fn hash_alg(&self) -> &String {
        match self {
            RealmClaims::Realm(r) => &r.hash_alg,
            RealmClaims::Realm2024(r) => &r.hash_alg,
        }
    }

    pub fn get_realm_key(&self) -> Result<Vec<u8>, Error> {
        match self {
            RealmClaims::Realm(r) => r.get_realm_key(),
            RealmClaims::Realm2024(r) => r.get_realm_key(),
        }
    }

    pub fn rak_hash_alg(&self) -> &String {
        match self {
            RealmClaims::Realm(r) => &r.rak_hash_alg,
            RealmClaims::Realm2024(r) => &r.rak_hash_alg,
        }
    }

    /// The Memory Encryption Context policy of the Realm.
    ///
    /// Appended with _rev03 here, as it is a string "private" | "shared"
    /// in draft-ffm-03 only. The claim format changes to an
    /// int (0: shared, 1: private) in draft-ffm-04.
    pub fn mec_policy_rev03(&self) -> Option<&String> {
        match self {
            RealmClaims::Realm(_) => None,
            RealmClaims::Realm2024(r) => Some(&r.mec_policy),
        }
    }
}
