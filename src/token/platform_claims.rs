// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::token::{ExtensionDevice, TbbRotpkItem};

use super::{
    common::decode_profile_name,
    platform::{PLATFORM_PROFILE, PLATFORM_PROFILE_LEGACY},
    platform_2024::PLATFORM_PROFILE_2024,
    Error, Platform, Platform2024, SwComponent,
};

#[non_exhaustive]
pub enum PlatformClaims {
    Platform(Platform),
    Platform2024(Platform2024),
}

impl Default for PlatformClaims {
    /// Return the latest version as the default
    fn default() -> Self {
        PlatformClaims::Platform2024(Platform2024::default())
    }
}

impl PlatformClaims {
    pub fn decode(buf: &Vec<u8>) -> Result<Self, Error> {
        let platform_profile = decode_profile_name(buf)?;
        match platform_profile {
            Some(profile) => {
                let p = profile.as_str();
                if p == PLATFORM_PROFILE || p == PLATFORM_PROFILE_LEGACY {
                    let platform_claims = Platform::decode(buf)?;
                    Ok(PlatformClaims::Platform(platform_claims))
                } else if p == PLATFORM_PROFILE_2024 {
                    let platform_claims = Platform2024::decode(buf)?;
                    Ok(PlatformClaims::Platform2024(platform_claims))
                } else {
                    Err(Error::UnknownProfile(format!(
                        "unexpected platform profile: {profile}"
                    )))
                }
            }
            None => Err(Error::Syntax("missing platform profile claim".to_string())),
        }
    }

    pub fn profile(&self) -> &String {
        match self {
            PlatformClaims::Platform(p) => &p.profile,
            PlatformClaims::Platform2024(p) => &p.profile,
        }
    }

    pub fn challenge(&self) -> &Vec<u8> {
        match self {
            PlatformClaims::Platform(p) => &p.challenge,
            PlatformClaims::Platform2024(p) => &p.challenge,
        }
    }

    pub fn impl_id(&self) -> &[u8; 32] {
        match self {
            PlatformClaims::Platform(p) => &p.impl_id,
            PlatformClaims::Platform2024(p) => &p.impl_id,
        }
    }

    pub fn inst_id(&self) -> &[u8; 33] {
        match self {
            PlatformClaims::Platform(p) => &p.inst_id,
            PlatformClaims::Platform2024(p) => &p.inst_id,
        }
    }

    pub fn config(&self) -> &Vec<u8> {
        match self {
            PlatformClaims::Platform(p) => &p.config,
            PlatformClaims::Platform2024(p) => &p.config,
        }
    }

    pub fn lifecycle(&self) -> u16 {
        match self {
            PlatformClaims::Platform(p) => p.lifecycle,
            PlatformClaims::Platform2024(p) => p.lifecycle,
        }
    }

    pub fn sw_components(&self) -> &Vec<SwComponent> {
        match self {
            PlatformClaims::Platform(p) => &p.sw_components,
            PlatformClaims::Platform2024(p) => &p.sw_components,
        }
    }

    pub fn verification_service(&self) -> Option<&String> {
        match self {
            PlatformClaims::Platform(p) => p.verification_service.as_ref(),
            PlatformClaims::Platform2024(p) => p.verification_service.as_ref(),
        }
    }

    pub fn hash_alg(&self) -> &String {
        match self {
            PlatformClaims::Platform(p) => &p.hash_alg,
            PlatformClaims::Platform2024(p) => &p.hash_alg,
        }
    }

    /// client_id is a MANDATORY claim introduced in Platform2024 for draft-ffm-03.
    ///
    /// Some(Value): client_id claim is in the token's profile and present.
    ///
    /// None: client_id claim is not in the token's profile.
    pub fn client_id(&self) -> Option<i128> {
        match self {
            PlatformClaims::Platform(_) => None,
            PlatformClaims::Platform2024(p) => Some(p.client_id),
        }
    }

    /// manufacturing_config is an OPTIONAL claim introduced in Platform2024 for draft-ffm-03.
    ///
    /// Some(Value): manufacturing_config claim is in the token's profile and present.
    ///
    /// None: manufacturing_config claim is not in the token's profile, OR in the token's profile but omitted.
    pub fn manufacturing_config(&self) -> Option<&Vec<u8>> {
        match self {
            PlatformClaims::Platform(_) => None,
            PlatformClaims::Platform2024(p) => p.manufacturing_config.as_ref(),
        }
    }

    /// extension is an OPTIONAL claim introduced in Platform2024 for draft-ffm-03.
    ///
    /// Some(Value): extension claim is in the token's profile and present.
    ///
    /// None: extension claim is not in the token's profile, OR in the token's profile but omitted.
    pub fn extension(&self) -> Option<&Vec<ExtensionDevice>> {
        match self {
            PlatformClaims::Platform(_) => None,
            PlatformClaims::Platform2024(p) => p.extension.as_ref(),
        }
    }

    /// tbb_rotpk is an OPTIONAL claim introduced in Platform2024 for draft-ffm-03.
    ///
    /// Some(Value): tbb_rotpk claim is in the token's profile and present.
    ///
    /// None: tbb_rotpk claim is not in the token's profile, OR in the token's profile but omitted.
    pub fn tbb_rotpk(&self) -> Option<&Vec<TbbRotpkItem>> {
        match self {
            PlatformClaims::Platform(_) => None,
            PlatformClaims::Platform2024(p) => p.tbb_rotpk.as_ref(),
        }
    }

    /// peer_signers is an OPTIONAL claim introduced in Platform2024 for draft-ffm-03.
    ///
    /// Some(Value): peer_signers claim is in the token's profile and present.
    ///
    /// None: peer_signers claim is not in the token's profile, OR in the token's profile but omitted.
    pub fn peer_signers(&self) -> Option<&Vec<u8>> {
        match self {
            PlatformClaims::Platform(_) => None,
            PlatformClaims::Platform2024(p) => p.peer_signers.as_ref(),
        }
    }
}
