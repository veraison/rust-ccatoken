// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#[derive(thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Syntax error: {0}")]
    Syntax(String),
    #[error("Semantic error: {0}")]
    Sema(String),
    #[error("Unknown claim: {0}")]
    UnknownClaim(String),
    #[error("Missing claim: {0}")]
    MissingClaim(String),
    #[error("Duplicated claim: {0}")]
    DuplicatedClaim(String),
    #[error("Claim type mismatch: {0}")]
    TypeMismatch(String),
    #[error("Missing Platform Token: {0}")]
    UnknownProfile(String),
    #[error("Unknown profile: {0}")]
    MissingPlatformToken(String),
    #[error("Missing Realm Token: {0}")]
    MissingRealmToken(String),
    #[error("Not found Trust Anchor: {0}")]
    NotFoundTA(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("key error: {0}")]
    Key(String),
    #[error("Compose Cose Key error: {0}")]
    ComposeCoseKey(String),
    #[error("Hash Algorithm Unknown: {0}")]
    UnknownHash(String),
    #[error("Binding Check Mismatch: {0}")]
    BindingMismatch(String),
    #[error("Hasher Creation Failed: {0}")]
    HasherCreationFail(String),
    #[error("Hash Calculation Failed: {0}")]
    HashCalculateFail(String),
    #[error("No Cose Alg in Header: {0}")]
    NoCoseAlgInHeader(String),
    #[error("Bad internal state: {0}")]
    BadInternalState(String),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax(e)
            | Error::Sema(e)
            | Error::UnknownClaim(e)
            | Error::MissingClaim(e)
            | Error::DuplicatedClaim(e)
            | Error::TypeMismatch(e)
            | Error::UnknownProfile(e)
            | Error::MissingPlatformToken(e)
            | Error::MissingRealmToken(e)
            | Error::NotFoundTA(e)
            | Error::Parse(e)
            | Error::Key(e)
            | Error::ComposeCoseKey(e)
            | Error::UnknownHash(e)
            | Error::BindingMismatch(e)
            | Error::HasherCreationFail(e)
            | Error::HashCalculateFail(e)
            | Error::NoCoseAlgInHeader(e)
            | Error::BadInternalState(e) => {
                write!(f, "{e}")
            }
        }
    }
}
