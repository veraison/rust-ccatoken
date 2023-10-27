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
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Syntax(e)
            | Error::Sema(e)
            | Error::UnknownClaim(e)
            | Error::MissingClaim(e)
            | Error::DuplicatedClaim(e)
            | Error::TypeMismatch(e) => {
                write!(f, "{}", e)
            }
        }
    }
}
