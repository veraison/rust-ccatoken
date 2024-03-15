// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

//! Arm CCA attestation token verification and appraisal.
//!
//! This crate provides an API to decode, verify and appraise attestation
//! evidence produced by an Armv9-A CCA platform.  For detailed information
//! about the format, see §A.7 of the Realm Management Monitor [RMM]
//! specification.
//!
//! The API allows:
//! * Decoding a CBOR-encoded CCA attestation token
//! * Cryptographically verifying the integrity and authenticity of the token
//! * Appraising the contents of the token against user-supplied reference values
//!
//! [RMM]: https://developer.arm.com/documentation/den0137/latest

pub mod store;
pub mod token;
