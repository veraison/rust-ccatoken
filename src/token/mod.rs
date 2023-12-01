// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

//! The token module provides an [`Evidence`] object to encapsulate business
//! logics and associated state used for verification and appraisal of a CCA
//! attestation token.
//!
//! # Example
//!
//! The following example assumes that the trust anchor (`tas`) and reference
//! value (`rvs`) stores have already been initialised, and that `token`
//! contains a CBOR encoded CCA token.
//!
//! ```
//! use ccatoken::token::Evidence;
//! use ccatoken::store::MemoRefValueStore;
//! use ccatoken::store::MemoTrustAnchorStore;
//!
//! const token: &[u8; 1222] = include_bytes!("../../testdata/cca-token.cbor");
//!
//! let mut e = Evidence::decode(&token.to_vec()).expect("decoding CCA token");
//!
//! const jta: &str = include_str!("../../testdata/ta.json");
//! let mut tas = MemoTrustAnchorStore::new();
//! tas.load_json(jta).expect("loading trust anchors");
//!
//! // verify the Platform COSE Sign1 object using a matching CPAK
//! // verify the Realm COSE Sign1 object using the inlined RAK
//! // check the binding between Platform and Realm is correct
//! //
//! // TODO(PR#16)
//! //
//! // e.verify(&tas).expect("verifying CCA token");
//!
//! const jrv: &str = include_str!("../../testdata/rv.json");
//! let mut rvs = MemoRefValueStore::new();
//! rvs.load_json(jrv).expect("loading reference values");
//!
//! // appraise the content of the Platform claims-set against the relevant
//! // reference values
//! // appraise the content of the Realm claims-set against the relevant
//! // reference values
//! // populate the trustworthiness vectors accordingly
//! e.appraise(&rvs).expect("appraising CCA token");
//!
//! // Obtain the verification and appraisal results
//! let (platform_tvec, realm_tvec) = e.get_trust_vectors();
//!
//! // use the returned trustworthiness vectors
//! ```

pub use self::common::*;
pub use self::errors::Error;
pub use self::evidence::Evidence;
pub use self::platform::Platform;
pub use self::platform::SwComponent;
pub use self::realm::Realm;

mod common;
mod errors;
mod evidence;
mod platform;
mod realm;
