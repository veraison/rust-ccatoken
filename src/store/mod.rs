// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

//! The store module provides traits and concrete types to implement the
//! interface between:
//! * the verification logics and the store where CCA trust anchors (CPAK) are
//!   kept
//! * the appraisal logics and the store where CCA Platform and Realm reference
//!   values are kept
//!
//! A simple, in-memory implementation of both stores is also provided by the
//! [`MemoRefValueStore`] and [`MemoTrustAnchorStore`] objects.
//!
//! # Examples
//!
//! * Initialise an in-memory store for reference values:
//!
//! ```
//! let jrv = r#"
//!   {
//!     "platform": [
//!       {
//!         "implementation-id": "7f454c4602010100000000000000000003003e00010000005058000000000000",
//!         "sw-components": [
//!           {
//!             "measurement-value": "07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918",
//!             "signer-id": "07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
//!           },
//!         "platform-configuration": "0107060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
//!       }
//!     ],
//!     "realm": [
//!       {
//!         "initial-measurement": "ff00000000000000000000000000000000000000000000000000000000000000",
//!         "rak-hash-algorithm": "sha-256",
//!         "extensible-measurements": [
//!           "0000000000000000000000000000000000000000000000000000000000000001",
//!           "0000000000000000000000000000000000000000000000000000000000000002",
//!           "0000000000000000000000000000000000000000000000000000000000000003",
//!           "0000000000000000000000000000000000000000000000000000000000000004"
//!         ],
//!         "personalization-value": "54686520717569636b2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e54686520717569636b2062726f776e20666f7820"
//!       }
//!     ]
//!   }"#;
//!
//! let mut rvs: MemoRefValueStore = Default::default();
//! rvs.load_json(&jrv).expect("loading reference values");
//! ```
//!
//! * Initialise an in-memory store for trust anchors:
//!
//! ```
//! let jta = r#"
//! [
//!   {
//!     "pkey": {
//!       "crv": "P-256",
//!       "kty": "EC",
//!       "x": "TKRFE_RwSXooI8DdatPOYg_uiKm2XrtT_uEMEvqQZrw",
//!       "y": "CRx3H8NHN1lcxqKi92P0OsZBxX3VFaktllpD3SjtN7s"
//!     },
//!     "implementation-id": "7f454c4602010100000000000000000003003e00010000005058000000000000",
//!     "instance-id": "0107060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918"
//!   }
//! ]"#;
//!
//! let mut tas: MemoTrustAnchorStore = Default::default();
//! tas.load_json(&jta)?;
//! ```

pub use self::cpak::Cpak;
pub use self::errors::Error;
pub use self::irefvaluestore::IRefValueStore;
pub use self::itrustanchorstore::ITrustAnchorStore;
pub use self::memo_refvaluestore::MemoRefValueStore;
pub use self::memo_trustanchorstore::MemoTrustAnchorStore;
pub use self::platformrefvalue::PlatformRefValue;
pub use self::platformrefvalue::SwComponent;
pub use self::realmrefvalue::RealmRefValue;
pub use self::refvalues::RefValues;

mod cpak;
mod errors;
mod irefvaluestore;
mod itrustanchorstore;
mod memo_refvaluestore;
mod memo_trustanchorstore;
mod platformrefvalue;
mod realmrefvalue;
mod refvalues;
