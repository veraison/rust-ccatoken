// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::cpak::Cpak;

/// Interface to the store where the active CPAKs are stashed.
pub trait ITrustAnchorStore {
    /// Lookup a trust anchor from the store given the corresponding Instance ID
    fn lookup(&self, inst_id: &[u8; 33]) -> Option<Cpak>;
}
