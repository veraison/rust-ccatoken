// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use super::platformrefvalue::PlatformRefValue;
use super::realmrefvalue::RealmRefValue;

pub trait IRefValueStore {
    /// Lookup all platform reference values matching the given implementation identifier
    fn lookup_platform(&self, impl_id: &[u8; 32]) -> Option<Vec<PlatformRefValue>>;

    /// Lookup all realm reference values matching the given RIM
    fn lookup_realm(&self, rim: &[u8]) -> Option<Vec<RealmRefValue>>;
}
