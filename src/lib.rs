// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

pub fn parse_endorsements() -> bool {
    println!("TODO parse_endorsements()");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endorsement_dummy() {
        let result = parse_endorsements();
        assert!(result);
    }
}
