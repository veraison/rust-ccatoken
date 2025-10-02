# Test Data Organization for rust-ccatoken

This directory contains test data for the rust-ccatoken library. The files are organized as follows:

## Token Collections

Complete CCA token collections (containing both platform and realm tokens):

- `cca-token-01.cbor`: Standard valid CCA token
- `cca-token-01.diag`: Human-readable diagnostic format of `cca-token-01.cbor`
- `cca-token-02.cbor`: Alternative valid CCA token format
- `cca-token-02.diag`: Human-readable diagnostic format of `cca-token-02.cbor`
- `cca-token-draft-ffm-00.cbor`: Draft FFM format token
- `bug-33-repro.cbor`: Token that reproduces bug #33 (correctly signed platform but incorrectly signed realm)

## Platform and Realm Claims

Individual platform and realm claims for testing specific components:

- `platform-claims.cbor`: Platform claims CBOR data
- `platform-claims.diag`: Human-readable diagnostic format of `platform-claims.cbor`
- `realm-claims.cbor`: Realm claims CBOR data
- `realm-claims.diag`: Human-readable diagnostic format of `realm-claims.diag`

## Malformed Claims

Claims with specific issues for testing error handling:

- `realm-claims-missing-challenge.cbor`: Realm claims with missing challenge field
- `realm-claims-missing-challenge.diag`: Human-readable format of the above
- `realm-claims+spurious-numeric-key.cbor`: Realm claims with additional unexpected numeric key
- `realm-claims+spurious-numeric-key.diag`: Human-readable format of the above
- `realm-claims+spurious-text-key.cbor`: Realm claims with additional unexpected text key
- `realm-claims+spurious-text-key.diag`: Human-readable format of the above

## Trust Anchor Store Test Data

JSON files containing trust anchors for verification testing:

- `ta.json`: Standard trust anchor store
- `ta-02-ok.json`: Trust anchor store for `cca-token-02.cbor` with correct CPAK
- `ta-02-bad.json`: Trust anchor store for `cca-token-02.cbor` with incorrect CPAK
- `ta-tfa.json`: Trust anchor store for TFA testing

## Reference Value Store Test Data

JSON files containing reference values for appraisal testing:

- `rv.json`: Standard reference value store with matching values
- `rv-impl-id-mismatch.json`: Reference values with mismatched implementation ID
- `rv-swcomp-mismatch.json`: Reference values with mismatched SW component measurement
- `rv-rim-mismatch.json`: Reference values with mismatched realm initial measurement
- `rv-rem-mismatch.json`: Reference values with mismatched realm extensible measurement
- `rv-perso-mismatch.json`: Reference values with mismatched personalization value
- `rv-empty.json`: Empty reference value store

## Other Test Data

- `cpak.json`: CPAK (Confidential Platform Attestation Key) for testing
- `impl-id.bin`: Implementation ID binary data
- `inst-id.bin`: Instance ID binary data
- `pkey.json`: Public key data for testing

## Test Data Generation

The `Makefile` in this directory can be used to generate or regenerate test data as needed.