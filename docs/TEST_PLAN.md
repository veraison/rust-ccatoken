# Test Plan for rust-ccatoken

This document defines a comprehensive test plan for the `rust-ccatoken` library. The plan covers the three main functional areas of the library:

1. CBOR Decoding
2. Cryptographic Verification
3. Appraisal

For each area, we define a set of test cases with descriptions, test vectors, and expected outcomes.

## 1. CBOR Decoding Tests

These tests verify the library's ability to correctly parse and decode CCA tokens from their CBOR-encoded format.

### 1.1 Valid Token Decoding

**Description**: Verify that a well-formed CCA token can be successfully decoded.

**Test Vectors**:
- `testdata/cca-token-01.cbor`: Standard valid CCA token
- `testdata/cca-token-02.cbor`: Alternative valid CCA token format
- `testdata/cca-token-draft-ffm-00.cbor`: Draft FFM format token

**Expected Outcome**: All tokens should be successfully decoded without errors, with correct extraction of platform and realm claims.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let evidence = Evidence::decode(token.as_slice());
assert!(evidence.is_ok());
```

### 1.2 Platform Token Decoding

**Description**: Verify decoding of platform-specific token components.

**Test Vectors**:
- `testdata/platform-claims.cbor`: Platform claims CBOR data

**Expected Outcome**: Platform-specific fields should be correctly parsed:
- Implementation ID
- Instance ID
- Platform configuration
- SW components
- Challenge

```rust
// Test code example
let platform_claims = include_bytes!("../../testdata/platform-claims.cbor");
let platform = Platform::decode(platform_claims);
assert!(platform.is_ok());
assert_eq!(platform.unwrap().profile, "http://arm.com/CCA-SSD/1.0.0");
```

### 1.3 Realm Token Decoding

**Description**: Verify decoding of realm-specific token components.

**Test Vectors**:
- `testdata/realm-claims.cbor`: Realm claims CBOR data

**Expected Outcome**: Realm-specific fields should be correctly parsed:
- Initial measurement
- RAK hash algorithm
- Extensible measurements
- Personalization value

```rust
// Test code example
let realm_claims = include_bytes!("../../testdata/realm-claims.cbor");
let realm = Realm::decode(realm_claims);
assert!(realm.is_ok());
```

### 1.4 Malformed Token Handling

**Description**: Verify handling of tokens with malformed structures.

**Test Vectors**:
- `testdata/realm-claims-missing-challenge.cbor`: Realm claims with missing challenge field
- `testdata/realm-claims+spurious-numeric-key.cbor`: Realm claims with additional unexpected numeric key
- `testdata/realm-claims+spurious-text-key.cbor`: Realm claims with additional unexpected text key

**Expected Outcome**: 
- Missing required fields should result in appropriate error
- Spurious fields should be handled gracefully according to the specification

```rust
// Test code example
let malformed_token = include_bytes!("../../testdata/realm-claims-missing-challenge.cbor");
let result = Realm::decode(malformed_token);
// Should return an appropriate error for the missing field
assert!(matches!(result, Err(Error::MissingClaim(_))));
```

### 1.5 Token Collection Decoding

**Description**: Verify decoding of an entire token collection (both platform and realm tokens).

**Test Vectors**:
- `testdata/cca-token-01.cbor`: Complete token collection

**Expected Outcome**: Both platform and realm tokens should be extracted and decoded correctly from the collection.

```rust
// Test code example
let token_collection = include_bytes!("../../testdata/cca-token-01.cbor");
let evidence = Evidence::decode(token_collection.as_slice()).unwrap();
assert!(!evidence.platform.bytes.is_empty());
assert!(!evidence.realm.bytes.is_empty());
```

## 2. Cryptographic Verification Tests

These tests verify the library's ability to cryptographically validate CCA tokens.

### 2.1 Valid Token Verification

**Description**: Verify that a legitimate token with valid signatures can be successfully verified.

**Test Vectors**:
- Token: `testdata/cca-token-01.cbor`
- Trust Anchor Store: `testdata/ta.json`

**Expected Outcome**: The token should be verified successfully with both platform and realm trust vectors set to `TRUSTWORTHY_INSTANCE`.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let ta_json = include_str!("../../testdata/ta.json");
let mut tas = MemoTrustAnchorStore::new();
tas.load_json(ta_json).unwrap();

let result = evidence.verify(&tas);
assert!(result.is_ok());
assert_eq!(evidence.platform_tvec.instance_identity, TRUSTWORTHY_INSTANCE);
assert_eq!(evidence.realm_tvec.instance_identity, TRUSTWORTHY_INSTANCE);
```

### 2.2 Invalid Platform Signature

**Description**: Verify handling of tokens with invalid platform signatures.

**Test Vectors**:
- Token: `testdata/cca-token-02.cbor`
- Trust Anchor Store: `testdata/ta-02-bad.json` (contains incorrect CPAK)

**Expected Outcome**: The verification should set the platform trust vector to `CRYPTO_VALIDATION_FAILED` and the realm trust vector to `NO_CLAIM`.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-02.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let ta_json = include_str!("../../testdata/ta-02-bad.json");
let mut tas = MemoTrustAnchorStore::new();
tas.load_json(ta_json).unwrap();

let result = evidence.verify(&tas);
assert!(result.is_ok()); // Function succeeds but sets error in trust vector
assert_eq!(evidence.platform_tvec.instance_identity, CRYPTO_VALIDATION_FAILED);
assert_eq!(evidence.realm_tvec.instance_identity, NO_CLAIM);
```

### 2.3 Invalid Realm Signature

**Description**: Verify handling of tokens with invalid realm signatures.

**Test Vectors**:
- Token: `testdata/bug-33-repro.cbor` (contains correctly signed platform but incorrectly signed realm)
- Trust Anchor Store: `testdata/ta-tfa.json`

**Expected Outcome**: The verification should set the platform trust vector to `TRUSTWORTHY_INSTANCE` and the realm trust vector to `CRYPTO_VALIDATION_FAILED`.

```rust
// Test code example
let token = include_bytes!("../../testdata/bug-33-repro.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let ta_json = include_str!("../../testdata/ta-tfa.json");
let mut tas = MemoTrustAnchorStore::new();
tas.load_json(ta_json).unwrap();

let result = evidence.verify(&tas);
assert!(result.is_ok()); // Function succeeds but sets error in trust vector
assert_eq!(evidence.platform_tvec.instance_identity, TRUSTWORTHY_INSTANCE);
assert_eq!(evidence.realm_tvec.instance_identity, CRYPTO_VALIDATION_FAILED);
```

### 2.4 Invalid Binding

**Description**: Verify handling of tokens with invalid binding between platform and realm.

**Test Vectors**:
- A token where the platform's challenge does not match the hash of the realm's public key

**Expected Outcome**: The verification should set the realm trust vector to `CRYPTO_VALIDATION_FAILED`.

### 2.5 Trust Anchor Store Integration

**Description**: Verify the integration with the trust anchor store for CPAK lookup.

**Test Vectors**:
- Token: `testdata/cca-token-01.cbor`
- Trust Anchor Store: `testdata/ta.json`

**Expected Outcome**: The correct CPAK should be retrieved from the trust store based on the platform's implementation ID.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let ta_json = include_str!("../../testdata/ta.json");
let mut tas = MemoTrustAnchorStore::new();
tas.load_json(ta_json).unwrap();

// Should retrieve the correct CPAK and not return an error
let result = evidence.verify(&tas);
assert!(result.is_ok());
```

## 3. Appraisal Tests

These tests verify the library's ability to appraise CCA tokens against reference values.

### 3.1 Successful Appraisal

**Description**: Verify that a token can be successfully appraised against matching reference values.

**Test Vectors**:
- Token: `testdata/cca-token-01.cbor`
- Reference Value Store: `testdata/rv.json`

**Expected Outcome**: Both platform and realm should be appraised successfully with trust vectors indicating `TRUSTWORTHY_INSTANCE`.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let rv_json = include_str!("../../testdata/rv.json");
let mut rvs = MemoRefValueStore::new();
rvs.load_json(rv_json).unwrap();

let result = evidence.appraise(&rvs);
assert!(result.is_ok());
// Check trust vectors have been set correctly
assert!(evidence.platform_tvec.instance_identity.get() == TRUSTWORTHY_INSTANCE);
assert!(evidence.realm_tvec.instance_identity.get() == TRUSTWORTHY_INSTANCE);
```

### 3.2 Platform Implementation ID Mismatch

**Description**: Verify handling when the platform implementation ID does not match any reference values.

**Test Vectors**:
- A token with an implementation ID that doesn't match any in the reference value store

**Expected Outcome**: The platform trust vector should be set to `REFERENCE_VALUE_MISMATCH`.

### 3.3 Platform Software Component Mismatch

**Description**: Verify handling when a platform software component doesn't match reference values.

**Test Vectors**:
- A token with software component measurements that don't match the reference values

**Expected Outcome**: The platform trust vector should be set to `REFERENCE_VALUE_MISMATCH`.

### 3.4 Realm Initial Measurement Mismatch

**Description**: Verify handling when the realm initial measurement doesn't match the reference value.

**Test Vectors**:
- A token with a realm initial measurement that doesn't match the reference value

**Expected Outcome**: The realm trust vector should be set to `REFERENCE_VALUE_MISMATCH`.

### 3.5 Realm Extensible Measurement Mismatch

**Description**: Verify handling when a realm extensible measurement doesn't match the reference value.

**Test Vectors**:
- A token with realm extensible measurements that don't match the reference values

**Expected Outcome**: The realm trust vector should be set to `REFERENCE_VALUE_MISMATCH`.

### 3.6 Unknown Reference Values

**Description**: Verify handling when no reference values can be found for the token.

**Test Vectors**:
- An empty reference value store

**Expected Outcome**: The trust vectors should be set to `REFERENCE_VALUE_MISSING`.

## 4. End-to-End Tests

These tests verify the complete flow from decoding to verification to appraisal.

### 4.1 Complete Flow with Valid Token

**Description**: Verify the complete flow of decoding, verifying, and appraising a valid token.

**Test Vectors**:
- Token: `testdata/cca-token-01.cbor`
- Trust Anchor Store: `testdata/ta.json`
- Reference Value Store: `testdata/rv.json`

**Expected Outcome**: The token should be successfully decoded, verified, and appraised with both trust vectors indicating `TRUSTWORTHY_INSTANCE`.

```rust
// Test code example
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

// Verify the token
let ta_json = include_str!("../../testdata/ta.json");
let mut tas = MemoTrustAnchorStore::new();
tas.load_json(ta_json).unwrap();
evidence.verify(&tas).unwrap();

// Appraise the token
let rv_json = include_str!("../../testdata/rv.json");
let mut rvs = MemoRefValueStore::new();
rvs.load_json(rv_json).unwrap();
evidence.appraise(&rvs).unwrap();

// Check final trust vectors
assert_eq!(evidence.platform_tvec.instance_identity, TRUSTWORTHY_INSTANCE);
assert_eq!(evidence.realm_tvec.instance_identity, TRUSTWORTHY_INSTANCE);
```

### 4.2 Golden Value Extraction

**Description**: Verify the extraction of golden values from a valid token.

**Test Vectors**:
- Token: `testdata/cca-token-01.cbor`
- CPAK: `testdata/cpak.json`

**Expected Outcome**: Reference values and trust anchors should be successfully extracted from the token.

```rust
// Similar to the golden() function in main.rs
let token = include_bytes!("../../testdata/cca-token-01.cbor");
let mut evidence = Evidence::decode(token.as_slice()).unwrap();

let cpak_json = include_str!("../../testdata/cpak.json");
let cpak = map_str_to_cpak(&evidence.platform_claims, cpak_json).unwrap();

evidence.verify_with_cpak(cpak).unwrap();

// Extract reference values and trust anchors
let rv_json = map_evidence_to_refval(&evidence).unwrap();
let ta_json = map_evidence_to_trustanchor(&evidence.platform_claims, cpak_json).unwrap();

// The extracted values should be valid JSON
assert!(serde_json::from_str::<serde_json::Value>(&rv_json).is_ok());
assert!(serde_json::from_str::<serde_json::Value>(&ta_json).is_ok());
```

## 5. Implementation Plan

### 5.1 Existing Tests

Many of the tests defined in this plan are already implemented in the codebase, particularly in `src/token/evidence.rs`, `src/token/realm.rs`, and `src/token/platform.rs`. These should be reviewed and updated to ensure they align with this test plan.

### 5.2 Additional Tests Needed

The following tests should be added to complete the test coverage:

1. More comprehensive malformed token tests
2. Reference value mismatch tests for both platform and realm
3. Specific tests for handling unknown reference values
4. Additional binding verification tests
5. More comprehensive end-to-end tests

### 5.3 Test Data Organization

Test data should be organized in the `testdata` directory with clear naming conventions:

- `cca-token-*.cbor`: Complete token collections
- `platform-claims-*.cbor`: Platform-specific test vectors
- `realm-claims-*.cbor`: Realm-specific test vectors
- `ta-*.json`: Trust anchor store test data
- `rv-*.json`: Reference value store test data

Each test file should have a corresponding `.diag` file with a human-readable representation of the binary CBOR data.

### 5.4 Test Automation

All tests should be automated as part of the crate's test suite, runnable with `cargo test`. Integration tests that require command-line interaction should be implemented as separate tests that can be run with a specific feature flag.