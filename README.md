# rust-ccatoken

`rust-ccatoken` is an implementation of the Arm CCA attestation token (§A.7 of the [Realm Management Monitor (RMM) Specification](https://developer.arm.com/documentation/den0137/latest)) in Rust.


The library implements interfaces to:

* Decode a CBOR-encoded CCA token
* Verify the CCA token (Platform, Realm and their binding)
* Appraise CCA evidence using user-supplied reference values and endorsements
