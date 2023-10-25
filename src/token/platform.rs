// Copyright 2023 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#[derive(Debug)]
pub struct SWComponent {
    mtyp: Option<String>,         // 1, text
    mval: Vec<u8>,                // 2, bytes .size {32,48,64}
    version: Option<String>,      // 4, text
    signer_id: Vec<u8>,           // 5, bytes .size {32,48,64}
    hash_algo_id: Option<String>, // 6, text
}

#[derive(Debug)]
pub struct Platform {
    profile: String,                      // 265, text ("http://arm.com/CCA-SSD/1.0.0")
    challenge: Vec<u8>,                   // 10, bytes .size {32,48,64}
    impl_id: [u8; 32],                    // 2396, bytes .size 32
    inst_id: [u8; 33],                    // 256, bytes .size 33
    config: Vec<u8>,                      // 2401, bytes
    lifecycle: u16,                       // 2395, 0x0000..0x00ff ... 0x6000..0x60ff
    sw_components: Vec<SWComponent>,      // 2399, cca-platform-sw-component
    verification_service: Option<String>, // 2400, text
    hash_alg: String,                     // 2402, text
}
