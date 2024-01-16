// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause


#![no_main]

use libfuzzer_sys::fuzz_target;
use triptych::proof::Proof;

// Test basic deserialization and canonical serialization
fuzz_target!(|data: &[u8]| {
	// If deserialization succeeds, serialization should be canonical
	if let Ok(proof) = Proof::from_bytes(data) {
		assert_eq!(&proof.to_bytes(), data);
	}
});
