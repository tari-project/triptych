// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng,
    RngCore,
};
use zeroize::Zeroize;

/// A null random number generator that exists only for deterministic transcript-based weight generation.
/// It only produces zero.
/// This is DANGEROUS in general, and you almost certainly should not use it elsewhere!
pub(crate) struct NullRng;

impl RngCore for NullRng {
    #[allow(unused_variables)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.zeroize();
    }

    #[allow(unused_variables)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);

        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }
}

// This isn't really cryptographically secure!
// We only do this so `NullRng` can be used with `TranscriptRng` due to a trait bound.
impl CryptoRng for NullRng {}

#[cfg(test)]
mod test {
    use rand_core::RngCore;

    use super::NullRng;

    #[test]
    fn test_null_rng() {
        // Ensure that the null RNG supplies only zero
        let mut rng = NullRng;

        assert_eq!(rng.next_u32(), 0);
        assert_eq!(rng.next_u64(), 0);

        // Ensure that buffers are filled with only zero
        const BUFFER_SIZE: usize = 128;

        let mut buffer = [1u8; BUFFER_SIZE]; // start with nonzero
        rng.fill_bytes(&mut buffer);
        assert_eq!(buffer, [0u8; BUFFER_SIZE]);

        let mut buffer = [1u8; BUFFER_SIZE]; // start with nonzero
        rng.try_fill_bytes(&mut buffer).unwrap();
        assert_eq!(buffer, [0u8; BUFFER_SIZE]);
    }
}
