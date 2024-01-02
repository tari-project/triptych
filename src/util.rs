use rand_core::{
    impls::{next_u32_via_fill, next_u64_via_fill},
    CryptoRng,
    RngCore,
};

/// A "null" random number generator that exists only for deterministic transcript-based weight generation.
/// This is DANGEROUS in general, and you almost certainly should not use it elsewhere!
pub(crate) struct DangerousRng;

impl RngCore for DangerousRng {
    #[allow(unused_variables)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {}

    #[allow(unused_variables)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(())
    }

    fn next_u32(&mut self) -> u32 {
        next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        next_u64_via_fill(self)
    }
}

impl CryptoRng for DangerousRng {}
