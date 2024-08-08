// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{sync::Arc, vec, vec::Vec};

use curve25519_dalek::{traits::Identity, RistrettoPoint};
use snafu::prelude::*;

use crate::{Transcript, TriptychParameters, TRANSCRIPT_HASH_BYTES};

/// A Triptych input set.
///
/// An input set is constructed from a vector of verification keys.
/// Internally, it also contains cryptographic hash data to make proofs more efficient.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriptychInputSet {
    M: Arc<Vec<RistrettoPoint>>,
    hash: Vec<u8>,
}

impl TriptychInputSet {
    // Domain separator used for hashing
    const DOMAIN: &'static str = "Triptych input set";
    // Version identifier used for hashing
    const VERSION: u64 = 0;

    /// Generate a new [`TriptychInputSet`] from a slice `M` of verification keys.
    #[allow(non_snake_case)]
    pub fn new(M: &[RistrettoPoint]) -> Result<Self, StatementError> {
        Self::new_internal(M, M.len())
    }

    /// Generate a new padded [`TriptychInputSet`] from a slice `M` of verification keys and [`TriptychParameters`]
    /// `params`.
    ///
    /// If the verification key vector is shorter than specified by `params`, it will be padded by repeating the last
    /// element. If your use case cannot safely allow this, use [`TriptychInputSet::new`] instead.
    ///
    /// If the verification key vector is empty or longer than specified by `params`, returns a [`StatementError`].
    #[allow(non_snake_case)]
    pub fn new_with_padding(M: &[RistrettoPoint], params: &TriptychParameters) -> Result<Self, StatementError> {
        // Get the unpadded size
        let unpadded_size = M.len();

        // We cannot have the vector be too long
        if unpadded_size > params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }

        // Get the last element, which also ensures the vector is nonempty
        let last = M.last().ok_or(StatementError::InvalidParameter)?;

        // Pad the vector with the last element
        let mut M_padded = M.to_vec();
        M_padded.resize(params.get_N() as usize, *last);

        Self::new_internal(&M_padded, unpadded_size)
    }

    // Helper function to do the actual generation
    #[allow(non_snake_case)]
    fn new_internal(M: &[RistrettoPoint], unpadded_size: usize) -> Result<Self, StatementError> {
        // Ensure the verification key vector length doesn't overflow
        let unpadded_size = u32::try_from(unpadded_size).map_err(|_| StatementError::InvalidParameter)?;

        // Use Merlin for the transcript hash
        let mut transcript = Transcript::new(Self::DOMAIN.as_bytes());
        transcript.append_u64(b"version", Self::VERSION);
        transcript.append_message(b"unpadded_size", &unpadded_size.to_le_bytes());
        for item in M {
            transcript.append_message(b"M", item.compress().as_bytes());
        }
        let mut hash = vec![0u8; TRANSCRIPT_HASH_BYTES];
        transcript.challenge_bytes(b"hash", &mut hash);

        Ok(Self {
            M: Arc::new(M.to_vec()),
            hash,
        })
    }

    /// Get the verification keys for this [`TriptychInputSet`].
    pub fn get_keys(&self) -> &[RistrettoPoint] {
        &self.M
    }

    /// Get a cryptographic hash representation of this [`TriptychInputSet`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

/// A Triptych proof statement.
///
/// The statement consists of an [`TriptychInputSet`] of verification keys and a linking tag.
/// It also contains [`TriptychParameters`] that, among other things, enforce the size of the [`TriptychInputSet`].
#[allow(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct TriptychStatement {
    params: Arc<TriptychParameters>,
    input_set: TriptychInputSet,
    J: RistrettoPoint,
    hash: Vec<u8>,
}

/// Errors that can arise relating to [`TriptychStatement`].
#[derive(Debug, Snafu)]
pub enum StatementError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl TriptychStatement {
    // Domain separator used for hashing
    const DOMAIN: &'static str = "Triptych statement";
    // Version identifier used for hashing
    const VERSION: u64 = 0;

    /// Generate a new [`TriptychStatement`].
    ///
    /// The [`TriptychInputSet`] `input_set` must have a verification key vector whose size matches that specified by
    /// the [`TriptychParameters`] `params`, and which does not contain the identity group element.
    /// If either of these conditions is not met, returns a [`StatementError`].
    ///
    /// The linking tag `J` is assumed to have been computed from
    /// [`TriptychWitness::compute_linking_tag`](`crate::witness::TriptychWitness::compute_linking_tag`) data or
    /// otherwise provided externally.
    #[allow(non_snake_case)]
    pub fn new(
        params: &Arc<TriptychParameters>,
        input_set: &TriptychInputSet,
        J: &RistrettoPoint,
    ) -> Result<Self, StatementError> {
        // Check that the input vector is valid against the parameters
        if input_set.get_keys().len() != params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }
        if input_set.get_keys().contains(&RistrettoPoint::identity()) {
            return Err(StatementError::InvalidParameter);
        }

        // Use Merlin for the transcript hash
        let mut transcript = Transcript::new(Self::DOMAIN.as_bytes());
        transcript.append_u64(b"version", Self::VERSION);
        transcript.append_message(b"params", params.get_hash());
        transcript.append_message(b"input_set", input_set.get_hash());
        transcript.append_message(b"J", J.compress().as_bytes());
        let mut hash = vec![0u8; TRANSCRIPT_HASH_BYTES];
        transcript.challenge_bytes(b"hash", &mut hash);

        Ok(Self {
            params: params.clone(),
            input_set: input_set.clone(),
            J: *J,
            hash,
        })
    }

    /// Get the parameters for this [`TriptychStatement`].
    pub fn get_params(&self) -> &Arc<TriptychParameters> {
        &self.params
    }

    /// Get the input set for this [`TriptychStatement`].
    pub fn get_input_set(&self) -> &TriptychInputSet {
        &self.input_set
    }

    /// Get the linking tag for this [`TriptychStatement`].
    #[allow(non_snake_case)]
    pub fn get_J(&self) -> &RistrettoPoint {
        &self.J
    }

    /// Get a cryptographic hash representation of this [`TriptychStatement`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

#[cfg(test)]
mod test {
    use alloc::{borrow::ToOwned, vec::Vec};

    use curve25519_dalek::RistrettoPoint;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::{TriptychInputSet, TriptychParameters};

    // Helper function to generate random vectors
    fn random_vector(size: usize) -> Vec<RistrettoPoint> {
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);

        (0..size)
            .map(|_| RistrettoPoint::random(&mut rng))
            .collect::<Vec<RistrettoPoint>>()
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_padding() {
        // Generate parameters
        let params = TriptychParameters::new(2, 4).unwrap();
        let N = params.get_N() as usize;

        // Vector is empty
        assert!(TriptychInputSet::new_with_padding(&[], &params).is_err());

        // Vector is too long
        let M = random_vector(N + 1);
        assert!(TriptychInputSet::new_with_padding(&M, &params).is_err());

        // Vector is the right size
        let M = random_vector(N);
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &params).unwrap(),
            TriptychInputSet::new(&M).unwrap()
        );

        // Vector is padded
        let M = random_vector(N - 1);
        let mut M_padded = M.clone();
        M_padded.push(M.last().unwrap().to_owned());
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &params).unwrap().get_keys(),
            TriptychInputSet::new(&M_padded).unwrap().get_keys()
        );
        assert_ne!(
            TriptychInputSet::new_with_padding(&M, &params).unwrap().get_hash(),
            TriptychInputSet::new(&M_padded).unwrap().get_hash()
        )
    }
}
