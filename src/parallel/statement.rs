// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{sync::Arc, vec::Vec};

use blake3::Hasher;
use curve25519_dalek::{traits::Identity, RistrettoPoint};
use snafu::prelude::*;

use crate::parallel::TriptychParameters;

/// A Triptych input set.
///
/// An input set is constructed from a vector of verification keys and vector of auxiliary verification keys.
/// Internally, it also contains cryptographic hash data to make proofs more efficient.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriptychInputSet {
    M: Vec<RistrettoPoint>,
    M1: Vec<RistrettoPoint>,
    hash: Vec<u8>,
}

impl TriptychInputSet {
    // Version identifier used for hashing
    const VERSION: u64 = 0;

    /// Generate a new [`TriptychInputSet`] from a slice `M` of verification keys and slice `M1` of auxiliary
    /// verification keys.
    #[allow(non_snake_case)]
    pub fn new(M: &[RistrettoPoint], M1: &[RistrettoPoint]) -> Self {
        // Use `BLAKE3` for the transcript hash
        let mut hasher = Hasher::new();
        hasher.update(b"Parallel Triptych InputSet");
        hasher.update(&Self::VERSION.to_le_bytes());
        for item in M {
            hasher.update(item.compress().as_bytes());
        }
        for item in M1 {
            hasher.update(item.compress().as_bytes());
        }

        Self {
            M: M.to_vec(),
            M1: M1.to_vec(),
            hash: hasher.finalize().as_bytes().to_vec(),
        }
    }

    /// Generate a new padded [`TriptychInputSet`] from a slice `M` of verification keys, a slice `M1` of auxiliary
    /// verification keys, and [`TriptychParameters`] `params`.
    ///
    /// If either the verification key vector or auxiliary verification key vector are shorter than specified by
    /// `params`, they will be padded by repeating the corresponding last element. If your use case cannot safely
    /// allow this, use [`TriptychInputSet::new`] instead.
    ///
    /// If the verification key vector or auxiliary verification key vector are empty or longer than specified by
    /// `params`, returns a [`StatementError`].
    #[allow(non_snake_case)]
    pub fn new_with_padding(
        M: &[RistrettoPoint],
        M1: &[RistrettoPoint],
        params: &TriptychParameters,
    ) -> Result<Self, StatementError> {
        // The vectors must be the same length
        if M.len() != M1.len() {
            return Err(StatementError::InvalidParameter);
        }

        // We cannot have the vectors be too long
        if M.len() > params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }

        // Get the last elements, which also ensures the vectors are nonempty
        let last = M.last().ok_or(StatementError::InvalidParameter)?;
        let last1 = M1.last().ok_or(StatementError::InvalidParameter)?;

        // Pad the vectors with the corresponding last elements
        let mut M_padded = M.to_vec();
        M_padded.resize(params.get_N() as usize, *last);
        let mut M1_padded = M1.to_vec();
        M1_padded.resize(params.get_N() as usize, *last1);

        Ok(Self::new(&M_padded, &M1_padded))
    }

    /// Get the verification keys for this [`TriptychInputSet`].
    pub fn get_keys(&self) -> &[RistrettoPoint] {
        &self.M
    }

    /// Get the auxiliary verification keys for this [`TriptychInputSet`].
    pub fn get_auxiliary_keys(&self) -> &[RistrettoPoint] {
        &self.M1
    }

    /// Get a cryptographic hash representation of this [`TriptychInputSet`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

/// A Triptych proof statement.
///
/// The statement consists of an [`TriptychInputSet`] of verification and auxiliary verification keys, an offset, and a
/// linking tag. It also contains [`TriptychParameters`] that, among other things, enforce the size of the
/// [`TriptychInputSet`].
#[allow(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct TriptychStatement {
    params: Arc<TriptychParameters>,
    input_set: Arc<TriptychInputSet>,
    offset: RistrettoPoint,
    J: RistrettoPoint,
}

/// Errors that can arise relating to [`TriptychStatement`].
#[derive(Debug, Snafu)]
pub enum StatementError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl TriptychStatement {
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
        input_set: &Arc<TriptychInputSet>,
        offset: &RistrettoPoint,
        J: &RistrettoPoint,
    ) -> Result<Self, StatementError> {
        // Check that the input vectors are valid against the parameters
        if input_set.get_keys().len() != params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }
        if input_set.get_keys().contains(&RistrettoPoint::identity()) {
            return Err(StatementError::InvalidParameter);
        }
        if input_set
            .get_auxiliary_keys()
            .iter()
            .map(|p| p - offset)
            .collect::<Vec<RistrettoPoint>>()
            .contains(&RistrettoPoint::identity())
        {
            return Err(StatementError::InvalidParameter);
        }

        Ok(Self {
            params: params.clone(),
            input_set: input_set.clone(),
            offset: *offset,
            J: *J,
        })
    }

    /// Get the parameters for this [`TriptychStatement`].
    pub fn get_params(&self) -> &Arc<TriptychParameters> {
        &self.params
    }

    /// Get the input set for this [`TriptychStatement`].
    pub fn get_input_set(&self) -> &Arc<TriptychInputSet> {
        &self.input_set
    }

    /// Get the offset for this [`TriptychStatement`].
    pub fn get_offset(&self) -> &RistrettoPoint {
        &self.offset
    }

    /// Get the linking tag for this [`TriptychStatement`].
    #[allow(non_snake_case)]
    pub fn get_J(&self) -> &RistrettoPoint {
        &self.J
    }
}

#[cfg(test)]
mod test {
    use alloc::{borrow::ToOwned, vec::Vec};

    use curve25519_dalek::RistrettoPoint;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;

    use crate::parallel::{TriptychInputSet, TriptychParameters};

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

        // Vectors are empty
        assert!(TriptychInputSet::new_with_padding(&[], &[], &params).is_err());

        // Vectors are too long
        let M = random_vector(N + 1);
        let M1 = random_vector(N + 1);
        assert!(TriptychInputSet::new_with_padding(&M, &M1, &params).is_err());

        // Vectors are the right size
        let M = random_vector(N);
        let M1 = random_vector(N);
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &M1, &params).unwrap(),
            TriptychInputSet::new(&M, &M1)
        );

        // Vectors are padded
        let M = random_vector(N - 1);
        let mut M_padded = M.clone();
        M_padded.push(M.last().unwrap().to_owned());
        let M1 = random_vector(N - 1);
        let mut M1_padded = M1.clone();
        M1_padded.push(M1.last().unwrap().to_owned());
        assert_eq!(
            TriptychInputSet::new_with_padding(&M, &M1, &params).unwrap(),
            TriptychInputSet::new(&M_padded, &M1_padded)
        );
    }
}