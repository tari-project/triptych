// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{sync::Arc, vec::Vec};

use blake3::Hasher;
use curve25519_dalek::{traits::Identity, RistrettoPoint};
use snafu::prelude::*;

use crate::parameters::Parameters;

/// A Triptych input set.
///
/// An input set is constructed from a vector of verification keys.
/// Internally, it also contains cryptographic hash data to make proofs more efficient.
#[allow(non_snake_case)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputSet {
    M: Vec<RistrettoPoint>,
    hash: Vec<u8>,
}

impl InputSet {
    // Version identifier used for hashing
    const VERSION: u64 = 0;

    /// Generate a new [`InputSet`] from a slice `M` of verification keys.
    #[allow(non_snake_case)]
    pub fn new(M: &[RistrettoPoint]) -> Self {
        // Use `BLAKE3` for the transcript hash
        let mut hasher = Hasher::new();
        hasher.update("Triptych InputSet".as_bytes());
        hasher.update(&Self::VERSION.to_le_bytes());
        for item in M {
            hasher.update(item.compress().as_bytes());
        }

        Self {
            M: M.to_vec(),
            hash: hasher.finalize().as_bytes().to_vec(),
        }
    }

    /// Generate a new padded [`InputSet`] from a slice `M` of verification keys and [`Parameters`] `params`.
    ///
    /// If the verification key vector is shorter than specified by `params`, it will be padded by repeating the last
    /// element. If your use case cannot safely allow this, use [`InputSet::new`] instead.
    ///
    /// If the verification key vector is empty or longer than specified by `params`, returns a [`StatementError`].
    #[allow(non_snake_case)]
    pub fn new_with_padding(M: &[RistrettoPoint], params: &Parameters) -> Result<Self, StatementError> {
        // We cannot have the vector be too long
        if M.len() > params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }

        // Get the last element, which also ensures the vector is nonempty
        let last = M.last().ok_or(StatementError::InvalidParameter)?;

        // Pad the vector with the last element
        let mut M_padded = M.to_vec();
        M_padded.resize(params.get_N() as usize, *last);
        Ok(Self::new(&M_padded))
    }

    /// Get the verification keys for this [`InputSet`].
    pub fn get_keys(&self) -> &[RistrettoPoint] {
        &self.M
    }

    /// Get a cryptographic hash representation of this [`InputSet`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

/// A Triptych proof statement.
///
/// The statement consists of an [`InputSet`] of verification keys and a linking tag.
/// It also contains [`Parameters`] that, among other things, enforce the size of the [`InputSet`].
#[allow(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct Statement {
    params: Arc<Parameters>,
    input_set: Arc<InputSet>,
    J: RistrettoPoint,
}

/// Errors that can arise relating to [`Statement`].
#[derive(Debug, Snafu)]
pub enum StatementError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl Statement {
    /// Generate a new [`Statement`].
    ///
    /// The [`InputSet`] `input_set` must have a verification key vector whose size matches that specified by the
    /// [`Parameters`] `params`, and which does not contain the identity group element.
    /// If either of these conditions is not met, returns a [`StatementError`].
    ///
    /// The linking tag `J` is assumed to have been computed from
    /// [`Witness::compute_linking_tag`](`crate::witness::Witness::compute_linking_tag`) data or otherwise provided
    /// externally.
    #[allow(non_snake_case)]
    pub fn new(
        params: &Arc<Parameters>,
        input_set: &Arc<InputSet>,
        J: &RistrettoPoint,
    ) -> Result<Self, StatementError> {
        // Check that the input vector is valid against the parameters
        if input_set.get_keys().len() != params.get_N() as usize {
            return Err(StatementError::InvalidParameter);
        }
        if input_set.get_keys().contains(&RistrettoPoint::identity()) {
            return Err(StatementError::InvalidParameter);
        }

        Ok(Self {
            params: params.clone(),
            input_set: input_set.clone(),
            J: *J,
        })
    }

    /// Get the parameters for this [`Statement`].
    pub fn get_params(&self) -> &Arc<Parameters> {
        &self.params
    }

    /// Get the input set for this [`Statement`].
    pub fn get_input_set(&self) -> &Arc<InputSet> {
        &self.input_set
    }

    /// Get the linking tag for this [`Statement`].
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

    use crate::{parameters::Parameters, statement::InputSet};

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
        let params = Parameters::new(2, 4).unwrap();
        let N = params.get_N() as usize;

        // Vector is empty
        assert!(InputSet::new_with_padding(&[], &params).is_err());

        // Vector is too long
        let M = random_vector(N + 1);
        assert!(InputSet::new_with_padding(&M, &params).is_err());

        // Vector is the right size
        let M = random_vector(N);
        assert_eq!(InputSet::new_with_padding(&M, &params).unwrap(), InputSet::new(&M));

        // Vector is padded
        let M = random_vector(N - 1);
        let mut M_padded = M.clone();
        M_padded.push(M.last().unwrap().to_owned());
        assert_eq!(
            InputSet::new_with_padding(&M, &params).unwrap(),
            InputSet::new(&M_padded)
        );
    }
}
