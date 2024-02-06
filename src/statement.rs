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
#[derive(Clone, Eq, PartialEq)]
pub struct InputSet {
    M: Vec<RistrettoPoint>,
    hash: Vec<u8>,
}

impl InputSet {
    /// Generate a new [`InputSet`] from a slice `M` of verification keys.
    #[allow(non_snake_case)]
    pub fn new(M: &[RistrettoPoint]) -> Self {
        // Use `BLAKE3` for the transcript hash
        let mut hasher = Hasher::new();
        hasher.update("Triptych InputSet".as_bytes());
        for item in M {
            hasher.update(item.compress().as_bytes());
        }

        Self {
            M: M.to_vec(),
            hash: hasher.finalize().as_bytes().to_vec(),
        }
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
