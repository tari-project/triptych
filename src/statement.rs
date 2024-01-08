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
    /// Generate a new input set from a slice `M` of verification keys.
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

    /// Get the verification keys for this input set.
    pub fn get_keys(&self) -> &[RistrettoPoint] {
        &self.M
    }

    /// Get a cryptographic hash representation of this input set, suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}

/// A Triptych proof statement.
///
/// The statement consists of an input set of verification keys, a linking tag, and an optional message.
/// If provided, the message is bound to any proof generated using the statement.
/// It also contains parameters that, among other things, enforce the size of the input set.
#[allow(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct Statement {
    params: Arc<Parameters>,
    input_set: Arc<InputSet>,
    J: RistrettoPoint,
    message: Option<Vec<u8>>,
}

/// Errors that can arise relating to `Statement`.
#[derive(Debug, Snafu)]
pub enum StatementError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl Statement {
    /// Generate a new Triptych proof statement.
    ///
    /// The input set `input_set` must have a verification key vector whose size matches that specified by the
    /// parameters `params`, and which does not contain the identity group element.
    /// If either of these conditions is not met, returns an error.
    ///
    /// If provided, the optional `message` will be bound to any proof generated using the resulting statement.
    /// The linking tag `J` is assumed to have been computed from witness data or otherwise provided externally.
    #[allow(non_snake_case)]
    pub fn new(
        params: &Arc<Parameters>,
        input_set: &Arc<InputSet>,
        J: &RistrettoPoint,
        message: Option<&[u8]>,
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
            message: message.map(|m| m.to_vec()),
        })
    }

    /// Get the parameters for this statement.
    pub fn get_params(&self) -> &Arc<Parameters> {
        &self.params
    }

    /// Get the input set for this statement.
    pub fn get_input_set(&self) -> &Arc<InputSet> {
        &self.input_set
    }

    /// Get the linking tag for this statement.
    #[allow(non_snake_case)]
    pub fn get_J(&self) -> &RistrettoPoint {
        &self.J
    }

    /// Get the message for this statement
    pub fn get_message(&self) -> Option<&[u8]> {
        match &self.message {
            Some(message) => Some(message.as_slice()),
            None => None,
        }
    }
}
