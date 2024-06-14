// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::vec::Vec;
use core::iter::once;

use blake3::Hasher;
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    traits::{MultiscalarMul, VartimeMultiscalarMul},
    RistrettoPoint,
    Scalar,
};
use snafu::prelude::*;

use crate::util::OperationTiming;

/// Public parameters used for generating and verifying Triptych proofs.
///
/// Parameters require a base and exponent that define the size of verification key vectors, as well as group generators
/// `G`, `H`, and `U` required by the protocol. You can either use [`TriptychParameters::new`] to have these generators
/// defined securely for you, or use [`TriptychParameters::new_with_generators`] if your use case requires specific
/// values for these.
#[allow(non_snake_case)]
#[derive(Clone, Eq, PartialEq)]
pub struct TriptychParameters {
    n: u32,
    m: u32,
    G: RistrettoPoint,
    H: RistrettoPoint,
    U: RistrettoPoint,
    CommitmentG: Vec<RistrettoPoint>,
    CommitmentH: RistrettoPoint,
    hash: Vec<u8>,
}

/// Errors that can arise relating to [`TriptychParameters`].
#[derive(Debug, Snafu)]
pub enum ParameterError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl TriptychParameters {
    // Version identifier used for hashing
    const VERSION: u64 = 0;

    /// Generate new [`TriptychParameters`] for Triptych proofs.
    ///
    /// The base `n > 1` and exponent `m > 1` define the size of verification key vectors, so it must be the case that
    /// `n**m` does not overflow [`prim@u32`]. If any of these conditions is not met, returns a [`ParameterError`].
    ///
    /// This function produces group generators `G`, `H` and `U` for you.
    /// If your use case requires specific generators, use [`TriptychParameters::new_with_generators`] instead.
    #[allow(non_snake_case)]
    pub fn new(n: u32, m: u32) -> Result<Self, ParameterError> {
        // Use the default base point for `G` (this is arbitrary)
        let G = RISTRETTO_BASEPOINT_POINT;

        // Use `BLAKE3` to generate `H`
        let mut H_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(b"Triptych H");
        hasher.finalize_xof().fill(&mut H_bytes);
        let H = RistrettoPoint::from_uniform_bytes(&H_bytes);

        // Use `BLAKE3` to generate `U`
        let mut U_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(b"Triptych U");
        hasher.finalize_xof().fill(&mut U_bytes);
        let U = RistrettoPoint::from_uniform_bytes(&U_bytes);

        Self::new_with_generators(n, m, &G, &H, &U)
    }

    /// Generate new [`TriptychParameters`] for Triptych proofs.
    ///
    /// The base `n > 1` and exponent `m > 1` define the size of verification key vectors, so it must be the case that
    /// `n**m` does not overflow [`prim@u32`]. If any of these conditions is not met, returns a [`ParameterError`].
    ///
    /// You must also provide independent group generators `G`, `H` and `U`:
    /// - The generator `G` is used to define verification keys.
    /// - The generator `H` is used to define auxiliary verification keys.
    /// - The generator `U` is used to define linking tags.
    ///
    /// The security of these generators cannot be checked by this function.
    /// If you'd rather have the generators securely defined for you, use [`TriptychParameters::new`] instead.
    #[allow(non_snake_case)]
    pub fn new_with_generators(
        n: u32,
        m: u32,
        G: &RistrettoPoint,
        H: &RistrettoPoint,
        U: &RistrettoPoint,
    ) -> Result<Self, ParameterError> {
        // These bounds are required by the protocol
        if n < 2 || m < 2 {
            return Err(ParameterError::InvalidParameter);
        }

        // Check that the parameters don't overflow `u32`
        if n.checked_pow(m).is_none() {
            return Err(ParameterError::InvalidParameter);
        }

        // Use `BLAKE3` to generate `CommitmentH`
        let mut CommitmentH_bytes = [0u8; 64];
        let mut hasher = Hasher::new();
        hasher.update(b"Triptych CommitmentH");
        hasher.finalize_xof().fill(&mut CommitmentH_bytes);
        let CommitmentH = RistrettoPoint::from_uniform_bytes(&CommitmentH_bytes);

        // Use `BLAKE3` for the commitment matrix generators
        let mut hasher = Hasher::new();
        hasher.update(b"Triptych CommitmentG");
        hasher.update(&n.to_le_bytes());
        hasher.update(&m.to_le_bytes());
        let mut hasher_xof = hasher.finalize_xof();
        let mut CommitmentG_bytes = [0u8; 64];
        let CommitmentG = (0..n.checked_mul(m).ok_or(ParameterError::InvalidParameter)?)
            .map(|_| {
                hasher_xof.fill(&mut CommitmentG_bytes);
                RistrettoPoint::from_uniform_bytes(&CommitmentG_bytes)
            })
            .collect::<Vec<RistrettoPoint>>();

        // Use `BLAKE3` for the transcript hash
        let mut hasher = Hasher::new();
        hasher.update(b"Parallel Triptych Parameters");
        hasher.update(&Self::VERSION.to_le_bytes());
        hasher.update(&n.to_le_bytes());
        hasher.update(&m.to_le_bytes());
        hasher.update(G.compress().as_bytes());
        hasher.update(H.compress().as_bytes());
        hasher.update(U.compress().as_bytes());
        for item in &CommitmentG {
            hasher.update(item.compress().as_bytes());
        }
        hasher.update(CommitmentH.compress().as_bytes());

        Ok(TriptychParameters {
            n,
            m,
            G: *G,
            H: *H,
            U: *U,
            CommitmentG,
            CommitmentH,
            hash: hasher.finalize().as_bytes().to_vec(),
        })
    }

    /// Commit to a matrix.
    ///
    /// This requires that `matrix` be an `m x n` scalar matrix.
    /// You can decide if you want to use variable-time operations via the `vartime` flag.
    pub(crate) fn commit_matrix(
        &self,
        matrix: &[Vec<Scalar>],
        mask: &Scalar,
        timing: OperationTiming,
    ) -> Result<RistrettoPoint, ParameterError> {
        // Check that the matrix dimensions are valid
        if matrix.len() != (self.m as usize) || matrix.iter().any(|m| m.len() != (self.n as usize)) {
            return Err(ParameterError::InvalidParameter);
        }

        // Flatten before evaluating the commitment
        let scalars = matrix.iter().flatten().chain(once(mask)).collect::<Vec<&Scalar>>();
        let points = self.get_CommitmentG().iter().chain(once(self.get_CommitmentH()));

        match timing {
            OperationTiming::Constant => Ok(RistrettoPoint::multiscalar_mul(scalars, points)),
            OperationTiming::Variable => Ok(RistrettoPoint::vartime_multiscalar_mul(scalars, points)),
        }
    }

    /// Get the group generator `G` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining verification keys.
    #[allow(non_snake_case)]
    pub fn get_G(&self) -> &RistrettoPoint {
        &self.G
    }

    /// Get the group generator `H` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining auxiliary verification keys.
    #[allow(non_snake_case)]
    pub fn get_H(&self) -> &RistrettoPoint {
        &self.H
    }

    /// Get the group generator `U` from these [`TriptychParameters`].
    ///
    /// This is the generator used for defining linking tags.
    #[allow(non_snake_case)]
    pub fn get_U(&self) -> &RistrettoPoint {
        &self.U
    }

    /// Get the value `n` from these [`TriptychParameters`].
    ///
    /// This is the base used for defining the verification key vector size.
    pub fn get_n(&self) -> u32 {
        self.n
    }

    /// Get the value `m` from these [`TriptychParameters`].
    ///
    /// This is the exponent used for defining the verification key vector size.
    pub fn get_m(&self) -> u32 {
        self.m
    }

    /// Get the value `N == n**m` from these [`TriptychParameters`].
    ///
    /// This is the verification key vector size.
    #[allow(non_snake_case)]
    pub fn get_N(&self) -> u32 {
        // This is guaranteed not to overflow
        self.n.pow(self.m)
    }

    /// Get the value `CommitmentG` from these [`TriptychParameters`].
    #[allow(non_snake_case)]
    pub(crate) fn get_CommitmentG(&self) -> &Vec<RistrettoPoint> {
        &self.CommitmentG
    }

    /// Get the value `CommitmentH` from these [`TriptychParameters`].
    #[allow(non_snake_case)]
    pub(crate) fn get_CommitmentH(&self) -> &RistrettoPoint {
        &self.CommitmentH
    }

    /// Get a cryptographic hash representation of these [`TriptychParameters`], suitable for transcripting.
    pub(crate) fn get_hash(&self) -> &[u8] {
        &self.hash
    }
}
