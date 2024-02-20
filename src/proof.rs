// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::{vec, vec::Vec};
use core::{iter::once, slice, slice::ChunksExact};

use curve25519_dalek::{
    ristretto::CompressedRistretto,
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
    RistrettoPoint,
    Scalar,
};
use itertools::izip;
use merlin::Transcript;
use rand_core::CryptoRngCore;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

use crate::{
    gray::GrayIterator,
    statement::Statement,
    transcript::ProofTranscript,
    util::{delta, NullRng, OperationTiming},
    witness::Witness,
};

// Size of serialized proof elements in bytes
const SERIALIZED_BYTES: usize = 32;

/// A Triptych proof.
#[allow(non_snake_case)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    A: RistrettoPoint,
    B: RistrettoPoint,
    C: RistrettoPoint,
    D: RistrettoPoint,
    X: Vec<RistrettoPoint>,
    Y: Vec<RistrettoPoint>,
    f: Vec<Vec<Scalar>>,
    z_A: Scalar,
    z_C: Scalar,
    z: Scalar,
}

/// Errors that can arise relating to [`Proof`].
#[derive(Debug, Snafu)]
pub enum ProofError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
    /// A transcript challenge was invalid.
    #[snafu(display("A transcript challenge was invalid"))]
    InvalidChallenge,
    /// Proof deserialization failed.
    #[snafu(display("Proof deserialization failed"))]
    FailedDeserialization,
    /// Proof verification failed.
    #[snafu[display("Proof verification failed")]]
    FailedVerification,
}

impl Proof {
    /// Generate a Triptych [`Proof`].
    ///
    /// The proof is generated by supplying a [`Witness`] `witness` and corresponding [`Statement`] `statement`.
    /// If the witness and statement do not share the same parameters, or if the statement is invalid for the witness,
    /// returns a [`ProofError`].
    ///
    /// This function provides a cryptographically-secure random number generator for you.
    ///
    /// You must also supply a [`Transcript`] `transcript`.
    ///
    /// This function specifically avoids constant-time operations for efficiency.
    #[cfg(feature = "rand")]
    pub fn prove_vartime(
        witness: &Witness,
        statement: &Statement,
        transcript: &mut Transcript,
    ) -> Result<Self, ProofError> {
        use rand_core::OsRng;

        Self::prove_internal(witness, statement, &mut OsRng, transcript, OperationTiming::Variable)
    }

    /// Generate a Triptych [`Proof`].
    ///
    /// The proof is generated by supplying a [`Witness`] `witness` and corresponding [`Statement`] `statement`.
    /// If the witness and statement do not share the same parameters, or if the statement is invalid for the witness,
    /// returns a [`ProofError`].
    ///
    /// You must also supply a [`CryptoRngCore`] random number generator `rng` and a [`Transcript`] `transcript`.
    ///
    /// This function specifically avoids constant-time operations for efficiency.
    pub fn prove_with_rng_vartime<R: CryptoRngCore>(
        witness: &Witness,
        statement: &Statement,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<Self, ProofError> {
        Self::prove_internal(witness, statement, rng, transcript, OperationTiming::Variable)
    }

    /// Generate a Triptych [`Proof`].
    ///
    /// The proof is generated by supplying a [`Witness`] `witness` and corresponding [`Statement`] `statement`.
    /// If the witness and statement do not share the same parameters, or if the statement is invalid for the witness,
    /// returns a [`ProofError`].
    ///
    /// This function provides a cryptographically-secure random number generator for you.
    ///
    /// You must also supply a [`Transcript`] `transcript`.
    ///
    /// This function makes some attempt at avoiding timing side-channel attacks using constant-time operations.
    #[cfg(feature = "rand")]
    pub fn prove(witness: &Witness, statement: &Statement, transcript: &mut Transcript) -> Result<Self, ProofError> {
        use rand_core::OsRng;

        Self::prove_internal(witness, statement, &mut OsRng, transcript, OperationTiming::Constant)
    }

    /// Generate a Triptych [`Proof`].
    ///
    /// The proof is generated by supplying a [`Witness`] `witness` and corresponding [`Statement`] `statement`.
    /// If the witness and statement do not share the same parameters, or if the statement is invalid for the witness,
    /// returns a [`ProofError`].
    ///
    /// You must also supply a [`CryptoRngCore`] random number generator `rng` and a [`Transcript`] `transcript`.
    ///
    /// This function makes some attempt at avoiding timing side-channel attacks using constant-time operations.
    pub fn prove_with_rng<R: CryptoRngCore>(
        witness: &Witness,
        statement: &Statement,
        rng: &mut R,
        transcript: &mut Transcript,
    ) -> Result<Self, ProofError> {
        Self::prove_internal(witness, statement, rng, transcript, OperationTiming::Constant)
    }

    /// The actual prover functionality.
    #[allow(clippy::too_many_lines, non_snake_case)]
    fn prove_internal<R: CryptoRngCore>(
        witness: &Witness,
        statement: &Statement,
        rng: &mut R,
        transcript: &mut Transcript,
        timing: OperationTiming,
    ) -> Result<Self, ProofError> {
        // Check that the witness and statement have identical parameters
        if witness.get_params() != statement.get_params() {
            return Err(ProofError::InvalidParameter);
        }

        // Extract values for convenience
        let r = witness.get_r();
        let l = witness.get_l();
        let M = statement.get_input_set().get_keys();
        let params = statement.get_params();
        let J = statement.get_J();

        // Check that the witness is valid against the statement, in constant time if needed
        let mut M_l = RistrettoPoint::identity();

        match timing {
            OperationTiming::Constant => {
                for (index, item) in M.iter().enumerate() {
                    M_l.conditional_assign(item, index.ct_eq(&(l as usize)));
                }
            },
            OperationTiming::Variable => {
                M_l = M[l as usize];
            },
        }

        if M_l != r * params.get_G() {
            return Err(ProofError::InvalidParameter);
        }
        if &(r * J) != params.get_U() {
            return Err(ProofError::InvalidParameter);
        }

        // Set up the transcript
        let mut transcript = ProofTranscript::new(transcript, statement, rng, Some(witness));

        // Compute the `A` matrix commitment
        let r_A = Scalar::random(transcript.as_mut_rng());
        let mut a = (0..params.get_m())
            .map(|_| {
                (0..params.get_n())
                    .map(|_| Scalar::random(transcript.as_mut_rng()))
                    .collect::<Vec<Scalar>>()
            })
            .collect::<Vec<Vec<Scalar>>>();
        for j in (0..params.get_m()).map(|j| j as usize) {
            a[j][0] = -a[j][1..].iter().sum::<Scalar>();
        }
        let A = params
            .commit_matrix(&a, &r_A, timing)
            .map_err(|_| ProofError::InvalidParameter)?;

        // Compute the `B` matrix commitment
        let r_B = Scalar::random(transcript.as_mut_rng());
        let l_decomposed = match timing {
            OperationTiming::Constant => {
                GrayIterator::decompose(params.get_n(), params.get_m(), l).ok_or(ProofError::InvalidParameter)?
            },
            OperationTiming::Variable => GrayIterator::decompose_vartime(params.get_n(), params.get_m(), l)
                .ok_or(ProofError::InvalidParameter)?,
        };
        let sigma = (0..params.get_m())
            .map(|j| {
                (0..params.get_n())
                    .map(|i| delta(l_decomposed[j as usize], i))
                    .collect::<Vec<Scalar>>()
            })
            .collect::<Vec<Vec<Scalar>>>();
        let B = params
            .commit_matrix(&sigma, &r_B, timing)
            .map_err(|_| ProofError::InvalidParameter)?;

        // Compute the `C` matrix commitment
        let two = Scalar::from(2u32);
        let r_C = Scalar::random(transcript.as_mut_rng());
        let a_sigma = (0..params.get_m())
            .map(|j| {
                (0..params.get_n())
                    .map(|i| a[j as usize][i as usize] * (Scalar::ONE - two * sigma[j as usize][i as usize]))
                    .collect::<Vec<Scalar>>()
            })
            .collect::<Vec<Vec<Scalar>>>();
        let C = params
            .commit_matrix(&a_sigma, &r_C, timing)
            .map_err(|_| ProofError::InvalidParameter)?;

        // Compute the `D` matrix commitment
        let r_D = Scalar::random(transcript.as_mut_rng());
        let a_square = (0..params.get_m())
            .map(|j| {
                (0..params.get_n())
                    .map(|i| -a[j as usize][i as usize] * a[j as usize][i as usize])
                    .collect::<Vec<Scalar>>()
            })
            .collect::<Vec<Vec<Scalar>>>();
        let D = params
            .commit_matrix(&a_square, &r_D, timing)
            .map_err(|_| ProofError::InvalidParameter)?;

        // Random masks
        let rho = Zeroizing::new(
            (0..params.get_m())
                .map(|_| Scalar::random(transcript.as_mut_rng()))
                .collect::<Vec<Scalar>>(),
        );

        // Compute `p` polynomial vector coefficients using repeated convolution
        let mut p = Vec::<Vec<Scalar>>::with_capacity(params.get_N() as usize);
        let mut k_decomposed = vec![0; params.get_m() as usize];
        for (gray_index, _, gray_new) in
            GrayIterator::new(params.get_n(), params.get_m()).ok_or(ProofError::InvalidParameter)?
        {
            k_decomposed[gray_index] = gray_new;

            // Set the initial coefficients using the first degree-one polynomial (`j = 0`)
            let mut coefficients = Vec::new();
            coefficients.resize(
                (params.get_m() as usize)
                    .checked_add(1)
                    .ok_or(ProofError::InvalidParameter)?,
                Scalar::ZERO,
            );
            coefficients[0] = a[0][k_decomposed[0] as usize];
            coefficients[1] = sigma[0][k_decomposed[0] as usize];

            // Use convolution against each remaining degree-one polynomial
            for j in 1..params.get_m() {
                // For the degree-zero portion, simply multiply each coefficient accordingly
                let degree_0_portion = coefficients
                    .iter()
                    .map(|c| a[j as usize][k_decomposed[j as usize] as usize] * c)
                    .collect::<Vec<Scalar>>();

                // For the degree-one portion, we also need to increase each exponent by one
                // Rotating the coefficients is fine here since the highest is always zero!
                let mut shifted_coefficients = coefficients.clone();
                shifted_coefficients.rotate_right(1);
                let degree_1_portion = shifted_coefficients
                    .iter()
                    .map(|c| sigma[j as usize][k_decomposed[j as usize] as usize] * c)
                    .collect::<Vec<Scalar>>();

                coefficients = degree_0_portion
                    .iter()
                    .zip(degree_1_portion.iter())
                    .map(|(x, y)| x + y)
                    .collect::<Vec<Scalar>>();
            }

            p.push(coefficients);
        }

        // Compute `X` vector
        let X = rho
            .iter()
            .enumerate()
            .map(|(j, rho)| {
                let X_points = M.iter().chain(once(params.get_G()));
                let X_scalars = p.iter().map(|p| &p[j]).chain(once(rho));

                match timing {
                    OperationTiming::Constant => RistrettoPoint::multiscalar_mul(X_scalars, X_points),
                    OperationTiming::Variable => RistrettoPoint::vartime_multiscalar_mul(X_scalars, X_points),
                }
            })
            .collect::<Vec<RistrettoPoint>>();

        // Compute `Y` vector
        let Y = rho.iter().map(|rho| rho * J).collect::<Vec<RistrettoPoint>>();

        // Run the Fiat-Shamir commitment phase to get the challenge powers
        let xi_powers = transcript.commit(params, &A, &B, &C, &D, &X, &Y)?;

        // Compute the `f` matrix
        let f = (0..params.get_m())
            .map(|j| {
                (1..params.get_n())
                    .map(|i| sigma[j as usize][i as usize] * xi_powers[1] + a[j as usize][i as usize])
                    .collect::<Vec<Scalar>>()
            })
            .collect::<Vec<Vec<Scalar>>>();

        // Compute the remaining response values
        let z_A = r_A + xi_powers[1] * r_B;
        let z_C = xi_powers[1] * r_C + r_D;
        let z = r * xi_powers[params.get_m() as usize] -
            rho.iter()
                .zip(xi_powers.iter())
                .map(|(rho, xi_power)| rho * xi_power)
                .sum::<Scalar>();

        Ok(Self {
            A,
            B,
            C,
            D,
            X,
            Y,
            f,
            z_A,
            z_C,
            z,
        })
    }

    /// Verify a Triptych [`Proof`].
    ///
    /// Verification requires that the `statement` and `transcript` match those used when the proof was generated.
    ///
    /// If this requirement is not met, or if the proof is invalid, returns a [`ProofError`].
    pub fn verify(&self, statement: &Statement, transcript: &mut Transcript) -> Result<(), ProofError> {
        // Verify as a trivial batch
        Self::verify_batch(
            slice::from_ref(statement),
            slice::from_ref(self),
            slice::from_mut(transcript),
        )
    }

    /// Verify a batch of Triptych [`Proofs`](`Proof`).
    ///
    /// Verification requires that the `statements` and `transcripts` match those used when the `proofs` were generated,
    /// and that they share a common [`InputSet`](`crate::statement::InputSet`) and
    /// [`Parameters`](`crate::parameters::Parameters`).
    ///
    /// If any of the above requirements are not met, or if the batch is empty, or if any proof is invalid, returns a
    /// [`ProofError`].
    #[allow(clippy::too_many_lines, non_snake_case)]
    pub fn verify_batch(
        statements: &[Statement],
        proofs: &[Proof],
        transcripts: &mut [Transcript],
    ) -> Result<(), ProofError> {
        // Check that we have the same number of statements, proofs, and transcripts
        if statements.len() != proofs.len() {
            return Err(ProofError::InvalidParameter);
        }
        if statements.len() != transcripts.len() {
            return Err(ProofError::InvalidParameter);
        }

        // An empty batch is considered trivially invalid
        let first_statement = statements.first().ok_or(ProofError::InvalidParameter)?;

        // Each statement must use the same input set (checked using the hash for efficiency)
        if !statements
            .iter()
            .map(|s| s.get_input_set().get_hash())
            .all(|h| h == first_statement.get_input_set().get_hash())
        {
            return Err(ProofError::InvalidParameter);
        }

        // Each statement must use the same parameters (checked using the hash for efficiency)
        if !statements
            .iter()
            .map(|s| s.get_params().get_hash())
            .all(|h| h == first_statement.get_params().get_hash())
        {
            return Err(ProofError::InvalidParameter);
        }

        // Extract common values for convenience
        let M = first_statement.get_input_set().get_keys();
        let params = first_statement.get_params();

        // Check that all proof semantics are valid for the statement
        for proof in proofs {
            if proof.X.len() != params.get_m() as usize {
                return Err(ProofError::InvalidParameter);
            }
            if proof.Y.len() != params.get_m() as usize {
                return Err(ProofError::InvalidParameter);
            }
            if proof.f.len() != params.get_m() as usize {
                return Err(ProofError::InvalidParameter);
            }
            for f_row in &proof.f {
                if f_row.len() != params.get_n().checked_sub(1).ok_or(ProofError::InvalidParameter)? as usize {
                    return Err(ProofError::InvalidParameter);
                }
            }
        }

        // Determine the size of the final check vector, which must not overflow `usize`
        let batch_size = u32::try_from(proofs.len()).map_err(|_| ProofError::InvalidParameter)?;

        // This is unlikely to overflow; even if it does, the only effect is unnecessary reallocation
        #[allow(clippy::arithmetic_side_effects)]
        let final_size = usize::try_from(
            1 // G
            + params.get_n() * params.get_m() // CommitmentG
            + 1 // CommitmentH
            + params.get_N() // M
            + 1 // U
            + batch_size * (
                4 // A, B, C, D
                + 1 // J
                + 2 * params.get_m() // X, Y
            ),
        )
        .map_err(|_| ProofError::InvalidParameter)?;

        // Set up the point vector for the final check
        let points = proofs
            .iter()
            .zip(statements.iter())
            .flat_map(|(p, s)| {
                once(&p.A)
                    .chain(once(&p.B))
                    .chain(once(&p.C))
                    .chain(once(&p.D))
                    .chain(once(s.get_J()))
                    .chain(p.X.iter())
                    .chain(p.Y.iter())
            })
            .chain(once(params.get_G()))
            .chain(params.get_CommitmentG().iter())
            .chain(once(params.get_CommitmentH()))
            .chain(M.iter())
            .chain(once(params.get_U()))
            .collect::<Vec<&RistrettoPoint>>();

        // Start the scalar vector, putting the common elements last
        let mut scalars = Vec::with_capacity(final_size);

        // Set up common scalars
        let mut G_scalar = Scalar::ZERO;
        let mut CommitmentG_scalars = vec![Scalar::ZERO; params.get_CommitmentG().len()];
        let mut CommitmentH_scalar = Scalar::ZERO;
        let mut M_scalars = vec![Scalar::ZERO; M.len()];
        let mut U_scalar = Scalar::ZERO;

        // Set up a transcript generator for use in weighting
        let mut transcript_weights = Transcript::new("Triptych verifier weights".as_bytes());

        let mut null_rng = NullRng;

        // Generate all verifier challenges
        let mut xi_powers_all = Vec::with_capacity(proofs.len());
        for (statement, proof, transcript) in izip!(statements.iter(), proofs.iter(), transcripts.iter_mut()) {
            // Set up the transcript
            let mut transcript = ProofTranscript::new(transcript, statement, &mut null_rng, None);

            // Run the Fiat-Shamir commitment phase to get the challenge powers
            xi_powers_all.push(transcript.commit(params, &proof.A, &proof.B, &proof.C, &proof.D, &proof.X, &proof.Y)?);

            // Run the Fiat-Shamir response phase to get the transcript generator and weight
            let mut transcript_rng = transcript.response(&proof.f, &proof.z_A, &proof.z_C, &proof.z);
            transcript_weights.append_u64("proof".as_bytes(), transcript_rng.as_rngcore().next_u64());
        }

        // Finalize the weighting transcript into a pseudorandom number generator
        let mut transcript_weights_rng = transcript_weights.build_rng().finalize(&mut null_rng);

        // Process each proof
        for (proof, xi_powers) in proofs.iter().zip(xi_powers_all.iter()) {
            // Reconstruct the remaining `f` terms
            let f = (0..params.get_m())
                .map(|j| {
                    let mut f_j = Vec::with_capacity(params.get_n() as usize);
                    f_j.push(xi_powers[1] - proof.f[j as usize].iter().sum::<Scalar>());
                    f_j.extend(proof.f[j as usize].iter());
                    f_j
                })
                .collect::<Vec<Vec<Scalar>>>();

            // Check that `f` does not contain zero, which breaks batch inversion
            for f_row in &f {
                if f_row.contains(&Scalar::ZERO) {
                    return Err(ProofError::InvalidParameter);
                }
            }

            // Generate nonzero weights for this proof's verification equations
            let mut w1 = Scalar::ZERO;
            let mut w2 = Scalar::ZERO;
            let mut w3 = Scalar::ZERO;
            let mut w4 = Scalar::ZERO;
            while w1 == Scalar::ZERO || w2 == Scalar::ZERO || w3 == Scalar::ZERO || w4 == Scalar::ZERO {
                w1 = Scalar::random(&mut transcript_weights_rng);
                w2 = Scalar::random(&mut transcript_weights_rng);
                w3 = Scalar::random(&mut transcript_weights_rng);
                w4 = Scalar::random(&mut transcript_weights_rng);
            }

            // Get the challenge for convenience
            let xi = xi_powers[1];

            // G
            G_scalar -= w3 * proof.z;

            // CommitmentG
            for (CommitmentG_scalar, f_item) in CommitmentG_scalars
                .iter_mut()
                .zip(f.iter().flatten().map(|f| w1 * f + w2 * f * (xi - f)))
            {
                *CommitmentG_scalar += f_item;
            }

            // CommitmentH
            CommitmentH_scalar += w1 * proof.z_A + w2 * proof.z_C;

            // A
            scalars.push(-w1);

            // B
            scalars.push(-w1 * xi_powers[1]);

            // C
            scalars.push(-w2 * xi_powers[1]);

            // D
            scalars.push(-w2);

            // J
            scalars.push(-w4 * proof.z);

            // X
            for xi_power in &xi_powers[0..(params.get_m() as usize)] {
                scalars.push(-w3 * xi_power);
            }

            // Y
            for xi_power in &xi_powers[0..(params.get_m() as usize)] {
                scalars.push(-w4 * xi_power);
            }

            // Set up the initial `f` product and Gray iterator
            let mut f_product = f.iter().map(|f_row| f_row[0]).product::<Scalar>();
            let gray_iterator =
                GrayIterator::new(params.get_n(), params.get_m()).ok_or(ProofError::InvalidParameter)?;

            // Invert each element of `f` for efficiency
            let mut f_inverse_flat = f.iter().flatten().copied().collect::<Vec<Scalar>>();
            Scalar::batch_invert(&mut f_inverse_flat);
            let f_inverse = f_inverse_flat
                .chunks_exact(params.get_n() as usize)
                .collect::<Vec<&[Scalar]>>();

            // M
            let mut U_scalar_proof = Scalar::ZERO;
            for (M_scalar, (gray_index, gray_old, gray_new)) in M_scalars.iter_mut().zip(gray_iterator) {
                // Update the `f` product
                f_product *= f_inverse[gray_index][gray_old as usize] * f[gray_index][gray_new as usize];

                *M_scalar += w3 * f_product;
                U_scalar_proof += f_product;
            }

            // U
            U_scalar += w4 * U_scalar_proof;
        }

        // Add all common elements to the scalar vector
        scalars.push(G_scalar);
        scalars.extend(CommitmentG_scalars);
        scalars.push(CommitmentH_scalar);
        scalars.extend(M_scalars);
        scalars.push(U_scalar);

        // Perform the final check; this can be done in variable time since it holds no secrets
        if RistrettoPoint::vartime_multiscalar_mul(scalars.iter(), points) == RistrettoPoint::identity() {
            Ok(())
        } else {
            Err(ProofError::FailedVerification)
        }
    }

    /// Serialize a [`Proof`] to a canonical byte vector.
    #[allow(non_snake_case)]
    pub fn to_bytes(&self) -> Vec<u8> {
        // This cannot overflow
        #[allow(clippy::arithmetic_side_effects)]
        let mut result = Vec::with_capacity(
            8 // `n - 1`, `m`
            + SERIALIZED_BYTES * (
                4 // `A, B, C, D`
                + self.X.len()
                + self.Y.len()
                + 3 // `z_A, z_C, z`
                + self.f.len() * self.f[0].len()
            ),
        );
        #[allow(clippy::cast_possible_truncation)]
        let n_minus_1 = self.f[0].len() as u32;
        #[allow(clippy::cast_possible_truncation)]
        let m = self.f.len() as u32;
        result.extend(n_minus_1.to_le_bytes());
        result.extend(m.to_le_bytes());

        result.extend_from_slice(self.A.compress().as_bytes());
        result.extend_from_slice(self.B.compress().as_bytes());
        result.extend_from_slice(self.C.compress().as_bytes());
        result.extend_from_slice(self.D.compress().as_bytes());
        result.extend_from_slice(self.z_A.as_bytes());
        result.extend_from_slice(self.z_C.as_bytes());
        result.extend_from_slice(self.z.as_bytes());
        for X in &self.X {
            result.extend_from_slice(X.compress().as_bytes());
        }
        for Y in &self.Y {
            result.extend_from_slice(Y.compress().as_bytes());
        }
        for f_row in &self.f {
            for f in f_row {
                result.extend_from_slice(f.as_bytes());
            }
        }

        result
    }

    /// Deserialize a [`Proof`] from a canonical byte slice.
    ///
    /// If `bytes` does not represent a canonical encoding, returns a [`ProofError`].
    #[allow(non_snake_case)]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        // Helper to parse a `u32` from a `u8` iterator
        let parse_u32 = |iter: &mut dyn Iterator<Item = &u8>| {
            // Get the next four bytes
            let bytes = iter.take(4).copied().collect::<Vec<u8>>();
            if bytes.len() != 4 {
                return Err(ProofError::FailedDeserialization);
            }
            let array: [u8; 4] = bytes.try_into().map_err(|_| ProofError::FailedDeserialization)?;

            // Parse the bytes into a `u32`
            Ok(u32::from_le_bytes(array))
        };

        // Helper to parse a scalar from a chunk iterator
        let parse_scalar = |chunks: &mut ChunksExact<'_, u8>| -> Result<Scalar, ProofError> {
            chunks
                .next()
                .ok_or(ProofError::FailedDeserialization)
                .and_then(|slice| {
                    let bytes: [u8; SERIALIZED_BYTES] =
                        slice.try_into().map_err(|_| ProofError::FailedDeserialization)?;
                    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or(ProofError::FailedDeserialization)
                })
        };

        // Helper to parse a compressed point from a chunk iterator
        let parse_point = |chunks: &mut ChunksExact<'_, u8>| -> Result<RistrettoPoint, ProofError> {
            chunks
                .next()
                .ok_or(ProofError::FailedDeserialization)
                .and_then(|slice| {
                    let bytes: [u8; SERIALIZED_BYTES] =
                        slice.try_into().map_err(|_| ProofError::FailedDeserialization)?;

                    CompressedRistretto::from_slice(&bytes)
                        .map_err(|_| ProofError::FailedDeserialization)?
                        .decompress()
                        .ok_or(ProofError::FailedDeserialization)
                })
        };

        // Set up the slice iterator
        let mut iter = bytes.iter();

        // Parse the encoded vector dimensions and check that `n, m > 1` and that they do not overflow
        let n_minus_1 = parse_u32(&mut iter)?;
        if n_minus_1.checked_add(1).ok_or(ProofError::FailedDeserialization)? < 2 {
            return Err(ProofError::FailedDeserialization);
        }
        let m = parse_u32(&mut iter)?;
        if m < 2 {
            return Err(ProofError::FailedDeserialization);
        }

        // The rest of the serialization is of encoded proof elements
        let mut chunks = iter.as_slice().chunks_exact(SERIALIZED_BYTES);

        // Extract the fixed proof elements
        let A = parse_point(&mut chunks)?;
        let B = parse_point(&mut chunks)?;
        let C = parse_point(&mut chunks)?;
        let D = parse_point(&mut chunks)?;
        let z_A = parse_scalar(&mut chunks)?;
        let z_C = parse_scalar(&mut chunks)?;
        let z = parse_scalar(&mut chunks)?;

        // Extract the `X` and `Y` vectors
        let X = (0..m)
            .map(|_| parse_point(&mut chunks))
            .collect::<Result<Vec<RistrettoPoint>, ProofError>>()?;
        let Y = (0..m)
            .map(|_| parse_point(&mut chunks))
            .collect::<Result<Vec<RistrettoPoint>, ProofError>>()?;

        // Extract the `f` matrix
        let f = (0..m)
            .map(|_| {
                (0..n_minus_1)
                    .map(|_| parse_scalar(&mut chunks))
                    .collect::<Result<Vec<Scalar>, ProofError>>()
            })
            .collect::<Result<Vec<Vec<Scalar>>, ProofError>>()?;

        // Ensure no data is left over
        if !chunks.remainder().is_empty() {
            return Err(ProofError::FailedDeserialization);
        }
        if chunks.next().is_some() {
            return Err(ProofError::FailedDeserialization);
        }

        // Perform a sanity check on all vectors
        if X.len() != m as usize || Y.len() != m as usize {
            return Err(ProofError::FailedDeserialization);
        }
        if f.len() != m as usize {
            return Err(ProofError::FailedDeserialization);
        }
        for f_row in &f {
            if f_row.len() != n_minus_1 as usize {
                return Err(ProofError::FailedDeserialization);
            }
        }

        Ok(Proof {
            A,
            B,
            C,
            D,
            X,
            Y,
            f,
            z_A,
            z_C,
            z,
        })
    }
}

#[cfg(test)]
mod test {
    use alloc::{sync::Arc, vec::Vec};

    use curve25519_dalek::{RistrettoPoint, Scalar};
    use itertools::izip;
    use merlin::Transcript;
    use rand_chacha::ChaCha12Rng;
    use rand_core::{CryptoRngCore, SeedableRng};

    use crate::{
        parameters::Parameters,
        proof::Proof,
        statement::{InputSet, Statement},
        witness::Witness,
    };

    // Generate a batch of witnesses, statements, and transcripts
    #[allow(non_snake_case)]
    #[allow(clippy::arithmetic_side_effects)]
    fn generate_data<R: CryptoRngCore>(
        n: u32,
        m: u32,
        b: usize,
        rng: &mut R,
    ) -> (Vec<Witness>, Vec<Statement>, Vec<Transcript>) {
        // Generate parameters
        let params = Arc::new(Parameters::new(n, m).unwrap());

        // Generate witnesses; for this test, we use adjacent indexes for simplicity
        // This means the batch size must not exceed the input set size!
        assert!(b <= params.get_N() as usize);
        let mut witnesses = Vec::with_capacity(b);
        witnesses.push(Witness::random(&params, rng));
        for _ in 1..b {
            let r = Scalar::random(rng);
            let l = (witnesses.last().unwrap().get_l() + 1) % params.get_N();
            witnesses.push(Witness::new(&params, l, &r).unwrap());
        }

        // Generate input set from all witnesses
        let mut M = (0..params.get_N())
            .map(|_| RistrettoPoint::random(rng))
            .collect::<Vec<RistrettoPoint>>();
        for witness in &witnesses {
            M[witness.get_l() as usize] = witness.compute_verification_key();
        }
        let input_set = Arc::new(InputSet::new(&M));

        // Generate statements
        let mut statements = Vec::with_capacity(b);
        for witness in &witnesses {
            let J = witness.compute_linking_tag();
            statements.push(Statement::new(&params, &input_set, &J).unwrap());
        }

        // Generate transcripts
        let transcripts = (0..b)
            .map(|i| {
                let mut transcript = Transcript::new("Test transcript".as_bytes());
                transcript.append_u64("index".as_bytes(), i as u64);

                transcript
            })
            .collect::<Vec<Transcript>>();

        (witnesses, statements, transcripts)
    }

    #[test]
    #[cfg(feature = "rand")]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_prove_verify() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate and verify a proof
        let proof = Proof::prove(&witnesses[0], &statements[0], &mut transcripts[0].clone()).unwrap();
        assert!(proof.verify(&statements[0], &mut transcripts[0]).is_ok());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_prove_verify_with_rng() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate and verify a proof
        let proof =
            Proof::prove_with_rng(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone()).unwrap();
        assert!(proof.verify(&statements[0], &mut transcripts[0]).is_ok());
    }

    #[test]
    #[cfg(feature = "rand")]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_prove_verify_vartime() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate and verify a proof
        let proof = Proof::prove_vartime(&witnesses[0], &statements[0], &mut transcripts[0].clone()).unwrap();
        assert!(proof.verify(&statements[0], &mut transcripts[0]).is_ok());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_prove_verify_vartime_with_rng() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate and verify a proof
        let proof = Proof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone())
            .unwrap();
        assert!(proof.verify(&statements[0], &mut transcripts[0]).is_ok());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_serialize_deserialize() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate and verify a proof
        let proof = Proof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone())
            .unwrap();
        assert!(proof.verify(&statements[0], &mut transcripts[0]).is_ok());

        // Serialize the proof
        let serialized = proof.to_bytes();

        // Deserialize the proof
        let deserialized = Proof::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized, proof);
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_prove_verify_batch() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        const batch: usize = 3; // batch size
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, batch, &mut rng);

        // Generate the proofs and verify as a batch
        let proofs = izip!(witnesses.iter(), statements.iter(), transcripts.clone().iter_mut())
            .map(|(w, s, t)| Proof::prove_with_rng_vartime(w, s, &mut rng, t).unwrap())
            .collect::<Vec<Proof>>();
        assert!(Proof::verify_batch(&statements, &proofs, &mut transcripts).is_ok());
    }

    #[test]
    fn test_prove_verify_empty_batch() {
        // An empty batch is invalid by definition
        assert!(Proof::verify_batch(&[], &[], &mut []).is_err());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_evil_message() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate a proof
        let proof =
            Proof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0]).unwrap();

        // Generate a modified transcript
        let mut evil_transcript = Transcript::new("Evil transcript".as_bytes());

        // Attempt to verify the proof against the new statement, which should fail
        assert!(proof.verify(&statements[0], &mut evil_transcript).is_err());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_evil_input_set() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate a proof
        let proof = Proof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone())
            .unwrap();

        // Generate a statement with a modified input set
        let mut M = statements[0].get_input_set().get_keys().to_vec();
        let index = ((witnesses[0].get_l() + 1) % witnesses[0].get_params().get_N()) as usize;
        M[index] = RistrettoPoint::random(&mut rng);
        let evil_input_set = Arc::new(InputSet::new(&M));
        let evil_statement =
            Statement::new(statements[0].get_params(), &evil_input_set, statements[0].get_J()).unwrap();

        // Attempt to verify the proof against the new statement, which should fail
        assert!(proof.verify(&evil_statement, &mut transcripts[0]).is_err());
    }

    #[test]
    #[allow(non_snake_case, non_upper_case_globals)]
    fn test_evil_linking_tag() {
        // Generate data
        const n: u32 = 2;
        const m: u32 = 4;
        let mut rng = ChaCha12Rng::seed_from_u64(8675309);
        let (witnesses, statements, mut transcripts) = generate_data(n, m, 1, &mut rng);

        // Generate a proof
        let proof = Proof::prove_with_rng_vartime(&witnesses[0], &statements[0], &mut rng, &mut transcripts[0].clone())
            .unwrap();

        // Generate a statement with a modified linking tag
        let evil_statement = Statement::new(
            statements[0].get_params(),
            statements[0].get_input_set(),
            &RistrettoPoint::random(&mut rng),
        )
        .unwrap();

        // Attempt to verify the proof against the new statement, which should fail
        assert!(proof.verify(&evil_statement, &mut transcripts[0]).is_err());
    }
}
