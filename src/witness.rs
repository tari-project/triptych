// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

use alloc::sync::Arc;

use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_core::CryptoRngCore;
use snafu::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::parameters::Parameters;

/// A Triptych proof witness.
///
/// The witness consists of a signing key and an index where the corresponding verification key will appear in  the
/// [`InputSet`](`crate::statement::InputSet`) of a [`Statement`](`crate::statement::Statement`). It also contains
/// [`Parameters`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Witness {
    #[zeroize(skip)]
    params: Arc<Parameters>,
    l: u32,
    r: Scalar,
}

/// Errors that can arise relating to [`Witness`].
#[derive(Debug, Snafu)]
pub enum WitnessError {
    /// An invalid parameter was provided.
    #[snafu(display("An invalid parameter was provided"))]
    InvalidParameter,
}

impl Witness {
    /// Generate a new [`Witness`] from secret data.
    ///
    /// The signing key `r` must be nonzero, and the index `l` must be valid for the [`Parameters`] `params`.
    /// If any of these conditions is not met, returns a [`WitnessError`].
    ///
    /// If you'd like a [`Witness`] generated securely for you, use [`Witness::random`] instead.
    #[allow(non_snake_case)]
    pub fn new(params: &Arc<Parameters>, l: u32, r: &Scalar) -> Result<Self, WitnessError> {
        if r == &Scalar::ZERO {
            return Err(WitnessError::InvalidParameter);
        }
        if l >= params.get_N() {
            return Err(WitnessError::InvalidParameter);
        }

        Ok(Self {
            params: params.clone(),
            l,
            r: *r,
        })
    }

    /// Generate a new random [`Witness`].
    ///
    /// You must provide [`Parameters`] `params` and a [`CryptoRngCore`] random number generator `rng`.
    /// This will generate a [`Witness`] with a cryptographically-secure signing key and random index.
    ///
    /// If you'd rather provide your own secret data, use [`Witness::new`] instead.
    #[allow(clippy::cast_possible_truncation)]
    pub fn random<R: CryptoRngCore>(params: &Arc<Parameters>, rng: &mut R) -> Self {
        // Generate a random index using wide reduction
        // This can't truncate since `N` is bounded by `u32`
        // It is also defined since `N > 0`
        #[allow(clippy::arithmetic_side_effects)]
        let l = (rng.as_rngcore().next_u64() % u64::from(params.get_N())) as u32;

        Self {
            params: params.clone(),
            l,
            r: Scalar::random(rng),
        }
    }

    /// Get the [`Parameters`] from this [`Witness`].
    pub fn get_params(&self) -> &Arc<Parameters> {
        &self.params
    }

    /// Get the index from this [`Witness`].
    pub fn get_l(&self) -> u32 {
        self.l
    }

    /// Get the signing key from this [`Witness`].
    pub fn get_r(&self) -> &Scalar {
        &self.r
    }

    /// Compute the linking tag for the [`Witness`] signing key.
    #[allow(non_snake_case)]
    pub fn compute_linking_tag(&self) -> RistrettoPoint {
        *Zeroizing::new(self.r.invert()) * self.params.get_U()
    }

    /// Compute the verification key for the [`Witness`] signing key.
    pub fn compute_verification_key(&self) -> RistrettoPoint {
        self.r * self.params.get_G()
    }
}
