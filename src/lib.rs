// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! An experimental Rust implementation of the Triptych zero-knowledge proving system.
//!
//! # Overview
//!
//! [Triptych](https://eprint.iacr.org/2020/018) is a zero-knowledge proving system designed to function as a linkable ring signature.
//! This is a construction that allows a signer to sign a message against a set of arbitrary verification keys.
//! Successful verification of a signature means that the signer knew the signing key corresponding to one of the
//! verification keys, but does not reveal which. It also produces a linking tag; if any two verified signatures have
//! the same linking tag, they were produced using the same signing key. However, it is not possible to determine the
//! signing key associated to a linking tag, nor the corresponding verification key.
//!
//! Triptych proofs scale nicely, with their size increasingly only logarithmically with the size of the verification
//! key set. Proofs sharing the same verification key set can also be verified efficiently in batches to save time.
//!
//! More formally, let `G` and `U` be fixed independent generators of the Ristretto group.
//! Let `N = n**m`, where `n, m > 1` are fixed parameters.
//! The Triptych proving system protocol is a sigma protocol for the following relation, where `M` is an `N`-vector of
//! group elements:
//!
//! `{ M, J ; (l, r) : M[l] = r*G, r*J = U }`
//!
//! It's possible to use the Fiat-Shamir transformation to produce a non-interactive protocol that can additionally bind
//! an arbitrary message into the transcript. This produces the linkable ring signature.
//!
//! # Implementation notes
//!
//! This implementation makes several opinionated choices:
//! - It uses [Ristretto](https://ristretto.group/) for group operations.
//! - It uses [Merlin](https://merlin.cool/) for Fiat-Shamir transcript operations.
//! - It uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) for other cryptographic hashing operations.
//!
//! The implementation keeps dependencies to a minimum, and is `no_std` friendly.
//!
//! There are several features that are enabled by default:
//! - `rand`: adds additional prover functionality that supplies a cryptographically-secure random number generator
//! - `serde`: adds proof serialization and deserialization via `serde`
//! - `std`: adds corresponding dependency features
//!
//! The underlying [curve library](https://crates.io/crates/curve25519-dalek) chooses an arithmetic backend based on CPU feature detection.
//! Using a nightly compiler broadens the backend set, and may provide better performance.
//! You can examine performance using the benchmarks: either `cargo bench` or `cargo +nightly bench`.
//!
//! Proofs support a custom serialization format designed to be efficient and canonical.
//! This functionality has an associated fuzzer that can be run using a nightly compiler: `cargo +nightly fuzz run
//! proofs`.
//!
//! # Warning
//!
//! While this implementation is written with security in mind, it is currently **experimental** and not suitable for
//! production use.
//!
//! # Example
//!
//! Here's a complete example of how to generate and verify a Triptych proof; see the documentation for additional
//! functionality.
//!
//! ```
//! # #[cfg(feature = "rand")]
//! # {
//! # extern crate alloc;
//! use alloc::sync::Arc;
//!
//! use curve25519_dalek::RistrettoPoint;
//! use rand_core::OsRng;
//! use triptych::*;
//!
//! let mut rng = OsRng;
//!
//! // Generate parameters
//! // This is `Arc`-wrapped to facilitate efficient reuse!
//! const n: u32 = 2;
//! const m: u32 = 3;
//! let params = Arc::new(TriptychParameters::new(n, m).unwrap());
//!
//! // Generate a random witness, which includes the signing key and an index where it will appear
//! let witness = TriptychWitness::random(&params, &mut rng);
//!
//! // Generate an input set of random verification keys, placing ours at the chosen index
//! // This is `Arc`-wrapped to facilitate efficient reuse!
//! let M = (0..params.get_N())
//!     .map(|i| {
//!         if i == witness.get_l() {
//!             witness.compute_verification_key()
//!         } else {
//!             RistrettoPoint::random(&mut rng)
//!         }
//!     })
//!     .collect::<Vec<RistrettoPoint>>();
//! let input_set = Arc::new(TriptychInputSet::new(&M));
//!
//! // Generate the statement, which includes the verification key vector and linking tag
//! let J = witness.compute_linking_tag();
//! let statement = TriptychStatement::new(&params, &input_set, &J).unwrap();
//!
//! // Generate a transcript
//! let mut transcript = Transcript::new(b"Test transcript");
//!
//! // Generate a proof from the witness
//! let proof = TriptychProof::prove(&witness, &statement, &mut transcript.clone()).unwrap();
//!
//! // The proof should verify against the same statement and transcript
//! assert!(proof.verify(&statement, &mut transcript).is_ok());
//! # }
//! ```

#![no_std]

extern crate alloc;

pub use merlin::Transcript;

/// Iterated arbitrary-base Gray code functionaity.
pub(crate) mod gray;
/// Public parameters used for generating and verifying Triptych proofs.
pub mod parameters;
pub use parameters::TriptychParameters;
/// Triptych proofs.
pub mod proof;
pub use proof::TriptychProof;
/// Triptych proof statements.
pub mod statement;
pub use statement::{TriptychInputSet, TriptychStatement};
/// Triptych proof transcripts.
pub(crate) mod transcript;
/// Various utility functionality.
pub(crate) mod util;
/// Triptych proof witnesses.
pub mod witness;
pub use witness::TriptychWitness;
