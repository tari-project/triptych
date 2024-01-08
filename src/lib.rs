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
//! an arbitrary message into the proof. This produces the linkable ring signature.
//!
//! # Implementation notes
//!
//! This implementation makes several opinionated choices:
//! - It uses [Ristretto](https://ristretto.group/) for group operations.
//! - It uses [Merlin](https://merlin.cool/) for Fiat-Shamir transcript operations.
//! - It uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) for other cryptographic hashing operations.
//!
//! It's possible to generalize these if done safely, but the implementation doesn't (yet) do this.
//!
//! The implementation keeps dependencies to a minimum, and is `no_std` right out of the box.
//! You can enable the optional `serde` feature for proof (de)serialization support.
//! You can enable the optional `std` feature for corresponding dependency features.
//!
//! # Security
//!
//! The implementation uses [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) to securely wipe the signing key `r` after use.
//! However, it does not do so for the index `l`.
//!
//! Care is taken to keep signing key operations constant time to avoid leaking key data.
//! However, index-related operations may not be constant time.
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
//! # extern crate alloc;
//! use alloc::sync::Arc;
//!
//! # use triptych::parameters::Parameters;
//! use curve25519_dalek::RistrettoPoint;
//! use rand_core::OsRng;
//! # use triptych::statement::InputSet;
//! # use triptych::statement::Statement;
//! # use triptych::witness::Witness;
//! # use triptych::proof::Proof;
//!
//! let mut rng = OsRng;
//!
//! // Generate parameters
//! // This is `Arc`-wrapped to facilitate efficient reuse!
//! const n: u32 = 2;
//! const m: u32 = 3;
//! let params = Arc::new(Parameters::new(n, m).unwrap());
//!
//! // Generate a random witness, which includes the signing key and an index where it will appear
//! let witness = Witness::random(&params, &mut rng);
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
//! let input_set = Arc::new(InputSet::new(&M));
//!
//! // Generate the statement, which includes the verification key vector, linking tag, and optional message
//! let J = witness.compute_linking_tag();
//! let message = "This message will be bound to the proof".as_bytes();
//! let statement = Statement::new(&params, &input_set, &J, Some(message)).unwrap();
//!
//! // Generate a proof from the witness
//! let proof = Proof::prove(&witness, &statement, &mut rng).unwrap();
//!
//! // The proof should verify against the same statement
//! assert!(proof.verify(&statement));
//! ```

#![no_std]

extern crate alloc;

/// Iterated arbitrary-base Gray code functionaity.
pub mod gray;
/// Public parameters used for generating and verifying Triptych proofs.
pub mod parameters;
/// Triptych proofs.
pub mod proof;
/// Triptych proof statements.
pub mod statement;
/// Various utility functionality.
pub(crate) mod util;
/// Triptych proof witnesses.
pub mod witness;
