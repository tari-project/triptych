# Triptych

An experimental Rust implementation of the Triptych zero-knowledge proving system.

## Overview

[Triptych](https://eprint.iacr.org/2020/018) is a zero-knowledge proving system designed to function as a linkable ring signature.
This is a construction that allows a signer to sign a message against a set of arbitrary verification keys.
Successful verification of a signature means that the signer knew the signing key corresponding to one of the verification keys, but does not reveal which.
It also produces a linking tag; if any two verified signatures have the same linking tag, they were produced using the same signing key.
However, it is not possible to determine the signing key associated to a linking tag, nor the corresponding verification key.

Triptych proofs scale nicely, with their size increasingly only logarithmically with the size of the verification key set. Proofs sharing the same verification key set can also be verified efficiently in batches to save time.

More formally, let `G` and `U` be fixed independent generators of the Ristretto group.
Let `N = n**m`, where `n, m > 1` are fixed parameters.
The Triptych proving system protocol is a sigma protocol for the following relation, where `M` is an `N`-vector of group elements:

`{ M, J ; (l, r) : M[l] = r*G, r*J = U }`

It's possible to use the Fiat-Shamir transformation to produce a non-interactive protocol that can additionally bind an arbitrary message into the proof.
This produces the linkable ring signature.

## Implementation notes

This implementation makes several opinionated choices:
- It uses [Ristretto](https://ristretto.group/) for group operations.
- It uses [Merlin](https://merlin.cool/) for Fiat-Shamir transcript operations.
- It uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) for other cryptographic hashing operations.

It's possible to generalize these if done safely, but the implementation doesn't (yet) do this.

The implementation keeps dependencies to a minimum, and is `no_std` right out of the box.
You can enable the optional `serde` feature for proof (de)serialization support.
You can enable the optional `std` feature for corresponding dependency features.

## Security

The implementation uses [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) to securely wipe the signing key `r` after use.
However, it does not do so for the index `l`.

Care is taken to keep signing key operations constant time to avoid leaking key data.
However, index-related operations may not be constant time.

## Warning

While this implementation is written with security in mind, it is currently **experimental** and not suitable for production use.