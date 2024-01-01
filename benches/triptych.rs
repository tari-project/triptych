// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![allow(missing_docs)]

#[macro_use]
extern crate criterion;
extern crate alloc;

use alloc::sync::Arc;

use criterion::Criterion;
use curve25519_dalek::RistrettoPoint;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use triptych::{
    parameters::Parameters,
    proof::Proof,
    statement::{InputSet, Statement},
    witness::Witness,
};

// Parameters
static N_VALUES: [u32; 1] = [2];
static M_VALUES: [u32; 4] = [2, 4, 8, 10];

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
fn generate_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = Arc::new(Parameters::new(n, m).unwrap());

            let label = format!("Generate proof: n = {}, m = {} (N = {})", n, m, params.get_N());
            group.bench_function(&label, |b| {
                // Generate witness
                let witness = Witness::random(&params, &mut rng);

                // Generate input set
                let M = (0..params.get_N())
                    .map(|i| {
                        if i == witness.get_l() {
                            witness.compute_verification_key()
                        } else {
                            RistrettoPoint::random(&mut rng)
                        }
                    })
                    .collect::<Vec<RistrettoPoint>>();
                let input_set = Arc::new(InputSet::new(&M));

                // Generate statement
                let J = witness.compute_linking_tag();
                let statement = Statement::new(&params, &input_set, &J).unwrap();

                // Start the benchmark
                b.iter(|| {
                    // Generate the proof
                    let _proof =
                        Proof::prove(&witness, &statement, Some("Proof message".as_bytes()), &mut rng).unwrap();
                })
            });
        }
    }
    group.finish();
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
fn verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = Arc::new(Parameters::new(n, m).unwrap());

            let label = format!("Verify proof: n = {}, m = {} (N = {})", n, m, params.get_N());
            group.bench_function(&label, |b| {
                // Generate witness
                let witness = Witness::random(&params, &mut rng);

                // Generate input set
                let M = (0..params.get_N())
                    .map(|i| {
                        if i == witness.get_l() {
                            witness.compute_verification_key()
                        } else {
                            RistrettoPoint::random(&mut rng)
                        }
                    })
                    .collect::<Vec<RistrettoPoint>>();
                let input_set = Arc::new(InputSet::new(&M));

                // Generate statement
                let J = witness.compute_linking_tag();
                let statement = Statement::new(&params, &input_set, &J).unwrap();

                let message = "Proof message".as_bytes();
                let proof = Proof::prove(&witness, &statement, Some(message), &mut rng).unwrap();

                // Start the benchmark
                b.iter(|| {
                    assert!(proof.verify(&statement, Some(message), &mut rng));
                })
            });
        }
    }
    group.finish();
}

criterion_group! {
    name = generate;
    config = Criterion::default();
    targets = generate_proof
}

criterion_group! {
    name = verify;
    config = Criterion::default();
    targets = verify_proof
}

criterion_main!(generate, verify);
