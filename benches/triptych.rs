// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

#![allow(missing_docs)]

#[macro_use]
extern crate criterion;
extern crate alloc;

use alloc::sync::Arc;

use criterion::Criterion;
use curve25519_dalek::{RistrettoPoint, Scalar};
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;
use triptych::{
    parameters::Parameters,
    proof::Proof,
    statement::{InputSet, Statement},
    witness::Witness,
};

// Parameters
const N_VALUES: [u32; 1] = [2];
const M_VALUES: [u32; 4] = [2, 4, 8, 10];
const BATCH_SIZES: [usize; 2] = [2, 4];

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
                let message = "Proof message".as_bytes();
                let statement = Statement::new(&params, &input_set, &J, Some(message)).unwrap();

                // Start the benchmark
                b.iter(|| {
                    // Generate the proof
                    let _proof = Proof::prove(&witness, &statement, &mut rng).unwrap();
                })
            });
        }
    }
    group.finish();
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
fn generate_proof_vartime(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate_proof_vartime");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            // Generate parameters
            let params = Arc::new(Parameters::new(n, m).unwrap());

            let label = format!(
                "Generate proof (variable time): n = {}, m = {} (N = {})",
                n,
                m,
                params.get_N()
            );
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
                let message = "Proof message".as_bytes();
                let statement = Statement::new(&params, &input_set, &J, Some(message)).unwrap();

                // Start the benchmark
                b.iter(|| {
                    // Generate the proof
                    let _proof = Proof::prove_vartime(&witness, &statement, &mut rng).unwrap();
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
                let message = "Proof message".as_bytes();
                let statement = Statement::new(&params, &input_set, &J, Some(message)).unwrap();

                let proof = Proof::prove(&witness, &statement, &mut rng).unwrap();

                // Start the benchmark
                b.iter(|| {
                    assert!(proof.verify(&statement));
                })
            });
        }
    }
    group.finish();
}

#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
fn verify_batch_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_batch_proof");
    let mut rng = ChaCha12Rng::seed_from_u64(8675309);

    for n in N_VALUES {
        for m in M_VALUES {
            for batch in BATCH_SIZES {
                // Generate parameters
                let params = Arc::new(Parameters::new(n, m).unwrap());

                let label = format!(
                    "Verify batch proof: n = {}, m = {} (N = {}), {}-batch",
                    n,
                    m,
                    params.get_N(),
                    batch
                );
                group.bench_function(&label, |b| {
                    // Generate witnesses; for this test, we use adjacent indexes for simplicity
                    // This means the batch size must not exceed the input set size!
                    assert!(batch <= params.get_N() as usize);
                    let mut witnesses = Vec::with_capacity(batch);
                    witnesses.push(Witness::random(&params, &mut rng));
                    for _ in 1..batch {
                        let r = Scalar::random(&mut rng);
                        let l = (witnesses.last().unwrap().get_l() + 1) % params.get_N();
                        witnesses.push(Witness::new(&params, l, &r).unwrap());
                    }

                    // Generate input set from all witnesses
                    let mut M = (0..params.get_N())
                        .map(|_| RistrettoPoint::random(&mut rng))
                        .collect::<Vec<RistrettoPoint>>();
                    for witness in &witnesses {
                        M[witness.get_l() as usize] = witness.compute_verification_key();
                    }
                    let input_set = Arc::new(InputSet::new(&M));

                    // Generate statements
                    let mut statements = Vec::with_capacity(batch);
                    for witness in &witnesses {
                        let J = witness.compute_linking_tag();
                        let message = "Proof message".as_bytes();
                        statements.push(Statement::new(&params, &input_set, &J, Some(message)).unwrap());
                    }

                    // Generate proofs
                    let proofs = witnesses
                        .iter()
                        .zip(statements.iter())
                        .map(|(w, s)| Proof::prove_vartime(w, s, &mut rng).unwrap())
                        .collect::<Vec<Proof>>();

                    // Start the benchmark
                    b.iter(|| {
                        assert!(Proof::verify_batch(&statements, &proofs));
                    })
                });
            }
        }
    }
    group.finish();
}

criterion_group! {
    name = generate;
    config = Criterion::default();
    targets = generate_proof, generate_proof_vartime
}

criterion_group! {
    name = verify;
    config = Criterion::default();
    targets = verify_proof, verify_batch_proof
}

criterion_main!(generate, verify);
