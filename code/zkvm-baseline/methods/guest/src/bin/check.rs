//! Isolated zkVM diagnostic for the selected Poseidon accelerator backend.
//!
//! This is intentionally a separate guest binary so its fixed boundary-vector
//! work cannot alter the `baseline` method's receipt journal or cycle counts.

use risc0_zkvm::guest::env;

fn main() {
    let result = relation::accelerator_self_test().expect("accelerator self-test failed");
    env::commit(&result);
}
