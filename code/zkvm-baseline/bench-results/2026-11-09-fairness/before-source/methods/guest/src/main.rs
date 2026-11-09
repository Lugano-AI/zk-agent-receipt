use risc0_zkvm::guest::env;

fn main() {
    let input: relation::Input = env::read();
    let journal = relation::verify(&input).expect("relation failed");
    env::commit(&journal);
}
