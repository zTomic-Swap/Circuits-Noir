use ecdh::{bjj::BJJ, ECDHTrait, Point};
use poseidon::poseidon2::Poseidon2;

mod merkle_tree;
// The main function is now a true proving circuit.
// It takes the expected_commitment as a public input and has no return value.
fn main(
    alice_priv_key: Field,
    bob_pub_key_x: Field,
    bob_pub_key_y: Field,
    order_id: Field,
    
    merkle_proof: [Field; 20],
    is_even: [bool; 20],

    hash_lock_nonce: pub Field,
    nullifier_hash: pub Field,
    root: pub Field,
) {
    // --- The internal logic remains identical ---
    let bob_pub_key = Point::new(bob_pub_key_x, bob_pub_key_y);

    let alice_ecdh: BJJ = BJJ::new(alice_priv_key);

    let shared_secret = alice_ecdh.derive_shared_key(bob_pub_key);

    let reconstructed_hash_lock = Poseidon2::hash([bob_pub_key_x, hash_lock_nonce], 2);

    let derived_commitment = Poseidon2::hash([reconstructed_hash_lock, shared_secret], 2);

    let computed_nullifier_hash = Poseidon2::hash([shared_secret, bob_pub_key_x, order_id], 3);

    let computed_merkle_root = merkle_tree::compute_merkle_root(derived_commitment, merkle_proof, is_even);

    assert(computed_nullifier_hash == nullifier_hash);

    assert(computed_merkle_root == root);
}

// #[test]
// fn test_main_circuit_alice() {
//     // --- 1. SETUP: Identical to before ---
//     let alice_sk: Field = 0x12345;
//     let bob_sk: Field = 0x67890;
//     let hash_lock_nonce: Field = 0xabcde;

//     let bob_ecdh = BJJ::new(bob_sk);
//     let bob_pk: Point = bob_ecdh.derive_public_key();

//     // --- 2. PRE-COMPUTATION: Calculate the expected result off-circuit ---
//     let alice_ecdh = BJJ::new(alice_sk);
//     let expected_shared_secret = alice_ecdh.derive_shared_key(bob_pk);

//     let expected_hash_lock = Poseidon2::hash([bob_pk.x, hash_lock_nonce], 2);

//     let expected_commitment = Poseidon2::hash([expected_hash_lock, expected_shared_secret], 2);

//     // --- 3. EXECUTION & VERIFICATION: Call the circuit with all public inputs ---
//     // We now pass the `expected_commitment` as the final argument.
//     // The test will automatically fail if the `assert` inside `main` is not satisfied.
//     main(alice_sk, bob_pk.x, bob_pk.y, hash_lock_nonce, expected_commitment);
// }
