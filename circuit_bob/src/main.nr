use ecdh::{bjj::BJJ, ECDHTrait, Point};
use poseidon::poseidon2::Poseidon2;
mod merkle_tree;
// Bob's main function is now a proving circuit.
// It takes Alice's public key, the nonce, and the final commitment as public inputs.
fn main(
    bob_priv_key: Field,
    alice_pub_key_x:  Field,
    alice_pub_key_y:  Field,
    hash_lock_nonce:  Field,
    order_id: Field,
    
    merkle_proof: [Field; 20],
    is_even: [bool; 20],

    nullifier_hash: pub Field,
    root: pub Field,
) {
    // --- The internal logic remains identical ---
    let bob_ecdh = BJJ::new(bob_priv_key);

    // Bob needs his own public key to construct the hash lock, so he derives it internally.
    let bob_pub_key = bob_ecdh.derive_public_key();

    let alice_pub_key = Point::new(alice_pub_key_x, alice_pub_key_y);

    let shared_secret = bob_ecdh.derive_shared_key(alice_pub_key);

    let reconstructed_hash_lock = Poseidon2::hash([bob_pub_key.x, hash_lock_nonce], 2);

    let derived_commitment = Poseidon2::hash([reconstructed_hash_lock, shared_secret], 2);

    let computed_nullifier_hash = Poseidon2::hash([shared_secret, alice_pub_key_x, order_id], 3);

    let computed_merkle_root = merkle_tree::compute_merkle_root(derived_commitment, merkle_proof, is_even);

    assert(computed_nullifier_hash == nullifier_hash);

    assert(computed_merkle_root == root);
}

// #[test]
// fn test_main_circuit_bob() {
//     // --- 1. SETUP: Identical to before ---
//     let alice_sk: Field = 0xabcde;
//     let bob_sk: Field = 0x12345;
//     let hash_lock_nonce: Field = 0x67890;

//     let alice_ecdh = BJJ::new(alice_sk);
//     let alice_pk: Point = alice_ecdh.derive_public_key();

//     let bob_ecdh = BJJ::new(bob_sk);
//     let bob_pk: Point = bob_ecdh.derive_public_key();

//     // --- 2. PRE-COMPUTATION: Calculate the expected result off-circuit ---
//     let expected_shared_secret = bob_ecdh.derive_shared_key(alice_pk);

//     let expected_hash_lock = Poseidon2::hash([bob_pk.x, hash_lock_nonce], 2);

//     let expected_commitment = Poseidon2::hash([expected_hash_lock, expected_shared_secret], 2);

//     // --- 3. EXECUTION & VERIFICATION: Call the circuit with all public inputs ---
//     // The test will fail if the `assert` inside `main` is not satisfied.
//     main(bob_sk, alice_pk.x, alice_pk.y, hash_lock_nonce, expected_commitment);
// }
