use ecdh::{bjj::BJJ, ECDHTrait, Point};
use poseidon::poseidon2::Poseidon2;

fn prove_shared_secret(alice_pub_key: Point, bob_priv_key: Field) -> Field {

    let bob_ecdh = BJJ::new(bob_priv_key);
    

    let shared_key = bob_ecdh.derive_shared_key(alice_pub_key);
    

    Poseidon2::hash([shared_key], 1)

}

fn main(alice_pk_x: pub Field, alice_pk_y: pub Field, bob_priv_key: pub Field, secret_hash: pub Field) {
    let alice_pub_key = Point::new(alice_pk_x, alice_pk_y);


    let computed_hash = prove_shared_secret(alice_pub_key, bob_priv_key);


    assert(computed_hash == secret_hash);
}


#[test]
fn test_main_circuit() {

    let alice_sk: Field = 0x60c0102756aac2cf5d7277792a469bff83dfe3d3e7e50ad5a55383f3a89283e;
    let bob_sk: Field = 0x86cdaad8886954a2eb20142fb98468d476a2d6c7b2c571af42cdc041b1a923c;

    let alice_ecdh = BJJ::new(alice_sk);
    let alice_pk: Point = alice_ecdh.derive_public_key();
    let bob_pk: Point = BJJ::new(bob_sk).derive_public_key();
    let shared_secret = alice_ecdh.derive_shared_key(bob_pk);
    

    let expected_secret_hash = Poseidon2::hash([shared_secret], 1);

    main(alice_pk.x, alice_pk.y, bob_sk, expected_secret_hash);
}