# Ztomic-Swap Zero-Knowledge Circuits

The provided Noir circuits define the core logic for **Ztomic-Swap**, an optimized, privacy-preserving atomic swap protocol. It utilizes zk-SNARKs to prove correct key derivation and commitment validity without revealing the parties' secrets. The protocol relies on **ECDH** for shared secret generation and **Poseidon2** for hashing commitments and nullifiers, with a **Merkle Tree** for state tracking.

***

## 1. Core Cryptographic Primitives

| Primitive | Purpose | Formula / Use |
| :--- | :--- | :--- |
| **Commitment** | The deposit hash locking the funds, proven to be a member of the Merkle tree. | $\text{Commitment} = \text{Poseidon2}(\text{HashLock}, \text{SharedSecret})$ |
| **Hash Lock** | The time-lock component of the swap, derived from the Responder's Public Key and a Nonce. | $\text{HashLock} = \text{Poseidon2}(\text{ResponderPK.x}, \text{Nonce})$ |
| **Shared Secret** | A private key derived via ECDH, known only to the Initiator (Alice) and Responder (Bob). | $\text{SharedSecret} = \text{ECDH}(\text{PartySK}, \text{CounterPartyPK})$ |
| **Nullifier** | A unique, private secret used to mark a Commitment as spent on the smart contract, preventing double-spending. | $\text{Nullifier} = \text{Poseidon2}(\text{SharedSecret}, \text{CounterPartyPK.x}, \text{OrderID})$ |
| **Merkle Root** | The root of the historical Merkle tree on the smart contract, against which the Commitment is proven. | $\text{Root} = \text{Iterative Poseidon2}(\text{Commitment}, \text{ProofPath})$ |

***

## 2. Alice's Circuit: `main` (Initiator's Withdrawal Proof)

Alice (the Initiator) uses this circuit to prove she possesses the necessary private key and the crucial secret (**Hash Lock Nonce**) to unlock the swap, allowing her to withdraw the Responder's asset.

| Input Type | Field | Description | Role in the Swap |
| :--- | :--- | :--- | :--- |
| **Private** | `alice_priv_key` | Alice's ECDH secret key. | Proves ownership of the Alice side of the Shared Secret. |
| **Private** | `merkle_proof`, `is_even` | Path and direction to prove commitment membership. | Proves Alice's original commitment is in the tree. |
| **Public** | `bob_pub_key_x`, `bob_pub_key_y` | Bob's ECDH public key. | Used with `alice_priv_key` to derive the `SharedSecret`. |
| **Public** | `order_id` | Unique swap identifier. | Used in Nullifier calculation. |
| **Public** | `hash_lock_nonce` | **The secret revealed by Bob's commitment.** | **Crucial Input:** Used to reconstruct the **Hash Lock** and consequently the **Commitment**. |
| **Public** | `nullifier_hash` | The expected Nullifier Hash value. | Contract checks this against the spent list. |
| **Public** | `root` | The valid Merkle Root from the contract history. | Used as the target for the Merkle proof verification. |

### Circuit Logic

The circuit enforces the following steps:

1.  **Shared Secret Derivation:** $\text{SharedSecret} = \text{ECDH}(\text{alice\_priv\_key}, \text{bob\_pub\_key})$.
2.  **Hash Lock Reconstruction:** $\text{ReconstructedHashLock} = \text{Poseidon2}(\text{bob\_pub\_key.x}, \text{hash\_lock\_nonce})$.
3.  **Commitment Reconstruction:** $\text{DerivedCommitment} = \text{Poseidon2}(\text{ReconstructedHashLock}, \text{SharedSecret})$.
4.  **Nullifier Check:** The circuit computes the Nullifier Hash and **asserts** it matches the public input `nullifier_hash`.
    $$\text{ComputedNullifierHash} = \text{Poseidon2}(\text{SharedSecret}, \text{BobPK.x}, \text{OrderID})$$
5.  **Merkle Proof Check:** The circuit computes the Merkle Root from the `DerivedCommitment` and **asserts** it matches the public input `root`.

***

## 3. Bob's Circuit: `main` (Responder's Withdrawal Proof)

Bob (the Responder) uses this circuit after Alice's withdrawal. At this point, the **Hash Lock Nonce** has been exposed via the public inputs of Alice's successful transaction, allowing Bob to use it to reconstruct his commitment and finalize his withdrawal.

| Input Type | Field | Description | Role in the Swap |
| :--- | :--- | :--- | :--- |
| **Private** | `bob_priv_key` | Bob's ECDH secret key. | Proves ownership of the Bob side of the Shared Secret. |
| **Private** | `merkle_proof`, `is_even` | Path and direction to prove commitment membership. | Proves Bob's original commitment is in the tree. |
| **Public** | `alice_pub_key_x`, `alice_pub_key_y` | Alice's ECDH public key. | Used with `bob\_priv\_key` to derive the `SharedSecret`. |
| **Public** | `order_id` | Unique swap identifier. | Used in Nullifier calculation. |
| **Public** | `hash_lock_nonce` | **The secret revealed by Alice's successful withdrawal.** | **Crucial Input:** Used to reconstruct the **Hash Lock** and consequently the **Commitment**. |
| **Public** | `nullifier_hash` | The expected Nullifier Hash value. | Contract checks this against the spent list. |
| **Public** | `root` | The valid Merkle Root from the contract history. | Used as the target for the Merkle proof verification. |

### Circuit Logic

The circuit enforces the following steps:

1.  **Shared Secret Derivation:** $\text{SharedSecret} = \text{ECDH}(\text{bob\_priv\_key}, \text{alice\_pub\_key})$.
2.  **Hash Lock Reconstruction:** Bob derives his own Public Key internally.
    $$\text{ReconstructedHashLock} = \text{Poseidon2}(\text{BobPK.x (derived internally)}, \text{hash\_lock\_nonce})$$
3.  **Commitment Reconstruction:** $\text{DerivedCommitment} = \text{Poseidon2}(\text{ReconstructedHashLock}, \text{SharedSecret})$.
4.  **Nullifier Check:** The circuit computes the Nullifier Hash and **asserts** it matches the public input `nullifier_hash`.
    $$\text{ComputedNullifierHash} = \text{Poseidon2}(\text{SharedSecret}, \text{AlicePK.x}, \text{OrderID})$$
5.  **Merkle Proof Check:** The circuit computes the Merkle Root from the `DerivedCommitment` and **asserts** it matches the public input `root`.

***

## 4. Merkle Tree Module (`merkle_tree::compute_merkle_root`)

This auxiliary module provides the necessary logic to verify a Merkle path inside the ZK circuit.

* **Inputs:** `leaf` (the commitment), `merkle\_proof` (an array of sibling hashes), and `is\_even` (a boolean array indicating the position of the current hash relative to the sibling).
* **Logic:** It iteratively applies the **Poseidon2** hash function. The proof is verified level-by-level, ensuring the correct ordering of hashing (i.e., $\text{Poseidon2}(\text{left}, \text{right})$) at each step based on the `is\_even` flag.
* **Depth:** The proof size is fixed to 20 levels (`[Field; 20]`), supporting up to $2^{20}$ (approximately 1 million) commitments.
