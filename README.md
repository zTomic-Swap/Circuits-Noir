# Ztomic-Swap Zero-Knowledge Circuits (Noir)

The provided Noir circuits define the core logic for **Ztomic-Swap**, an optimized, privacy-preserving atomic swap protocol. It uses zk-SNARKs for private proof generation, relying on **ECDH** for key exchange, **Poseidon2** for hashing, and a **Merkle Tree** for managing state history.

---

## 1. Core Cryptographic Primitives

| Primitive | Purpose | Simple Derivation |
| :--- | :--- | :--- |
| **Commitment** | The deposit hash locking the funds, proven to be a member of the Merkle tree. | $\text{Commitment} = \text{Hash}(\text{HashLock}, \text{SharedSecret})$ |
| **Hash Lock** | The time-lock component of the swap, derived from the Responder's Public Key and a Nonce. | $\text{HashLock} = \text{Hash}(\text{ResponderPK.x}, \text{Nonce})$ |
| **Shared Secret** | A private key derived via ECDH, known only to the Initiator (Alice) and Responder (Bob). | $\text{SharedSecret} = \text{ECDH}(\text{PartySK}, \text{CounterPartyPK})$ |
| **Nullifier** | A unique, private secret used to mark a Commitment as spent on the smart contract, preventing double-spending. | $\text{Nullifier} = \text{Hash}(\text{SharedSecret}, \text{CounterPartyPK.x}, \text{OrderID})$ |
| **Merkle Root** | The root of the historical Merkle tree on the smart contract, against which the Commitment is proven. | $\text{Root} = \text{Iterative Hash}(\text{Commitment}, \text{ProofPath})$ |

---

## 2. Alice's Circuit: `main` (Initiator's Withdrawal Proof)

Alice (the Initiator) uses this circuit to prove she possesses the necessary private key and the crucial secret (**Hash Lock Nonce**) to unlock the swap and withdraw the Responder's asset.

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

The circuit enforces the following steps and asserts the consistency of the derived values with the public inputs:

1.  **Shared Secret Derivation:**
    $$\text{SharedSecret} = \text{ECDH}(\text{Alice's Private Key}, \text{Bob's Public Key})$$
2.  **Hash Lock Reconstruction:**
    $$\text{ReconstructedHashLock} = \text{Hash}(\text{Bob's Public Key X-coord}, \text{Hash Lock Nonce})$$
3.  **Commitment Reconstruction:**
    $$\text{DerivedCommitment} = \text{Hash}(\text{ReconstructedHashLock}, \text{SharedSecret})$$
4.  **Nullifier Check:** The computed Nullifier Hash must match the public input.
    $$\text{assert}(\text{Hash}(\text{Shared Secret}, \text{BobPK.x}, \text{Order ID}) == \text{Public Nullifier Hash})$$
5.  **Merkle Proof Check:** The computed Merkle Root must match the public input.
    $$\text{assert}(\text{Computed Merkle Root}(\text{Derived Commitment}, \text{Proof}) == \text{Public Root})$$

---

## 3. Bob's Circuit: `main` (Responder's Withdrawal Proof)

Bob (the Responder) uses this circuit after Alice's withdrawal. The **Hash Lock Nonce** has now been exposed, allowing Bob to use it to reconstruct his commitment and finalize his withdrawal.

| Input Type | Field | Description | Role in the Swap |
| :--- | :--- | :--- | :--- |
| **Private** | `bob_priv_key` | Bob's ECDH secret key. | Proves ownership of the Bob side of the Shared Secret. |
| **Private** | `merkle_proof`, `is_even` | Path and direction to prove commitment membership. | Proves Bob's original commitment is in the tree. |
| **Public** | `alice_pub_key_x`, `alice_pub_key_y` | Alice's ECDH public key. | Used with `bob_priv_key` to derive the `SharedSecret`. |
| **Public** | `order_id` | Unique swap identifier. | Used in Nullifier calculation. |
| **Public** | `hash_lock_nonce` | **The secret revealed by Alice's successful withdrawal.** | **Crucial Input:** Used to reconstruct the **Hash Lock** and consequently the **Commitment**. |
| **Public** | `nullifier_hash` | The expected Nullifier Hash value. | Contract checks this against the spent list. |
| **Public** | `root` | The valid Merkle Root from the contract history. | Used as the target for the Merkle proof verification. |

### Circuit Logic

The circuit enforces the following steps:

1.  **Shared Secret Derivation:**
    $$\text{SharedSecret} = \text{ECDH}(\text{Bob's Private Key}, \text{Alice's Public Key})$$
2.  **Hash Lock Reconstruction:** Bob derives his Public Key internally from his private key.
    $$\text{ReconstructedHashLock} = \text{Hash}(\text{BobPK.x (derived internally)}, \text{Hash Lock Nonce})$$
3.  **Commitment Reconstruction:**
    $$\text{DerivedCommitment} = \text{Hash}(\text{ReconstructedHashLock}, \text{SharedSecret})$$
4.  **Nullifier Check:** The computed Nullifier Hash must match the public input.
    $$\text{assert}(\text{Hash}(\text{Shared Secret}, \text{AlicePK.x}, \text{Order ID}) == \text{Public Nullifier Hash})$$
5.  **Merkle Proof Check:** The computed Merkle Root must match the public input.
    $$\text{assert}(\text{Computed Merkle Root}(\text{Derived Commitment}, \text{Proof}) == \text{Public Root})$$

---

## 4. Merkle Tree Module (`merkle_tree::compute_merkle_root`)

This auxiliary module provides the necessary logic to verify a Merkle path inside the ZK circuit.

* **Inputs:** `leaf` (the commitment), `merkle\_proof` (an array of sibling hashes, fixed size 20), and `is\_even` (a boolean array indicating the position of the current hash relative to the sibling).
* **Logic:** The circuit iteratively applies the **Poseidon2** hash function for 20 levels. At each step, it hashes the current hash with the next sibling hash from the proof, correctly ordering them based on the `is\_even` flag.
* **Depth:** The fixed depth of 20 supports up to $2^{20}$ (approximately **1,048,576**) commitments in the tree.
