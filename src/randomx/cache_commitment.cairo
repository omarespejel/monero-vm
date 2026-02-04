use openzeppelin_merkle_tree::merkle_proof;

/// Verifies a Merkle proof for a cache leaf under the given root.
/// This is the prototype gate: authenticated cache lookup.
pub fn verify_cache_leaf(root: felt252, leaf: felt252, proof: Span<felt252>) -> bool {
    merkle_proof::verify_poseidon(proof, root, leaf)
}
