pub mod trie_cursor;
pub mod trie_hash_calculation_mode;
pub mod trie_leaf;
pub mod trie_merkle_proofs;
pub mod trie_path;
pub mod trie_ptr;
pub mod nodes;

pub use {
    trie_cursor::TrieCursor,
    trie_hash_calculation_mode::TrieHashCalculationMode,
    trie_leaf::TrieLeaf,
    trie_merkle_proofs::{ProofTrieNode, ProofTriePtr, TrieMerkleProof},
    trie_path::{TriePath, TRIEPATH_MAX_LEN},
    trie_ptr::{TriePtr, TRIEPTR_SIZE}
};


/// We don't actually instantiate a Trie, but we still need to pass a type parameter for the
/// storage implementation.
pub struct Trie {}