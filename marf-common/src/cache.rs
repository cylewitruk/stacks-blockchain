use crate::tries::TriePtr;

mod trie_cache_state;
mod trie_cache;
#[cfg(test)]
mod tests;

pub use {
    trie_cache_state::TrieCacheState,
    trie_cache::TrieCache
};

/// Fully-qualified address of a Trie node.  Includes both the block's blob rowid and the pointer within the
/// block's blob as to where it is stored.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TrieNodeAddr(u32, TriePtr);



