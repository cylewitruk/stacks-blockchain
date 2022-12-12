use std::collections::HashMap;

use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, tries::{TriePtr, TrieNodeType}};

use super::TrieNodeAddr;

/// Cache state for all node caching strategies.
pub struct TrieCacheState<T: MarfTrieId> {
    /// Mapping between trie blob IDs (i.e. rowids) and the MarfTrieId of the trie.  Contents are
    /// never evicted, since the size of this map grows only at the rate of new Stacks blocks.
    block_hash_cache: HashMap<u32, T>,

    /// Mapping between trie blob hashes and their IDs
    block_id_cache: HashMap<T, u32>,

    /// cached nodes
    node_cache: HashMap<TrieNodeAddr, TrieNodeType>,
    /// cached trie root hashes
    hash_cache: HashMap<TrieNodeAddr, TrieHash>,
}

impl<T: MarfTrieId> TrieCacheState<T> {
    pub fn new() -> TrieCacheState<T> {
        TrieCacheState {
            block_hash_cache: HashMap::new(),
            block_id_cache: HashMap::new(),
            node_cache: HashMap::new(),
            hash_cache: HashMap::new(),
        }
    }

    /// Obtain a possibly-cached node and its hash.
    /// Only return data if we have *both* the node and hash
    pub fn load_node_and_hash(
        &self,
        block_id: u32,
        trieptr: &TriePtr,
    ) -> Option<(TrieNodeType, TrieHash)> {
        match (
            self.load_node(block_id, trieptr),
            self.load_node_hash(block_id, trieptr),
        ) {
            (Some(node), Some(hash)) => Some((node, hash)),
            _ => None,
        }
    }

    /// Obtain a possibly-cached node
    pub fn load_node(&self, block_id: u32, trieptr: &TriePtr) -> Option<TrieNodeType> {
        self.node_cache
            .get(&TrieNodeAddr(block_id, trieptr.clone()))
            .cloned()
    }

    /// Obtain a possibly-cached node hash
    pub fn load_node_hash(&self, block_id: u32, trieptr: &TriePtr) -> Option<TrieHash> {
        self.hash_cache
            .get(&TrieNodeAddr(block_id, trieptr.clone()))
            .cloned()
    }

    /// Cache a node and hash
    pub fn store_node_and_hash(
        &mut self,
        block_id: u32,
        trieptr: TriePtr,
        node: TrieNodeType,
        hash: TrieHash,
    ) {
        self.store_node(block_id, trieptr.clone(), node);
        self.store_node_hash(block_id, trieptr, hash)
    }

    /// Cache just a node
    pub fn store_node(&mut self, block_id: u32, trieptr: TriePtr, node: TrieNodeType) {
        self.node_cache
            .insert(TrieNodeAddr(block_id, trieptr), node);
    }

    /// Cache just a node hash
    pub fn store_node_hash(&mut self, block_id: u32, trieptr: TriePtr, hash: TrieHash) {
        self.hash_cache
            .insert(TrieNodeAddr(block_id, trieptr), hash);
    }

    /// Load up a block hash, given its ID
    pub fn load_block_hash(&self, block_id: u32) -> Option<T> {
        self.block_hash_cache.get(&block_id).cloned()
    }

    /// Cache a block hash, given its ID
    pub fn store_block_hash(&mut self, block_id: u32, block_hash: T) {
        assert!(!self.block_hash_cache.contains_key(&block_id));
        self.block_id_cache.insert(block_hash.clone(), block_id);
        self.block_hash_cache.insert(block_id, block_hash);
    }

    /// Get an immutable reference to a block hash, given the ID
    pub fn ref_block_hash(&self, block_id: u32) -> Option<&T> {
        self.block_hash_cache.get(&block_id)
    }

    /// Get the block ID, given its hash
    pub fn load_block_id(&self, block_hash: &T) -> Option<u32> {
        self.block_id_cache.get(block_hash).map(|id| *id)
    }
}