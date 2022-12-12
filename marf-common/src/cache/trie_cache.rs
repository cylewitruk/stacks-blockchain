use stacks_common::types::chainstate::TrieHash;

use crate::{
    MarfTrieId, 
    tries::{TriePtr, TrieNodeType, TrieNodeID}, 
    utils::Utils
};

use super::TrieCacheState;

/// Trie node cache strategies
pub enum TrieCache<T: MarfTrieId> {
    /// Do nothing
    Noop(TrieCacheState<T>),
    /// Cache every node in RAM
    Everything(TrieCacheState<T>),
    /// Cache only TrieNode256's
    Node256(TrieCacheState<T>),
}

impl<T: MarfTrieId> TrieCache<T> {
    /// Instantiate the default strategy.  This can be taken from the `STACKS_MARF_CACHE_STRATEGY`
    /// environ, or failing that, it will use a no-op strategy.
    pub fn default() -> TrieCache<T> {
        if let Ok(strategy) = std::env::var("STACKS_MARF_CACHE_STRATEGY") {
            TrieCache::new(&strategy)
        } else {
            TrieCache::Noop(TrieCacheState::new())
        }
    }

    /// Make a new cache strategy.
    /// `strategy` must be one of "noop", "everything", or "node256".
    /// Any other option causes a runtime panic.
    pub fn new(strategy: &str) -> TrieCache<T> {
        match strategy {
            "noop" => TrieCache::Noop(TrieCacheState::new()),
            "everything" => TrieCache::Everything(TrieCacheState::new()),
            "node256" => TrieCache::Node256(TrieCacheState::new()),
            _ => {
                error!(
                    "Unsupported trie node cache strategy '{}'; falling back to `Noop` strategy",
                    strategy
                );
                TrieCache::Noop(TrieCacheState::new())
            }
        }
    }

    /// Get the inner trie cache state, as an immutable reference
    fn state_ref(&self) -> &TrieCacheState<T> {
        match self {
            TrieCache::Noop(ref state) => state,
            TrieCache::Everything(ref state) => state,
            TrieCache::Node256(ref state) => state,
        }
    }

    /// Get the inner trie cache state, as a mutable reference
    fn state_mut(&mut self) -> &mut TrieCacheState<T> {
        match self {
            TrieCache::Noop(ref mut state) => state,
            TrieCache::Everything(ref mut state) => state,
            TrieCache::Node256(ref mut state) => state,
        }
    }

    /// Load a node from the cache, given its block ID and trie pointer within the block.
    pub fn load_node(&mut self, block_id: u32, trieptr: &TriePtr) -> Option<TrieNodeType> {
        if let TrieCache::Noop(_) = self {
            None
        } else {
            self.state_mut().load_node(block_id, trieptr)
        }
    }

    /// Load both a node and its hash, given its block ID and trie pointer within the block.
    /// Returns None if either the hash or the node are missing -- both must be cached.
    pub fn load_node_and_hash(
        &mut self,
        block_id: u32,
        trieptr: &TriePtr,
    ) -> Option<(TrieNodeType, TrieHash)> {
        if let TrieCache::Noop(_) = self {
            None
        } else {
            self.state_mut().load_node_and_hash(block_id, trieptr)
        }
    }

    /// Load a node's hash, given its node's block ID and trie pointer within the block.
    pub fn load_node_hash(&mut self, block_id: u32, trieptr: &TriePtr) -> Option<TrieHash> {
        if let TrieCache::Noop(_) = self {
            None
        } else {
            self.state_mut().load_node_hash(block_id, trieptr)
        }
    }

    /// Store a node and its hash to the cache.  `trieptr` must NOT be a backpointer
    pub fn store_node_and_hash(
        &mut self,
        block_id: u32,
        trieptr: TriePtr,
        node: TrieNodeType,
        hash: TrieHash,
    ) {
        assert!(!Utils::is_backptr(trieptr.id()));
        match self {
            TrieCache::Noop(_) => {}
            TrieCache::Everything(ref mut state) => {
                state.store_node_and_hash(block_id, trieptr, node, hash);
            }
            TrieCache::Node256(ref mut state) => match node {
                TrieNodeType::Node256(data) => {
                    state.store_node_and_hash(block_id, trieptr, TrieNodeType::Node256(data), hash);
                }
                _ => {}
            },
        }
    }

    /// Store a node to the cache.  `trieptr` must NOT be a backpointer
    pub fn store_node(&mut self, block_id: u32, trieptr: TriePtr, node: TrieNodeType) {
        assert!(!Utils::is_backptr(trieptr.id()));
        match self {
            TrieCache::Noop(_) => {}
            TrieCache::Everything(ref mut state) => state.store_node(block_id, trieptr, node),
            TrieCache::Node256(ref mut state) => match node {
                TrieNodeType::Node256(data) => {
                    state.store_node(block_id, trieptr, TrieNodeType::Node256(data))
                }
                _ => {}
            },
        }
    }

    /// Store a node's hash to the cache.  `trieptr` must NOT be a backpointer
    pub fn store_node_hash(&mut self, block_id: u32, trieptr: TriePtr, hash: TrieHash) {
        assert!(!Utils::is_backptr(trieptr.id()));
        match self {
            TrieCache::Noop(_) => {
                trace!(
                    "Noop node hash cache store for ({},{:?},{})",
                    block_id,
                    &trieptr,
                    &hash
                );
            }
            TrieCache::Everything(ref mut state) => {
                state.store_node_hash(block_id, trieptr, hash);
            }
            TrieCache::Node256(ref mut state) => match trieptr.id {
                x if x == TrieNodeID::Node256 as u8 => {
                    state.store_node_hash(block_id, trieptr, hash);
                }
                _ => {}
            },
        }
    }

    /// Load a block's hash, given its block ID.
    pub fn load_block_hash(&mut self, block_id: u32) -> Option<T> {
        self.state_mut().load_block_hash(block_id)
    }

    /// Store a block's ID and hash to teh cache.
    pub fn store_block_hash(&mut self, block_id: u32, block_hash: T) {
        self.state_mut().store_block_hash(block_id, block_hash)
    }

    /// Get an immutable reference to the block hash, given its ID
    pub fn ref_block_hash(&self, block_id: u32) -> Option<&T> {
        self.state_ref().ref_block_hash(block_id)
    }

    /// Get the block ID, given the block hash
    pub fn load_block_id(&self, block_hash: &T) -> Option<u32> {
        self.state_ref().load_block_id(block_hash)
    }
}