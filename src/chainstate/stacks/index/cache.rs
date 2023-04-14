// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2022 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::char::from_digit;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::env;
use std::fmt;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::io::{BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::iter::FromIterator;
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::os;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::{cmp, error};

use rusqlite::{
    types::{FromSql, ToSql},
    Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OpenFlags, OptionalExtension,
    Transaction, NO_PARAMS,
};

use crate::chainstate::stacks::index::bits::{
    get_node_byte_len, get_node_hash, read_block_identifier, read_hash_bytes, read_node_hash_bytes,
    read_nodetype, read_root_hash, write_nodetype_bytes,
};
use crate::chainstate::stacks::index::node::{
    clear_backptr, is_backptr, set_backptr, TrieNode, TrieNode16, TrieNode256, TrieNode4,
    TrieNode48, TrieNodeID, TrieNodeType, TriePath, TriePtr,
};
use crate::chainstate::stacks::index::Error;
use crate::chainstate::stacks::index::TrieLeaf;
use crate::chainstate::stacks::index::{trie_sql, ClarityMarfTrieId, MarfTrieId};
use crate::util_lib::db::sql_pragma;
use crate::util_lib::db::sqlite_open;
use crate::util_lib::db::tx_begin_immediate;
use crate::util_lib::db::tx_busy_handler;
use crate::util_lib::db::Error as db_error;
use crate::util_lib::db::SQLITE_MMAP_SIZE;

use stacks_common::types::chainstate::BlockHeaderHash;
use stacks_common::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE, TrieCachingStrategy};

/// Fully-qualified address of a Trie node.  Includes both the block's blob rowid and the pointer within the
/// block's blob as to where it is stored.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct TrieNodeAddr(u32, TriePtr);

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
            match strategy.as_ref() {
                "noop" => TrieCache::new(&TrieCachingStrategy::Noop),
                "everything" => TrieCache::new(&TrieCachingStrategy::Everything),
                "node256" => TrieCache::new(&TrieCachingStrategy::Node256),
                _ => {
                    error!(
                        "Unsupported trie node cache strategy '{}'; falling back to `Noop` strategy",
                        strategy
                    );
                    TrieCache::Noop(TrieCacheState::new())
                }

            }
        } else {
            TrieCache::Noop(TrieCacheState::new())
        }
    }

    /// Make a new cache strategy.
    /// `strategy` must be one of "noop", "everything", or "node256".
    /// Any other option causes a runtime panic.
    pub fn new(strategy: &TrieCachingStrategy) -> TrieCache<T> {
        match strategy {
            TrieCachingStrategy::Noop => TrieCache::Noop(TrieCacheState::new()),
            TrieCachingStrategy::Everything => TrieCache::Everything(TrieCacheState::new()),
            TrieCachingStrategy::Node256 => TrieCache::Node256(TrieCacheState::new())
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
        assert!(!is_backptr(trieptr.id()));
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
        assert!(!is_backptr(trieptr.id()));
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
        assert!(!is_backptr(trieptr.id()));
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