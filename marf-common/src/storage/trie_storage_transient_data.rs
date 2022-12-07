use stacks_common::types::chainstate::TrieHash;

use crate::MarfTrieId;

use super::UncommittedState;

///
///  TrieStorageTransientData holds all the data that _isn't_ committed
///   to the underlying SQL storage. Used internally to simplify
///   the TrieStorageConnection/TrieFileStorage interactions
///
pub struct TrieStorageTransientData<TTrieId: MarfTrieId> {
    /// This is all the nodes written but not yet committed to disk.
    pub uncommitted_writes: Option<(TTrieId, UncommittedState<TTrieId>)>,

    /// Currently-open block (may be `uncommitted_writes.unwrap().0`)
    pub cur_block: TTrieId,
    /// Tracking the row_id for the cur_block. If cur_block == uncommitted_writes,
    ///   this value should always be None
    pub cur_block_id: Option<u32>,

    /// Runtime statistics on reading nodes
    pub read_count: u64,
    pub read_backptr_count: u64,
    pub read_node_count: u64,
    pub read_leaf_count: u64,

    /// Runtime statistics on writing nodes
    pub write_count: u64,
    pub write_node_count: u64,
    pub write_leaf_count: u64,

    /// List of ancestral trie root hashes that must be hashed with the `uncommitted_writes` root node
    /// hash to produce the MarfTrieId for the trie when it gets written to disk.  This is
    /// maintained by the MARF whenever it needs to update the trie root hash after a leaf insert,
    /// so that a batch of leaf inserts into `uncommitted_writes` don't require an ancestor trie hash
    /// query more than once.
    pub trie_ancestor_hash_bytes_cache: Option<(TTrieId, Vec<TrieHash>)>,

    /// Is the trie opened read-only?
    pub readonly: bool,

    /// Does this trie represent unconfirmed state?
    pub unconfirmed: bool,
}

impl<TTrieId: MarfTrieId> TrieStorageTransientData<TTrieId> {
    /// Target the transient data to a particular block, and optionally its block ID
    pub fn set_block(&mut self, bhh: TTrieId, id: Option<u32>) {
        trace!("set_block({},{:?})", &bhh, &id);
        self.cur_block_id = id;
        self.cur_block = bhh;
    }

    pub fn clear_block_id(&mut self) {
        self.cur_block_id = None;
    }

    pub fn retarget_block(&mut self, bhh: TTrieId) {
        self.cur_block = bhh;
    }
}