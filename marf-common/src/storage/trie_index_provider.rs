use stacks_common::types::chainstate::TrieHash;

use crate::{MarfError, MarfTrieId, tries::{TriePtr, nodes::TrieNodeType}};

pub trait TrieIndexProvider<TTrieId: MarfTrieId> {
    fn new(&self) -> Self;

    /// Retrieves the block hash for the specified block identifier from the underlying store.
    fn get_block_hash(&self, local_id: u32) -> Result<TTrieId, MarfError>;

    /// Retrieves the block identifier for the specified block hash from the underlying store.
    fn get_block_identifier(&self, bhh: &TTrieId) -> Result<u32, MarfError>;
    fn get_node_hash_bytes(&self, block_id: u32, ptr: &TriePtr) -> Result<TrieHash, MarfError>;
    fn get_node_hash_bytes_by_bhh(&self, bhh: &TTrieId, ptr: &TriePtr) -> Result<TrieHash, MarfError>;
    fn read_all_block_hashes_and_roots(&self) -> Result<Vec<(TrieHash, TTrieId)>, MarfError>;
    fn get_confirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError>;
    fn get_unconfirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError>;
    fn read_node_type(&self, block_id: u32, ptr: &TriePtr, ) -> Result<(TrieNodeType, TrieHash), MarfError>;
    fn read_node_type_nohash(&self, block_id: u32, ptr: &TriePtr) -> Result<TrieNodeType, MarfError>;
    fn count_blocks(&self) -> Result<u32, MarfError>;
    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, MarfError>;
    fn update_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, MarfError>;

    /// Get the offset and length of a trie blob in the trie blobs file.
    fn get_external_trie_offset_length(&self, block_id: u32) -> Result<(u64, u64), MarfError>;

    /// Get the offset of a trie blob in the blobs file, given its block header hash.
    fn get_external_trie_offset_length_by_bhh(&self, bhh: &TTrieId) -> Result<(u64, u64), MarfError>;

    /// Determine the offset in the blobs file at which the last trie ends.  This is also the offset at
    /// which the next trie will be appended.
    fn get_external_blobs_length(&self) -> Result<u64, MarfError>;

    /// Add a new row for an external trie blob -- i.e. we're creating a new trie whose blob will be
    /// stored in an external file, but its metadata will be in the DB.
    /// Returns the new row ID
    fn write_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, MarfError>;

}