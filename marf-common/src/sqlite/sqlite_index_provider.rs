use rusqlite::Connection;

use crate::storage::TrieIndexProvider;

pub struct SqliteIndexProvider<'a> {
    db: &'a Connection
}

impl<'a> TrieIndexProvider for SqliteIndexProvider<'a> {
    fn new(db_path: &str) -> Self {
        
    }

    fn get_block_hash<T: crate::MarfTrieId>(&self, local_id: u32) -> Result<T, crate::MarfError> {
        todo!()
    }

    fn get_block_identifier<T: crate::MarfTrieId>(&self, bhh: &T) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn get_node_hash_bytes(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        todo!()
    }

    fn get_node_hash_bytes_by_bhh<TTrieId: crate::MarfTrieId>(&self, bhh: &TTrieId, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        todo!()
    }

    fn read_all_block_hashes_and_roots<TTrieId: crate::MarfTrieId>(&self) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, TTrieId)>, crate::MarfError> {
        todo!()
    }

    fn get_confirmed_block_identifier<TTrieId: crate::MarfTrieId>(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        todo!()
    }

    fn get_unconfirmed_block_identifier<TTrieId: crate::MarfTrieId>(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        todo!()
    }

    fn read_node_type(&self, block_id: u32, ptr: &crate::tries::TriePtr, ) -> Result<(crate::tries::nodes::TrieNodeType, stacks_common::types::chainstate::TrieHash), crate::MarfError> {
        todo!()
    }

    fn read_node_type_nohash(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<crate::tries::nodes::TrieNodeType, crate::MarfError> {
        todo!()
    }

    fn count_blocks(&self) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, crate::MarfError> {
        todo!()
    }

    fn update_external_trie_blob<TTrieId: crate::MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn get_external_trie_offset_length(&self, block_id: u32) -> Result<(u64, u64), crate::MarfError> {
        todo!()
    }

    fn get_external_trie_offset_length_by_bhh<TTrieId: crate::MarfTrieId>(&self, bhh: &TTrieId) -> Result<(u64, u64), crate::MarfError> {
        todo!()
    }

    fn get_external_blobs_length(&self) -> Result<u64, crate::MarfError> {
        todo!()
    }

    fn write_external_trie_blob<TTrieId: crate::MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }
}