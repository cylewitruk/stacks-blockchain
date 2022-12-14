use crate::{MarfTrieId, sqlite::SqliteIndexProvider};

use super::TrieIndexProvider;

pub enum TrieIndex {
    SQLite(SqliteIndexProvider<'static>),
    RocksDB,
}

impl<TTrieId: MarfTrieId> TrieIndexProvider<TTrieId> for TrieIndex {
    fn get_block_identifier(&self, bhh: &TTrieId) -> Result<u32, crate::MarfError> {
        let x = match self {
            TrieIndex::SQLite(p) => p.get_block_identifier(bhh),
            TrieIndex::RocksDB => todo!()
        };
    }

    fn get_node_hash_bytes(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        todo!()
    }

    fn get_node_hash_bytes_by_bhh(&self, bhh: &TTrieId, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        todo!()
    }

    fn read_all_block_hashes_and_roots(&self) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, TTrieId)>, crate::MarfError> {
        todo!()
    }

    fn get_confirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        todo!()
    }

    fn get_unconfirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        todo!()
    }

    fn read_node_type(&self, block_id: u32, ptr: &crate::tries::TriePtr, ) -> Result<(crate::tries::TrieNodeType, stacks_common::types::chainstate::TrieHash), crate::MarfError> {
        todo!()
    }

    fn read_node_type_nohash(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<crate::tries::TrieNodeType, crate::MarfError> {
        todo!()
    }

    fn count_blocks(&self) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, crate::MarfError> {
        todo!()
    }

    fn update_external_trie_blob(
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

    fn get_external_trie_offset_length_by_bhh(&self, bhh: &TTrieId) -> Result<(u64, u64), crate::MarfError> {
        todo!()
    }

    fn get_external_blobs_length(&self) -> Result<u64, crate::MarfError> {
        todo!()
    }

    fn write_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn write_trie_blob(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn write_trie_blob_to_mined(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn write_trie_blob_to_unconfirmed(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    fn drop_lock(&self, bhh: &TTrieId) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn lock_bhh_for_extension(
        &mut self,
        bhh: &TTrieId,
        unconfirmed: bool,
    ) -> Result<bool, crate::MarfError> {
        todo!()
    }

    fn read_node_hash_bytes(
        &self,
        w: &mut dyn std::io::Write,
        block_id: u32,
        ptr: &crate::tries::TriePtr,
    ) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn drop_unconfirmed_trie(&self, bhh: &TTrieId) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn format(&mut self) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn open_trie_blob(&self, block_id: u32) -> Result<std::io::Cursor<Vec<u8>>, crate::MarfError> {
        todo!()
    }

    fn reopen_readonly(&self) -> Result<Box<dyn TrieIndexProvider<TTrieId>>, crate::MarfError> {
        todo!()
    }

    fn begin_transaction(&mut self) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn commit_transaction(&mut self) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn rollback_transaction(&mut self) -> Result<(), crate::MarfError> {
        todo!()
    }

    fn read_all_block_hashes_and_offsets(&self) -> Result<Vec<(TTrieId, u64)>, crate::MarfError> {
        todo!()
    }
}