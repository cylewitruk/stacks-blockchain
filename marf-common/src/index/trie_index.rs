use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, sqlite::SqliteIndexProvider, MarfError, tries::{TriePtr, TrieNodeType}};

pub enum TrieIndex<'a> {
    SQLite(SqliteIndexProvider<'a>),
    RocksDB,
}

impl<'a> TrieIndex<'a> {
    pub fn get_block_identifier<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<u32, MarfError> {
        match self {
            TrieIndex::SQLite(p) => p.get_block_identifier(bhh),
            TrieIndex::RocksDB => todo!()
        }
    }

    pub fn get_node_hash_bytes(&self, block_id: u32, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        todo!()
    }

    pub fn get_node_hash_bytes_by_bhh<TTrieId: MarfTrieId>(&self, bhh: &TTrieId, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        todo!()
    }

    pub fn read_all_block_hashes_and_roots<TTrieId: MarfTrieId>(&self) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, TTrieId)>, MarfError> {
        todo!()
    }

    pub fn get_confirmed_block_identifier<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError> {
        todo!()
    }

    pub fn get_unconfirmed_block_identifier<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError> {
        todo!()
    }

    pub fn read_node_type(&self, block_id: u32, ptr: &TriePtr, ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        todo!()
    }

    pub fn read_node_type_nohash(&self, block_id: u32, ptr: &TriePtr) -> Result<TrieNodeType, MarfError> {
        todo!()
    }

    pub fn count_blocks(&self) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, MarfError> {
        todo!()
    }

    pub fn update_external_trie_blob<TTrieId: MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    pub fn get_external_trie_offset_length(&self, block_id: u32) -> Result<(u64, u64), MarfError> {
        todo!()
    }

    pub fn get_external_trie_offset_length_by_bhh<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<(u64, u64), MarfError> {
        todo!()
    }

    pub fn get_external_blobs_length(&self) -> Result<u64, MarfError> {
        todo!()
    }

    pub fn write_external_trie_blob<TTrieId: MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob<TTrieId: MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob_to_mined<TTrieId: MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob_to_unconfirmed<TTrieId: MarfTrieId>(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    pub fn drop_lock<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<(), crate::MarfError> {
        todo!()
    }

    pub fn lock_bhh_for_extension<TTrieId: MarfTrieId>(
        &mut self,
        bhh: &TTrieId,
        unconfirmed: bool,
    ) -> Result<bool, crate::MarfError> {
        todo!()
    }

    pub fn read_node_hash_bytes(
        &self,
        w: &mut dyn std::io::Write,
        block_id: u32,
        ptr: &crate::tries::TriePtr,
    ) -> Result<(), crate::MarfError> {
        todo!()
    }

    pub fn drop_unconfirmed_trie<TTrieId: MarfTrieId>(&self, bhh: &TTrieId) -> Result<(), MarfError> {
        todo!()
    }

    pub fn format(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    pub fn open_trie_blob(&self, block_id: u32) -> Result<std::io::Cursor<Vec<u8>>, MarfError> {
        todo!()
    }

    pub fn reopen_readonly(&self) -> Result<TrieIndex<'a>, MarfError> {
        todo!()
    }

    pub fn begin_transaction(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    pub fn commit_transaction(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    pub fn rollback_transaction(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    #[cfg(test)]
    pub fn read_all_block_hashes_and_offsets<TTrieId: MarfTrieId>(&self) -> Result<Vec<(TTrieId, u64)>, MarfError> {
        todo!()
    }
}