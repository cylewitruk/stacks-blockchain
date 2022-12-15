use stacks_common::types::chainstate::TrieHash;

use crate::{sqlite::SqliteIndexProvider, MarfError, tries::{TriePtr, TrieNodeType}, BlockMap, MarfTrieId};

pub enum TrieIndex<'a, TTrieId: MarfTrieId> {
    SQLite(SqliteIndexProvider<'a, TTrieId>),
    RocksDB,
}

impl<'a, TTrieId: MarfTrieId> TrieIndex<'a, TTrieId> {
    pub fn get_block_identifier(&self, bhh: &TTrieId) -> Result<u32, MarfError> {
        match self {
            TrieIndex::SQLite(p) => p.get_block_identifier(bhh),
            TrieIndex::RocksDB => todo!()
        }
    }

    pub fn get_node_hash_bytes(&self, block_id: u32, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        todo!()
    }

    pub fn get_node_hash_bytes_by_bhh(&self, bhh: &TTrieId, ptr: &TriePtr) -> Result<TrieHash, MarfError> {
        todo!()
    }

    pub fn read_all_block_hashes_and_roots(&self) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, TTrieId)>, MarfError> {
        todo!()
    }

    pub fn get_confirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError> {
        todo!()
    }

    pub fn get_unconfirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, MarfError> {
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

    pub fn update_external_trie_blob(
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

    pub fn get_external_trie_offset_length_by_bhh(&self, bhh: &TTrieId) -> Result<(u64, u64), MarfError> {
        todo!()
    }

    pub fn get_external_blobs_length(&self) -> Result<u64, MarfError> {
        todo!()
    }

    pub fn write_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob_to_mined(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        todo!()
    }

    pub fn write_trie_blob_to_unconfirmed(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, crate::MarfError> {
        todo!()
    }

    pub fn drop_lock(&self, bhh: &TTrieId) -> Result<(), crate::MarfError> {
        todo!()
    }

    pub fn lock_bhh_for_extension(
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

    pub fn drop_unconfirmed_trie(&self, bhh: &TTrieId) -> Result<(), MarfError> {
        todo!()
    }

    pub fn format(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    pub fn open_trie_blob(&self, block_id: u32) -> Result<std::io::Cursor<Vec<u8>>, MarfError> {
        todo!()
    }

    pub fn reopen_readonly(&self) -> Result<TrieIndex<'a, TTrieId>, MarfError> {
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
    pub fn read_all_block_hashes_and_offsets(&self) -> Result<Vec<(TTrieId, u64)>, MarfError> {
        todo!()
    }
}

impl<'a, TTrieId: MarfTrieId> BlockMap for TrieIndex<'a, TTrieId> {
    type TrieId = TTrieId;

    fn get_block_hash(&self, id: u32) -> Result<Self::TrieId, MarfError> {
        todo!()
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Self::TrieId, MarfError> {
        todo!()
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        todo!()
    }

    fn get_block_id(&self, bhh: &Self::TrieId) -> Result<u32, MarfError> {
        todo!()
    }

    fn get_block_id_caching(&mut self, bhh: &Self::TrieId) -> Result<u32, MarfError> {
        todo!()
    }
}