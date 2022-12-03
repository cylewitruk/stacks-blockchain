use std::ops::{Deref, DerefMut};

use crate::{MarfTrieId, BlockMap, MarfError};

use super::{TrieStorageConnection, TrieIndexProvider};

///
/// TrieStorageTransaction is a pointer to an open TrieFileStorage with an
///   open SQLite transaction. Any storage methods which require a transaction
///   are defined _only_ for this struct (e.g., the flush methods).
///
pub struct TrieStorageTransaction<'a, TTrieId, TIndex>(TrieStorageConnection<'a, TTrieId, TIndex>) 
    where 
        TTrieId: MarfTrieId, 
        TIndex: TrieIndexProvider;

impl<'a, TTrieId: MarfTrieId, TIndex: TrieIndexProvider> Deref for TrieStorageTransaction<'a, TTrieId, TIndex> {
    type Target = TrieStorageConnection<'a, TTrieId, TIndex>;
    fn deref(&self) -> &TrieStorageConnection<'a, TTrieId, TIndex> {
        &self.0
    }
}

impl<'a, TTrieId: MarfTrieId, TIndex: TrieIndexProvider> DerefMut for TrieStorageTransaction<'a, TTrieId, TIndex> {
    fn deref_mut(&mut self) -> &mut TrieStorageConnection<'a, TTrieId, &mut dyn TrieIndexProvider> {
        &mut self.0
    }
}

impl<'a, TTrieId: MarfTrieId, TIndex: TrieIndexProvider> BlockMap for TrieStorageTransaction<'a, TTrieId, TIndex> {
    type TrieId = TTrieId;

    fn get_block_hash(&self, id: u32) -> Result<TTrieId, MarfError> {
        self.deref().get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&TTrieId, MarfError> {
        self.deref_mut().get_block_hash_caching(id)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.deref().is_block_hash_cached(id)
    }

    fn get_block_id(&self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        self.deref().get_block_id(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        self.deref_mut().get_block_id_caching(block_hash)
    }
}