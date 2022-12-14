use std::io::Write;

use crate::{MarfTrieId, tries::TriePtr, MarfError, TrieCache, BlockMap, index::TrieIndex};

use super::{NodeHashReader};

pub struct TrieCursor<'a> {
    index: &'a mut TrieIndex,
    block_id: u32,
}

impl NodeHashReader for TrieCursor<'_> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), MarfError> {
        self.index.read_node_hash_bytes(w, self.block_id, ptr)
    }
}

pub struct TrieHashMapCursor<'a, TTrieId: MarfTrieId> {
    index: &'a TrieIndex,
    cache: &'a mut TrieCache<TTrieId>,
    unconfirmed: bool,
}

impl<T: MarfTrieId> BlockMap<T> for TrieHashMapCursor<'_, T> {

    fn get_block_hash(&self, id: u32) -> Result<T, MarfError> {
        self.index.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, MarfError> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &T) -> Result<u32, MarfError> {
        self.index.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &T) -> Result<u32, MarfError> {
        // don't use the cache if we're unconfirmed
        if self.unconfirmed {
            self.get_block_id(block_hash)
        } else {
            if let Some(block_id) = self.cache.load_block_id(block_hash) {
                Ok(block_id)
            } else {
                let block_id = self.get_block_id(block_hash)?;
                self.cache.store_block_hash(block_id, block_hash.clone());
                Ok(block_id)
            }
        }
    }
}