#[cfg(test)]
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::{MarfTrieId, MarfError};

pub trait BlockMap<TTrieId: MarfTrieId> {
    fn get_block_hash(&self, id: u32) -> Result<&TTrieId, MarfError>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&TTrieId, MarfError>;
    fn is_block_hash_cached(&self, id: u32) -> bool;
    fn get_block_id(&self, bhh: &TTrieId) -> Result<u32, MarfError>;
    fn get_block_id_caching(&mut self, bhh: &TTrieId) -> Result<u32, MarfError>;
}

#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

#[cfg(test)]
impl<TTrieId: MarfTrieId> BlockMap<TTrieId> for () {
    fn get_block_hash(&self, _id: u32) -> Result<BlockHeaderHash, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&BlockHeaderHash, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &BlockHeaderHash) -> Result<u32, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn get_block_id_caching(&mut self, _bhh: &BlockHeaderHash) -> Result<u32, MarfError> {
        Err(MarfError::NotFoundError)
    }
}