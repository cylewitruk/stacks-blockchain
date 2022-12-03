#[cfg(test)]
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::{MarfTrieId, MarfError};

pub trait BlockMap {
    type TrieId: MarfTrieId;
    fn get_block_hash(&self, id: u32) -> Result<Self::TrieId, MarfError>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Self::TrieId, MarfError>;
    fn is_block_hash_cached(&self, id: u32) -> bool;
    fn get_block_id(&self, bhh: &Self::TrieId) -> Result<u32, MarfError>;
    fn get_block_id_caching(&mut self, bhh: &Self::TrieId) -> Result<u32, MarfError>;
}

#[cfg(test)]
impl BlockMap for () {
    type TrieId = BlockHeaderHash;
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