#[cfg(test)]
use stacks_common::types::chainstate::BlockHeaderHash;

use crate::{MarfError, MarfTrieId};

pub trait BlockMap<T: MarfTrieId> {
    fn get_block_hash(&self, id: u32) -> Result<T, MarfError>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&T, MarfError>;
    fn is_block_hash_cached(&self, id: u32) -> bool;
    fn get_block_id(&self, bhh: &T) -> Result<u32, MarfError>;
    fn get_block_id_caching(&mut self, bhh: &T) -> Result<u32, MarfError>;
}

#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

#[cfg(test)]
impl<T: MarfTrieId> BlockMap<T> for () {
    fn get_block_hash(&self, _id: u32) -> Result<T, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&T, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &T) -> Result<u32, MarfError> {
        Err(MarfError::NotFoundError)
    }
    fn get_block_id_caching(&mut self, _bhh: &T) -> Result<u32, MarfError> {
        Err(MarfError::NotFoundError)
    }
}