use crate::{MarfError, MarfTrieId};

pub trait TrieIndexProvider {
    fn new() -> Self;
    fn get_block_hash<T: MarfTrieId>(&self, local_id: u32) -> Result<T, MarfError>;
    fn get_block_identifier<T: MarfTrieId>(&self, bhh: &T) -> Result<u32, MarfError>;
}