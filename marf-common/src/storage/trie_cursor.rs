use std::io::Write;

use crate::{MarfTrieId, tries::TriePtr, MarfError, TrieCache};

use super::{TrieIndexProvider, NodeHashReader};

pub struct TrieCursor<'a, TTrieId: MarfTrieId> {
    index: &'a dyn TrieIndexProvider<TTrieId>,
    block_id: u32,
}

impl<TTrieId: MarfTrieId> NodeHashReader for TrieCursor<'_, TTrieId> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), MarfError> {
        self.index.read_node_hash_bytes(&mut w, self.block_id, ptr)
    }
}

pub struct TrieHashMapCursor<'a, TTrieId: MarfTrieId> {
    index: &'a dyn TrieIndexProvider<TTrieId>,
    cache: &'a mut TrieCache<TTrieId>,
    unconfirmed: bool,
}