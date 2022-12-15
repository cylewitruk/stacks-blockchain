use std::{
    io::{Write, SeekFrom, Seek}
};

use crate::{tries::TriePtr, MarfError, utils::Utils, index::TrieIndex, MarfTrieId};

use super::{NodeHashReader, TrieFile};

/// NodeHashReader for TrieFile
pub struct TrieFileNodeHashReader<'a, TTrieId> 
    where TTrieId: MarfTrieId 
{
    db: &'a mut TrieIndex<'a, TTrieId>,
    file: &'a mut TrieFile,
    block_id: u32
}

impl<'a, TTrieId> TrieFileNodeHashReader<'a, TTrieId> 
    where TTrieId: MarfTrieId 
{
    pub fn new(
        db: &'a mut TrieIndex<'a, TTrieId>,
        file: &'a mut TrieFile,
        block_id: u32,
    ) -> TrieFileNodeHashReader<'a, TTrieId> {
        TrieFileNodeHashReader { db, file, block_id }
    }
}

impl<'a, TTrieId> NodeHashReader for TrieFileNodeHashReader<'a, TTrieId> 
    where TTrieId: MarfTrieId 
{
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), MarfError> {
        let trie_offset = self.file.get_trie_offset(self.db, self.block_id)?;
        self.file
            .seek(SeekFrom::Start(trie_offset + (ptr.ptr() as u64)))?;
        let hash_buff = Utils::read_hash_bytes(self.file)?;
        w.write_all(&hash_buff).map_err(|e| e.into())
    }
}