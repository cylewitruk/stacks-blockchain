use std::io::{Write, SeekFrom};

use crate::{tries::TriePtr, MarfError, utils::Utils};

use super::{TrieIndexProvider, NodeHashReader, TrieFile};

/// NodeHashReader for TrieFile
pub struct TrieFileNodeHashReader<'a, TIndex: TrieIndexProvider> {
    db: &'a TIndex,
    file: &'a mut TrieFile,
    block_id: u32,
}

impl<'a, TIndex: TrieIndexProvider> TrieFileNodeHashReader<'a, TIndex> {
    pub fn new(
        db: &'a TIndex,
        file: &'a mut TrieFile,
        block_id: u32,
    ) -> TrieFileNodeHashReader<'a, TIndex> {
        TrieFileNodeHashReader { db, file, block_id }
    }
}

impl<TIndex: TrieIndexProvider> NodeHashReader for TrieFileNodeHashReader<'_, TIndex> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), MarfError> {
        let trie_offset = self.file.get_trie_offset(self.db, self.block_id)?;
        self.file
            .seek(SeekFrom::Start(trie_offset + (ptr.ptr() as u64)))?;
        let hash_buff = Utils::read_hash_bytes(self.file)?;
        w.write_all(&hash_buff).map_err(|e| e.into())
    }
}