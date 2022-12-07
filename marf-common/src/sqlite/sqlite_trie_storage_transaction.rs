use stacks_common::types::chainstate::TrieHash;

use crate::{storage::{TrieStorageTransactionTrait, TrieFileStorageTrait}, MarfTrieId, MarfError};

use super::SqliteIndexProvider;

impl<'a, TTrieId, TIndex> TrieStorageTransactionTrait<TTrieId, TIndex> for SqliteIndexProvider<'a> 
    where TTrieId: MarfTrieId
{
    fn reopen_readonly(&self) -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError> {
        todo!()
    }

    fn flush(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    fn flush_to(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        todo!()
    }

    fn flush_mined(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        todo!()
    }

    fn drop_extending_trie(&mut self) {
        todo!()
    }

    fn drop_unconfirmed_trie(&mut self, bhh: &TTrieId) {
        todo!()
    }

    fn seal(&mut self) -> Result<TrieHash, MarfError> {
        todo!()
    }

    fn extend_to_block(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        todo!()
    }

    fn extend_to_unconfirmed_block(&mut self, bhh: &TTrieId) -> Result<bool, MarfError> {
        todo!()
    }

    fn format(&mut self) -> Result<(), MarfError> {
        todo!()
    }

    fn commit_tx(self) {
        todo!()
    }

    fn rollback(self) {
        todo!()
    }
}