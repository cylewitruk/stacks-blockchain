use std::ops::{Deref, DerefMut};

use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, BlockMap, MarfError};

use super::{TrieStorageConnection, TrieIndexProvider, TrieFileStorageTrait};

pub trait TrieStorageTransactionTrait<TTrieId, TIndex>
    where TTrieId: MarfTrieId
{
    /// reopen this transaction as a read-only marf.
    ///  _does not_ preserve the cur_block/open tip
    fn reopen_readonly(&self) -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError>;

    /// Flush uncommitted state to disk.
    fn flush(&mut self) -> Result<(), MarfError>;

    /// Flush uncommitted state to disk, but under the given block hash.
    fn flush_to(&mut self, bhh: &TTrieId) -> Result<(), MarfError>;

    /// Flush uncommitted state to disk for a mined block (i.e. not part of the chainstate, and not
    /// an ancestor of any block), and do so under a given block hash.
    fn flush_mined(&mut self, bhh: &TTrieId) -> Result<(), MarfError>;

    /// Drop the uncommitted state and any associated cached state.
    fn drop_extending_trie(&mut self);

    /// Drop the unconfirmed state and uncommitted state.
    fn drop_unconfirmed_trie(&mut self, bhh: &TTrieId);

    /// Seal the inner uncommitted TrieRAM and return the MARF root hash.
    /// Only works if there's an uncommitted TrieRAM extension; panics if not.
    fn seal(&mut self) -> Result<TrieHash, MarfError>;

    /// Extend the forest of Tries to include a new confirmed block.
    /// Fails if the block already exists, or if the storage is read-only, or open
    /// only for unconfirmed state.
    fn extend_to_block(&mut self, bhh: &TTrieId) -> Result<(), MarfError>;

    /// Extend the forest of Tries to include a new unconfirmed block.
    /// If the unconfirmed block (bhh) already exists, then load up its trie as the uncommitted_writes
    /// trie.
    fn extend_to_unconfirmed_block(&mut self, bhh: &TTrieId) -> Result<bool, MarfError>;

    /// Clear out the underlying storage.
    fn format(&mut self) -> Result<(), MarfError>;

    fn commit_tx(self);

    fn rollback(self);
}

///
/// TrieStorageTransaction is a pointer to an open TrieFileStorage with an
///   open SQLite transaction. Any storage methods which require a transaction
///   are defined _only_ for this struct (e.g., the flush methods).
///
pub struct TrieStorageTransaction<'a, TTrieId>(pub TrieStorageConnection<'a, TTrieId>) 
    where TTrieId: MarfTrieId;

impl<'a, TTrieId: MarfTrieId> Deref for TrieStorageTransaction<'a, TTrieId> {
    type Target = TrieStorageConnection<'a, TTrieId>;
    fn deref(&self) -> &TrieStorageConnection<'a, TTrieId> {
        &self.0
    }
}

impl<'a, TTrieId: MarfTrieId> DerefMut for TrieStorageTransaction<'a, TTrieId> {
    fn deref_mut(&mut self) -> &mut TrieStorageConnection<'a, TTrieId> {
        &mut self.0
    }
}

impl<'a, TTrieId: MarfTrieId> BlockMap for TrieStorageTransaction<'a, TTrieId> {
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