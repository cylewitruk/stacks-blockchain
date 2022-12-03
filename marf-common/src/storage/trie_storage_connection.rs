use crate::{MarfTrieId, BlockMap, MarfError, TrieCache, tries::TrieHashCalculationMode, diagnostics::TrieBenchmark};

use super::{TrieStorageTransientData, TrieIndexProvider, TrieFile};

///
///  TrieStorageConnection is a pointer to an open TrieFileStorage,
///    with either a SQLite &Connection (non-mut, so it cannot start a TX)
///    or a Transaction. Mutations on TrieStorageConnection's `data` field
///    propagate to the TrieFileStorage that created the connection.
///  This is the main interface to the storage methods, and defines most
///    of the storage functionality.
///
pub struct TrieStorageConnection<'a, TTrieId, TIndex>
    where
        TTrieId: MarfTrieId, 
        TIndex: TrieIndexProvider
{
    pub db_path: &'a str,
    index: &'a TIndex,
    blobs: Option<&'a mut TrieFile>,
    data: &'a mut TrieStorageTransientData<TTrieId, TIndex>,
    cache: &'a mut TrieCache<TTrieId>,
    bench: &'a mut TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,

    /// row ID of a trie that represents unconfirmed state (i.e. trie state that will never become
    /// part of the MARF, but nevertheless represents a persistent scratch space).  If this field
    /// is Some(..), then the storage connection here was used to (re-)open an unconfirmed trie
    /// (via `open_unconfirmed()` or `open_block()` when `self.unconfirmed()` is `true`), or used
    /// to create an unconfirmed trie (via `extend_to_unconfirmed_block()`).
    unconfirmed_block_id: Option<u32>,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: &'a mut Option<TTrieId>,
}

impl<'a, TTrieId: MarfTrieId, TIndex: TrieIndexProvider> BlockMap for TrieStorageConnection<'a, TTrieId, TIndex> {
    type TrieId = TTrieId;

    fn get_block_hash(&self, id: u32) -> Result<TTrieId, MarfError> {
        //trie_sql::get_block_hash(&self.db, id)
        self.index.get_block_hash(id)
    }

    fn get_block_hash_caching(&mut self, id: u32) -> Result<&TTrieId, MarfError> {
        if !self.is_block_hash_cached(id) {
            let block_hash = self.get_block_hash(id)?;
            self.cache.store_block_hash(id, block_hash.clone());
        }
        self.cache.ref_block_hash(id).ok_or(MarfError::NotFoundError)
    }

    fn is_block_hash_cached(&self, id: u32) -> bool {
        self.cache.ref_block_hash(id).is_some()
    }

    fn get_block_id(&self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        //trie_sql::get_block_identifier(&self.db, block_hash)
        self.index.get_block_identifier(block_hash)
    }

    fn get_block_id_caching(&mut self, block_hash: &TTrieId) -> Result<u32, MarfError> {
        // don't use the cache if we're unconfirmed
        if self.data.unconfirmed {
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