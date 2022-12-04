use crate::{MarfTrieId, MarfError, storage::TrieStorageTransientData, BlockMap, marf_open_opts::MarfOpenOpts, TrieCache, tries::TrieHashCalculationMode, diagnostics::TrieBenchmark};

use super::{TrieStorageConnection, TrieStorageTransaction, TrieIndexProvider, TrieFile};

pub struct TrieFileStorage<TTrieId, TIndex>
    where
        TTrieId: MarfTrieId,
        TIndex: TrieIndexProvider<TTrieId>
{
    pub db_path: String,

    index: TIndex,
    blobs: Option<TrieFile>,
    data: TrieStorageTransientData<TTrieId>,
    cache: TrieCache<TTrieId>,
    bench: TrieBenchmark,
    hash_calculation_mode: TrieHashCalculationMode,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<TTrieId>,
}

pub trait TrieFileStorageTrait<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>> {

    fn connection<'a>(&'a mut self) -> TrieStorageConnection<'a, TTrieId, TIndex>;
    fn transaction<'a>(&'a mut self) -> Result<TrieStorageTransaction<'a, TTrieId, TIndex>, MarfError>;
    fn open(db_path: &str, marf_opts: MarfOpenOpts) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError>;
    fn open_readonly(
        db_path: &str,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError>;
    fn open_unconfirmed(
        db_path: &str,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError>;

    /// Returns a new TrieFileStorage in read-only mode.
    ///
    /// Returns Err if the underlying SQLite database connection cannot be created.
    fn reopen_readonly(&self) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError>;
}

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>> TrieFileStorage<TTrieId, TIndex> {

    #[cfg(test)]
    pub fn new_memory(marf_opts: MarfOpenOpts) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError> {
        TrieFileStorage::open(":memory:", marf_opts)
    }

    pub fn open_readonly(
        db_path: &str,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError> {
        
    }

    pub fn readonly(&self) -> bool {
        self.data.readonly
    }

    /// Return true if this storage connection was opened with the intention of operating on an
    /// unconfirmed trie -- i.e. this is a storage connection for reading and writing a persisted
    /// scratch space trie, such as one for storing unconfirmed microblock transactions in the
    /// chain state.
    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    pub fn get_benchmarks(&self) -> TrieBenchmark {
        self.bench.clone()
    }

    pub fn bench_mut(&mut self) -> &mut TrieBenchmark {
        &mut self.bench
    }

    pub fn reset_benchmarks(&mut self) {
        self.bench.reset();
    }
}

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>> BlockMap for TrieFileStorage<TTrieId, TIndex> {
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