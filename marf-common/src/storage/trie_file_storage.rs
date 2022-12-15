use crate::{
    MarfTrieId, MarfError, storage::{TrieStorageTransientData}, BlockMap, 
    TrieCache, tries::TrieHashCalculationMode, diagnostics::TrieBenchmark, MarfOpenOpts, sqlite::SqliteIndexProvider, index::{TrieIndex, TrieIndexType}
};

use super::{TrieFile, TrieStorageConnection, TrieStorageTransaction};

pub struct TrieFileStorage<'a, TTrieId>
{
    pub db_path: String,

    pub index: TrieIndex<'a, TTrieId>,
    pub blobs: Option<TrieFile>,
    pub data: TrieStorageTransientData<TTrieId>,
    pub cache: TrieCache<TTrieId>,
    pub bench: TrieBenchmark,
    pub hash_calculation_mode: TrieHashCalculationMode,

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    pub test_genesis_block: Option<TTrieId>,
}

impl<'a, TTrieId: MarfTrieId> TrieFileStorage<'a, TTrieId> {
    pub fn connection(&mut self) -> TrieStorageConnection<TTrieId> {
        TrieStorageConnection {
            index: &self.index,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            unconfirmed_block_id: None,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        }
    }

    pub fn transaction(&mut self) -> Result<TrieStorageTransaction<TTrieId>, MarfError> {
        if self.is_readonly() {
            return Err(MarfError::ReadOnlyError);
        }

        self.index.begin_transaction();

        Ok(TrieStorageTransaction(TrieStorageConnection {
            index: &self.index,
            db_path: &self.db_path,
            data: &mut self.data,
            blobs: self.blobs.as_mut(),
            cache: &mut self.cache,
            bench: &mut self.bench,
            hash_calculation_mode: self.hash_calculation_mode,
            unconfirmed_block_id: None,

            #[cfg(test)]
            test_genesis_block: &mut self.test_genesis_block,
        }))
    }

    fn open_opts(
        db_path: &str,
        readonly: bool,
        unconfirmed: bool,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        let mut create_flag = false;
        let index = match marf_opts.trie_index_type {
            TrieIndexType::SQLite => {
                TrieIndex::SQLite(SqliteIndexProvider::new_from_db_path(&format!("{}.sqlite", db_path), readonly, &marf_opts).unwrap())
            },
            TrieIndexType::RocksDB => todo!()
        };

        // Create tables if needed

        let blobs = if marf_opts.external_blobs {
            Some(TrieFile::from_db_path(&db_path, readonly)?)
        } else {
            None
        };

        // Migrate tables if needed

        debug!(
            "Opened TrieFileStorage {}; external blobs: {}",
            db_path,
            blobs.is_some()
        );

        let cache = TrieCache::new(&marf_opts.cache_strategy);

        let ret = TrieFileStorage {
            db_path: db_path.to_string(),
            index,
            cache,
            blobs,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: marf_opts.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: None,
                cur_block: TTrieId::sentinel(),
                cur_block_id: None,

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                readonly: readonly,
                unconfirmed: unconfirmed,
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: None,
        };

        Ok(ret)
    }

    #[cfg(test)]
    pub fn new_memory(marf_opts: MarfOpenOpts) -> Result<TrieFileStorage<'a, TTrieId>, MarfError> {
        TrieFileStorage::open(":memory:", marf_opts)
    }

    pub fn open(db_path: &str, marf_opts: MarfOpenOpts) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        TrieFileStorage::open_opts(db_path, false, false, marf_opts)
    }

    pub fn open_readonly(
        db_path: &str,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        TrieFileStorage::open_opts(db_path, true, false, marf_opts)
    }

    pub fn open_unconfirmed(
        db_path: &str,
        mut marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        // no caching allowed for unconfirmed tries, since they can disappear
        marf_opts.cache_strategy = "noop".to_string();
        TrieFileStorage::open_opts(db_path, false, true, marf_opts)
    }

    pub fn is_readonly(&self) -> bool {
        self.data.readonly
    }

    /// Return true if this storage connection was opened with the intention of operating on an
    /// unconfirmed trie -- i.e. this is a storage connection for reading and writing a persisted
    /// scratch space trie, such as one for storing unconfirmed microblock transactions in the
    /// chain state.
    pub fn unconfirmed(&self) -> bool {
        self.data.unconfirmed
    }

    /// Returns a new TrieFileStorage in read-only mode.
    ///
    /// Returns Err if the underlying SQLite database connection cannot be created.
    pub fn reopen_readonly(&mut self) -> Result<TrieFileStorage<TTrieId>, MarfError> {
        let mut db = self.index.reopen_readonly()?;
        let cache = TrieCache::default();
        let blobs = if self.blobs.is_some() {
            Some(TrieFile::from_db_path(&self.db_path, true)?)
        } else {
            None
        };

        trace!("Make read-only view of TrieFileStorage: {}", &self.db_path);

        // TODO: borrow self.uncommitted_writes; don't copy them
        let ret = TrieFileStorage {
            db_path: self.db_path.clone(),
            index: db,
            blobs,
            cache,
            bench: TrieBenchmark::new(),
            hash_calculation_mode: self.hash_calculation_mode,

            data: TrieStorageTransientData {
                uncommitted_writes: self.data.uncommitted_writes.clone(),
                cur_block: self.data.cur_block.clone(),
                cur_block_id: self.data.cur_block_id.clone(),

                read_count: 0,
                read_backptr_count: 0,
                read_node_count: 0,
                read_leaf_count: 0,

                write_count: 0,
                write_node_count: 0,
                write_leaf_count: 0,

                trie_ancestor_hash_bytes_cache: None,

                readonly: true,
                unconfirmed: self.unconfirmed(),
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: self.test_genesis_block.clone(),
        };

        Ok(ret)
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

impl<'a, TTrieId: MarfTrieId> BlockMap for TrieFileStorage<'a, TTrieId> {
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