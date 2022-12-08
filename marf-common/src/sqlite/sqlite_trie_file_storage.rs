use std::{fs, io::{self, SeekFrom, Read}, env, path::Path};

use rusqlite::{Transaction, Connection, OpenFlags};

use crate::{
    MarfError, MarfOpenOpts, 
    storage::{TrieFile, TrieStorageTransientData, TrieStorageConnection, TrieStorageTransaction, TrieIndexProvider}, 
    MarfTrieId, diagnostics::TrieBenchmark, TrieCache, errors::DBError, tries::TrieHashCalculationMode, sqlite::SQL_MARF_SCHEMA_VERSION};

use super::{SqliteUtils, SqliteIndexProvider};


impl<TTrieId: MarfTrieId> SqliteTrieFileStorage<TTrieId> {
    pub fn sqlite_conn(&self) -> &Connection {
        &self.db
    }

    pub fn sqlite_tx<'a>(&'a mut self) -> Result<Transaction<'a>, DBError> {
        SqliteUtils::tx_begin_immediate(&mut self.db)
    }

    fn open_opts(
        &self,
        db_path: &str, 
        readonly: bool, 
        unconfirmed: bool, 
        marf_opts: MarfOpenOpts
    ) -> Result<&SqliteTrieFileStorage<TTrieId>, MarfError> 
    {
        let mut create_flag = false;
        let open_flags = if db_path != ":memory:" {
            match fs::metadata(db_path) {
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        // need to create
                        if !readonly {
                            create_flag = true;
                            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
                        } else {
                            return Err(MarfError::NotFoundError);
                        }
                    } else {
                        return Err(MarfError::IOError(e));
                    }
                }
                Ok(_md) => {
                    // can just open
                    if !readonly {
                        OpenFlags::SQLITE_OPEN_READ_WRITE
                    } else {
                        OpenFlags::SQLITE_OPEN_READ_ONLY
                    }
                }
            }
        } else {
            create_flag = true;
            if !readonly {
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_CREATE
            }
        };

        let mut db = SqliteUtils::marf_sqlite_open(db_path, open_flags, false)?;
        let db_path = db_path.to_string();

        let index = SqliteIndexProvider::new(&db);

        if create_flag {
            SqliteUtils::create_tables_if_needed(&mut &db)?;
        }

        let mut blobs = if marf_opts.external_blobs {
            Some(TrieFile::from_db_path(&db_path, readonly)?)
        } else {
            None
        };

        let prev_schema_version = SqliteUtils::migrate_tables_if_needed::<TTrieId>(&mut db)?;
        if prev_schema_version != SQL_MARF_SCHEMA_VERSION || marf_opts.force_db_migrate {
            if let Some(blobs) = blobs.as_mut() {
                if TrieFile::exists(&db_path)? {
                    // migrate blobs out of the old DB
                    //Self::export_trie_blobs(&dyn index, &db_path);
                    self.export_trie_blobs(&index, &db_path);
                }
            }
        }
        if SqliteUtils::detect_partial_migration(&db)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        debug!(
            "Opened TrieFileStorage {}; external blobs: {}",
            db_path,
            blobs.is_some()
        );

        let cache = TrieCache::new(&marf_opts.cache_strategy);
        let index = Box::new(SqliteIndexProvider::new(&db));

        let ret = SqliteTrieFileStorage::<TTrieId> {
            db_path,
            db,
            marf_opts,
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

                readonly,
                unconfirmed,
            },

            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            #[cfg(test)]
            test_genesis_block: None,
        };

        Ok(&ret)
    }

    /// Read a trie blob in its entirety from the DB
    fn read_trie_blob_from_db(db: &Connection, block_id: u32) -> Result<Vec<u8>, MarfError> {
        let trie_blob = {
            let mut fd = SqliteUtils::open_trie_blob_readonly(db, block_id)?;
            let mut trie_blob = vec![];
            fd.read_to_end(&mut trie_blob)?;
            trie_blob
        };
        Ok(trie_blob)
    }

    /// Vacuum the database and report the size before and after.
    ///
    /// Returns database errors.  Filesystem errors from reporting the file size change are masked.
    fn inner_post_migrate_vacuum(db: &Connection, db_path: &str) -> Result<(), MarfError> {
        // for fun, report the shrinkage
        let size_before_opt = fs::metadata(db_path)
            .map(|stat| Some(stat.len()))
            .unwrap_or(None);

        info!("Preemptively vacuuming the database file to free up space after copying trie blobs to a separate file");
        SqliteUtils::sql_vacuum(db)?;

        let size_after_opt = fs::metadata(db_path)
            .map(|stat| Some(stat.len()))
            .unwrap_or(None);

        match (size_before_opt, size_after_opt) {
            (Some(sz_before), Some(sz_after)) => {
                debug!("Shrank DB from {} to {} bytes", sz_before, sz_after);
            }
            _ => {}
        }

        Ok(())
    }

    /// Vacuum the database, and set up and tear down the necessary environment variables to
    /// use same parent directory for scratch space.
    ///
    /// Infallible -- any vacuum errors are masked.
    fn post_migrate_vacuum(db: &Connection, db_path: &str) {
        // set SQLITE_TMPDIR if it isn't set already
        let mut set_sqlite_tmpdir = false;
        let mut old_tmpdir_opt = None;
        if let Some(parent_path) = Path::new(db_path).parent() {
            if let Err(_) = env::var("SQLITE_TMPDIR") {
                debug!(
                    "Sqlite will store temporary migration state in '{}'",
                    parent_path.display()
                );
                env::set_var("SQLITE_TMPDIR", parent_path);
                set_sqlite_tmpdir = true;
            }

            // also set TMPDIR
            old_tmpdir_opt = env::var("TMPDIR").ok();
            env::set_var("TMPDIR", parent_path);
        }

        // don't materialize the error; just warn
        let res = Self::inner_post_migrate_vacuum(db, db_path);
        if let Err(e) = res {
            warn!("Failed to VACUUM the MARF DB post-migration: {:?}", &e);
        }

        if set_sqlite_tmpdir {
            debug!("Unset SQLITE_TMPDIR");
            env::remove_var("SQLITE_TMPDIR");
        }
        if let Some(old_tmpdir) = old_tmpdir_opt {
            debug!("Restore TMPDIR to '{}'", &old_tmpdir);
            env::set_var("TMPDIR", old_tmpdir);
        } else {
            debug!("Unset TMPDIR");
            env::remove_var("TMPDIR");
        }
    }

    /// Copy the trie blobs out of a sqlite3 DB into their own file.
    /// NOTE: this is *not* thread-safe.  Do not call while the DB is being used by another thread.
    pub fn export_trie_blobs(
        &mut self,
        index: &SqliteIndexProvider,
        db_path: &str,
    ) -> Result<(), MarfError> {
        if SqliteUtils::detect_partial_migration(&self.db)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        let max_block = index.count_blocks()?;
        info!(
            "Migrate {} blocks to external blob storage at {}",
            max_block,
            &self.get_path()
        );

        for block_id in 0..(max_block + 1) {
            match index.is_unconfirmed_block(block_id) {
                Ok(true) => {
                    test_debug!("Skip block_id {} since it's unconfirmed", block_id);
                    continue;
                }
                Err(MarfError::NotFoundError) => {
                    test_debug!("Skip block_id {} since it's not a block", block_id);
                    continue;
                }
                Ok(false) => {
                    // get the blob
                    let trie_blob = Self::read_trie_blob_from_db(&self.db, block_id)?;

                    // get the block ID
                    let bhh: TTrieId = index.get_block_hash(block_id)?;

                    // append the blob, replacing the current trie blob
                    if block_id % 1000 == 0 {
                        info!(
                            "Migrate block {} ({} of {}) to external blob storage",
                            &bhh, block_id, max_block
                        );
                    }

                    // append directly to file, so we can get the true offset
                    self.seek(SeekFrom::End(0))?;
                    let offset = self.stream_position()?;
                    self.write_all(&trie_blob)?;
                    self.flush()?;

                    test_debug!("Stored trie blob {} to offset {}", bhh, offset);
                    index.update_external_trie_blob(
                        &bhh,
                        offset,
                        trie_blob.len() as u64,
                        block_id,
                    )?;
                }
                Err(e) => {
                    test_debug!(
                        "Failed to determine if {} is unconfirmed: {:?}",
                        block_id,
                        &e
                    );
                    return Err(e);
                }
            }
        }

        Self::post_migrate_vacuum(&self.db, db_path);

        debug!("Mark MARF trie migration of '{}' as finished", db_path);
        SqliteUtils::set_migrated(&self.db).expect("FATAL: failed to mark DB as migrated");
        Ok(())
    }
}

impl<'a, TTrieId: MarfTrieId> TrieFileStorageTrait<'a, TTrieId> for SqliteTrieFileStorage<TTrieId> {
    fn connection(&mut self) -> TrieStorageConnection<TTrieId> {
        TrieStorageConnection::<TTrieId> {
            index: &*self.index,
            //index: &SqliteIndexProvider{db: SqliteUtils::marf_sqlite_open(&self.db_path, flags, foreign_keys)},
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

    fn transaction(&'a mut self) -> Result<TrieStorageTransaction<'a, TTrieId>, MarfError> {
        if self.is_readonly() {
            return Err(MarfError::ReadOnlyError);
        }

        let tx = SqliteUtils::tx_begin_immediate(&mut self.db)?;

        Ok(TrieStorageTransaction(TrieStorageConnection {
            index: self.index.as_ref(),
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

    fn open(&self, db_path: &str, marf_opts: crate::MarfOpenOpts) 
        -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError> 
    {
        SqliteTrieFileStorage::<TTrieId>::open_opts(self, db_path, false, false, marf_opts)
    }

    fn open_readonly(&self, db_path: &str, marf_opts: crate::MarfOpenOpts) 
        -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError> 
    {
        SqliteTrieFileStorage::<TTrieId>::open_opts(self, db_path, true, false, marf_opts)
    }

    fn open_unconfirmed(&self, db_path: &str, mut marf_opts: MarfOpenOpts) 
        -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError> 
    {
        // no caching allowed for unconfirmed tries, since they can disappear
        marf_opts.cache_strategy = "noop".to_string();
        SqliteTrieFileStorage::<TTrieId>::open_opts(self, db_path, false, true, marf_opts)
    }

    fn reopen_readonly(&self) -> Result<&dyn TrieFileStorageTrait<TTrieId>, MarfError> {
        SqliteTrieFileStorage::<TTrieId>::open_opts(self, &self.db_path, true, !self.data.unconfirmed, self.marf_opts.clone())
    }

    fn is_readonly(&self) -> bool {
        self.data.readonly
    }

    fn index(&self) -> &dyn TrieIndexProvider<TTrieId> {
        self.index.as_ref()
    }

    fn blobs(&self) -> Option<TrieFile> {
        self.blobs
    }

    fn data(&self) -> TrieStorageTransientData<TTrieId> {
        self.data
    }

    fn cache(&self) -> TrieCache<TTrieId> {
        self.cache
    }

    fn hash_calculation_mode(&self) -> crate::tries::TrieHashCalculationMode {
        self.hash_calculation_mode
    }

    // used in testing in order to short-circuit block-height lookups
    //   when the trie struct is tested outside of marf.rs usage
    #[cfg(test)]
    fn test_genesis_block(&self) -> Option<TTrieId> {
        self.test_genesis_block
    }

    
}