use std::{fs, io};

use rusqlite::{Transaction, Connection, OpenFlags, Error as SqliteError};

use crate::{
    MarfError, MarfOpenOpts, 
    storage::{TrieFileStorage, TrieFile, TrieStorageTransientData, TrieFileStorageTrait, TrieStorageConnection, TrieStorageTransaction, TrieIndexProvider}, 
    MarfTrieId, diagnostics::TrieBenchmark, TrieCache};

use super::{SqliteUtils, SqliteConnection, SqliteIndexProvider};

pub struct SqliteTrieFileStorage<TTrieId: MarfTrieId> {
    pub db: Connection,
    pub trie_id: TTrieId,
    pub index: SqliteIndexProvider
}

impl<TTrieId: MarfTrieId> SqliteTrieFileStorage<TTrieId> {
    pub fn sqlite_conn(&self) -> &Connection {
        &self.db
    }

    pub fn sqlite_tx<'a>(&'a mut self) -> Result<Transaction<'a>, SqliteError> {
        SqliteUtils::tx_begin_immediate(&mut self.db)
    }

    fn open_opts(
        &self,
        db_path: &str,
        readonly: bool,
        unconfirmed: bool,
        marf_opts: MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, SqliteIndexProvider>, MarfError> {
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

        let mut index = SqliteUtils::marf_sqlite_open(db_path, open_flags, false)?;
        let db_path = db_path.to_string();

        if create_flag {
            SqliteUtils::create_tables_if_needed(&mut &self.db)?;
        }

        let mut blobs = if marf_opts.external_blobs {
            Some(TrieFile::from_db_path(&db_path, readonly)?)
        } else {
            None
        };

        let prev_schema_version = SqliteUtils::migrate_tables_if_needed::<TTrieId>(&mut self.db)?;
        if prev_schema_version != SqliteUtils::SQL_MARF_SCHEMA_VERSION || marf_opts.force_db_migrate {
            if let Some(blobs) = blobs.as_mut() {
                if TrieFile::exists(&db_path)? {
                    // migrate blobs out of the old DB
                    blobs.export_trie_blobs::<TTrieId>(&self.db, &db_path)?;
                }
            }
        }
        if SqliteUtils::detect_partial_migration(&index)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        debug!(
            "Opened TrieFileStorage {}; external blobs: {}",
            db_path,
            blobs.is_some()
        );

        let cache = TrieCache::new(&marf_opts.cache_strategy);

        let ret = TrieFileStorage {
            db_path,
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
}

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> TrieFileStorageTrait<TTrieId, TIndex> for SqliteTrieFileStorage<TTrieId> {
    fn connection<'a>(&'a mut self) -> TrieStorageConnection<'a, TTrieId, TIndex> {
        TrieStorageTransaction::storage::connection {
            //index: SqliteConnection::ConnRef(&self.db),crate::storage::
            index: &SqliteIndexProvider::new(),
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

    fn transaction<'a>(&'a mut self) -> Result<TrieStorageTransaction<'a, TTrieId, SqliteIndexProvider>, MarfError> {
        if self.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        let tx = SqliteUtils::tx_begin_immediate(&mut self.db)?;

        Ok(TrieStorageTransaction(TrieStorageConnection {
            index: SqliteConnection::Tx(tx),
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

    fn open(db_path: &str, marf_opts: crate::MarfOpenOpts) -> Result<crate::storage::TrieFileStorage<TTrieId, SqliteIndexProvider>, crate::MarfError> {
        SqliteTrieFileStorage::open_opts(Self, db_path, false, false, marf_opts)
    }

    fn open_readonly(
        db_path: &str,
        marf_opts: crate::MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, SqliteIndexProvider>, crate::MarfError> {
        SqliteTrieFileStorage::open_opts(Self, db_path, true, false, marf_opts)
    }

    fn open_unconfirmed(
        db_path: &str,
        mut marf_opts: crate::MarfOpenOpts,
    ) -> Result<TrieFileStorage<TTrieId, SqliteIndexProvider>, crate::MarfError> {
        // no caching allowed for unconfirmed tries, since they can disappear
        marf_opts.cache_strategy = "noop".to_string();
        SqliteTrieFileStorage::open_opts(Self, db_path, false, true, marf_opts)
    }

    fn reopen_readonly(&self) -> Result<TrieFileStorage<TTrieId, SqliteIndexProvider>, crate::MarfError> {
        let index = SqliteUtils::marf_sqlite_open(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY, false)?;
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
            index: index,
            blobs,
            cache: cache,
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

    
}