use std::{fs, io::{self, Read, Seek}};

use rusqlite::{Connection, NO_PARAMS, ToSql, OptionalExtension, Transaction, OpenFlags, blob::Blob};
use stacks_common::types::chainstate::TrieHash;

use crate::{storage::{TrieIndexProvider, TrieStorageConnection, TrieBlob, TrieFile}, MarfError, utils::Utils, MarfTrieId, MarfOpenOpts};

use super::SqliteUtils;

pub struct SqliteIndexProvider<'a> {
    db_path: &'a str,
    db: Connection,
    tx: &'a mut Option<&'a mut Transaction<'a>>,
    marf_opts: &'a MarfOpenOpts
}

impl<'a> SqliteIndexProvider<'a> {
    /// Returns a new instance of `SqliteIndexProvider` using the provided `rusqlite::Connection`.
    fn new(db_path: &str, db: Connection, marf_opts: &MarfOpenOpts) -> Self {
        SqliteIndexProvider { db, tx: &mut None, db_path, marf_opts }
    }

    /// Returns a new memory-backed instance of `SqliteIndexProvider` (no data will be persisted to disk).
    pub fn new_memory(marf_opts: &MarfOpenOpts) -> Result<Self, MarfError> {
        let db_path = ":memory:";
        let db = Self::sqlite_open(db_path, false, marf_opts)?;
        Ok(SqliteIndexProvider::new(db_path, db, &marf_opts))
    }

    /// Returns a new disk-backed instance of `SqliteIndexProvider` using the provided database filepath.
    pub fn new_from_db_path(db_path: &str, readonly: bool, marf_opts: &MarfOpenOpts) -> Result<Self, MarfError> {
        let db = Self::sqlite_open(db_path, readonly, marf_opts)?;
        Ok(SqliteIndexProvider::new(db_path, db, &marf_opts))
    }

    /// Helper method to create the correct SQLite open flags.
    fn sqlite_open(db_path: &str, readonly: bool, marf_opts: &MarfOpenOpts) -> Result<Connection, MarfError> {
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

        // Create tables if needed
        if create_flag {
            SqliteUtils::create_tables_if_needed(&mut db)?;
        }

        // Migrate db if needed
        let prev_schema_version = SqliteUtils::migrate_tables_if_needed(&mut db)?;
        if prev_schema_version != super::SQL_MARF_SCHEMA_VERSION || marf_opts.force_db_migrate {
            if let Some(blobs) = blobs.as_mut() {
                if TrieFile::exists(&db_path)? {
                    // migrate blobs out of the old DB
                    blobs.export_trie_blobs::(&db, &db_path)?;
                }
            }
        }
        if SqliteUtils::detect_partial_migration(&db)? {
            panic!("PARTIAL MIGRATION DETECTED! This is an irrecoverable error. You will need to restart your node from genesis.");
        }

        Ok(db)
    }

    /// Recover from partially-written state -- i.e. blow it away.
    /// Doesn't get called automatically.
    pub fn recover(db_path: &String) -> Result<(), MarfError> {
        let conn = SqliteUtils::marf_sqlite_open(db_path, OpenFlags::SQLITE_OPEN_READ_WRITE, false)?;
        SqliteUtils::clear_lock_data(&conn)?;
        Ok(())
    }

    /// Returns true if this provider has an open transaction towards the underlying store, otherwise false.
    pub fn has_transaction(&self) -> bool {
        !self.tx.is_none()
    }

    /// Returns the currently open transaction.  Panics if there is no active transaction.
    pub (in crate::sqlite) fn sqlite_get_active_transaction(self) -> &'a mut Transaction<'a> {
        if !self.has_transaction() {
            panic!("BUG: Attempted to fetch SQLite transaction without an active transaction.")
        }

        self.tx.unwrap()
    }

    /// Begins a new SQLite transaction and sets the `tx` field on this struct.
    pub (in crate::sqlite) fn sqlite_begin_transaction(&mut self) -> Result<&mut Transaction, MarfError> {
        if self.has_transaction() {
            panic!("BUG: Attempted to begin SQLite transaction when one already exists.")
        }

        let trx = self.db.transaction()?;

        self.tx = &mut Some(&mut trx);

        Ok(&mut trx)
    }

    /// Commits the currently active transaction and unsets the `tx` field on this struct.
    pub (in crate::sqlite) fn sqlite_commit(&mut self) {
        if !self.has_transaction() {
            panic!("BUG: Attempted to commit SQLite transaction without an active transaction.")
        }

        self.tx.unwrap().commit()
            .expect("CORRUPTION: Failed to commit MARF.");
        self.tx = &mut None;
    }

    /// Rolls-back the currently active transaction and unsets the `tx` field on this struct.
    pub (in crate::sqlite) fn sqlite_rollback(&mut self) {
        if !self.has_transaction() {
            panic!("BUG: Attempted to rollback SQLite transaction without an active transaction.")
        }

        self.tx.unwrap().rollback()
            .expect("CORRUPTION: Failed to rollback MARF.")
    }

    /// Write the offset/length of a trie blob that was stored to an external file.
    /// Do this only once the trie is actually stored, since only the presence of this information is
    /// what guarantees that the blob is persisted.
    /// If block_id is Some(..), then an existing block ID's metadata will be updated.  Otherwise, a
    /// new row will be created.
    fn inner_write_external_trie_blob<T: MarfTrieId>(
        &self,
        block_hash: &T,
        offset: u64,
        length: u64,
        block_id: Option<u32>,
    ) -> Result<u32, MarfError> {
        let block_id = if let Some(block_id) = block_id {
            // existing entry (i.e. a migration)
            let empty_blob: &[u8] = &[];
            let args: &[&dyn ToSql] = &[
                block_hash,
                &empty_blob,
                &0,
                &SqliteUtils::u64_to_sql(offset)?,
                &SqliteUtils::u64_to_sql(length)?,
                &block_id,
            ];
            let mut s =
                self.db.prepare("UPDATE marf_data SET block_hash = ?1, data = ?2, unconfirmed = ?3, external_offset = ?4, external_length = ?5 WHERE block_id = ?6")?;
            s.execute(args)?;

            debug!(
                "Replaced block trie {} at rowid {} offset {}",
                block_hash, block_id, offset
            );
            block_id
        } else {
            // new entry
            let empty_blob: &[u8] = &[];
            let args: &[&dyn ToSql] = &[
                block_hash,
                &empty_blob,
                &0,
                &SqliteUtils::u64_to_sql(offset)?,
                &SqliteUtils::u64_to_sql(length)?,
            ];
            let mut s =
                self.db.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
            let block_id = s
                .insert(args)?
                .try_into()
                .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

            debug!(
                "Wrote block trie {} to rowid {} offset {}",
                block_hash, block_id, offset
            );
            block_id
        };

        Ok(block_id)
    }
}

impl<'a, TTrieId: MarfTrieId> TrieIndexProvider<TTrieId> for SqliteIndexProvider<'a> {
    /// Retrieves the block hash for the specified block id.
    fn get_block_hash(&self, local_id: u32) -> Result<TTrieId, crate::MarfError> {
        let result = self.db
            .query_row(
                "SELECT block_hash FROM marf_data WHERE block_id = ?",
                &[local_id],
                |row| row.get("block_hash"),
            )
            .optional()?;
            
        result.ok_or_else(|| {
            error!("Failed to get block header hash of local ID {}", local_id);
            MarfError::NotFoundError
        })
    }

    fn get_block_identifier(&self, bhh: &TTrieId) -> Result<u32, crate::MarfError> {
        self.db.query_row(
                "SELECT block_id FROM marf_data WHERE block_hash = ?",
                &[bhh],
                |row| row.get("block_id"),
            )
            .map_err(|e| e.into())
    }

    fn get_node_hash_bytes(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        let mut blob = self.db.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            block_id.into(),
            true,
        )?;

        let hash_buff = Utils::read_node_hash_bytes(&mut blob, ptr)?;

        Ok(TrieHash(hash_buff))
    }

    fn get_node_hash_bytes_by_bhh(&self, bhh: &TTrieId, ptr: &crate::tries::TriePtr) -> Result<stacks_common::types::chainstate::TrieHash, crate::MarfError> {
        let row_id: i64 = self.db.query_row(
            "SELECT block_id FROM marf_data WHERE block_hash = ?",
            &[bhh],
            |r| r.get("block_id"),
        )?;

        let mut blob = self.db.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            row_id,
            true,
        )?;

        let hash_buff = Utils::read_node_hash_bytes(&mut blob, ptr)?;

        Ok(TrieHash(hash_buff))
    }

    fn read_all_block_hashes_and_roots(&self) -> Result<Vec<(stacks_common::types::chainstate::TrieHash, TTrieId)>, crate::MarfError> {
        let mut s = self.db.prepare(
            "SELECT block_hash, data FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash",
        )?;

        let rows = s.query_and_then(NO_PARAMS, |row| {
            let block_hash: TTrieId = row.get_unwrap("block_hash");
            let data = row
                .get_raw("data")
                .as_blob()
                .expect("DB Corruption: MARF data is non-blob");

            let start = TrieStorageConnection::<TTrieId>::root_ptr_disk() as usize;
            let trie_hash = TrieHash(Utils::read_hash_bytes(&mut &data[start..])?);

            Ok((trie_hash, block_hash))
        })?;

        rows.collect()
    }

    fn get_confirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        self.db.query_row(
            "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 0",
            &[bhh],
            |row| row.get("block_id"),
        )
        .optional()
        .map_err(|e| e.into())
    }

    fn get_unconfirmed_block_identifier(&self, bhh: &TTrieId) -> Result<Option<u32>, crate::MarfError> {
        self.db.query_row(
            "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
            &[bhh],
            |row| row.get("block_id"),
        )
        .optional()
        .map_err(|e| e.into())
    }

    fn read_node_type(&self, block_id: u32, ptr: &crate::tries::TriePtr, ) -> Result<(crate::tries::nodes::TrieNodeType, stacks_common::types::chainstate::TrieHash), crate::MarfError> {
        let mut blob = self.db.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            block_id.into(),
            true,
        )?;

        Utils::read_nodetype(&mut blob, ptr)
    }

    fn read_node_type_nohash(&self, block_id: u32, ptr: &crate::tries::TriePtr) -> Result<crate::tries::nodes::TrieNodeType, crate::MarfError> {
        let mut blob = self.db.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            block_id.into(),
            true,
        )?;

        Utils::read_nodetype_nohash(&mut blob, ptr)
    }

    fn count_blocks(&self) -> Result<u32, crate::MarfError> {
        let result = self.db.query_row(
            "SELECT IFNULL(MAX(block_id), 0) AS count FROM marf_data WHERE unconfirmed = 0",
            NO_PARAMS,
            |row| row.get("count"),
        )?;

        Ok(result)
    }

    fn is_unconfirmed_block(&self, block_id: u32) -> Result<bool, crate::MarfError> {
        let res: i64 = self.db.query_row(
            "SELECT unconfirmed FROM marf_data WHERE block_id = ?1",
            &[&block_id],
            |row| row.get("unconfirmed"),
        )?;

        Ok(res != 0)
    }

    fn update_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
        block_id: u32,
    ) -> Result<u32, crate::MarfError> {
        self.inner_write_external_trie_blob(block_hash, offset, length, Some(block_id))
    }

    fn get_external_trie_offset_length(&self, block_id: u32) -> Result<(u64, u64), crate::MarfError> {
        let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_id = ?1";
        let args: &[&dyn ToSql] = &[&block_id];

        let (offset, length) = SqliteUtils::query_row(&self.db, qry, args)?
            .ok_or(MarfError::NotFoundError)?;

        Ok((offset, length))
    }

    fn get_external_trie_offset_length_by_bhh(&self, bhh: &TTrieId) -> Result<(u64, u64), crate::MarfError> {
        let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1";
        let args: &[&dyn ToSql] = &[bhh];

        let (offset, length) = SqliteUtils::query_row(&self.db, qry, args)?
            .ok_or(MarfError::NotFoundError)?;

        Ok((offset, length))
    }

    fn get_external_blobs_length(&self) -> Result<u64, crate::MarfError> {
        let qry = "SELECT (external_offset + external_length) AS blobs_length FROM marf_data ORDER BY external_offset DESC LIMIT 1";
        let max_len = SqliteUtils::query_row(&self.db, qry, NO_PARAMS)?
            .unwrap_or(0);

        Ok(max_len)
    }

    fn write_external_trie_blob(
        &self,
        block_hash: &TTrieId,
        offset: u64,
        length: u64,
    ) -> Result<u32, crate::MarfError> {
        self.inner_write_external_trie_blob(block_hash, offset, length, None)
    }

    fn write_trie_blob(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        let args: &[&dyn ToSql] = &[block_hash, &data, &0, &0, &0];
        let mut s =
            self.db.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
        let block_id = s
            .insert(args)?
            .try_into()
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

        debug!("Wrote block trie {} to rowid {}", block_hash, block_id);
        Ok(block_id)
    }

    fn write_trie_blob_to_mined(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        if let Ok(block_id) = SqliteUtils::get_mined_block_identifier(&self.db, block_hash) {
            // already exists; update
            let args: &[&dyn ToSql] = &[&data, &block_id];
            let mut s = self.db.prepare("UPDATE mined_blocks SET data = ? WHERE block_id = ?")?;
            s.execute(args)
                .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
        } else {
            // doesn't exist yet; insert
            let args: &[&dyn ToSql] = &[block_hash, &data];
            let mut s = self.db.prepare("INSERT INTO mined_blocks (block_hash, data) VALUES (?, ?)")?;
            s.execute(args)
                .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
        };
    
        let block_id = SqliteUtils::get_mined_block_identifier(&self.db, block_hash)?;
    
        debug!(
            "Wrote mined block trie {} to rowid {}",
            block_hash, block_id
        );
        Ok(block_id)
    }

    fn write_trie_blob_to_unconfirmed(
        &self,
        block_hash: &TTrieId,
        data: &[u8],
    ) -> Result<u32, MarfError> {
        if let Ok(Some(_)) = Self::get_confirmed_block_identifier(self, block_hash) {
            panic!("BUG: tried to overwrite confirmed MARF trie {}", block_hash);
        }

        if let Ok(Some(block_id)) = Self::get_unconfirmed_block_identifier(self, block_hash) {
            // already exists; update
            let args: &[&dyn ToSql] = &[&data, &block_id];
            let mut s = self.db.prepare("UPDATE marf_data SET data = ? WHERE block_id = ?")?;
            s.execute(args)
                .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
        } else {
            // doesn't exist yet; insert
            let args: &[&dyn ToSql] = &[block_hash, &data, &1];
            let mut s =
                self.db.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, 0, 0)")?;
            s.execute(args)
                .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
        };

        let block_id = Self::get_unconfirmed_block_identifier(self, block_hash)?
            .expect(&format!("BUG: stored {} but got no block ID", block_hash));

        debug!(
            "Wrote unconfirmed block trie {} to rowid {}",
            block_hash, block_id
        );
        Ok(block_id)
    }

    fn drop_lock(&self, bhh: &TTrieId) -> Result<(), MarfError> {
        self.db.execute(
            "DELETE FROM block_extension_locks WHERE block_hash = ?",
            &[bhh],
        )?;
        Ok(())
    }

    fn lock_bhh_for_extension(
        &self,
        bhh: &TTrieId,
        unconfirmed: bool,
    ) -> Result<bool, MarfError> {
        let tx = self.sqlite_get_active_transaction();

        if !unconfirmed {
            // confirmed tries can only be extended once.
            // unconfirmed tries can be overwritten.
            let is_bhh_committed = tx
                .query_row(
                    "SELECT 1 FROM marf_data WHERE block_hash = ? LIMIT 1",
                    &[bhh],
                    |_row| Ok(()),
                )
                .optional()?
                .is_some();
            if is_bhh_committed {
                return Ok(false);
            }
        }
    
        let is_bhh_locked = tx
            .query_row(
                "SELECT 1 FROM block_extension_locks WHERE block_hash = ? LIMIT 1",
                &[bhh],
                |_row| Ok(()),
            )
            .optional()?
            .is_some();
        if is_bhh_locked {
            return Ok(false);
        }
    
        tx.execute(
            "INSERT INTO block_extension_locks (block_hash) VALUES (?)",
            &[bhh],
        )?;
        Ok(true)
    }

    fn drop_unconfirmed_trie(&self, bhh: &TTrieId) -> Result<(), MarfError> {
        debug!("Drop unconfirmed trie sqlite blob {}", bhh);
        self.db.execute(
            "DELETE FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
            &[bhh],
        )?;
        debug!("Dropped unconfirmed trie sqlite blob {}", bhh);
        Ok(())
    }

    fn open_trie_blob(&self, block_id: u32) -> Result<&mut dyn TrieBlob, MarfError> {
        let blob = self.db.blob_open(
            rusqlite::DatabaseName::Main,
            "marf_data",
            "data",
            block_id.into(),
            true,
        )?;
        Ok(&mut blob)
    }

    fn format(&self) -> Result<(), MarfError> {
        let tx = self.sqlite_get_active_transaction();
        SqliteUtils::clear_tables(tx)?;
        Ok(())
    }

    fn reopen_readonly(&self) -> Result<&dyn TrieIndexProvider<TTrieId>, MarfError> {
        let db = Self::sqlite_open(&self.db_path, true, self.marf_opts)?;
        let provider = SqliteIndexProvider::new_from_db_path(&self.db_path, true, self.marf_opts)?;
        Ok(&provider)
    }

    fn begin_transaction(&mut self) -> Result<(), MarfError> {
        self.sqlite_begin_transaction();
        Ok(())
    }

    fn commit_transaction(&mut self) -> Result<(), MarfError> {
        self.sqlite_commit();
        Ok(())
    }

    fn rollback_transaction(&mut self) -> Result<(), MarfError> {
        self.sqlite_rollback();
        Ok(())
    }
}