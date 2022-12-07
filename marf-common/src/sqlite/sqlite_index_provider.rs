use rusqlite::{Connection, OpenFlags, NO_PARAMS, ToSql, OptionalExtension, Transaction};
use stacks_common::types::chainstate::TrieHash;

use crate::{storage::{TrieIndexProvider, TrieStorageConnection}, MarfError, utils::Utils, MarfTrieId};

use super::SqliteUtils;

pub struct SqliteIndexProvider<'a> {
    db: &'a Connection,
    tx: &'a mut Option<Transaction<'a>>
}

impl<'a> SqliteIndexProvider<'a> {
    pub fn new(db: &Connection) -> Self {
        SqliteIndexProvider { db, tx: &mut None }
    }

    pub fn has_transaction(&self) -> bool {
        !self.tx.is_none()
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

            let start = TrieStorageConnection::<TTrieId, SqliteIndexProvider>::root_ptr_disk() as usize;
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

        let (offset, length) = SqliteUtils::query_row(self.db, qry, args)?
            .ok_or(MarfError::NotFoundError)?;

        Ok((offset, length))
    }

    fn get_external_trie_offset_length_by_bhh(&self, bhh: &TTrieId) -> Result<(u64, u64), crate::MarfError> {
        let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1";
        let args: &[&dyn ToSql] = &[bhh];

        let (offset, length) = SqliteUtils::query_row(self.db, qry, args)?
            .ok_or(MarfError::NotFoundError)?;

        Ok((offset, length))
    }

    fn get_external_blobs_length(&self) -> Result<u64, crate::MarfError> {
        let qry = "SELECT (external_offset + external_length) AS blobs_length FROM marf_data ORDER BY external_offset DESC LIMIT 1";
        let max_len = SqliteUtils::query_row(self.db, qry, NO_PARAMS)?
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
}