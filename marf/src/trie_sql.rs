/*
 copyright: (c) 2013-2020 by Blockstack PBC, a public benefit corporation.

 This file is part of Blockstack.

 Blockstack is free software. You may redistribute or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License or
 (at your option) any later version.

 Blockstack is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY, including without the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Blockstack. If not, see <http://www.gnu.org/licenses/>.
*/

use std::convert::TryInto;
use std::io::Write;

use rusqlite::{
    blob::Blob,
    types::ToSql,
    Connection, OptionalExtension, Transaction, NO_PARAMS,
};

use crate::bits::{
    read_node_hash_bytes as bits_read_node_hash_bytes, read_nodetype, read_nodetype_nohash,
};

use crate::node::{TrieNodeType, TriePtr};
use crate::Error;
use crate::{trie_sql, MarfTrieId};
use crate::sqliteutils::query_count;
use crate::sqliteutils::query_row;
use crate::sqliteutils::tx_begin_immediate;
use crate::sqliteutils::u64_to_sql;
use stacks_common::types::chainstate::TrieHash;









pub fn get_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_mined_block_identifier<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<u32, Error> {
    conn.query_row(
        "SELECT block_id FROM mined_blocks WHERE block_hash = ?",
        &[bhh],
        |row| row.get("block_id"),
    )
    .map_err(|e| e.into())
}

pub fn get_confirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 0",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_unconfirmed_block_identifier<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<Option<u32>, Error> {
    conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
        |row| row.get("block_id"),
    )
    .optional()
    .map_err(|e| e.into())
}

pub fn get_block_hash<T: MarfTrieId>(conn: &Connection, local_id: u32) -> Result<T, Error> {
    let result = conn
        .query_row(
            "SELECT block_hash FROM marf_data WHERE block_id = ?",
            &[local_id],
            |row| row.get("block_hash"),
        )
        .optional()?;
    result.ok_or_else(|| {
        error!("Failed to get block header hash of local ID {}", local_id);
        Error::NotFoundError
    })
}

/// Write a serialized trie to sqlite
pub fn write_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    let args: &[&dyn ToSql] = &[block_hash, &data, &0, &0, &0];
    let mut s =
        conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
    let block_id = s
        .insert(args)?
        .try_into()
        .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");

    debug!("Wrote block trie {} to rowid {}", block_hash, block_id);
    Ok(block_id)
}

/// Write the offset/length of a trie blob that was stored to an external file.
/// Do this only once the trie is actually stored, since only the presence of this information is
/// what guarantees that the blob is persisted.
/// If block_id is Some(..), then an existing block ID's metadata will be updated.  Otherwise, a
/// new row will be created.
fn inner_write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: Option<u32>,
) -> Result<u32, Error> {
    let block_id = if let Some(block_id) = block_id {
        // existing entry (i.e. a migration)
        let empty_blob: &[u8] = &[];
        let args: &[&dyn ToSql] = &[
            block_hash,
            &empty_blob,
            &0,
            &u64_to_sql(offset)?,
            &u64_to_sql(length)?,
            &block_id,
        ];
        let mut s =
            conn.prepare("UPDATE marf_data SET block_hash = ?1, data = ?2, unconfirmed = ?3, external_offset = ?4, external_length = ?5 WHERE block_id = ?6")?;
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
            &u64_to_sql(offset)?,
            &u64_to_sql(length)?,
        ];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, ?, ?)")?;
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

/// Update the row for an external trie blob -- i.e. we're migrating blobs from sqlite storage to
/// file storage.
pub fn update_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
    block_id: u32,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(conn, block_hash, offset, length, Some(block_id))
}

/// Add a new row for an external trie blob -- i.e. we're creating a new trie whose blob will be
/// stored in an external file, but its metadata will be in the DB.
/// Returns the new row ID
pub fn write_external_trie_blob<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    offset: u64,
    length: u64,
) -> Result<u32, Error> {
    inner_write_external_trie_blob(conn, block_hash, offset, length, None)
}

/// Write a serialized trie blob for a trie that was mined
pub fn write_trie_blob_to_mined<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(block_id) = get_mined_block_identifier(conn, block_hash) {
        // already exists; update
        let args: &[&dyn ToSql] = &[&data, &block_id];
        let mut s = conn.prepare("UPDATE mined_blocks SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args: &[&dyn ToSql] = &[block_hash, &data];
        let mut s = conn.prepare("INSERT INTO mined_blocks (block_hash, data) VALUES (?, ?)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_mined_block_identifier(conn, block_hash)?;

    debug!(
        "Wrote mined block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

/// Write a serialized unconfirmed trie blob
pub fn write_trie_blob_to_unconfirmed<T: MarfTrieId>(
    conn: &Connection,
    block_hash: &T,
    data: &[u8],
) -> Result<u32, Error> {
    if let Ok(Some(_)) = get_confirmed_block_identifier(conn, block_hash) {
        panic!("BUG: tried to overwrite confirmed MARF trie {}", block_hash);
    }

    if let Ok(Some(block_id)) = get_unconfirmed_block_identifier(conn, block_hash) {
        // already exists; update
        let args: &[&dyn ToSql] = &[&data, &block_id];
        let mut s = conn.prepare("UPDATE marf_data SET data = ? WHERE block_id = ?")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    } else {
        // doesn't exist yet; insert
        let args: &[&dyn ToSql] = &[block_hash, &data, &1];
        let mut s =
            conn.prepare("INSERT INTO marf_data (block_hash, data, unconfirmed, external_offset, external_length) VALUES (?, ?, ?, 0, 0)")?;
        s.execute(args)
            .expect("EXHAUSTION: MARF cannot track more than 2**31 - 1 blocks");
    };

    let block_id = get_unconfirmed_block_identifier(conn, block_hash)?
        .expect(&format!("BUG: stored {} but got no block ID", block_hash));

    debug!(
        "Wrote unconfirmed block trie {} to rowid {}",
        block_hash, block_id
    );
    Ok(block_id)
}

/// Open a trie blob. Returns a Blob<'a> readable/writeable handle to it.
pub fn open_trie_blob<'a>(conn: &'a Connection, block_id: u32) -> Result<Blob<'a>, Error> {
    let blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    Ok(blob)
}

/// Open a trie blob. Returns a Blob<'a> readable handle to it.
pub fn open_trie_blob_readonly<'a>(conn: &'a Connection, block_id: u32) -> Result<Blob<'a>, Error> {
    let blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        false,
    )?;
    Ok(blob)
}

#[cfg(test)]
pub fn read_all_block_hashes_and_roots<T: MarfTrieId>(
    conn: &Connection,
) -> Result<Vec<(TrieHash, T)>, Error> {
    use crate::{storage::TrieStorageConnection, bits::read_hash_bytes};

    let mut s = conn.prepare(
        "SELECT block_hash, data FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash",
    )?;
    let rows = s.query_and_then(NO_PARAMS, |row| {
        let block_hash: T = row.get_unwrap("block_hash");
        let data = row
            .get_raw("data")
            .as_blob()
            .expect("DB Corruption: MARF data is non-blob");
        let start = TrieStorageConnection::<T>::root_ptr_disk() as usize;
        let trie_hash = TrieHash(read_hash_bytes(&mut &data[start..])?);
        Ok((trie_hash, block_hash))
    })?;
    rows.collect()
}

/// Read a node's hash from a sqlite-stored blob, given the block ID
pub fn read_node_hash_bytes<W: Write>(
    conn: &Connection,
    w: &mut W,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

/// Read a node's hash from a sqlite-stored blob, given its block header hash
pub fn read_node_hash_bytes_by_bhh<W: Write, T: MarfTrieId>(
    conn: &Connection,
    w: &mut W,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<(), Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        row_id,
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    w.write_all(&hash_buff).map_err(|e| e.into())
}

/// Read a node and its hash from a sqlite-stored trie blob
pub fn read_node_type(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<(TrieNodeType, TrieHash), Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    read_nodetype(&mut blob, ptr)
}

/// Read a node from a sqlite-stored trie blob, excluding its hash.
pub fn read_node_type_nohash(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<TrieNodeType, Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    read_nodetype_nohash(&mut blob, ptr)
}

/// Get the offset and length of a trie blob in the trie blobs file.
pub fn get_external_trie_offset_length(
    conn: &Connection,
    block_id: u32,
) -> Result<(u64, u64), Error> {
    let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_id = ?1";
    let args: &[&dyn ToSql] = &[&block_id];
    let (offset, length) = query_row(conn, qry, args)?.ok_or(Error::NotFoundError)?;
    Ok((offset, length))
}

/// Get the offset of a trie blob in the blobs file, given its block header hash.
pub fn get_external_trie_offset_length_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
) -> Result<(u64, u64), Error> {
    let qry = "SELECT external_offset, external_length FROM marf_data WHERE block_hash = ?1";
    let args: &[&dyn ToSql] = &[bhh];
    let (offset, length) = query_row(conn, qry, args)?.ok_or(Error::NotFoundError)?;
    Ok((offset, length))
}

/// Determine the offset in the blobs file at which the last trie ends.  This is also the offset at
/// which the next trie will be appended.
pub fn get_external_blobs_length(conn: &Connection) -> Result<u64, Error> {
    let qry = "SELECT (external_offset + external_length) AS blobs_length FROM marf_data ORDER BY external_offset DESC LIMIT 1";
    let max_len = query_row(conn, qry, NO_PARAMS)?.unwrap_or(0);
    Ok(max_len)
}



pub fn get_node_hash_bytes(
    conn: &Connection,
    block_id: u32,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        block_id.into(),
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
    conn: &Connection,
    bhh: &T,
    ptr: &TriePtr,
) -> Result<TrieHash, Error> {
    let row_id: i64 = conn.query_row(
        "SELECT block_id FROM marf_data WHERE block_hash = ?",
        &[bhh],
        |r| r.get("block_id"),
    )?;
    let mut blob = conn.blob_open(
        rusqlite::DatabaseName::Main,
        "marf_data",
        "data",
        row_id,
        true,
    )?;
    let hash_buff = bits_read_node_hash_bytes(&mut blob, ptr)?;
    Ok(TrieHash(hash_buff))
}

pub fn tx_lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Connection,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
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

pub fn lock_bhh_for_extension<T: MarfTrieId>(
    tx: &Transaction,
    bhh: &T,
    unconfirmed: bool,
) -> Result<bool, Error> {
    tx_lock_bhh_for_extension(tx, bhh, unconfirmed)?;
    Ok(true)
}

pub fn count_blocks(conn: &Connection) -> Result<u32, Error> {
    let result = conn.query_row(
        "SELECT IFNULL(MAX(block_id), 0) AS count FROM marf_data WHERE unconfirmed = 0",
        NO_PARAMS,
        |row| row.get("count"),
    )?;
    Ok(result)
}

pub fn is_unconfirmed_block(conn: &Connection, block_id: u32) -> Result<bool, Error> {
    let res: i64 = conn.query_row(
        "SELECT unconfirmed FROM marf_data WHERE block_id = ?1",
        &[&block_id],
        |row| row.get("unconfirmed"),
    )?;
    Ok(res != 0)
}

pub fn drop_lock<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    conn.execute(
        "DELETE FROM block_extension_locks WHERE block_hash = ?",
        &[bhh],
    )?;
    Ok(())
}

pub fn drop_unconfirmed_trie<T: MarfTrieId>(conn: &Connection, bhh: &T) -> Result<(), Error> {
    debug!("Drop unconfirmed trie sqlite blob {}", bhh);
    conn.execute(
        "DELETE FROM marf_data WHERE block_hash = ? AND unconfirmed = 1",
        &[bhh],
    )?;
    debug!("Dropped unconfirmed trie sqlite blob {}", bhh);
    Ok(())
}

pub fn clear_lock_data(conn: &Connection) -> Result<(), Error> {
    conn.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    Ok(())
}

pub fn clear_tables(tx: &Transaction) -> Result<(), Error> {
    tx.execute("DELETE FROM block_extension_locks", NO_PARAMS)?;
    tx.execute("DELETE FROM marf_data", NO_PARAMS)?;
    tx.execute("DELETE FROM mined_blocks", NO_PARAMS)?;
    Ok(())
}
