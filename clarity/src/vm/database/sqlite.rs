// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use rusqlite::types::{FromSql, ToSql};
use rusqlite::{
    Connection, Error as SqliteError, ErrorCode as SqliteErrorCode, OptionalExtension, Row,
    Savepoint, NO_PARAMS,
};
use hex::{decode, decode_to_slice, encode};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

use crate::types::chainstate::StacksBlockId;

use stacks_common::util::db_common::tx_busy_handler;

use crate::vm::contracts::Contract;
use crate::vm::errors::{
    Error, IncomparableError, InterpreterError, InterpreterResult as Result, RuntimeErrorType,
};

const SQL_FAIL_MESSAGE: &str = "PANIC: SQL Failure in Smart Contract VM.";

pub struct SqliteConnection {
    conn: Connection,
}

/// Upserts a data entry for the given key and value.
fn sqlite_put(conn: &Connection, key: &str, value: &str) {
    trace!("sqlite_put (key={}, value={})", &key, &value);

    let value_bytes = compress_prepend_size(value.as_bytes());

    let params: [&dyn ToSql; 2] = [&key, &value_bytes];

    match conn.execute(
        "REPLACE INTO clarity_data (key, value) VALUES (?, ?)",
        &params,
    ) {
        Ok(_) => {}
        Err(e) => {
            error!("Failed to insert/replace ({},{}): {:?}", key, value, &e);
            panic!("{}", SQL_FAIL_MESSAGE);
        }
    };
}

/// Attempts to retrieve the data entry for the given key. Returns `None` if no entry is found.
fn sqlite_get(conn: &Connection, key: &str) -> Option<String> {
    trace!("sqlite_get (key={})", key);
    
    let params: [&dyn ToSql; 1] = [&key];
    let mut stmt = conn.prepare("SELECT value FROM clarity_data WHERE key = ?").unwrap();
    let row: Option<Vec<u8>> = stmt.query_row(params, |row| row.get(0)).optional()
        .unwrap_or_else(|err| {
            error!("Failed to query '{}': {:?}", key, &err);
            panic!("{}", SQL_FAIL_MESSAGE);
        });

    let result = match row {
        Some(x) => {
            let decompressed = decompress_size_prepended(x.as_slice()).unwrap_or_else(|err| {
                panic!("Failed to decompress metadata value with key {}: {:?}", key, err)
            });
            let value_string = String::from_utf8(decompressed).unwrap_or_else(|err| {
                panic!("Failed to convert metadata value with key {} to utf8 string: {:?}", key, err)
            });
            Some(value_string)
        }
        _ => None
    };

    trace!("sqlite_get {}: {:?}", key, &result);
    result
}

/// Determines if a data entry for the given `key` exists.
fn sqlite_has_entry(conn: &Connection, key: &str) -> bool {
    trace!("sqlite_has_entry (key={})", &key);

    let params: [&dyn ToSql; 1] = [&key];
    let mut stmt = conn.prepare("SELECT key FROM clarity_data WHERE key = ?").unwrap();
    stmt.exists(params)
        .unwrap_or_else(|err| {
            error!("Failed to query '{}': {:?}", &key, &err);
            panic!("{}", SQL_FAIL_MESSAGE);
        })
}

impl SqliteConnection {
    pub fn put(conn: &Connection, key: &str, value: &str) {
        sqlite_put(conn, key, value)
    }

    pub fn get(conn: &Connection, key: &str) -> Option<String> {
        sqlite_get(conn, key)
    }

    /// Inserts a new metadata entry for the given key, block hash and value. The value will be
    /// automatically compressed using LZ4.
    pub fn insert_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
        value: &str,
    ) {
        trace!("insert_metadata (key={}, blockhash={})", &key, &bhh);

        let value_bytes = compress_prepend_size(value.as_bytes());

        let key = format!("clr-meta::{}::{}", contract_hash, key);
        let params: [&dyn ToSql; 3] = [&key, &bhh, &value_bytes];

        if let Err(e) = conn.execute(
            "INSERT INTO clarity_metadata (key, blockhash, value) VALUES (?, ?, ?)",
            &params,
        ) {
            error!(
                "Failed to insert ({},{},{}): {:?}",
                &bhh,
                &key,
                &value.to_string(),
                &e
            );
            panic!("{}", SQL_FAIL_MESSAGE);
        }
    }

    /// Updates the block hash of all metadata entries with the given `from` block hash to the given `to` block hash.
    pub fn commit_metadata_to(conn: &Connection, from: &StacksBlockId, to: &StacksBlockId) {
        /*let from_bytes = decode(from)
            .map_err(|_| InterpreterError::DBError("Error decoding blockhash to bytes.".to_string()))
            .unwrap();

        let to_bytes = decode(to)
            .map_err(|_| InterpreterError::DBError("Error decoding blockhash to bytes.".to_string()))
            .unwrap();*/

        let params = [to, from];
        if let Err(e) = conn.execute(
            "UPDATE clarity_metadata SET blockhash = ? WHERE blockhash = ?",
            &params,
        ) {
            error!("Failed to update {} to {}: {:?}", &from, &to, &e);
            panic!("{}", SQL_FAIL_MESSAGE);
        }
    }

    /// Removes all metadata entries related to the given block hash.
    pub fn drop_metadata(conn: &Connection, from: &StacksBlockId) {
        if let Err(e) = conn.execute("DELETE FROM clarity_metadata WHERE blockhash = ?", &[from]) {
            error!("Failed to drop metadata from {}: {:?}", &from, &e);
            panic!("{}", SQL_FAIL_MESSAGE);
        }
    }

    pub fn get_metadata(
        conn: &Connection,
        bhh: &StacksBlockId,
        contract_hash: &str,
        key: &str,
    ) -> Option<String> {
        let key = format!("clr-meta::{}::{}", contract_hash, key);

        let params: [&dyn ToSql; 2] = [&bhh, &key];
        let mut stmt = conn.prepare("SELECT value FROM clarity_metadata WHERE blockhash = ? AND key = ?").unwrap();
        let row: Option<Vec<u8>> = stmt.query_row(params, |row| row.get(0)).optional()
            .unwrap_or_else(|err| {
                error!("Failed to query '{}': {:?}", key, &err);
                panic!("{}", SQL_FAIL_MESSAGE);
            });
    
        match row {
            Some(x) => {
                let decompressed = decompress_size_prepended(x.as_slice()).unwrap_or_else(|err| {
                    panic!("Failed to decompress metadata value with key {} and blockhash {}: {:?}", key, bhh, err)
                });
                let value_string = String::from_utf8(decompressed).unwrap_or_else(|err| {
                    panic!("Failed to convert metadata value with key {} and blockhash {} to utf8 string: {:?}", key, bhh, err)
                });
                Some(value_string)
            },
            _ => None
        }
    }

    pub fn has_entry(conn: &Connection, key: &str) -> bool {
        sqlite_has_entry(conn, key)
    }
}

impl SqliteConnection {
    pub fn initialize_conn(conn: &Connection) -> Result<()> {
        trace!("Setting journal-mode to WAL");
        conn.query_row("PRAGMA journal_mode = WAL;", NO_PARAMS, |_row| Ok(()))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        trace!("Checking if clarity_schema_version exists...");
        let clarity_schema_version_exists: bool = conn
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE name=?", &["clarity_schema_version"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        // If the clarity_schema_version table does not exist then we are using schema v1. This will be used
        // for migrations, so we need to create this table first and set the version to 1.
        if !clarity_schema_version_exists {
            trace!("clarity_schema_version does not exist, creating it.");
            conn.execute("CREATE TABLE clarity_schema_version (version INTEGER PRIMARY KEY)", NO_PARAMS)
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

            trace!("Setting clarity schema version to 1.");
            conn.execute("INSERT INTO clarity_schema_version VALUES (1)", NO_PARAMS)
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

            // Create the v1 tables if not already existing (to come to schema version 1).
            conn.execute("CREATE TABLE IF NOT EXISTS data_table (key TEXT PRIMARY KEY, value TEXT)", NO_PARAMS)
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
    
            conn.execute(
                    "CREATE TABLE IF NOT EXISTS metadata_table (key TEXT NOT NULL, blockhash TEXT, value TEXT, UNIQUE (key, blockhash))",
                    NO_PARAMS,
                )
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        }

        // Retrieve the current clarity schema version
        trace!("Checking clarity schema version...");
        let clarity_schema_version: i64 = conn
            .query_row("SELECT version FROM clarity_schema_version LIMIT 1", NO_PARAMS, |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
        trace!("Schema version is {}", clarity_schema_version);

        if clarity_schema_version == 1 {
            // Create clarity_data table
            trace!("Creating clarity_data table.");
            conn.execute("CREATE TABLE clarity_data (key TEXT PRIMARY KEY, value BLOB)", NO_PARAMS)
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
    
            // Create index for clarity_data
            trace!("Creating clarity_data index.");
            conn.execute("CREATE INDEX clarity_data_index ON clarity_data (key)", NO_PARAMS)
                .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

            // Create clarity_metadata (to replace metadata_table)
            trace!("Creating clarity_metadata table.");
            conn.execute(
                "CREATE TABLE IF NOT EXISTS clarity_metadata (key TEXT NOT NULL, blockhash BLOB, value BLOB)",
                NO_PARAMS,
            )
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
    
            // Create index for clarity_metadata
            trace!("Creating clarity_metadata index.");
            conn.execute(
                "CREATE UNIQUE INDEX clarity_metadata_index ON clarity_metadata (key, blockhash)",
                NO_PARAMS,
            )
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

            trace!("Migrating data_table -> clarity_data (schema version 2).");
            {
                let mut stmt = conn.prepare("SELECT key, value FROM data_table")
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                let mut rows = stmt.query(NO_PARAMS)
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                while let Some(row) = rows.next().expect("FATAL: Failed to read row from Sqlite (data_table->clarity_data migration)") {
                    let key_str: String = row.get_unwrap(0);
                    let value_str: String = row.get_unwrap(1);

                    let value_bytes = decode(value_str)
                        .map_err(|_| InterpreterError::DBError("Error decoding hex value from data_table to bytes.".to_string()))?;

                    let params:[&dyn ToSql; 2] = [&key_str, &value_bytes];
                    
                    let rows_affected = conn
                        .execute("INSERT INTO clarity_data VALUES (?, ?)", params)
                        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                    if rows_affected == 0 {
                        panic!("Error when performing database migration (metadata_table->clarity_metadata): row not inserted.");
                    }
                }

                conn.execute("DROP TABLE data_table", NO_PARAMS)
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
            }

            trace!("Migrating metadata_table -> clarity_metadata (schema version 2");
            {
                let mut stmt = conn.prepare("SELECT key, blockhash, value FROM metadata_table")
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                let mut rows = stmt.query(NO_PARAMS)
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                while let Some(row) = rows.next().expect("FATAL: Failed to read row from Sqlite (data_table->clarity_data migration)") {
                    let key_str: String = row.get_unwrap(0);
                    let blockhash_str: String = row.get_unwrap(1);
                    let value_str: String = row.get_unwrap(2);

                    let blockhash_bytes = decode(blockhash_str)
                        .map_err(|_| InterpreterError::DBError("Error decoding hex value from data_table to bytes.".to_string()))?;
                    let value_bytes = compress_prepend_size(value_str.as_bytes());

                    let params: [&dyn ToSql; 3] = [&key_str, &blockhash_bytes, &value_bytes];

                    let rows_affected = conn.execute(
                            "INSERT INTO clarity_metadata VALUES (?, ?, ?",
                            params
                        )
                        .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

                    if rows_affected == 0 {
                        panic!("Error when performing database migration (data_table->clarity_data): row not inserted.");
                    }
                }

                conn.execute("DROP TABLE metadata_table", NO_PARAMS)
                    .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;
            }

            trace!("Database migration complete!");

        }

        Self::check_schema(conn)?;

        Ok(())
    }

    pub fn memory() -> Result<Connection> {
        let mut contract_db = SqliteConnection::inner_open(":memory:")?;
        SqliteConnection::initialize_conn(&mut contract_db)?;
        Ok(contract_db)
    }

    pub fn open(filename: &str) -> Result<Connection> {
        let contract_db = SqliteConnection::inner_open(filename)?;
        SqliteConnection::check_schema(&contract_db)?;
        Ok(contract_db)
    }

    pub fn check_schema(conn: &Connection) -> Result<()> {
        let sql = "SELECT sql FROM sqlite_master WHERE name=?";
        
        /*let _: String = conn
            .query_row(sql, &["data_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        let _: String = conn
            .query_row(sql, &["metadata_table"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;*/

        let _: String = conn
            .query_row(sql, &["clarity_metadata"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        let _: String = conn
            .query_row(sql, &["clarity_data"], |row| row.get(0))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(())
    }

    pub fn inner_open(filename: &str) -> Result<Connection> {
        let conn = Connection::open(filename)
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        conn.busy_handler(Some(tx_busy_handler))
            .map_err(|x| InterpreterError::SqliteError(IncomparableError { err: x }))?;

        Ok(conn)
    }
}
