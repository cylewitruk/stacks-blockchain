use core::time;
use std::{thread::sleep, path::Path};

use rusqlite::{Connection, ToSql, Error as SqliteError, Row, Transaction, TransactionBehavior, OpenFlags, NO_PARAMS};

use crate::{errors::DBError, MarfTrieId};

use rand::thread_rng;

pub type DBConn = rusqlite::Connection;
pub type DBTx<'a> = rusqlite::Transaction<'a>;

// 256MB
pub const SQLITE_MMAP_SIZE: i64 = 256 * 1024 * 1024;

// 32K
pub const SQLITE_MARF_PAGE_SIZE: i64 = 32768;

pub static SQL_MARF_SCHEMA_VERSION: u64 = 2;

static SQL_MARF_DATA_TABLE: &str = "
CREATE TABLE IF NOT EXISTS marf_data (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   -- the trie itself.
   -- if not used, then set to a zero-byte entry.
   data BLOB NOT NULL,
   unconfirmed INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_marf_data ON marf_data(block_hash);
CREATE INDEX IF NOT EXISTS unconfirmed_marf_data ON marf_data(unconfirmed);
";
static SQL_MARF_MINED_TABLE: &str = "
CREATE TABLE IF NOT EXISTS mined_blocks (
   block_id INTEGER PRIMARY KEY, 
   block_hash TEXT UNIQUE NOT NULL,
   data BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS block_hash_mined_blocks ON mined_blocks(block_hash);
";

static SQL_EXTENSION_LOCKS_TABLE: &str = "
CREATE TABLE IF NOT EXISTS block_extension_locks (block_hash TEXT PRIMARY KEY);
";

static SQL_MARF_DATA_TABLE_SCHEMA_2: &str = "
-- pointer to a .blobs file with the externally-stored blob data.
-- if not used, then set to 1.
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER DEFAULT 1 NOT NULL
);
CREATE TABLE IF NOT EXISTS migrated_version (
    version INTEGER DEFAULT 1 NOT NULL
);
ALTER TABLE marf_data ADD COLUMN external_offset INTEGER DEFAULT 0 NOT NULL;
ALTER TABLE marf_data ADD COLUMN external_length INTEGER DEFAULT 0 NOT NULL;
CREATE INDEX IF NOT EXISTS index_external_offset ON marf_data(external_offset);

INSERT OR REPLACE INTO schema_version (version) VALUES (2);
INSERT OR REPLACE INTO migrated_version (version) VALUES (1);
";

pub trait FromRow<T> {
    fn from_row<'a>(row: &'a Row) -> Result<T, DBError>;
}

pub trait FromColumn<T> {
    fn from_column<'a>(row: &'a Row, column_name: &str) -> Result<T, DBError>;
}

pub struct SqliteUtils;

impl SqliteUtils {
    pub fn query_count<P>(conn: &Connection, sql_query: &str, sql_args: P) -> Result<i64, DBError>
    where
        P: IntoIterator,
        P::Item: ToSql,
    {
        Self::query_int(conn, sql_query, sql_args)
    }

    /// boilerplate code for querying a single row
    ///   if more than 1 row is returned, excess rows are ignored.
    pub fn query_row<T, P>(
        conn: &Connection, 
        sql_query: &str, 
        sql_args: P) -> Result<Option<T>, DBError>
    where
        P: IntoIterator,
        P::Item: ToSql,
        T: FromRow<T>,
    {
        Self::log_sql_eqp(conn, sql_query);
        let query_result = conn.query_row_and_then(sql_query, sql_args, |row| T::from_row(row));
        match query_result {
            Ok(x) => Ok(Some(x)),
            Err(DBError::SqliteError(SqliteError::QueryReturnedNoRows)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Boilerplate for querying a single integer (first and only item of the query must be an int)
    pub fn query_int<P>(conn: &Connection, sql_query: &str, sql_args: P) -> Result<i64, DBError>
    where
        P: IntoIterator,
        P::Item: ToSql,
    {
        Self::log_sql_eqp(conn, sql_query);
        let mut stmt = conn.prepare(sql_query)?;
        let mut rows = stmt.query(sql_args)?;
        let mut row_data = vec![];
        while let Some(row) = rows.next().map_err(|e| DBError::SqliteError(e))? {
            if row_data.len() > 0 {
                return Err(DBError::Overflow);
            }
            let i: i64 = row.get_unwrap(0);
            row_data.push(i);
        }

        if row_data.len() == 0 {
            return Err(DBError::NotFoundError);
        }

        Ok(row_data[0])
    }

    /// Begin an immediate-mode transaction, and handle busy errors with exponential backoff.
    /// Handling busy errors when the tx begins is preferable to doing it when the tx commits, since
    /// then we don't have to worry about any extra rollback logic.
    pub fn tx_begin_immediate<'a>(conn: &'a mut Connection) -> Result<DBTx<'a>, DBError> {
        Self::tx_begin_immediate_sqlite(conn).map_err(DBError::from)
    }

    /// Begin an immediate-mode transaction, and handle busy errors with exponential backoff.
    /// Handling busy errors when the tx begins is preferable to doing it when the tx commits, since
    /// then we don't have to worry about any extra rollback logic.
    /// Sames as `tx_begin_immediate` except that it returns a rusqlite error.
    pub fn tx_begin_immediate_sqlite<'a>(conn: &'a mut Connection) -> Result<DBTx<'a>, SqliteError> {
        conn.busy_handler(Some(Self::tx_busy_handler))?;
        let tx = Transaction::new(conn, TransactionBehavior::Immediate)?;
        Ok(tx)
    }

    pub fn tx_busy_handler(run_count: i32) -> bool {
        let mut sleep_count = 2;
        if run_count > 0 {
            sleep_count = 2u64.saturating_pow(run_count as u32);
        }
        sleep_count = sleep_count.saturating_add(thread_rng().gen::<u64>() % sleep_count);

        if sleep_count > 100 {
            let jitter = thread_rng().gen::<u64>() % 20;
            sleep_count = 100 - jitter;
        }

        debug!(
            "Database is locked; sleeping {}ms and trying again",
            &sleep_count
        );

        //sleep_ms(sleep_count);
        sleep(time::Duration::from_millis(sleep_count));
        true
    }

    pub fn u64_to_sql(x: u64) -> Result<i64, DBError> {
        if x > (i64::MAX as u64) {
            return Err(DBError::ParseError);
        }
        Ok(x as i64)
    }

    /// Helper to open a MARF
    fn marf_sqlite_open<P: AsRef<Path>>(
        db_path: P,
        open_flags: OpenFlags,
        foreign_keys: bool,
    ) -> Result<Connection, SqliteError> {
        let db = Self::sqlite_open(db_path, open_flags, foreign_keys)?;
        Self::sql_pragma(&db, "mmap_size", &SQLITE_MMAP_SIZE)?;
        Self::sql_pragma(&db, "page_size", &SQLITE_MARF_PAGE_SIZE)?;
        Ok(db)
    }

    /// Run a PRAGMA statement.  This can't always be done via execute(), because it may return a result (and
    /// rusqlite does not like this).
    pub fn sql_pragma(
        conn: &Connection,
        pragma_name: &str,
        pragma_value: &dyn ToSql,
    ) -> Result<(), DBError> {
        Self::inner_sql_pragma(conn, pragma_name, pragma_value).map_err(|e| DBError::SqliteError(e))
    }

    fn inner_sql_pragma(
        conn: &Connection,
        pragma_name: &str,
        pragma_value: &dyn ToSql,
    ) -> Result<(), SqliteError> {
        conn.pragma_update(None, pragma_name, pragma_value)
    }

    /// Open a database connection and set some typically-used pragmas
    pub fn sqlite_open<P: AsRef<Path>>(
        path: P,
        flags: OpenFlags,
        foreign_keys: bool,
    ) -> Result<Connection, SqliteError> {
        let db = Connection::open_with_flags(path, flags)?;
        db.busy_handler(Some(Self::tx_busy_handler))?;
        Self::inner_sql_pragma(&db, "journal_mode", &"WAL")?;
        Self::inner_sql_pragma(&db, "synchronous", &"NORMAL")?;
        if foreign_keys {
            Self::inner_sql_pragma(&db, "foreign_keys", &true)?;
        }
        Ok(db)
    }

    pub fn create_tables_if_needed(conn: &mut Connection) -> Result<(), DBError> {
        let tx = Self::tx_begin_immediate(conn)?;
    
        tx.execute_batch(SQL_MARF_DATA_TABLE)?;
        tx.execute_batch(SQL_MARF_MINED_TABLE)?;
        tx.execute_batch(SQL_EXTENSION_LOCKS_TABLE)?;
    
        tx.commit().map_err(|e| e.into())
    }
    
    fn get_schema_version(conn: &Connection) -> u64 {
        // if the table doesn't exist, then the version is 1.
        let sql = "SELECT version FROM schema_version";
        match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
            Ok(x) => x as u64,
            Err(e) => {
                debug!("Failed to get schema version: {:?}", &e);
                1u64
            }
        }
    }

    /// Get the last schema version before the last attempted migration
    fn get_migrated_version(conn: &Connection) -> u64 {
        // if the table doesn't exist, then the version is 1.
        let sql = "SELECT version FROM migrated_version";
        match conn.query_row(sql, NO_PARAMS, |row| row.get::<_, i64>("version")) {
            Ok(x) => x as u64,
            Err(e) => {
                debug!("Failed to get schema version: {:?}", &e);
                1u64
            }
        }
    }

    /// Migrate the MARF database to the currently-supported schema.
    /// Returns the version of the DB prior to the migration.
    pub fn migrate_tables_if_needed<T: MarfTrieId>(conn: &mut Connection) -> Result<u64, DBError> {
        let first_version = Self::get_schema_version(conn);
        loop {
            let version = Self::get_schema_version(conn);
            match version {
                1 => {
                    debug!("Migrate MARF data from schema 1 to schema 2");

                    // add external_* fields
                    let tx = Self::tx_begin_immediate(conn)?;
                    tx.execute_batch(SQL_MARF_DATA_TABLE_SCHEMA_2)?;
                    tx.commit()?;
                }
                x if x == SQL_MARF_SCHEMA_VERSION => {
                    // done
                    debug!("Migrated MARF data to schema {}", &SQL_MARF_SCHEMA_VERSION);
                    break;
                }
                x => {
                    let msg = format!(
                        "Unable to migrate MARF data table: unrecognized schema {}",
                        x
                    );
                    error!("{}", &msg);
                    panic!("{}", &msg);
                }
            }
        }
        if first_version == SQL_MARF_SCHEMA_VERSION
            && Self::get_migrated_version(conn) != SQL_MARF_SCHEMA_VERSION
            && !Self::detect_partial_migration(conn)?
        {
            // no migration will need to happen, so stop checking
            debug!("Marking MARF data as fully-migrated");
            Self::set_migrated(conn)?;
        }
        Ok(first_version)
    }

    /// Do we have a partially-migrated database?
    /// Either all tries have offset and length 0, or they all don't.  If we have a mixture, then we're
    /// corrupted.
    pub fn detect_partial_migration(conn: &Connection) -> Result<bool, DBError> {
        let migrated_version = Self::get_migrated_version(conn);
        let schema_version = Self::get_schema_version(conn);
        if migrated_version == schema_version {
            return Ok(false);
        }

        let num_migrated = Self::query_count(
            conn,
            "SELECT COUNT(*) FROM marf_data WHERE external_offset = 0 AND external_length = 0 AND unconfirmed = 0",
            NO_PARAMS,
        )?;
        let num_not_migrated = Self::query_count(
            conn,
            "SELECT COUNT(*) FROM marf_data WHERE external_offset != 0 AND external_length != 0 AND unconfirmed = 0",
            NO_PARAMS,
        )?;
        Ok(num_migrated > 0 && num_not_migrated > 0)
    }

    /// Mark a migration as completed
    pub fn set_migrated(conn: &Connection) -> Result<(), DBError> {
        conn.execute(
            "UPDATE migrated_version SET version = ?1",
            &[&Self::u64_to_sql(SQL_MARF_SCHEMA_VERSION)?],
        )
        .map_err(|e| e.into())
        .and_then(|_| Ok(()))
    }

    /// Generate debug output to be fed into an external script to examine query plans.
    /// TODO: it uses mocked arguments, which it assumes are strings. This does not always result in a
    /// valid query.
    #[cfg(test)]
    fn log_sql_eqp(conn: &Connection, sql_query: &str) {
        if std::env::var("BLOCKSTACK_DB_TRACE") != Ok("1".to_string()) {
            return;
        }

        let mut parts = sql_query.clone().split(" ");
        let mut full_sql = if let Some(part) = parts.next() {
            part.to_string()
        } else {
            sql_query.to_string()
        };

        while let Some(part) = parts.next() {
            if part.starts_with("?") {
                full_sql = format!("{} \"mock_arg\"", full_sql.trim());
            } else {
                full_sql = format!("{} {}", full_sql.trim(), part.trim());
            }
        }

        let path = Self::get_db_path(conn).unwrap_or("ERROR!".to_string());
        let eqp_sql = format!("\"{}\" EXPLAIN QUERY PLAN {}", &path, full_sql.trim());
        debug!("{}", &eqp_sql);
    }

    #[cfg(not(test))]
    fn log_sql_eqp(_conn: &Connection, _sql_query: &str) {}

    /// Load the path of the database from the connection
    #[cfg(test)]
    fn get_db_path(conn: &Connection) -> Result<String, DBError> {
        let sql = "PRAGMA database_list";
        let path: Result<Option<String>, SqliteError> =
            conn.query_row_and_then(sql, rusqlite::NO_PARAMS, |row| row.get(2));
        match path {
            Ok(Some(path)) => Ok(path),
            Ok(None) => Ok("<unknown>".to_string()),
            Err(e) => Err(DBError::SqliteError(e)),
        }
    }
}