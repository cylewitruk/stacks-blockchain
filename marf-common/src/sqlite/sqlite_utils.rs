use core::time;
use std::{thread::sleep, path::Path};

use rusqlite::{Connection, ToSql, Error as SqliteError, Row, Transaction, TransactionBehavior, OpenFlags};

use crate::{errors::DBError};

use rand::thread_rng;



pub type DBConn = rusqlite::Connection;
pub type DBTx<'a> = rusqlite::Transaction<'a>;

// 256MB
pub const SQLITE_MMAP_SIZE: i64 = 256 * 1024 * 1024;

// 32K
pub const SQLITE_MARF_PAGE_SIZE: i64 = 32768;

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