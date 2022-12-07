use std::{
    io, 
    io::Error as IOError,
    fmt, 
    error
};

use serde_json::Error as SerdeJsonError;

use rusqlite::Error as SqliteError;

use crate::tries::TriePtr;

#[derive(Debug, Clone, PartialEq)]
pub enum CursorError {
    PathDiverged,
    BackptrEncountered(TriePtr),
    ChrNotFound,
}

impl fmt::Display for CursorError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CursorError::PathDiverged => write!(f, "Path diverged"),
            CursorError::BackptrEncountered(_) => write!(f, "Back-pointer encountered"),
            CursorError::ChrNotFound => write!(f, "Node child not found"),
        }
    }
}

impl error::Error for CursorError {
    fn cause(&self) -> Option<&dyn error::Error> {
        None
    }
}

#[derive(Debug)]
pub enum MarfError {
    NotOpenedError,
    IOError(io::Error),
    SQLError(rusqlite::Error),
    RequestedIdentifierForExtensionTrie,
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    BlockHashMapCorruptionError(Option<Box<MarfError>>),
    ReadOnlyError,
    UnconfirmedError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(CursorError),
    RestoreMarfBlockError(Box<MarfError>),
    NonMatchingForks([u8; 32], [u8; 32]),
}

impl From<io::Error> for MarfError {
    fn from(err: io::Error) -> Self {
        MarfError::IOError(err)
    }
}

impl From<DBError> for MarfError {
    fn from(e: DBError) -> MarfError {
        match e {
            DBError::SqliteError(se) => MarfError::SQLError(se),
            DBError::NotFoundError => MarfError::NotFoundError,
            _ => MarfError::CorruptionError(format!("{}", &e)),
        }
    }
}

impl From<SqliteError> for MarfError {
    fn from(e: SqliteError) -> MarfError {
        MarfError::SQLError(e)
    }
}

impl fmt::Display for MarfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MarfError::IOError(ref e) => fmt::Display::fmt(e, f),
            MarfError::SQLError(ref e) => fmt::Display::fmt(e, f),
            MarfError::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            MarfError::CursorError(ref e) => fmt::Display::fmt(e, f),
            MarfError::BlockHashMapCorruptionError(ref opt_e) => {
                f.write_str("Corrupted MARF BlockHashMap")?;
                match opt_e {
                    Some(e) => write!(f, ": {}", e),
                    None => Ok(()),
                }
            }
            MarfError::NotOpenedError => write!(f, "Tried to read data from unopened storage"),
            MarfError::NotFoundError => write!(f, "Object not found"),
            MarfError::BackptrNotFoundError => write!(f, "Object not found from backptrs"),
            MarfError::ExistsError => write!(f, "Object exists"),
            MarfError::BadSeekValue => write!(f, "Bad seek value"),
            MarfError::ReadOnlyError => write!(f, "Storage is in read-only mode"),
            MarfError::UnconfirmedError => write!(f, "Storage is in unconfirmed mode"),
            MarfError::NotDirectoryError => write!(f, "Not a directory"),
            MarfError::PartialWriteError => {
                write!(f, "Data is partially written and not yet recovered")
            }
            MarfError::InProgressError => write!(f, "Write was in progress"),
            MarfError::WriteNotBegunError => write!(f, "Write has not begun"),
            MarfError::RestoreMarfBlockError(_) => write!(
                f,
                "Failed to restore previous open block during block header check"
            ),
            MarfError::NonMatchingForks(_, _) => {
                write!(f, "The supplied blocks are not in the same fork")
            }
            MarfError::RequestedIdentifierForExtensionTrie => {
                write!(f, "BUG: MARF requested the identifier for a RAM trie")
            }
        }
    }
}

impl error::Error for MarfError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            MarfError::IOError(ref e) => Some(e),
            MarfError::SQLError(ref e) => Some(e),
            MarfError::RestoreMarfBlockError(ref e) => Some(e),
            MarfError::BlockHashMapCorruptionError(ref opt_e) => match opt_e {
                Some(ref e) => Some(e),
                None => None,
            },
            _ => None,
        }
    }
}









#[derive(Debug)]
pub enum DBError {
    /// Not implemented
    NotImplemented,
    /// Database doesn't exist
    NoDBError,
    /// Read-only and tried to write
    ReadOnly,
    /// Type error -- can't represent the given data in the database
    TypeError,
    /// Database is corrupt -- we got data that shouldn't be there, or didn't get data when we
    /// should have
    Corruption,
    /// Serialization error -- can't serialize data
    SerializationError(SerdeJsonError),
    /// Parse error -- failed to load data we stored directly
    ParseError,
    /// Operation would overflow
    Overflow,
    /// Data not found
    NotFoundError,
    /// Data already exists
    ExistsError,
    /// Data corresponds to a non-canonical PoX sortition
    InvalidPoxSortition,
    /// Sqlite3 error
    SqliteError(SqliteError),
    /// I/O error
    IOError(IOError),
    /// MARF index error
    IndexError(MarfError),
    /// Old schema error
    OldSchema(u64),
    /// Database is too old for epoch
    TooOldForEpoch,
    /// Other error
    Other(String),
}

impl fmt::Display for DBError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DBError::NotImplemented => write!(f, "Not implemented"),
            DBError::NoDBError => write!(f, "Database does not exist"),
            DBError::ReadOnly => write!(f, "Database is opened read-only"),
            DBError::TypeError => write!(f, "Invalid or unrepresentable database type"),
            DBError::Corruption => write!(f, "Database is corrupt"),
            DBError::SerializationError(ref e) => fmt::Display::fmt(e, f),
            DBError::ParseError => write!(f, "Parse error"),
            DBError::Overflow => write!(f, "Numeric overflow"),
            DBError::NotFoundError => write!(f, "Not found"),
            DBError::ExistsError => write!(f, "Already exists"),
            DBError::InvalidPoxSortition => write!(f, "Invalid PoX sortition"),
            DBError::IOError(ref e) => fmt::Display::fmt(e, f),
            DBError::SqliteError(ref e) => fmt::Display::fmt(e, f),
            DBError::IndexError(ref e) => fmt::Display::fmt(e, f),
            DBError::OldSchema(ref s) => write!(f, "Old database schema: {}", s),
            DBError::TooOldForEpoch => {
                write!(f, "Database is not compatible with current system epoch")
            }
            DBError::Other(ref s) => fmt::Display::fmt(s, f),
        }
    }
}

impl error::Error for DBError {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            DBError::NotImplemented => None,
            DBError::NoDBError => None,
            DBError::ReadOnly => None,
            DBError::TypeError => None,
            DBError::Corruption => None,
            DBError::SerializationError(ref e) => Some(e),
            DBError::ParseError => None,
            DBError::Overflow => None,
            DBError::NotFoundError => None,
            DBError::ExistsError => None,
            DBError::InvalidPoxSortition => None,
            DBError::SqliteError(ref e) => Some(e),
            DBError::IOError(ref e) => Some(e),
            DBError::IndexError(ref e) => Some(e),
            DBError::OldSchema(ref _s) => None,
            DBError::TooOldForEpoch => None,
            DBError::Other(ref _s) => None,
        }
    }
}

impl From<SqliteError> for DBError {
    fn from(e: SqliteError) -> DBError {
        DBError::SqliteError(e)
    }
}

impl From<MarfError> for DBError {
    fn from(e: MarfError) -> DBError {
        DBError::IndexError(e)
    }
}