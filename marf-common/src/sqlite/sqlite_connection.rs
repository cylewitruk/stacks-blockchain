use std::ops::Deref;

use rusqlite::{Connection, Transaction};

pub enum SqliteConnection<'a> {
    ConnRef(&'a Connection),
    Tx(Transaction<'a>),
}

impl<'a> Deref for SqliteConnection<'a> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        match self {
            SqliteConnection::ConnRef(x) => x,
            SqliteConnection::Tx(tx) => tx,
        }
    }
}