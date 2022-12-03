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

use std::ops::DerefMut;

use rusqlite::{Connection, Transaction};

use crate::{
    bits::{get_leaf_hash, get_node_hash},
    node::{
        clear_backptr, is_backptr, set_backptr, CursorError, TrieCursor,
        TrieNode256, TrieNodeID, TrieNodeType, TriePath, TriePtr,
    },
    storage::{
        TrieFileStorage, TrieHashCalculationMode, TrieStorageConnection, TrieStorageTransaction,
    },
    sqliteutils::Error as db_error,
    trie::Trie,
    Error,
    MARFValue,
    MarfTrieId,
    TrieHashExtension,
    TrieLeaf, 
    TrieMerkleProof
};

use stacks_common::util::hash::Sha512Trunc256Sum;
use stacks_common::types::chainstate::TrieHash;













impl<'a, T: MarfTrieId> MarfConnection<T> for MarfTransaction<'a, T> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<T>) -> R,
    {
        exec(&mut self.storage)
    }
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_tx()
    }
}






