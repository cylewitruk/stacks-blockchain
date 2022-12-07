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

use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rusqlite::Connection;
use stacks_common::types::chainstate::TrieHash;

use crate::{
    bits::{
        read_hash_bytes, read_nodetype_at_head, read_nodetype_at_head_nohash,
    },
    node::{
        TrieNodeType, TriePtr,
    },
    storage::NodeHashReader,
    Error,
    trie_sql, 
    MarfTrieId
};

use crate::sqliteutils::sql_vacuum;












