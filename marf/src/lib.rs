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


use sha2::Digest;
use sha2::Sha512_256 as TrieHasher;

use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

mod sqliteutils;

pub mod cache;
pub mod file;
pub mod marf;
pub mod node;
pub mod profile;
pub mod proofs;
pub mod storage;
pub mod trie;
pub mod trie_sql;

#[macro_use]
extern crate stacks_common;

#[macro_use(slog_debug, slog_trace, slog_error, slog_info, slog_warn)]
extern crate slog;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
pub mod test;



















