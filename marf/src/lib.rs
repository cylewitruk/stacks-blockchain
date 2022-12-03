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

use std::error;
use std::fmt;
use std::hash::Hash;
use std::io;

use sha2::Digest;
use sha2::Sha512_256 as TrieHasher;

use crate::sqliteutils::Error as db_error;
use stacks_common::types::chainstate::BurnchainHeaderHash;
use stacks_common::types::chainstate::SortitionId;
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::chainstate::{TrieHash, TRIEHASH_ENCODED_SIZE};

mod sqliteutils;

pub mod bits;
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


















impl MarfTrieId for SortitionId {}
impl MarfTrieId for StacksBlockId {}
impl MarfTrieId for BurnchainHeaderHash {}
#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

pub trait TrieHashExtension {
    fn from_empty_data() -> TrieHash;
    fn from_data(data: &[u8]) -> TrieHash;
    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> TrieHash;
    fn to_string(&self) -> String;
}

impl TrieHashExtension for TrieHash {
    /// TrieHash of zero bytes
    fn from_empty_data() -> TrieHash {
        // sha2-512/256 hash of empty string.
        // this is used so frequently it helps performance if we just have a constant for it.
        TrieHash([
            0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51,
            0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e,
            0xce, 0xf0, 0x96, 0x7a,
        ])
    }

    /// TrieHash from bytes
    fn from_data(data: &[u8]) -> TrieHash {
        if data.len() == 0 {
            return TrieHash::from_empty_data();
        }

        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();
        hasher.update(data);
        tmp.copy_from_slice(hasher.finalize().as_slice());

        TrieHash(tmp)
    }

    fn from_data_array<B: AsRef<[u8]>>(data: &[B]) -> TrieHash {
        if data.len() == 0 {
            return TrieHash::from_empty_data();
        }

        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();

        for item in data.iter() {
            hasher.update(item);
        }
        tmp.copy_from_slice(hasher.finalize().as_slice());
        TrieHash(tmp)
    }

    /// Convert to a String that can be used in e.g. sqlite
    fn to_string(&self) -> String {
        let s = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                          self.0[0],     self.0[1],       self.0[2],       self.0[3],
                          self.0[4],     self.0[5],       self.0[6],       self.0[7],
                          self.0[8],     self.0[9],       self.0[10],      self.0[11],
                          self.0[12],    self.0[13],      self.0[14],      self.0[15],
                          self.0[16],    self.0[17],      self.0[18],      self.0[19],
                          self.0[20],    self.0[21],      self.0[22],      self.0[23],
                          self.0[24],    self.0[25],      self.0[26],      self.0[27],
                          self.0[28],    self.0[29],      self.0[30],      self.0[31]);
        s
    }
}