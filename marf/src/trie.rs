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

/// This module defines the methods for reading and inserting into a Trie

use sha2::Digest;

use crate::{
    bits::{get_leaf_hash, get_node_hash},
    marf::MARF,
    node::{
        clear_backptr, is_backptr, set_backptr, TrieCursor, TrieNode, TrieNode16,
        TrieNode256, TrieNode4, TrieNode48, TrieNodeID, TrieNodeType, TriePtr,
    },
    storage::{
        TrieHashCalculationMode, TrieStorageConnection,
    },
    Error, TrieHashExtension, MarfTrieId, TrieHasher, TrieLeaf, TrieHash,
    TRIEHASH_ENCODED_SIZE
};

use stacks_common::util::macros::is_trace;






