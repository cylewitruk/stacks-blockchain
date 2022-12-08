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
use std::fmt;
use std::io::{Read, Write};
use std::ops::Deref;

use crate::{
    bits::{
        get_leaf_hash, get_node_hash, read_root_hash, write_path_to_bytes,
    },
    marf::MARF,
    node::{
        is_backptr, ConsensusSerializable, CursorError, TrieCursor,
        TrieNode, TrieNodeID, TrieNodeType, TriePath, TriePtr,
    },
    storage::TrieStorageConnection,
    trie::Trie,
    Error, BlockMap, MarfTrieId, TrieHashExtension, ClarityMarfTrieId, MARFValue, ProofTrieNode, 
    ProofTriePtr, TrieMerkleProof, TrieMerkleProofType,
};

use stacks_common::{
    util::{hash::to_hex, slice_partialeq},
    codec::{read_next, Error as codec_error, StacksMessageCodec},
    types::chainstate::TrieHash
};

impl<T: MarfTrieId> ConsensusSerializable<()> for ProofTrieNode<T> {
    fn write_consensus_bytes<W: Write>(
        &self,
        _additional_data: &mut (),
        w: &mut W,
    ) -> Result<(), Error> {
        w.write_all(&[self.id])?;
        for ptr in self.ptrs.iter() {
            w.write_all(&[ptr.id, ptr.chr])?;
            w.write_all(ptr.back_block.as_bytes())?;
        }
        write_path_to_bytes(&self.path, w)
    }
}

impl<T: MarfTrieId> ProofTriePtr<T> {
    fn try_from_trie_ptr<M: BlockMap>(
        other: &TriePtr,
        block_map: &mut M,
    ) -> Result<ProofTriePtr<T>, Error> {
        let id = other.id;
        let chr = other.chr;
        let back_block = if is_backptr(id) {
            block_map
                .get_block_hash_caching(other.back_block)?
                .clone()
                .to_bytes()
        } else {
            [0u8; 32]
        };
        Ok(ProofTriePtr {
            id,
            chr,
            back_block: back_block.into(),
        })
    }
}

impl<T: MarfTrieId> ProofTrieNode<T> {
    fn ptrs(&self) -> &[ProofTriePtr<T>] {
        &self.ptrs
    }

    fn try_from_trie_node<N: TrieNode, M: BlockMap>(
        other: &N,
        block_map: &mut M,
    ) -> Result<ProofTrieNode<T>, Error> {
        let id = other.id();
        let path = other.path().clone();
        let ptrs: Result<Vec<_>, Error> = other
            .ptrs()
            .iter()
            .map(|trie_ptr| ProofTriePtr::try_from_trie_ptr(trie_ptr, block_map))
            .collect();
        Ok(ProofTrieNode {
            id,
            path,
            ptrs: ptrs?,
        })
    }
}

define_u8_enum!( TrieMerkleProofTypeIndicator {
    Node4 = 0, Node16 = 1, Node48 = 2, Node256 = 3, Leaf = 4, Shunt = 5
});

impl<T: ClarityMarfTrieId> PartialEq for TrieMerkleProofType<T> {
    fn eq(&self, other: &TrieMerkleProofType<T>) -> bool {
        match (self, other) {
            (
                TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)),
                TrieMerkleProofType::Node4((ref other_chr, ref other_node, ref other_hashes)),
            ) => chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes),
            (
                TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)),
                TrieMerkleProofType::Node16((ref other_chr, ref other_node, ref other_hashes)),
            ) => chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes),
            (
                TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)),
                TrieMerkleProofType::Node48((ref other_chr, ref other_node, ref other_hashes)),
            ) => chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes),
            (
                TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)),
                TrieMerkleProofType::Node256((ref other_chr, ref other_node, ref other_hashes)),
            ) => chr == other_chr && node == other_node && slice_partialeq(hashes, other_hashes),
            (
                TrieMerkleProofType::Leaf((ref chr, ref node)),
                TrieMerkleProofType::Leaf((ref other_chr, ref other_node)),
            ) => chr == other_chr && node == other_node,
            (
                TrieMerkleProofType::Shunt((ref idx_1, ref hashes_1)),
                TrieMerkleProofType::Shunt((ref idx_2, ref hashes_2)),
            ) => idx_1 == idx_2 && hashes_1 == hashes_2,
            (_, _) => false,
        }
    }
}



i


