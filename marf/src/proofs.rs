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

pub fn hashes_fmt(hashes: &[TrieHash]) -> String {
    let mut strs = vec![];
    if hashes.len() < 48 {
        for i in 0..hashes.len() {
            strs.push(format!("{:?}", hashes[i]));
        }
        strs.join(",")
    } else {
        for i in 0..hashes.len() / 4 {
            strs.push(format!(
                "{:?},{:?},{:?},{:?}",
                hashes[4 * i],
                hashes[4 * i + 1],
                hashes[4 * i + 2],
                hashes[4 * i + 3]
            ));
        }
        format!("\n{}", strs.join("\n"))
    }
}

impl<T: MarfTrieId> fmt::Debug for TrieMerkleProofType<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)) => write!(
                f,
                "TrieMerkleProofType::Node4(0x{:02x}, node={:?}, hashes={})",
                chr,
                node,
                hashes_fmt(hashes)
            ),
            TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)) => write!(
                f,
                "TrieMerkleProofType::Node16(0x{:02x}, node={:?}, hashes={})",
                chr,
                node,
                hashes_fmt(hashes)
            ),
            TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)) => write!(
                f,
                "TrieMerkleProofType::Node48(0x{:02x}, node={:?}, hashes={})",
                chr,
                node,
                hashes_fmt(hashes)
            ),
            TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)) => write!(
                f,
                "TrieMerkleProofType::Node256(0x{:02x}, node={:?}, hashes={})",
                chr,
                node,
                hashes_fmt(hashes)
            ),
            TrieMerkleProofType::Leaf((ref chr, ref node)) => write!(
                f,
                "TrieMerkleProofType::Leaf(0x{:02x}, node={:?})",
                chr, node
            ),
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => write!(
                f,
                "TrieMerkleProofType::Shunt(idx={}, hashes={:?})",
                idx, hashes
            ),
        }
    }
}

impl<T: MarfTrieId> Deref for TrieMerkleProof<T> {
    type Target = Vec<TrieMerkleProofType<T>>;
    fn deref(&self) -> &Vec<TrieMerkleProofType<T>> {
        &self.0
    }
}

fn serialize_id_hash_node<W: Write, T: MarfTrieId>(
    fd: &mut W,
    id: &u8,
    node: &ProofTrieNode<T>,
    hashes: &[TrieHash],
) -> Result<(), codec_error> {
    id.consensus_serialize(fd)?;
    node.consensus_serialize(fd)?;
    for hash in hashes.iter() {
        hash.consensus_serialize(fd)?;
    }
    Ok(())
}

macro_rules! deserialize_id_hash_node {
    ($fd:expr, $HashesArray:expr) => {{
        let id = read_next($fd)?;
        let node = read_next($fd)?;
        let mut array = $HashesArray;
        for i in 0..array.len() {
            array[i] = read_next($fd)?;
        }
        (id, node, array)
    }};
}

impl<T: MarfTrieId> StacksMessageCodec for ProofTriePtr<T> {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.id.consensus_serialize(fd)?;
        self.chr.consensus_serialize(fd)?;
        self.back_block.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ProofTriePtr<T>, codec_error> {
        let id = read_next(fd)?;
        let chr = read_next(fd)?;
        let back_block = read_next(fd)?;

        Ok(ProofTriePtr {
            id,
            chr,
            back_block,
        })
    }
}

impl<T: MarfTrieId> StacksMessageCodec for ProofTrieNode<T> {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.id.consensus_serialize(fd)?;
        self.path.consensus_serialize(fd)?;
        self.ptrs.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ProofTrieNode<T>, codec_error> {
        let id = read_next(fd)?;
        let path = read_next(fd)?;
        let ptrs = read_next(fd)?;

        Ok(ProofTrieNode { id, path, ptrs })
    }
}

impl<T: MarfTrieId> StacksMessageCodec for TrieMerkleProofType<T> {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        let type_byte = match self {
            TrieMerkleProofType::Node4(_) => TrieMerkleProofTypeIndicator::Node4,
            TrieMerkleProofType::Node16(_) => TrieMerkleProofTypeIndicator::Node16,
            TrieMerkleProofType::Node48(_) => TrieMerkleProofTypeIndicator::Node48,
            TrieMerkleProofType::Node256(_) => TrieMerkleProofTypeIndicator::Node256,
            TrieMerkleProofType::Leaf(_) => TrieMerkleProofTypeIndicator::Leaf,
            TrieMerkleProofType::Shunt(_) => TrieMerkleProofTypeIndicator::Shunt,
        } as u8;

        type_byte.consensus_serialize(fd)?;

        match self {
            TrieMerkleProofType::Node4((id, proof_node, hashes)) => {
                serialize_id_hash_node(fd, id, proof_node, hashes)
            }
            TrieMerkleProofType::Node16((id, proof_node, hashes)) => {
                serialize_id_hash_node(fd, id, proof_node, hashes)
            }
            TrieMerkleProofType::Node48((id, proof_node, hashes)) => {
                serialize_id_hash_node(fd, id, proof_node, hashes)
            }
            TrieMerkleProofType::Node256((id, proof_node, hashes)) => {
                serialize_id_hash_node(fd, id, proof_node, hashes)
            }
            TrieMerkleProofType::Leaf((id, leaf_node)) => {
                id.consensus_serialize(fd)?;
                leaf_node.consensus_serialize(fd)
            }
            TrieMerkleProofType::Shunt((id, hashes)) => {
                id.consensus_serialize(fd)?;
                hashes.consensus_serialize(fd)
            }
        }
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieMerkleProofType<T>, codec_error> {
        let type_byte = TrieMerkleProofTypeIndicator::from_u8(read_next(fd)?).ok_or_else(|| {
            codec_error::DeserializeError("Bad type byte in Trie Merkle Proof".into())
        })?;

        let codec = match type_byte {
            TrieMerkleProofTypeIndicator::Node4 => {
                TrieMerkleProofType::Node4(deserialize_id_hash_node!(fd, [TrieHash([0; 32]); 3]))
            }
            TrieMerkleProofTypeIndicator::Node16 => {
                TrieMerkleProofType::Node16(deserialize_id_hash_node!(fd, [TrieHash([0; 32]); 15]))
            }
            TrieMerkleProofTypeIndicator::Node48 => {
                TrieMerkleProofType::Node48(deserialize_id_hash_node!(fd, [TrieHash([0; 32]); 47]))
            }
            TrieMerkleProofTypeIndicator::Node256 => TrieMerkleProofType::Node256(
                deserialize_id_hash_node!(fd, [TrieHash([0; 32]); 255]),
            ),
            TrieMerkleProofTypeIndicator::Leaf => {
                let id = read_next(fd)?;
                let leaf_node = read_next(fd)?;
                TrieMerkleProofType::Leaf((id, leaf_node))
            }
            TrieMerkleProofTypeIndicator::Shunt => {
                let id = read_next(fd)?;
                let hashes = read_next(fd)?;
                TrieMerkleProofType::Shunt((id, hashes))
            }
        };

        Ok(codec)
    }
}

impl<T: MarfTrieId> StacksMessageCodec for TrieMerkleProof<T> {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.0.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieMerkleProof<T>, codec_error> {
        let proof_parts: Vec<TrieMerkleProofType<T>> = read_next(fd)?;
        Ok(TrieMerkleProof(proof_parts))
    }
}


