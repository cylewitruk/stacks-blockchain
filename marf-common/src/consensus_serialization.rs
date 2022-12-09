use std::{io::{Write, Read}, fmt, ops::Deref};

use stacks_common::{types::chainstate::TrieHash, codec::{StacksMessageCodec, read_next, Error as CodecError}};

use crate::{MarfError, BlockMap, utils::Utils, tries::{nodes::TrieNode, ProofTrieNode, trie_merkle_proofs::{TrieMerkleProofType, TrieMerkleProofTypeIndicator}, TrieMerkleProof, ProofTriePtr, TrieLeaf}, MarfTrieId};

/// Trait for types that can serialize to consensus bytes
/// This is implemented by `TrieNode`s and `ProofTrieNode`s
///  and allows hash calculation routines to be the same for
///  both types.
/// The type `M` is used for any additional data structures required
///   (BlockHashMap for TrieNode and () for ProofTrieNode)
pub trait ConsensusSerializable<M> {
    /// Encode the consensus-relevant bytes of this node and write it to w.
    fn write_consensus_bytes<W: Write>(
        &self,
        additional_data: &mut M,
        w: &mut W,
    ) -> Result<(), MarfError>;

    #[cfg(test)]
    fn to_consensus_bytes(&self, additional_data: &mut M) -> Vec<u8> {
        let mut r = Vec::new();
        self.write_consensus_bytes(additional_data, &mut r)
            .expect("Failed to write to byte buffer");
        r
    }
}

impl<TTrieId: TrieNode, TBlockMap: BlockMap<TTrieId>> ConsensusSerializable<TBlockMap> for TTrieId {
    fn write_consensus_bytes<W: Write>(&self, map: &mut TBlockMap, w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[self.id()])?;
        Utils::ptrs_consensus_hash(self.ptrs(), map, w)?;
        Utils::write_path_to_bytes(self.path().as_slice(), w)
    }
}

impl<T: MarfTrieId> ConsensusSerializable<()> for ProofTrieNode<T> {
    fn write_consensus_bytes<W: Write>(
        &self,
        _additional_data: &mut (),
        w: &mut W,
    ) -> Result<(), MarfError> {
        w.write_all(&[self.id])?;
        for ptr in self.ptrs.iter() {
            w.write_all(&[ptr.id, ptr.chr])?;
            w.write_all(ptr.back_block.as_bytes())?;
        }
        Utils::write_path_to_bytes(&self.path, w)
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
) -> Result<(), CodecError> {
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
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.id.consensus_serialize(fd)?;
        self.chr.consensus_serialize(fd)?;
        self.back_block.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ProofTriePtr<T>, CodecError> {
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
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.id.consensus_serialize(fd)?;
        self.path.consensus_serialize(fd)?;
        self.ptrs.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<ProofTrieNode<T>, CodecError> {
        let id = read_next(fd)?;
        let path = read_next(fd)?;
        let ptrs = read_next(fd)?;

        Ok(ProofTrieNode { id, path, ptrs })
    }
}

impl<T: MarfTrieId> StacksMessageCodec for TrieMerkleProofType<T> {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
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

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieMerkleProofType<T>, CodecError> {
        let type_byte = TrieMerkleProofTypeIndicator::from_u8(read_next(fd)?).ok_or_else(|| {
            CodecError::DeserializeError("Bad type byte in Trie Merkle Proof".into())
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
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.0.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieMerkleProof<T>, CodecError> {
        let proof_parts: Vec<TrieMerkleProofType<T>> = read_next(fd)?;
        Ok(TrieMerkleProof(proof_parts))
    }
}

impl StacksMessageCodec for TrieLeaf {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), CodecError> {
        self.path.consensus_serialize(fd)?;
        self.data.consensus_serialize(fd)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<TrieLeaf, CodecError> {
        let path = read_next(fd)?;
        let data = read_next(fd)?;

        Ok(TrieLeaf { path, data })
    }
}