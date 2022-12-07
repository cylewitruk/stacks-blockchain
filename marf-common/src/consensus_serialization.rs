use std::io::Write;

use crate::{MarfError, BlockMap, utils::Utils, tries::{nodes::TrieNode, ProofTrieNode}, MarfTrieId};

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

impl<TTrieId: TrieNode, TBlockMap: BlockMap> ConsensusSerializable<TBlockMap> for TTrieId {
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