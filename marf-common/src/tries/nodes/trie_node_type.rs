use std::io::Write;

use crate::{errors::MarfError, BlockMap, tries::{TrieLeaf, TriePtr}, consensus_serialization::ConsensusSerializable, MarfTrieId};

use super::{TrieNode4, TrieNode16, TrieNode48, TrieNode256, TrieNode};

#[derive(Debug, Clone, PartialEq)]
pub enum TrieNodeType {
    Node4(TrieNode4),
    Node16(TrieNode16),
    Node48(Box<TrieNode48>),
    Node256(Box<TrieNode256>),
    Leaf(TrieLeaf),
}

macro_rules! with_node {
    ($self: expr, $pat:pat, $s:expr) => {
        match $self {
            TrieNodeType::Node4($pat) => $s,
            TrieNodeType::Node16($pat) => $s,
            TrieNodeType::Node48($pat) => $s,
            TrieNodeType::Node256($pat) => $s,
            TrieNodeType::Leaf($pat) => $s,
        }
    };
}

impl TrieNodeType {
    pub fn is_leaf(&self) -> bool {
        match self {
            TrieNodeType::Leaf(_) => true,
            _ => false,
        }
    }

    pub fn is_node4(&self) -> bool {
        match self {
            TrieNodeType::Node4(_) => true,
            _ => false,
        }
    }

    pub fn is_node16(&self) -> bool {
        match self {
            TrieNodeType::Node16(_) => true,
            _ => false,
        }
    }

    pub fn is_node48(&self) -> bool {
        match self {
            TrieNodeType::Node48(_) => true,
            _ => false,
        }
    }

    pub fn is_node256(&self) -> bool {
        match self {
            TrieNodeType::Node256(_) => true,
            _ => false,
        }
    }

    pub fn id(&self) -> u8 {
        with_node!(self, ref data, data.id())
    }

    pub fn walk(&self, chr: u8) -> Option<TriePtr> {
        with_node!(self, ref data, data.walk(chr))
    }

    pub fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), MarfError> {
        with_node!(self, ref data, data.write_bytes(w))
    }

    pub fn write_consensus_bytes<TTrieId: MarfTrieId, W: Write, M: BlockMap<TTrieId>>(
        &self,
        map: &mut M,
        w: &mut W,
    ) -> Result<(), MarfError> {
        with_node!(self, ref data, data.write_consensus_bytes(map, w))
    }

    pub fn byte_len(&self) -> usize {
        with_node!(self, ref data, data.byte_len())
    }

    pub fn insert(&mut self, ptr: &TriePtr) -> bool {
        with_node!(self, ref mut data, data.insert(ptr))
    }

    pub fn replace(&mut self, ptr: &TriePtr) -> bool {
        with_node!(self, ref mut data, data.replace(ptr))
    }

    pub fn ptrs(&self) -> &[TriePtr] {
        with_node!(self, ref data, data.ptrs())
    }

    pub fn ptrs_mut(&mut self) -> &mut [TriePtr] {
        match self {
            TrieNodeType::Node4(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node16(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node48(ref mut data) => &mut data.ptrs,
            TrieNodeType::Node256(ref mut data) => &mut data.ptrs,
            TrieNodeType::Leaf(_) => panic!("Leaf has no ptrs"),
        }
    }

    pub fn max_ptrs(&self) -> usize {
        match self {
            TrieNodeType::Node4(_) => 4,
            TrieNodeType::Node16(_) => 16,
            TrieNodeType::Node48(_) => 48,
            TrieNodeType::Node256(_) => 256,
            TrieNodeType::Leaf(_) => 0,
        }
    }

    pub fn path_bytes(&self) -> &Vec<u8> {
        with_node!(self, ref data, &data.path)
    }

    pub fn set_path(&mut self, new_path: Vec<u8>) -> () {
        with_node!(self, ref mut data, data.path = new_path)
    }
}