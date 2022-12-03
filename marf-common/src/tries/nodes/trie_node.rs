use std::io::{Read, Write};

use crate::{utils::Utils, errors::MarfError, tries::TriePtr};

use super::{TrieNodeType};

/// All Trie nodes implement the following methods:
pub trait TrieNode {
    /// Node ID for encoding/decoding
    fn id(&self) -> u8;

    /// Is the node devoid of children?
    fn empty() -> Self;

    /// Follow a path character to a child pointer
    fn walk(&self, chr: u8) -> Option<TriePtr>;

    /// Insert a child pointer if the path character slot is not occupied.
    /// Return true if inserted, false if the slot is already filled
    fn insert(&mut self, ptr: &TriePtr) -> bool;

    /// Replace an existing child pointer with a new one.  Returns true if replaced; false if the
    /// child does not exist.
    fn replace(&mut self, ptr: &TriePtr) -> bool;

    /// Read an encoded instance of this node from a byte stream and instantiate it.
    fn from_bytes<R: Read>(r: &mut R) -> Result<Self, MarfError>
    where
        Self: std::marker::Sized;

    /// Get a reference to the children of this node.
    fn ptrs(&self) -> &[TriePtr];

    /// Get a reference to the children of this node.
    fn path(&self) -> &Vec<u8>;

    /// Construct a TrieNodeType from a TrieNode
    fn as_trie_node_type(&self) -> TrieNodeType;

    /// Encode this node instance into a byte stream and write it to w.
    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[self.id()])?;
        Utils::write_ptrs_to_bytes(self.ptrs(), w)?;
        Utils::write_path_to_bytes(self.path().as_slice(), w)
    }

    #[cfg(test)]
    fn to_bytes(&self) -> Vec<u8> {
        let mut r = Vec::new();
        self.write_bytes(&mut r)
            .expect("Failed to write to byte buffer");
        r
    }

    /// Calculate how many bytes this node will take to encode.
    fn byte_len(&self) -> usize {
        Utils::get_ptrs_byte_len(self.ptrs()) + Utils::get_path_byte_len(self.path())
    }
}