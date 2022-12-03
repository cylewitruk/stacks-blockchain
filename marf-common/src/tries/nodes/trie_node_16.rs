use std::{fmt, io::Read};

use stacks_common::util::hash::to_hex;

use crate::{utils::Utils, MarfError, tries::TriePtr};

use super::{TrieNode4, TrieNode, TrieNodeType, TrieNodeID};

/// Trie node with 16 children
#[derive(Clone, PartialEq)]
pub struct TrieNode16 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 16],
}

impl TrieNode16 {
    pub fn new(path: &Vec<u8>) -> TrieNode16 {
        TrieNode16 {
            path: path.clone(),
            ptrs: [TriePtr::default(); 16],
        }
    }

    /// Promote a Node4 to a Node16
    pub fn from_node4(node4: &TrieNode4) -> TrieNode16 {
        let mut ptrs = [TriePtr::default(); 16];
        for i in 0..4 {
            ptrs[i] = node4.ptrs[i].clone();
        }
        TrieNode16 {
            path: node4.path.clone(),
            ptrs: ptrs,
        }
    }
}

impl fmt::Debug for TrieNode16 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode16(path={} ptrs={})",
            &to_hex(&self.path),
            Utils::ptrs_fmt(&self.ptrs)
        )
    }
}

impl TrieNode for TrieNode16 {
    fn id(&self) -> u8 {
        TrieNodeID::Node16 as u8
    }

    fn empty() -> TrieNode16 {
        TrieNode16 {
            path: vec![],
            ptrs: [TriePtr::default(); 16],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        for i in 0..16 {
            if self.ptrs[i].id != TrieNodeID::Empty as u8 && self.ptrs[i].chr == chr {
                return Some(self.ptrs[i].clone());
            }
        }
        return None;
    }

    fn from_bytes<R: Read>(r: &mut R) -> Result<TrieNode16, MarfError> {
        let mut ptrs_slice = [TriePtr::default(); 16];
        Utils::ptrs_from_bytes(TrieNodeID::Node16 as u8, r, &mut ptrs_slice)?;

        let path = Utils::path_from_bytes(r)?;

        Ok(TrieNode16 {
            path,
            ptrs: ptrs_slice,
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        for i in 0..16 {
            if self.ptrs[i].id() == TrieNodeID::Empty as u8 {
                self.ptrs[i] = ptr.clone();
                return true;
            }
        }
        return false;
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        for i in 0..16 {
            if self.ptrs[i].id() != TrieNodeID::Empty as u8 && self.ptrs[i].chr() == ptr.chr() {
                self.ptrs[i] = ptr.clone();
                return true;
            }
        }
        return false;
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node16(self.clone())
    }
}