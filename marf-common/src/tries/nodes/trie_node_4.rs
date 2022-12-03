use std::{fmt, io::Read};

use stacks_common::util::hash::to_hex;

use crate::{MarfError, tries::TriePtr, utils::Utils};

use super::{TrieNode, TrieNodeID, TrieNodeType};

/// Trie node with four children
#[derive(Clone, PartialEq)]
pub struct TrieNode4 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 4],
}

impl fmt::Debug for TrieNode4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode4(path={} ptrs={})",
            &to_hex(&self.path),
            Utils::ptrs_fmt(&self.ptrs)
        )
    }
}

impl TrieNode4 {
    pub fn new(path: &Vec<u8>) -> TrieNode4 {
        TrieNode4 {
            path: path.clone(),
            ptrs: [TriePtr::default(); 4],
        }
    }
}

impl TrieNode for TrieNode4 {
    fn id(&self) -> u8 {
        TrieNodeID::Node4 as u8
    }

    fn empty() -> TrieNode4 {
        TrieNode4 {
            path: vec![],
            ptrs: [TriePtr::default(); 4],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        for i in 0..4 {
            if self.ptrs[i].id() != TrieNodeID::Empty as u8 && self.ptrs[i].chr() == chr {
                return Some(self.ptrs[i].clone());
            }
        }
        return None;
    }

    fn from_bytes<R: Read>(r: &mut R) -> Result<TrieNode4, MarfError> {
        let mut ptrs_slice = [TriePtr::default(); 4];
        Utils::ptrs_from_bytes(TrieNodeID::Node4 as u8, r, &mut ptrs_slice)?;
        let path = Utils::path_from_bytes(r)?;

        Ok(TrieNode4 {
            path,
            ptrs: ptrs_slice,
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        for i in 0..4 {
            if self.ptrs[i].id() == TrieNodeID::Empty as u8 {
                self.ptrs[i] = ptr.clone();
                return true;
            }
        }
        return false;
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        for i in 0..4 {
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
        TrieNodeType::Node4(self.clone())
    }
}