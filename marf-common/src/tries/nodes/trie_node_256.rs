use std::{fmt, io::Read};

use stacks_common::util::{hash::to_hex, slice_partialeq};

use crate::{utils::Utils, MarfError, tries::TriePtr};

use super::{TrieNode4, TrieNode, TrieNodeID, TrieNodeType, TrieNode48};

/// Trie node with 256 children
#[derive(Clone)]
pub struct TrieNode256 {
    pub path: Vec<u8>,
    pub ptrs: [TriePtr; 256],
}

impl fmt::Debug for TrieNode256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode256(path={} ptrs={})",
            &to_hex(&self.path),
            Utils::ptrs_fmt(&self.ptrs)
        )
    }
}

impl PartialEq for TrieNode256 {
    fn eq(&self, other: &TrieNode256) -> bool {
        self.path == other.path && slice_partialeq(&self.ptrs, &other.ptrs)
    }
}

impl TrieNode256 {
    pub fn new(path: &Vec<u8>) -> TrieNode256 {
        TrieNode256 {
            path: path.clone(),
            ptrs: [TriePtr::default(); 256],
        }
    }

    pub fn from_node4(node4: &TrieNode4) -> TrieNode256 {
        let mut ptrs = [TriePtr::default(); 256];
        for i in 0..4 {
            let c = node4.ptrs[i].chr();
            ptrs[c as usize] = node4.ptrs[i].clone();
        }
        TrieNode256 {
            path: node4.path.clone(),
            ptrs: ptrs,
        }
    }

    /// Promote a node48 to a node256
    pub fn from_node48(node48: &TrieNode48) -> TrieNode256 {
        let mut ptrs = [TriePtr::default(); 256];
        for i in 0..48 {
            let c = node48.ptrs[i].chr();
            ptrs[c as usize] = node48.ptrs[i].clone();
        }
        TrieNode256 {
            path: node48.path.clone(),
            ptrs: ptrs,
        }
    }
}

impl TrieNode for TrieNode256 {
    fn id(&self) -> u8 {
        TrieNodeID::Node256 as u8
    }

    fn empty() -> TrieNode256 {
        TrieNode256 {
            path: vec![],
            ptrs: [TriePtr::default(); 256],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        if self.ptrs[chr as usize].id() != TrieNodeID::Empty as u8 {
            return Some(self.ptrs[chr as usize].clone());
        }
        return None;
    }

    fn from_bytes<R: Read>(r: &mut R) -> Result<TrieNode256, MarfError> {
        let mut ptrs_slice = [TriePtr::default(); 256];
        Utils::ptrs_from_bytes(TrieNodeID::Node256 as u8, r, &mut ptrs_slice)?;

        let path = Utils::path_from_bytes(r)?;

        Ok(TrieNode256 {
            path,
            ptrs: ptrs_slice,
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }
        let c = ptr.chr() as usize;
        self.ptrs[c] = ptr.clone();
        return true;
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        let c = ptr.chr() as usize;
        if self.ptrs[c].id() != TrieNodeID::Empty as u8 && self.ptrs[c].chr() == ptr.chr() {
            self.ptrs[c] = ptr.clone();
            return true;
        } else {
            return false;
        }
    }

    fn ptrs(&self) -> &[TriePtr] {
        &self.ptrs
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Node256(Box::new(self.clone()))
    }
}