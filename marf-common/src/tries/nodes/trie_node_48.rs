use std::{fmt, io::{Read, Write}};

use stacks_common::util::{hash::to_hex, slice_partialeq};

use crate::{utils::Utils, MarfError, tries::TriePtr};

use super::{TrieNode, TrieNodeID, TrieNode16, TrieNodeType};

/// Trie node with 48 children
#[derive(Clone)]
pub struct TrieNode48 {
    pub path: Vec<u8>,
    indexes: [i8; 256], // indexes[i], if non-negative, is an index into ptrs.
    pub ptrs: [TriePtr; 48],
}

impl fmt::Debug for TrieNode48 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieNode48(path={} ptrs={})",
            &to_hex(&self.path),
            Utils::ptrs_fmt(&self.ptrs)
        )
    }
}

impl PartialEq for TrieNode48 {
    fn eq(&self, other: &TrieNode48) -> bool {
        self.path == other.path
            && slice_partialeq(&self.ptrs, &other.ptrs)
            && slice_partialeq(&self.indexes, &other.indexes)
    }
}

impl TrieNode48 {
    pub fn new(path: &Vec<u8>) -> TrieNode48 {
        TrieNode48 {
            path: path.clone(),
            indexes: [-1; 256],
            ptrs: [TriePtr::default(); 48],
        }
    }

    /// Promote a node16 to a node48
    pub fn from_node16(node16: &TrieNode16) -> TrieNode48 {
        let mut ptrs = [TriePtr::default(); 48];
        let mut indexes = [-1i8; 256];
        for i in 0..16 {
            ptrs[i] = node16.ptrs[i].clone();
            indexes[ptrs[i].chr() as usize] = i as i8;
        }
        TrieNode48 {
            path: node16.path.clone(),
            indexes: indexes,
            ptrs: ptrs,
        }
    }
}

impl TrieNode for TrieNode48 {
    fn id(&self) -> u8 {
        TrieNodeID::Node48 as u8
    }

    fn empty() -> TrieNode48 {
        TrieNode48 {
            path: vec![],
            indexes: [-1; 256],
            ptrs: [TriePtr::default(); 48],
        }
    }

    fn walk(&self, chr: u8) -> Option<TriePtr> {
        let idx = self.indexes[chr as usize];
        if idx >= 0 && idx < 48 && self.ptrs[idx as usize].id() != TrieNodeID::Empty as u8 {
            return Some(self.ptrs[idx as usize].clone());
        }
        return None;
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[self.id()])?;
        Utils::write_ptrs_to_bytes(self.ptrs(), w)?;

        for i in self.indexes.iter() {
            w.write_all(&[*i as u8])?;
        }

        Utils::write_path_to_bytes(self.path().as_slice(), w)
    }

    fn byte_len(&self) -> usize {
        Utils::get_ptrs_byte_len(&self.ptrs) + 256 + Utils::get_path_byte_len(&self.path)
    }

    fn from_bytes<R: Read>(r: &mut R) -> Result<TrieNode48, MarfError> {
        let mut ptrs_slice = [TriePtr::default(); 48];
        Utils::ptrs_from_bytes(TrieNodeID::Node48 as u8, r, &mut ptrs_slice)?;

        let mut indexes = [0u8; 256];
        let l_indexes = r.read(&mut indexes).map_err(MarfError::IOError)?;

        if l_indexes != 256 {
            return Err(MarfError::CorruptionError(
                "Node48: Failed to read 256 indexes".to_string(),
            ));
        }

        let path = Utils::path_from_bytes(r)?;

        let indexes_i8: Vec<i8> = indexes
            .iter()
            .map(|i| {
                let j = *i as i8;
                j
            })
            .collect();
        let mut indexes_slice = [0i8; 256];
        indexes_slice.copy_from_slice(&indexes_i8[..]);

        // not a for-loop because "for ptr in ptrs_slice.iter()" is actually kinda slow
        let mut i = 0;
        while i < ptrs_slice.len() {
            let ptr = &ptrs_slice[i];
            if !(ptr.id() == TrieNodeID::Empty as u8
                || (indexes_slice[ptr.chr() as usize] >= 0
                    && indexes_slice[ptr.chr() as usize] < 48))
            {
                return Err(MarfError::CorruptionError(
                    "Node48: corrupt index array: invalid index value".to_string(),
                ));
            }
            i += 1;
        }

        // not a for-loop because "for i in 0..256" is actually kinda slow
        i = 0;
        while i < 256 {
            if !(indexes_slice[i] < 0
                || (indexes_slice[i] >= 0
                    && (indexes_slice[i] as usize) < ptrs_slice.len()
                    && ptrs_slice[indexes_slice[i] as usize].id() != TrieNodeID::Empty as u8))
            {
                return Err(MarfError::CorruptionError(
                    "Node48: corrupt index array: index points to empty node".to_string(),
                ));
            }
            i += 1;
        }

        Ok(TrieNode48 {
            path,
            indexes: indexes_slice,
            ptrs: ptrs_slice,
        })
    }

    fn insert(&mut self, ptr: &TriePtr) -> bool {
        if self.replace(ptr) {
            return true;
        }

        let c = ptr.chr();
        for i in 0..48 {
            if self.ptrs[i].id() == TrieNodeID::Empty as u8 {
                self.indexes[c as usize] = i as i8;
                self.ptrs[i] = ptr.clone();
                return true;
            }
        }
        return false;
    }

    fn replace(&mut self, ptr: &TriePtr) -> bool {
        let i = self.indexes[ptr.chr() as usize];
        if i >= 0 {
            self.ptrs[i as usize] = ptr.clone();
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
        TrieNodeType::Node48(Box::new(self.clone()))
    }
}