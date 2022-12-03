use std::{fmt, io::{Read, Write}};

use crate::{MarfValue, utils::Utils, MarfError, MARF_VALUE_ENCODED_SIZE};

use super::{nodes::{TrieNode, TrieNodeID, TrieNodeType}, TriePtr};

/// Leaf of a Trie.
#[derive(Clone)]
pub struct TrieLeaf {
    pub path: Vec<u8>,   // path to be lazily expanded
    pub data: MarfValue, // the actual data
}

impl TrieLeaf {
    pub fn new(path: &Vec<u8>, data: &Vec<u8>) -> TrieLeaf {
        assert!(data.len() <= 40);
        let mut bytes = [0u8; 40];
        bytes.copy_from_slice(&data[..]);
        TrieLeaf {
            path: path.clone(),
            data: MarfValue(bytes),
        }
    }

    pub fn from_value(path: &Vec<u8>, value: MarfValue) -> TrieLeaf {
        TrieLeaf {
            path: path.clone(),
            data: value,
        }
    }
}

impl fmt::Debug for TrieLeaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TrieLeaf(path={} data={})",
            &Utils::to_hex(&self.path),
            &self.data.to_hex()
        )
    }
}

impl PartialEq for TrieLeaf {
    fn eq(&self, other: &TrieLeaf) -> bool {
        self.path == other.path && Utils::slice_partialeq(self.data.as_bytes(), other.data.as_bytes())
    }
}

impl TrieNode for TrieLeaf {
    fn id(&self) -> u8 {
        TrieNodeID::Leaf as u8
    }

    fn empty() -> TrieLeaf {
        TrieLeaf::new(&vec![], &[0u8; 40].to_vec())
    }

    fn walk(&self, _chr: u8) -> Option<TriePtr> {
        None
    }

    fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[self.id()])?;
        Utils::write_path_to_bytes(&self.path, w)?;
        w.write_all(&self.data.0[..])?;
        Ok(())
    }

    fn byte_len(&self) -> usize {
        1 + Utils::get_path_byte_len(&self.path) + self.data.len()
    }

    fn from_bytes<R: Read>(r: &mut R) -> Result<TrieLeaf, MarfError> {
        let mut idbuf = [0u8; 1];
        let l_idbuf = r.read(&mut idbuf).map_err(MarfError::IOError)?;

        if l_idbuf != 1 {
            return Err(MarfError::CorruptionError(
                "Leaf: failed to read ID".to_string(),
            ));
        }

        if Utils::clear_backptr(idbuf[0]) != TrieNodeID::Leaf as u8 {
            return Err(MarfError::CorruptionError(format!(
                "Leaf: bad ID {:x}",
                idbuf[0]
            )));
        }

        let path = Utils::path_from_bytes(r)?;
        let mut leaf_data = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        let l_leaf_data = r.read(&mut leaf_data).map_err(MarfError::IOError)?;

        if l_leaf_data != (MARF_VALUE_ENCODED_SIZE as usize) {
            return Err(MarfError::CorruptionError(format!(
                "Leaf: read only {} out of {} bytes",
                l_leaf_data, MARF_VALUE_ENCODED_SIZE
            )));
        }

        Ok(TrieLeaf {
            path: path,
            data: MarfValue(leaf_data),
        })
    }

    fn insert(&mut self, _ptr: &TriePtr) -> bool {
        panic!("can't insert into a leaf");
    }

    fn replace(&mut self, _ptr: &TriePtr) -> bool {
        panic!("can't replace in a leaf");
    }

    fn ptrs(&self) -> &[TriePtr] {
        &[]
    }

    fn path(&self) -> &Vec<u8> {
        &self.path
    }

    fn as_trie_node_type(&self) -> TrieNodeType {
        TrieNodeType::Leaf(self.clone())
    }
}