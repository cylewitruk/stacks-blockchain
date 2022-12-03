use std::io::{Write, Read, ErrorKind};

use crate::{errors::MarfError, BlockMap, tries::{TriePtr, nodes::TrieNodeID, TRIEPTR_SIZE}, storage::TrieIndexProvider};

pub struct Utils;

impl Utils {
    /// A node ID encodes a back-pointer if its high bit is set
    pub fn is_backptr(id: u8) -> bool {
        id & 0x80 != 0
    }

    /// Set the back-pointer bit
    pub fn set_backptr(id: u8) -> u8 {
        id | 0x80
    }

    /// Clear the back-pointer bit
    pub fn clear_backptr(id: u8) -> u8 {
        id & 0x7f
    }

    pub fn ptrs_fmt(ptrs: &[TriePtr]) -> String {
        let mut strs = vec![];
        for i in 0..ptrs.len() {
            if ptrs[i].id != TrieNodeID::Empty as u8 {
                strs.push(format!(
                    "id{}chr{:02x}ptr{}bblk{}",
                    ptrs[i].id, ptrs[i].chr, ptrs[i].ptr, ptrs[i].back_block
                ))
            }
        }
        strs.join(",")
    }

    fn write_ptrs_to_bytes<W: Write>(ptrs: &[TriePtr], w: &mut W) -> Result<(), MarfError> {
        for ptr in ptrs.iter() {
            ptr.write_bytes(w)?;
        }
        Ok(())
    }

    /// Helper to determine how many bytes a Trie node's child pointers will take to encode.
    pub fn get_ptrs_byte_len(ptrs: &[TriePtr]) -> usize {
        let node_id_len = 1;
        node_id_len + TRIEPTR_SIZE * ptrs.len()
    }

    /// Read a Trie node's children from a Readable object, and write them to the given ptrs_buf slice.
    /// Returns the Trie node ID detected.
    pub fn ptrs_from_bytes<R: Read>(
        node_id: u8,
        r: &mut R,
        ptrs_buf: &mut [TriePtr],
    ) -> Result<u8, MarfError> {
        if !Self::check_node_id(node_id) {
            trace!("Bad node ID {:x}", node_id);
            return Err(MarfError::CorruptionError(format!(
                "Bad node ID: {:x}",
                node_id
            )));
        }

        let num_ptrs = Self::node_id_to_ptr_count(node_id);
        let mut bytes = vec![0u8; 1 + num_ptrs * TRIEPTR_SIZE];
        r.read_exact(&mut bytes).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                MarfError::CorruptionError(format!(
                    "Failed to read 1 + {} bytes of ptrs",
                    num_ptrs * TRIEPTR_SIZE
                ))
            } else {
                eprintln!("failed: {:?}", &e);
                MarfError::IOError(e)
            }
        })?;

        // verify the id is correct
        let nid = bytes[0];
        if Self::clear_backptr(nid) != Self::clear_backptr(node_id) {
            trace!("Bad idbuf: {:x} != {:x}", nid, node_id);
            return Err(MarfError::CorruptionError(
                "Failed to read expected node ID".to_string(),
            ));
        }

        let ptr_bytes = &bytes[1..];

        let mut i = 0;
        while i < num_ptrs {
            ptrs_buf[i] = TriePtr::from_bytes(&ptr_bytes[i * TRIEPTR_SIZE..(i + 1) * TRIEPTR_SIZE]);
            i += 1;
        }
        Ok(nid)
    }

    pub fn ptrs_consensus_hash<W: Write, M: BlockMap>(
        ptrs: &[TriePtr],
        map: &mut M,
        w: &mut W,
    ) -> Result<(), MarfError> {
        for ptr in ptrs.iter() {
            ptr.write_consensus_bytes(map, w)?;
        }
        Ok(())
    }

    pub fn write_path_to_bytes<W: Write>(path: &[u8], w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[path.len() as u8])?;
        w.write_all(path)?;
        Ok(())
    }
}
