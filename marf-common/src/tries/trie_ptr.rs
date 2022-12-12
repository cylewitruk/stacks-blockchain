use std::{io::Write};

use stacks_common::types::chainstate::BLOCK_HEADER_HASH_ENCODED_SIZE;

use crate::{utils::Utils, errors::MarfError, BlockMap, MarfTrieId};

pub const TRIEPTR_SIZE: usize = 10; // full size of a TriePtr

/// Child pointer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TriePtr {
    pub id: u8, // ID of the child.  Will have bit 0x80 set if the child is a back-pointer (in which case, back_block will be nonzero)
    pub chr: u8, // Path character at which this child resides
    pub ptr: u32, // Storage-specific pointer to where the child's encoded bytes can be found
    pub back_block: u32, // Pointer back to the block that contains the child, if it's not in this trie
}

impl Default for TriePtr {
    #[inline]
    fn default() -> TriePtr {
        TriePtr {
            id: 0,
            chr: 0,
            ptr: 0,
            back_block: 0,
        }
    }
}

impl TriePtr {
    #[inline]
    pub fn new(id: u8, chr: u8, ptr: u32) -> TriePtr {
        TriePtr {
            id: id,
            chr: chr,
            ptr: ptr,
            back_block: 0,
        }
    }

    #[inline]
    pub fn id(&self) -> u8 {
        self.id
    }

    #[inline]
    pub fn chr(&self) -> u8 {
        self.chr
    }

    #[inline]
    pub fn ptr(&self) -> u32 {
        self.ptr
    }

    #[inline]
    pub fn back_block(&self) -> u32 {
        self.back_block
    }

    #[inline]
    pub fn from_backptr(&self) -> TriePtr {
        TriePtr {
            id: Utils::clear_backptr(self.id),
            chr: self.chr,
            ptr: self.ptr,
            back_block: 0,
        }
    }

    #[inline]
    pub fn write_bytes<W: Write>(&self, w: &mut W) -> Result<(), MarfError> {
        w.write_all(&[self.id(), self.chr()])?;
        w.write_all(&self.ptr().to_be_bytes())?;
        w.write_all(&self.back_block().to_be_bytes())?;
        Ok(())
    }

    /// The parts of a child pointer that are relevant for consensus are only its ID, path
    /// character, and referred-to block hash.  The software doesn't care about the details of how/where
    /// nodes are stored.
    pub fn write_consensus_bytes<T: MarfTrieId, W: Write, M: BlockMap<T>>(
        &self,
        block_map: &mut M,
        w: &mut W,
    ) -> Result<(), MarfError> {
        w.write_all(&[self.id(), self.chr()])?;

        if Utils::is_backptr(self.id()) {
            w.write_all(
                block_map
                    .get_block_hash_caching(self.back_block())
                    .expect("Block identifier {} refered to an unknown block. Consensus failure.")
                    .as_bytes(),
            )?;
        } else {
            w.write_all(&[0; BLOCK_HEADER_HASH_ENCODED_SIZE])?;
        }
        Ok(())
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> TriePtr {
        assert!(bytes.len() >= TRIEPTR_SIZE);
        let id = bytes[0];
        let chr = bytes[1];
        let ptr = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        let back_block = u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);

        TriePtr {
            id: id,
            chr: chr,
            ptr: ptr,
            back_block: back_block,
        }
    }
}