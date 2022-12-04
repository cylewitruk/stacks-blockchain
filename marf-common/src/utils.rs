use std::io::{Write, Read, ErrorKind, Seek, SeekFrom};

use stacks_common::{types::chainstate::TrieHash, util::hash::to_hex};

use crate::{errors::MarfError, BlockMap, tries::{TriePtr, nodes::{TrieNodeID, TrieNodeType, TrieNode4, TrieNode16, TrieNode256, TrieNode48, TrieNode}, TRIEPTR_SIZE, TRIEPATH_MAX_LEN, TrieLeaf}, storage::{TrieIndexProvider, TrieStorageConnection}, consensus_serialization::ConsensusSerializable, MarfTrieId, TRIEHASH_ENCODED_SIZE};

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

    pub fn write_ptrs_to_bytes<W: Write>(ptrs: &[TriePtr], w: &mut W) -> Result<(), MarfError> {
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

    /// Get the size of a Trie path (note that a Trie path is 32 bytes long, and can definitely _not_
    /// be over 255 bytes).
    pub fn get_path_byte_len(p: &Vec<u8>) -> usize {
        assert!(p.len() < 255);
        let path_len_byte_len = 1;
        path_len_byte_len + p.len()
    }

    /// Decode a trie path from a Readable object.
    /// Returns Error::CorruptionError if the path doesn't decode.
    pub fn path_from_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>, MarfError> {
        let mut lenbuf = [0u8; 1];
        r.read_exact(&mut lenbuf).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                MarfError::CorruptionError("Failed to read len buf".to_string())
            } else {
                eprintln!("failed: {:?}", &e);
                MarfError::IOError(e)
            }
        })?;

        if lenbuf[0] as usize > TRIEPATH_MAX_LEN {
            trace!(
                "Path length is {} (expected <= {})",
                lenbuf[0],
                TRIEPATH_MAX_LEN
            );
            return Err(MarfError::CorruptionError(format!(
                "Node path is longer than {} bytes (got {})",
                TRIEPATH_MAX_LEN, lenbuf[0]
            )));
        }

        let mut retbuf = vec![0; lenbuf[0] as usize];
        r.read_exact(&mut retbuf).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                MarfError::CorruptionError(format!("Failed to read {} bytes of path", lenbuf[0]))
            } else {
                eprintln!("failed: {:?}", &e);
                MarfError::IOError(e)
            }
        })?;

        Ok(retbuf)
    }

    /// Helper to verify that a Trie node's ID byte is valid.
    pub fn check_node_id(nid: u8) -> bool {
        let node_id = Self::clear_backptr(nid);
        TrieNodeID::from_u8(node_id).is_some()
    }

    /// Helper to return the number of children in a Trie, given its ID.
    pub fn node_id_to_ptr_count(node_id: u8) -> usize {
        match TrieNodeID::from_u8(Self::clear_backptr(node_id))
            .expect(&format!("Unknown node ID {}", node_id))
        {
            TrieNodeID::Leaf => 1,
            TrieNodeID::Node4 => 4,
            TrieNodeID::Node16 => 16,
            TrieNodeID::Node48 => 48,
            TrieNodeID::Node256 => 256,
            TrieNodeID::Empty => panic!("node_id_to_ptr_count: tried getting empty node pointer count"),
        }
    }



    /// Calculate the hash of a TrieNode, given its childrens' hashes.
    pub fn get_node_hash<M, T: ConsensusSerializable<M> + std::fmt::Debug>(
        node: &T,
        child_hashes: &Vec<TrieHash>,
        map: &mut M,
    ) -> TrieHash {
        let mut hasher = crate::TrieHasher::new();

        node.write_consensus_bytes(map, &mut hasher)
            .expect("IO Failure pushing to hasher.");

        for child_hash in child_hashes {
            hasher.update(child_hash.as_ref());
        }

        let mut res = [0u8; 32];
        res.copy_from_slice(hasher.finalize().as_slice());

        let ret = TrieHash(res);

        trace!(
            "get_node_hash: hash {:?} = {:?} + {:?}",
            &ret,
            node,
            child_hashes
        );
        ret
    }

    /// Calculate the hash of a TrieLeaf
    pub fn get_leaf_hash(node: &TrieLeaf) -> TrieHash {
        let mut hasher = crate::TrieHasher::new();
        node.write_bytes(&mut hasher)
            .expect("IO Failure pushing to hasher.");

        let mut res = [0u8; 32];
        res.copy_from_slice(hasher.finalize().as_slice());

        let ret = TrieHash(res);

        trace!("get_leaf_hash: hash {:?} = {:?} + []", &ret, node);
        ret
    }

    pub fn get_nodetype_hash_bytes<T: MarfTrieId, M: BlockMap>(
        node: &TrieNodeType,
        child_hash_bytes: &Vec<TrieHash>,
        map: &mut M,
    ) -> TrieHash {
        match node {
            TrieNodeType::Node4(ref data) => Self::get_node_hash(data, child_hash_bytes, map),
            TrieNodeType::Node16(ref data) => Self::get_node_hash(data, child_hash_bytes, map),
            TrieNodeType::Node48(ref data) => Self::get_node_hash(data.as_ref(), child_hash_bytes, map),
            TrieNodeType::Node256(ref data) => Self::get_node_hash(data.as_ref(), child_hash_bytes, map),
            TrieNodeType::Leaf(ref data) => Self::get_node_hash(data, child_hash_bytes, map),
        }
    }

    /// Low-level method for reading a TrieHash into a byte buffer from a Read-able and Seek-able struct.
    /// The byte buffer must have sufficient space to hold the hash, or this program panics.
    pub fn read_hash_bytes<F: Read>(f: &mut F) -> Result<[u8; TRIEHASH_ENCODED_SIZE], MarfError> {
        let mut hashbytes = [0u8; TRIEHASH_ENCODED_SIZE];
        f.read_exact(&mut hashbytes).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                MarfError::CorruptionError(format!(
                    "Failed to read hash in full from {}",
                    to_hex(&hashbytes)
                ))
            } else {
                eprintln!("failed: {:?}", &e);
                MarfError::IOError(e)
            }
        })?;

        Ok(hashbytes)
    }

    pub fn read_block_identifier<F: Read + Seek>(f: &mut F) -> Result<u32, MarfError> {
        let mut bytes = [0u8; 4];
        f.read_exact(&mut bytes).map_err(|e| {
            if e.kind() == ErrorKind::UnexpectedEof {
                MarfError::CorruptionError(format!(
                    "Failed to read hash in full from {}",
                    f.seek(SeekFrom::Current(0)).unwrap()
                ))
            } else {
                eprintln!("failed: {:?}", &e);
                MarfError::IOError(e)
            }
        })?;

        Ok(u32::from_le_bytes(bytes))
    }

    /// Low-level method for reading a node's hash bytes into a buffer from a Read-able and Seek-able struct.
    /// The byte buffer must have sufficient space to hold the hash, or this program panics.
    pub fn read_node_hash_bytes<F: Read + Seek>(
        f: &mut F,
        ptr: &TriePtr,
    ) -> Result<[u8; TRIEHASH_ENCODED_SIZE], MarfError> {
        f.seek(SeekFrom::Start(ptr.ptr() as u64))
            .map_err(MarfError::IOError)?;
        Self::read_hash_bytes(f)
    }

    /// Read the root hash from a TrieFileStorage instance
    pub fn read_root_hash<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>>(
        s: &mut TrieStorageConnection<TTrieId, TIndex>
    ) -> Result<TrieHash, MarfError> {
        let ptr = s.root_trieptr();
        Ok(s.read_nodeslice_partialeq_hash_bytes(&ptr)?)
    }

    /// count the number of allocated children in a list of a node's children pointers.
    pub fn count_children(children: &[TriePtr]) -> usize {
        let mut cnt = 0;
        for i in 0..children.len() {
            if children[i].id() != TrieNodeID::Empty as u8 {
                cnt += 1;
            }
        }
        cnt
    }

    /// Read a node and its hash
    pub fn read_nodetype<F: Read + Seek>(
        f: &mut F,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        f.seek(SeekFrom::Start(ptr.ptr() as u64))
            .map_err(MarfError::IOError)?;
        trace!("read_nodetype at {:?}", ptr);
        Self::read_nodetype_at_head(f, ptr.id())
    }

    /// Read a node
    pub fn read_nodetype_nohash<F: Read + Seek>(
        f: &mut F,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType, MarfError> {
        f.seek(SeekFrom::Start(ptr.ptr() as u64))
            .map_err(MarfError::IOError)?;
        trace!("read_nodetype_nohash at {:?}", ptr);
        Self::read_nodetype_at_head_nohash(f, ptr.id())
    }

    /// Read a node and hash at the stream's current position
    pub fn read_nodetype_at_head<F: Read + Seek>(
        f: &mut F,
        ptr_id: u8,
    ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        Self::inner_read_nodetype_at_head(f, ptr_id, true).map(|(node, hash_opt)| {
            (
                node,
                hash_opt.expect("FATAL: queried hash but received None"),
            )
        })
    }

    /// Read a node at the stream's current position
    pub fn read_nodetype_at_head_nohash<F: Read + Seek>(
        f: &mut F,
        ptr_id: u8,
    ) -> Result<TrieNodeType, MarfError> {
        Self::inner_read_nodetype_at_head(f, ptr_id, false).map(|(node, _)| node)
    }

    /// Deserialize a node.
    /// Node wire format:
    /// 0               32 33               33+X         33+X+Y
    /// |---------------|--|------------------|-----------|
    ///   node hash      id  ptrs & ptr data      path
    ///
    /// X is fixed and determined by the TrieNodeType variant.
    /// Y is variable, but no more than TriePath::len().
    ///
    /// If `read_hash` is false, then the contents of the node hash are undefined.
    pub fn inner_read_nodetype_at_head<F: Read + Seek>(
        f: &mut F,
        ptr_id: u8,
        read_hash: bool,
    ) -> Result<(TrieNodeType, Option<TrieHash>), MarfError> {
        let h = if read_hash {
            let h = Self::read_hash_bytes(f)?;
            Some(TrieHash(h))
        } else {
            f.seek(SeekFrom::Current(TRIEHASH_ENCODED_SIZE as i64))?;
            None
        };

        let node = match TrieNodeID::from_u8(ptr_id).ok_or_else(|| {
            MarfError::CorruptionError(format!("read_node_type: Unknown trie node type {}", ptr_id))
        })? {
            TrieNodeID::Node4 => {
                let node = TrieNode4::from_bytes(f)?;
                TrieNodeType::Node4(node)
            }
            TrieNodeID::Node16 => {
                let node = TrieNode16::from_bytes(f)?;
                TrieNodeType::Node16(node)
            }
            TrieNodeID::Node48 => {
                let node = TrieNode48::from_bytes(f)?;
                TrieNodeType::Node48(Box::new(node))
            }
            TrieNodeID::Node256 => {
                let node = TrieNode256::from_bytes(f)?;
                TrieNodeType::Node256(Box::new(node))
            }
            TrieNodeID::Leaf => {
                let node = TrieLeaf::from_bytes(f)?;
                TrieNodeType::Leaf(node)
            }
            TrieNodeID::Empty => {
                return Err(MarfError::CorruptionError(
                    "read_node_type: stored empty node type".to_string(),
                ))
            }
        };

        Ok((node, h))
    }

    /// calculate how many bytes a node will be when serialized, including its hash.
    pub fn get_node_byte_len(node: &TrieNodeType) -> usize {
        let hash_len = TRIEHASH_ENCODED_SIZE;
        let node_byte_len = node.byte_len();
        hash_len + node_byte_len
    }

    /// write all the bytes for a node, including its hash, to the given Writeable object.
    /// Returns the number of bytes written.
    pub fn write_nodetype_bytes<F: Write + Seek>(
        f: &mut F,
        node: &TrieNodeType,
        hash: TrieHash,
    ) -> Result<u64, MarfError> {
        let start = f.stream_position().map_err(MarfError::IOError)?;
        f.write_all(hash.as_bytes())?;
        node.write_bytes(f)?;
        let end = f.stream_position().map_err(MarfError::IOError)?;
        trace!(
            "write_nodetype: {:?} {:?} at {}-{}",
            node,
            &hash,
            start,
            end
        );

        Ok(end - start)
    }

}
