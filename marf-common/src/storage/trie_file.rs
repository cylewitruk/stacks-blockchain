use std::{io::{SeekFrom, Cursor, self, Read, Write, Seek}, fs::{self, OpenOptions}, collections::HashMap};

use stacks_common::types::chainstate::TrieHash;

use crate::{MarfError, MarfTrieId, tries::{nodes::TrieNodeType, TriePtr}, utils::Utils};

use super::{TrieIndexProvider, TrieFileDisk, TrieFileRAM};

/// Mapping between block IDs and trie offsets
pub type TrieIdOffsets = HashMap<u32, u64>;

pub trait TrieFileTrait<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>> {
    /// Does the TrieFile exist at the expected path?
    fn exists(path: &str) -> Result<bool, MarfError>;

    /// Get a copy of the path to this TrieFile.
    /// If in RAM, then the path will be ":memory:"
    fn get_path(&self) -> String;

    /// Instantiate a TrieFile, given the associated DB path.
    /// If path is ':memory:', then it'll be an in-RAM TrieFile.
    /// Otherwise, it'll be stored as `$db_path.blobs`.
    fn from_db_path(path: &str, readonly: bool) -> Result<TrieFile, MarfError>;

    /// Append a new trie blob to external storage, and add the offset and length to the trie DB.
    /// Return the trie ID
    fn store_trie_blob(
        &mut self,
        index: &TIndex,
        bhh: &TTrieId,
        buffer: &[u8],
    ) -> Result<u32, MarfError>;

    /// Copy the trie blobs out of a sqlite3 DB into their own file.
    /// NOTE: this is *not* thread-safe.  Do not call while the DB is being used by another thread.
    fn export_trie_blobs(
        &mut self,
        index: &TIndex,
        db_path: &str,
    ) -> Result<(), MarfError>;

    /// Determine the file offset in the TrieFile where a serialized trie starts.
    /// The offsets are stored in the given DB, and are cached indefinitely once loaded.
    fn get_trie_offset(
        &mut self, 
        index: &TIndex, 
        block_id: u32
    ) -> Result<u64, MarfError>;

    /// Obtain a TrieHash for a node, given its block ID and pointer
    fn get_node_hash_bytes(
        &mut self,
        db: &TIndex,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, MarfError>;

    /// Obtain a TrieNodeType and its associated TrieHash for a node, given its block ID and
    /// pointer
    fn read_node_type(
        &mut self,
        db: &TIndex,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash), MarfError>;

    /// Obtain a TrieNodeType, given its block ID and pointer
    fn read_node_type_nohash(
        &mut self,
        db: &TIndex,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType, MarfError>;

    /// Obtain a TrieHash for a node, given the node's block's hash (used only in testing)
    #[cfg(test)]
    fn get_node_hash_bytes_by_bhh(
        &mut self,
        db: &TIndex,
        bhh: &TTrieId,
        ptr: &TriePtr,
    ) -> Result<TrieHash, MarfError>;

    /// Get all (root hash, trie hash) pairs for this TrieFile
    #[cfg(test)]
    fn read_all_block_hashes_and_roots(
        &mut self,
        db: &TIndex,
    ) -> Result<Vec<(TrieHash, TTrieId)>, MarfError>;

    /// Append a serialized trie to the TrieFile.
    /// Returns the offset at which it was appended.
    fn append_trie_blob(
        &mut self, 
        db: &TIndex, 
        buf: &[u8]
    ) -> Result<u64, MarfError>;

    #[cfg(test)]
    /// Read a trie blob in its entirety from the blobs file
    fn read_trie_blob(
        &mut self, 
        index: &TIndex, 
        block_id: u32
    ) -> Result<Vec<u8>, MarfError>;
    
}

/// This is flat-file storage for a MARF's tries.  All tries are stored as contiguous byte arrays
/// within a larger byte array.  The variants differ in how those bytes are backed.  The `RAM`
/// variant stores data in RAM in a byte buffer, and the `Disk` variant stores data in a flat file
/// on disk.  This structure is used to support external trie blobs, so that the tries don't need
/// to be stored in sqlite blobs (which incurs a sqlite paging overhead).  This is useful for when
/// the tries are too big to fit into a single page, such as the Stacks chainstate.
pub enum TrieFile {
    RAM(TrieFileRAM),
    Disk(TrieFileDisk),
}

/// Boilerplate Write implementation for TrieFile enum.  Plumbs through to the inner struct.
impl Write for TrieFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TrieFile::RAM(ref mut ram) => ram.write(buf),
            TrieFile::Disk(ref mut disk) => disk.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            TrieFile::RAM(ref mut ram) => ram.flush(),
            TrieFile::Disk(ref mut disk) => disk.flush(),
        }
    }
}

impl Seek for TrieFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            TrieFile::RAM(ref mut ram) => ram.seek(pos),
            TrieFile::Disk(ref mut disk) => disk.seek(pos),
        }
    }
}

/// Boilerplate Read implementation for TrieFile enum.  Plumbs through to the inner struct.
impl Read for TrieFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TrieFile::RAM(ref mut ram) => ram.read(buf),
            TrieFile::Disk(ref mut disk) => disk.read(buf),
        }
    }
}

impl TrieFile {
    /// Make a new disk-backed TrieFile
    fn new_disk(path: &str, readonly: bool) -> Result<TrieFile, MarfError> {
        let fd = OpenOptions::new()
            .read(true)
            .write(!readonly)
            .create(!readonly)
            .open(path)?;
        Ok(TrieFile::Disk(TrieFileDisk {
            fd,
            path: path.to_string(),
            trie_offsets: TrieIdOffsets::new(),
        }))
    }

    /// Make a new RAM-backed TrieFile
    fn new_ram(readonly: bool) -> TrieFile {
        TrieFile::RAM(TrieFileRAM {
            fd: Cursor::new(vec![]),
            readonly,
            trie_offsets: TrieIdOffsets::new(),
        })
    }

    /// Does the TrieFile exist at the expected path?
    pub fn exists(path: &str) -> Result<bool, MarfError> {
        if path == ":memory:" {
            Ok(false)
        } else {
            let blob_path = format!("{}.blobs", path);
            match fs::metadata(&blob_path) {
                Ok(_) => Ok(true),
                Err(e) => {
                    if e.kind() == io::ErrorKind::NotFound {
                        Ok(false)
                    } else {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    /// Get a copy of the path to this TrieFile.
    /// If in RAM, then the path will be ":memory:"
    pub fn get_path(&self) -> String {
        match self {
            TrieFile::RAM(_) => ":memory:".to_string(),
            TrieFile::Disk(ref disk) => disk.path.clone(),
        }
    }

    /// Instantiate a TrieFile, given the associated DB path.
    /// If path is ':memory:', then it'll be an in-RAM TrieFile.
    /// Otherwise, it'll be stored as `$db_path.blobs`.
    pub fn from_db_path(path: &str, readonly: bool) -> Result<TrieFile, MarfError> {
        if path == ":memory:" {
            Ok(TrieFile::new_ram(readonly))
        } else {
            let blob_path = format!("{}.blobs", path);
            TrieFile::new_disk(&blob_path, readonly)
        }
    }

    /// Append a new trie blob to external storage, and add the offset and length to the trie DB.
    /// Return the trie ID
    pub fn store_trie_blob<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
        bhh: &TTrieId,
        buffer: &[u8],
    ) -> Result<u32, MarfError> {
        let offset = self.append_trie_blob(db, buffer)?;
        test_debug!("Stored trie blob {} to offset {}", bhh, offset);
        db.write_external_trie_blob(bhh, offset, buffer.len() as u64)
    }

    /// Read a trie blob in its entirety from the blobs file
    #[cfg(test)]
    pub fn read_trie_blob<TTrieId: MarfTrieId>(&mut self, db: &dyn TrieIndexProvider<TTrieId>, block_id: u32) -> Result<Vec<u8>, MarfError> {
        let (offset, length) = db.get_external_trie_offset_length(block_id)?;
        self.seek(SeekFrom::Start(offset))?;

        let mut buf = vec![0u8; length as usize];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl TrieFile {
    /// Determine the file offset in the TrieFile where a serialized trie starts.
    /// The offsets are stored in the given DB, and are cached indefinitely once loaded.
    pub fn get_trie_offset<TTrieId: MarfTrieId>(&mut self, db: &dyn TrieIndexProvider<TTrieId>, block_id: u32) -> Result<u64, MarfError> {
        let offset_opt = match self {
            TrieFile::RAM(ref ram) => ram.trie_offsets.get(&block_id),
            TrieFile::Disk(ref disk) => disk.trie_offsets.get(&block_id),
        };
        match offset_opt {
            Some(offset) => Ok(*offset),
            None => {
                let (offset, _length) = db.get_external_trie_offset_length(block_id)?;
                match self {
                    TrieFile::RAM(ref mut ram) => ram.trie_offsets.insert(block_id, offset),
                    TrieFile::Disk(ref mut disk) => disk.trie_offsets.insert(block_id, offset),
                };
                Ok(offset)
            }
        }
    }

    /// Obtain a TrieHash for a node, given its block ID and pointer
    pub fn get_node_hash_bytes<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, MarfError> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        let hash_buff = Utils::read_hash_bytes(self)?;
        Ok(TrieHash(hash_buff))
    }

    /// Obtain a TrieNodeType and its associated TrieHash for a node, given its block ID and
    /// pointer
    pub fn read_node_type<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash), MarfError> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        Utils::read_nodetype_at_head(self, ptr.id())
    }

    /// Obtain a TrieNodeType, given its block ID and pointer
    pub fn read_node_type_nohash<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType, MarfError> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        Utils::read_nodetype_at_head_nohash(self, ptr.id())
    }

    /// Obtain a TrieHash for a node, given the node's block's hash (used only in testing)
    #[cfg(test)]
    pub fn get_node_hash_bytes_by_bhh<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
        bhh: &TTrieId,
        ptr: &TriePtr,
    ) -> Result<TrieHash, MarfError> {
        let (offset, _length) = db.get_external_trie_offset_length_by_bhh(bhh)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        let hash_buff = Utils::read_hash_bytes(self)?;
        Ok(TrieHash(hash_buff))
    }

    /// Get all (root hash, trie hash) pairs for this TrieFile
    #[cfg(test)]
    pub fn read_all_block_hashes_and_roots<TTrieId: MarfTrieId>(
        &mut self,
        db: &dyn TrieIndexProvider<TTrieId>,
    ) -> Result<Vec<(TrieHash, TTrieId)>, MarfError> {
        use crate::storage::TrieStorageConnection;

        let mut rows_raw = db.read_all_block_hashes_and_offsets()?;
        let result = rows_raw.iter().map(|x| {
            let block_hash = x.0;
            let offset = x.1;

            let start = TrieStorageConnection::<TTrieId>::root_ptr_disk() as u64;

            self.seek(SeekFrom::Start(offset + start))?;
            let hash_buff = Utils::read_hash_bytes(self)?;
            let root_hash = TrieHash(hash_buff);

            trace!(
                "Root hash for block {} at offset {} is {}",
                &block_hash,
                offset + start,
                &root_hash
            );
            Ok((root_hash, block_hash))
        });

        result.collect()

        /*let mut s =
            db.prepare("SELECT block_hash, external_offset FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash")?;
        let rows = s.query_and_then(NO_PARAMS, |row| {
            let block_hash: TTrieId = row.get_unwrap("block_hash");
            let offset_i64: i64 = row.get_unwrap("external_offset");
            let offset = offset_i64 as u64;
            let start = TrieStorageConnection::<TTrieId>::root_ptr_disk() as u64;

            self.seek(SeekFrom::Start(offset + start))?;
            let hash_buff = Utils::read_hash_bytes(self)?;
            let root_hash = TrieHash(hash_buff);

            trace!(
                "Root hash for block {} at offset {} is {}",
                &block_hash,
                offset + start,
                &root_hash
            );
            Ok((root_hash, block_hash))
        })?;
        rows.collect()*/
    }

    /// Append a serialized trie to the TrieFile.
    /// Returns the offset at which it was appended.
    pub fn append_trie_blob<TTrieId: MarfTrieId>(&mut self, db: &dyn TrieIndexProvider<TTrieId>, buf: &[u8]) -> Result<u64, MarfError> {
        let offset = db.get_external_blobs_length()?;
        test_debug!("Write trie of {} bytes at {}", buf.len(), offset);
        self.seek(SeekFrom::Start(offset))?;
        self.write_all(buf)?;
        self.flush()?;

        match self {
            TrieFile::Disk(ref mut data) => {
                data.fd.sync_data()?;
            }
            _ => {}
        }
        Ok(offset)
    }
}