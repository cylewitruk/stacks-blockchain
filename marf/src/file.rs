// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::Path;

use rusqlite::Connection;
use stacks_common::types::chainstate::TrieHash;

use crate::{
    bits::{
        read_hash_bytes, read_nodetype_at_head, read_nodetype_at_head_nohash,
    },
    node::{
        TrieNodeType, TriePtr,
    },
    storage::NodeHashReader,
    Error,
    trie_sql, 
    MarfTrieId
};

use crate::sqliteutils::sql_vacuum;



/// NodeHashReader for TrieFile
pub struct TrieFileNodeHashReader<'a> {
    db: &'a Connection,
    file: &'a mut TrieFile,
    block_id: u32,
}

impl<'a> TrieFileNodeHashReader<'a> {
    pub fn new(
        db: &'a Connection,
        file: &'a mut TrieFile,
        block_id: u32,
    ) -> TrieFileNodeHashReader<'a> {
        TrieFileNodeHashReader { db, file, block_id }
    }
}

impl NodeHashReader for TrieFileNodeHashReader<'_> {
    fn read_node_hash_bytes<W: Write>(&mut self, ptr: &TriePtr, w: &mut W) -> Result<(), Error> {
        let trie_offset = self.file.get_trie_offset(self.db, self.block_id)?;
        self.file
            .seek(SeekFrom::Start(trie_offset + (ptr.ptr() as u64)))?;
        let hash_buff = read_hash_bytes(self.file)?;
        w.write_all(&hash_buff).map_err(|e| e.into())
    }
}

impl TrieFile {
    /// Determine the file offset in the TrieFile where a serialized trie starts.
    /// The offsets are stored in the given DB, and are cached indefinitely once loaded.
    pub fn get_trie_offset(&mut self, db: &Connection, block_id: u32) -> Result<u64, Error> {
        let offset_opt = match self {
            TrieFile::RAM(ref ram) => ram.trie_offsets.get(&block_id),
            TrieFile::Disk(ref disk) => disk.trie_offsets.get(&block_id),
        };
        match offset_opt {
            Some(offset) => Ok(*offset),
            None => {
                let (offset, _length) = trie_sql::get_external_trie_offset_length(db, block_id)?;
                match self {
                    TrieFile::RAM(ref mut ram) => ram.trie_offsets.insert(block_id, offset),
                    TrieFile::Disk(ref mut disk) => disk.trie_offsets.insert(block_id, offset),
                };
                Ok(offset)
            }
        }
    }

    /// Obtain a TrieHash for a node, given its block ID and pointer
    pub fn get_node_hash_bytes(
        &mut self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        let hash_buff = read_hash_bytes(self)?;
        Ok(TrieHash(hash_buff))
    }

    /// Obtain a TrieNodeType and its associated TrieHash for a node, given its block ID and
    /// pointer
    pub fn read_node_type(
        &mut self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<(TrieNodeType, TrieHash), Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        read_nodetype_at_head(self, ptr.id())
    }

    /// Obtain a TrieNodeType, given its block ID and pointer
    pub fn read_node_type_nohash(
        &mut self,
        db: &Connection,
        block_id: u32,
        ptr: &TriePtr,
    ) -> Result<TrieNodeType, Error> {
        let offset = self.get_trie_offset(db, block_id)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        read_nodetype_at_head_nohash(self, ptr.id())
    }

    /// Obtain a TrieHash for a node, given the node's block's hash (used only in testing)
    #[cfg(test)]
    pub fn get_node_hash_bytes_by_bhh<T: MarfTrieId>(
        &mut self,
        db: &Connection,
        bhh: &T,
        ptr: &TriePtr,
    ) -> Result<TrieHash, Error> {
        let (offset, _length) = trie_sql::get_external_trie_offset_length_by_bhh(db, bhh)?;
        self.seek(SeekFrom::Start(offset + (ptr.ptr() as u64)))?;
        let hash_buff = read_hash_bytes(self)?;
        Ok(TrieHash(hash_buff))
    }

    /// Get all (root hash, trie hash) pairs for this TrieFile
    #[cfg(test)]
    pub fn read_all_block_hashes_and_roots<T: MarfTrieId>(
        &mut self,
        db: &Connection,
    ) -> Result<Vec<(TrieHash, T)>, Error> {
        use rusqlite::NO_PARAMS;
        use crate::storage::TrieStorageConnection;

        let mut s =
            db.prepare("SELECT block_hash, external_offset FROM marf_data WHERE unconfirmed = 0 ORDER BY block_hash")?;
        let rows = s.query_and_then(NO_PARAMS, |row| {
            let block_hash: T = row.get_unwrap("block_hash");
            let offset_i64: i64 = row.get_unwrap("external_offset");
            let offset = offset_i64 as u64;
            let start = TrieStorageConnection::<T>::root_ptr_disk() as u64;

            self.seek(SeekFrom::Start(offset + start))?;
            let hash_buff = read_hash_bytes(self)?;
            let root_hash = TrieHash(hash_buff);

            trace!(
                "Root hash for block {} at offset {} is {}",
                &block_hash,
                offset + start,
                &root_hash
            );
            Ok((root_hash, block_hash))
        })?;
        rows.collect()
    }

    /// Append a serialized trie to the TrieFile.
    /// Returns the offset at which it was appended.
    pub fn append_trie_blob(&mut self, db: &Connection, buf: &[u8]) -> Result<u64, Error> {
        let offset = trie_sql::get_external_blobs_length(db)?;
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

/// Boilerplate Write implementation for TrieFileDisk.  Plumbs through to the inner fd.
impl Write for TrieFileDisk {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
}

/// Boilerplate Write implementation for TrieFileRAM.  Plumbs through to the inner fd.
impl Write for TrieFileRAM {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fd.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.fd.flush()
    }
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

/// Boilerplate Read implementation for TrieFileDisk.  Plumbs through to the inner fd.
impl Read for TrieFileDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }
}

/// Boilerplate Read implementation for TrieFileRAM.  Plumbs through to the inner fd.
impl Read for TrieFileRAM {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
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

/// Boilerplate Seek implementation for TrieFileDisk.  Plumbs through to the inner fd
impl Seek for TrieFileDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
    }
}

/// Boilerplate Seek implementation for TrieFileDisk.  Plumbs through to the inner fd
impl Seek for TrieFileRAM {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
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
