use std::{fs, io::{Write, Read, Seek, SeekFrom, self}};

use super::trie_file::TrieIdOffsets;

/// Handle to a flat file containing Trie blobs
pub struct TrieFileDisk {
    pub (super) fd: fs::File,
    pub (super) path: String,
    pub (super) trie_offsets: TrieIdOffsets,
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

/// Boilerplate Read implementation for TrieFileDisk.  Plumbs through to the inner fd.
impl Read for TrieFileDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
    }
}

/// Boilerplate Seek implementation for TrieFileDisk.  Plumbs through to the inner fd
impl Seek for TrieFileDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
    }
}