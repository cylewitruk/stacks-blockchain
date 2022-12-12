use std::io::{Cursor, Seek, self, Read, Write, SeekFrom};

use super::trie_file::TrieIdOffsets;

/// Handle to a flat in-memory buffer containing Trie blobs (used for testing)
pub struct TrieFileRAM {
    pub (super) fd: Cursor<Vec<u8>>,
    pub (super) readonly: bool,
    pub (super) trie_offsets: TrieIdOffsets,
}

/// Boilerplate Seek implementation for TrieFileDisk.  Plumbs through to the inner fd
impl Seek for TrieFileRAM {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
    }
}

/// Boilerplate Read implementation for TrieFileRAM.  Plumbs through to the inner fd.
impl Read for TrieFileRAM {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fd.read(buf)
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