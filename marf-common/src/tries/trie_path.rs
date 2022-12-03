use stacks_common::types::chainstate::TrieHash;

/// A path in the Trie is the SHA2-512/256 hash of its key.
pub struct TriePath([u8; 32]);
impl_array_newtype!(TriePath, u8, 32);
impl_array_hexstring_fmt!(TriePath);
impl_byte_array_newtype!(TriePath, u8, 32);

pub const TRIEPATH_MAX_LEN: usize = 32;

impl TriePath {
    pub fn from_key(k: &str) -> TriePath {
        let h = TrieHash::from_data(k.as_bytes());
        let mut hb = [0u8; TRIEPATH_MAX_LEN];
        hb.copy_from_slice(h.as_bytes());
        TriePath(hb)
    }
}