use sha2::Digest;
use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, TRIEHASH_ENCODED_SIZE, MARF_VALUE_ENCODED_SIZE};

pub struct MarfValue(pub [u8; 40]);
impl_array_newtype!(MarfValue, u8, 40);
impl_array_hexstring_fmt!(MarfValue);
impl_byte_array_newtype!(MarfValue, u8, 40);
impl_byte_array_message_codec!(MarfValue, 40);


/// Structure that holds the actual data in a MARF leaf node.
/// It only stores the hash of some value string, but we add 8 extra bytes for future extensions.
/// If not used (the rule today), then they should all be 0.
impl MarfValue {
    /// Construct from a TRIEHASH_ENCODED_SIZE-length slice
    pub fn from_value_hash_bytes(h: &[u8; TRIEHASH_ENCODED_SIZE]) -> MarfValue {
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        for i in 0..TRIEHASH_ENCODED_SIZE {
            d[i] = h[i];
        }
        MarfValue(d)
    }

    /// Construct from a TrieHash
    pub fn from_value_hash(h: &TrieHash) -> MarfValue {
        MarfValue::from_value_hash_bytes(h.as_bytes())
    }

    /// Construct from a String that encodes a value inserted into the underlying data store
    pub fn from_value(s: &str) -> MarfValue {
        let mut tmp = [0u8; 32];

        let mut hasher = crate::TrieHasher::new();
        hasher.update(s.as_bytes());
        tmp.copy_from_slice(hasher.finalize().as_slice());

        MarfValue::from_value_hash_bytes(&tmp)
    }

    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Extract the value hash from the MARF value
    pub fn to_value_hash(&self) -> TrieHash {
        let mut h = [0u8; TRIEHASH_ENCODED_SIZE];
        h.copy_from_slice(&self.0[0..TRIEHASH_ENCODED_SIZE]);
        TrieHash(h)
    }
}

impl From<u32> for MarfValue {
    fn from(value: u32) -> MarfValue {
        let h = value.to_le_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a u32 into a MARF Value.");
        }
        for i in 0..h.len() {
            d[i] = h[i];
        }
        MarfValue(d)
    }
}

impl<T: MarfTrieId> From<T> for MarfValue {
    fn from(bhh: T) -> MarfValue {
        let h = bhh.to_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a BHH into a MARF Value.");
        }
        for i in 0..h.len() {
            d[i] = h[i];
        }
        MarfValue(d)
    }
}

impl From<MarfValue> for u32 {
    fn from(m: MarfValue) -> u32 {
        let h = m.0;
        let mut d = [0u8; 4];
        for i in 0..4 {
            d[i] = h[i];
        }
        for i in 4..h.len() {
            if h[i] != 0 {
                panic!("Failed to convert MARF value into u32: data stored after 4th byte");
            }
        }
        u32::from_le_bytes(d)
    }
}