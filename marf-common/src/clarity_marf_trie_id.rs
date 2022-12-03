use crate::{MarfValue, SENTINEL_ARRAY};
use stacks_common::types::chainstate::{BurnchainHeaderHash, StacksBlockId, SortitionId};

pub trait ClarityMarfTrieId:
    PartialEq + Clone + std::fmt::Display + std::fmt::Debug + std::convert::From<[u8; 32]>
{
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(self) -> [u8; 32];
    fn from_bytes(from: [u8; 32]) -> Self;
    fn sentinel() -> Self;
}

macro_rules! impl_clarity_marf_trie_id {
    ($thing:ident) => {
        impl ClarityMarfTrieId for $thing {
            fn as_bytes(&self) -> &[u8] {
                self.as_ref()
            }
            fn to_bytes(self) -> [u8; 32] {
                self.0
            }
            fn sentinel() -> Self {
                Self(SENTINEL_ARRAY.clone())
            }
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<MarfValue> for $thing {
            fn from(m: MarfValue) -> Self {
                let h = m.0;
                let mut d = [0u8; 32];
                for i in 0..32 {
                    d[i] = h[i];
                }
                for i in 32..h.len() {
                    if h[i] != 0 {
                        panic!(
                            "Failed to convert MARF value into BHH: data stored after 32nd byte"
                        );
                    }
                }
                Self(d)
            }
        }
    };
}

impl_clarity_marf_trie_id!(BurnchainHeaderHash);
impl_clarity_marf_trie_id!(StacksBlockId);
impl_clarity_marf_trie_id!(SortitionId);

#[cfg(test)]
use stacks_common::types::chainstate::BlockHeaderHash;
#[cfg(test)]
impl_clarity_marf_trie_id!(BlockHeaderHash);

