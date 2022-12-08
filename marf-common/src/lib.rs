#[macro_use(slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[macro_use(test_debug, debug, info, warn, error, trace, impl_byte_array_message_codec, 
    impl_array_newtype, impl_array_hexstring_fmt, impl_byte_array_newtype, define_u8_enum
)]
extern crate stacks_common;

mod utils;
mod block_map;
mod marf_value;
mod marf_trie_id;
mod consensus_serialization;
mod storage;
mod clarity_marf_trie_id;
mod marf_open_opts;
mod marf;
mod marf_transaction;
mod write_chain_tip;
mod marf_connection;
mod tries;
mod cache;
mod diagnostics;

pub mod errors;
pub mod sqlite;
mod trie_hash_extension;
mod compression;

pub use errors::{MarfError, CursorError};
pub use block_map::BlockMap;
pub use marf_value::MarfValue;
pub use marf_trie_id::MarfTrieId;
pub use clarity_marf_trie_id::ClarityMarfTrieId;
pub use marf_open_opts::MarfOpenOpts;
pub use marf::Marf;
pub use {
    write_chain_tip::WriteChainTip,
    marf_connection::MarfConnection,
    tries::Trie,
    cache::TrieCache,
    trie_hash_extension::TrieHashExtension
};

use sha2::Sha512_256 as TrieHasher;

pub const MARF_VALUE_ENCODED_SIZE: u32 = 40;
pub const SENTINEL_ARRAY: [u8; 32] = [255u8; 32];
pub const BLOCK_HASH_TO_HEIGHT_MAPPING_KEY: &str = "__MARF_BLOCK_HASH_TO_HEIGHT";
pub const BLOCK_HEIGHT_TO_HASH_MAPPING_KEY: &str = "__MARF_BLOCK_HEIGHT_TO_HASH";
pub const OWN_BLOCK_HEIGHT_KEY: &str = "__MARF_BLOCK_HEIGHT_SELF";