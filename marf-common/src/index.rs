mod trie_index;

pub use {
    trie_index::TrieIndex,
};

#[derive(Debug, Clone)]
pub enum TrieIndexType {
    SQLite,
    RocksDB
}