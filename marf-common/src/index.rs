mod trie_index;
mod trie_index_provider;

pub use {
    trie_index::TrieIndex,
    trie_index_provider::TrieIndexProvider
};

#[derive(Debug, Clone)]
pub enum TrieIndexType {
    SQLite,
    RocksDB
}