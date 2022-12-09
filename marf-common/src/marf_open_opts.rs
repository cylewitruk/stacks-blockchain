use crate::{tries::TrieHashCalculationMode, storage::TrieIndexType};


/// Options for opening a MARF
#[derive(Clone, Debug)]
pub struct MarfOpenOpts {
    /// Hash calculation mode for calculating a trie root hash
    pub hash_calculation_mode: TrieHashCalculationMode,
    /// Cache strategy to use
    pub cache_strategy: String,
    /// Store trie blobs externally from the DB, in a flat file (with a `.blobs` extension)
    pub external_blobs: bool,
    /// Unconditionally do a DB migration (used for testing)
    pub force_db_migrate: bool,
    /// The index storage type
    pub trie_index_type: TrieIndexType
}

impl<'a> MarfOpenOpts {
    pub fn default() -> MarfOpenOpts {
        let db_path = ":memory:";
        MarfOpenOpts {
            hash_calculation_mode: TrieHashCalculationMode::Deferred,
            cache_strategy: "noop".to_string(),
            external_blobs: false,
            force_db_migrate: false,
            trie_index_type: TrieIndexType::Sqlite
        }
    }

    pub fn new(
        hash_calculation_mode: TrieHashCalculationMode,
        cache_strategy: &'a str,
        external_blobs: bool,
        trie_index_type: TrieIndexType
    ) -> MarfOpenOpts {
        MarfOpenOpts {
            hash_calculation_mode,
            cache_strategy: cache_strategy.to_string(),
            external_blobs,
            force_db_migrate: false,
            trie_index_type
        }
    }

    #[cfg(test)]
    pub fn all() -> Vec<MarfOpenOpts> {
        vec![
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "everything", false, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "everything", false, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "everything", true, TrieIndexType::Sqlite),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "everything", true, TrieIndexType::Sqlite),
        ]
    }
}