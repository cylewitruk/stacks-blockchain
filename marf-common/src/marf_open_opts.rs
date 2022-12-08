use crate::tries::TrieHashCalculationMode;


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
    /// The file path of the index
    pub db_path: String,
    /// The index storage type
    pub trie_index_type: TrieIndexType
}

impl MarfOpenOpts {
    pub fn default() -> MarfOpenOpts {
        MarfOpenOpts {
            hash_calculation_mode: TrieHashCalculationMode::Deferred,
            cache_strategy: "noop".to_string(),
            external_blobs: false,
            force_db_migrate: false,
        }
    }

    pub fn new(
        hash_calculation_mode: TrieHashCalculationMode,
        cache_strategy: &str,
        external_blobs: bool,
    ) -> MarfOpenOpts {
        MarfOpenOpts {
            hash_calculation_mode,
            cache_strategy: cache_strategy.to_string(),
            external_blobs,
            force_db_migrate: false,
        }
    }

    #[cfg(test)]
    pub fn all() -> Vec<MarfOpenOpts> {
        vec![
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", false),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", false),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "noop", true),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "noop", true),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "everything", false),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "everything", false),
            MarfOpenOpts::new(TrieHashCalculationMode::Immediate, "everything", true),
            MarfOpenOpts::new(TrieHashCalculationMode::Deferred, "everything", true),
        ]
    }
}