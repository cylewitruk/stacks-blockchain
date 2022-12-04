use stacks_common::types::chainstate::TrieHash;

use crate::{storage::{TrieStorageConnection, TrieIndexProvider}, MarfTrieId, MarfValue, MarfError, Marf, tries::TrieMerkleProof};

///
/// This trait defines functions that are defined for both
///  MARF structs and MarfTransactions
///
pub trait MarfConnection<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<TTrieId, TIndex>) -> R;

    fn sqlite_conn(&self) -> &Connection;

    /// Resolve a key from the MARF to a MARFValue with respect to the given block height.
    fn get(&mut self, block_hash: &TTrieId, key: &str) -> Result<Option<MarfValue>, MarfError> {
        self.with_conn(|c| Marf::get_by_key(c, block_hash, key))
    }

    fn get_with_proof(
        &mut self,
        block_hash: &TTrieId,
        key: &str,
    ) -> Result<Option<(MarfValue, TrieMerkleProof<TTrieId, TIndex>)>, MarfError> {
        self.with_conn(|conn| {
            let marf_value = match Marf::get_by_key(conn, block_hash, key)? {
                None => return Ok(None),
                Some(x) => x,
            };
            let proof = TrieMerkleProof::from_raw_entry(conn, key, &marf_value, block_hash)?;
            Ok(Some((marf_value, proof)))
        })
    }

    fn get_block_at_height(&mut self, height: u32, tip: &TTrieId) -> Result<Option<TTrieId>, MarfError> {
        self.with_conn(|c| Marf::get_block_at_height(c, height, tip))
    }

    fn get_block_height(&mut self, ancestor: &TTrieId, tip: &TTrieId) -> Result<Option<u32>, MarfError> {
        self.with_conn(|c| Marf::get_block_height(c, ancestor, tip))
    }

    /// Get the root trie hash at a particular block
    fn get_root_hash_at(&mut self, block_hash: &TTrieId) -> Result<TrieHash, MarfError> {
        self.with_conn(|c| c.get_root_hash_at(block_hash))
    }

    /// Check if a block can open successfully, i.e.,
    ///   it's a known block, the storage system isn't issueing IOErrors, _and_ it's in the same fork
    ///   as the current block
    /// The MARF _must_ be open to a valid block for this check to be evaluated.
    fn check_ancestor_block_hash(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        self.with_conn(|conn| {
            let cur_block_hash = conn.get_cur_block();
            if cur_block_hash == *bhh {
                // a block is in its own fork
                return Ok(());
            }

            let bhh_height =
                Marf::get_block_height(conn, bhh, &cur_block_hash)?.ok_or_else(|| {
                    MarfError::NonMatchingForks(bhh.clone().to_bytes(), cur_block_hash.clone().to_bytes())
                })?;

            let actual_block_at_height = Marf::get_block_at_height(conn, bhh_height, &cur_block_hash)?
                .ok_or_else(|| MarfError::CorruptionError(format!(
                    "ERROR: Could not find block for height {}, but it was returned by MARF::get_block_height()", bhh_height)))?;

            if bhh != &actual_block_at_height {
                test_debug!("non-matching forks: {} != {}", bhh, &actual_block_at_height);
                return Err(MarfError::NonMatchingForks(
                    bhh.clone().to_bytes(),
                    cur_block_hash.to_bytes(),
                ));
            }

            // test open
            let result = conn.open_block(bhh);

            // restore
            conn.open_block(&cur_block_hash)
                .map_err(|e| MarfError::RestoreMarfBlockError(Box::new(e)))?;

            result
        })
    }
}