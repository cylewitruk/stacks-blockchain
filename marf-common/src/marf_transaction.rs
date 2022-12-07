use stacks_common::types::chainstate::TrieHash;

use crate::{MarfTrieId, storage::{TrieStorageTransaction}, WriteChainTip, MarfError, MarfValue, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, Marf, OWN_BLOCK_HEIGHT_KEY};

pub struct MarfTransaction<'a, TTrieId: MarfTrieId> {
    storage: TrieStorageTransaction<'a, TTrieId>,
    open_chain_tip: &'a mut Option<WriteChainTip<TTrieId>>,
}

///
/// MarfTransaction represents a connection to a MARF index,
///   with an open storage transaction. If this struct is
///   dropped without calling commit(), the storage transaction is
///   aborted
///
impl<'a, TTrieId> MarfTransaction<'a, TTrieId>
    where
        TTrieId: MarfTrieId
{
    pub fn commit(mut self) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush()?;
        }
        self.storage.commit_tx();
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(mut self, real_bhh: &TTrieId) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(MarfError::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_to(real_bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(MarfError::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            self.storage.flush_mined(bhh)?;
            self.storage.commit_tx();
        }
        Ok(())
    }

    pub fn get_open_chain_tip(&self) -> Option<&TTrieId> {
        self.open_chain_tip.as_ref().map(|tip| &tip.block_hash)
    }

    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|tip| tip.height)
    }

    pub fn get_block_height_of(
        &mut self,
        bhh: &TTrieId,
        current_block_hash: &TTrieId,
    ) -> Result<Option<u32>, MarfError> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            Marf::get_block_height_miner_tip(&mut self.storage, bhh, current_block_hash)
        }
    }

    #[cfg(test)]
    fn commit_tx(self) {
        self.storage.commit_tx()
    }

    /*pub fn sqlite_tx(&self) -> &Transaction<'a> {
        self.storage.sqlite_tx()
    }

    pub fn sqlite_tx_mut(&mut self) -> &mut Transaction<'a> {
        self.storage.sqlite_tx_mut()
    }*/

    /// Reopen this MARF transaction with readonly storage.
    ///   NOTE: any pending operations in the SQLite transaction _will not_
    ///         have materialized in the reopened view.
    pub fn reopen_readonly(&self) -> Result<Marf<TTrieId>, MarfError> {
        if self.open_chain_tip.is_some() {
            error!(
                "MARF at {} is already in the process of writing",
                &self.storage.db_path
            );
            return Err(MarfError::InProgressError);
        }

        let ro_storage = self.storage.reopen_readonly()?;
        Ok(Marf {
            storage: ro_storage,
            open_chain_tip: None,
        })
    }

    /// Begin writing the next trie in the MARF, given the block header hash that will contain the
    /// associated block's new state.  Call commit() or commit_to() to persist the changes.
    /// Fails if the block already exists.
    /// Storage will point to new chain tip on success.
    pub fn begin(&mut self, chain_tip: &TTrieId, next_chain_tip: &TTrieId) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            return Err(MarfError::InProgressError);
        }
        if self.storage.has_block(next_chain_tip)? {
            error!("Block data already exists: {}", next_chain_tip);
            return Err(MarfError::ExistsError);
        }

        let block_height = self.inner_get_extension_height(chain_tip, next_chain_tip)?;
        Marf::extend_trie(&mut self.storage, next_chain_tip)?;
        self.inner_setup_extension(chain_tip, next_chain_tip, block_height, true)
    }

    /// Set up the trie extension we're making.
    /// Sets storage pointer to chain_tip.
    /// Returns the height next_chain_tip would be at.
    fn inner_get_extension_height(
        &mut self,
        chain_tip: &TTrieId,
        next_chain_tip: &TTrieId,
    ) -> Result<u32, MarfError> {
        // current chain tip must exist if it's not the "sentinel"
        let is_parent_sentinel = chain_tip == &TTrieId::sentinel();
        if !is_parent_sentinel {
            debug!("Extending off of existing node {}", chain_tip);
        } else {
            debug!("First-ever block {}", next_chain_tip; "block" => %next_chain_tip);
        }

        self.storage.open_block(chain_tip)?;

        let block_height = if !is_parent_sentinel {
            let height = Marf::get_block_height_miner_tip(&mut self.storage, chain_tip, chain_tip)?
                .ok_or(MarfError::CorruptionError(format!(
                    "Failed to find block height for `{:?}`",
                    chain_tip
                )))?;
            height
                .checked_add(1)
                .expect("FATAL: block height overflow!")
        } else {
            0
        };

        Ok(block_height)
    }

    /// Set up a new extension.
    /// Opens storage to chain_tip/
    fn inner_setup_extension(
        &mut self,
        chain_tip: &TTrieId,
        next_chain_tip: &TTrieId,
        block_height: u32,
        new_extension: bool,
    ) -> Result<(), MarfError> {
        self.storage.open_block(next_chain_tip)?;
        self.open_chain_tip.replace(WriteChainTip {
            block_hash: next_chain_tip.clone(),
            height: block_height,
        });

        if new_extension {
            self.set_block_heights(chain_tip, next_chain_tip, block_height)
                .map_err(|e| {
                    self.open_chain_tip.take();
                    e
                })?;
        }

        debug!("Opened {} to {}", chain_tip, next_chain_tip);
        Ok(())
    }

    pub fn set_block_heights(
        &mut self,
        block_hash: &TTrieId,
        next_block_hash: &TTrieId,
        height: u32,
    ) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        let mut keys = vec![];
        let mut values = vec![];

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash);

        debug!(
            "Set {}::{} = {}",
            BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height, next_block_hash
        );
        debug!(
            "Set {}::{} = {}",
            BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, next_block_hash, height
        );
        debug!("Set {} = {}", OWN_BLOCK_HEIGHT_KEY, height);

        keys.push(OWN_BLOCK_HEIGHT_KEY.to_string());
        values.push(MarfValue::from(height));

        keys.push(height_key);
        values.push(MarfValue::from(next_block_hash.clone()));

        keys.push(hash_key);
        values.push(MarfValue::from(height));

        if height > 0 {
            let prev_height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height - 1);
            let prev_hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);

            debug!(
                "Set {}::{} = {}",
                BLOCK_HEIGHT_TO_HASH_MAPPING_KEY,
                height - 1,
                block_hash
            );
            debug!(
                "Set {}::{} = {}",
                BLOCK_HASH_TO_HEIGHT_MAPPING_KEY,
                block_hash,
                height - 1
            );

            keys.push(prev_height_key);
            values.push(MarfValue::from(block_hash.clone()));

            keys.push(prev_hash_key);
            values.push(MarfValue::from(height - 1));
        }

        self.insert_batch(&keys, values)?;
        Ok(())
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    pub fn insert_batch(
        &mut self,
        keys: &Vec<String>,
        values: Vec<MarfValue>,
    ) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        assert_eq!(keys.len(), values.len());

        let block_hash = match self.open_chain_tip {
            None => Err(MarfError::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => Ok(block_hash.clone()),
        }?;

        if keys.len() == 0 {
            return Ok(());
        }

        Marf::inner_insert_batch(&mut self.storage, &block_hash, keys, values)?;
        Ok(())
    }

    /// Begin extending the MARF to an unconfirmed trie.  The resulting trie will have a block hash
    /// equal to MARF::make_unconfirmed_block_hash(chain_tip) to avoid collision
    /// and block hash reuse.
    pub fn begin_unconfirmed(&mut self, chain_tip: &TTrieId) -> Result<TTrieId, MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.open_chain_tip.is_some() {
            return Err(MarfError::InProgressError);
        }
        if !self.storage.unconfirmed() {
            return Err(MarfError::UnconfirmedError);
        }

        // chain_tip must exist and must be confirmed
        if !self.storage.has_confirmed_block(chain_tip)? {
            error!("No such confirmed block {}", chain_tip);
            return Err(MarfError::NotFoundError);
        }

        let unconfirmed_tip = Marf::make_unconfirmed_chain_tip(chain_tip);

        let block_height = self.inner_get_extension_height(chain_tip, &unconfirmed_tip)?;

        let created = self.storage.extend_to_unconfirmed_block(&unconfirmed_tip)?;
        if created {
            Marf::root_copy(&mut self.storage, chain_tip)?;
        }

        self.inner_setup_extension(chain_tip, &unconfirmed_tip, block_height, created)?;
        Ok(unconfirmed_tip)
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(mut self) {
        if !self.storage.readonly() {
            self.storage.drop_extending_trie();
            self.open_chain_tip.take();
            self.storage
                .open_block(&TTrieId::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            self.storage.rollback()
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                trace!("Dropping unconfirmed trie {}", &tip.block_hash);
                self.storage.drop_unconfirmed_trie(&tip.block_hash);
                self.storage
                    .open_block(&TTrieId::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                // Dropping unconfirmed state cannot be done with a tx rollback,
                //   because the unconfirmed state may already have been written
                //   to the sqlite table before this transaction began
                self.storage.commit_tx()
            } else {
                trace!("drop_unconfirmed() noop");
            }
        }
    }

    /// Seal the in-RAM MARF state so that no subsequent writes will be permitted.
    /// Returns the new root hash of the MARF.
    /// Runtime-panics if the MARF was already sealed.
    pub fn seal(&mut self) -> Result<TrieHash, MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        let root_hash = self.storage.seal()?;
        Ok(root_hash)
    }
}