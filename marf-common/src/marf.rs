use stacks_common::{types::chainstate::TrieHash, util::hash::Sha512Trunc256Sum};

use crate::{
    MarfTrieId,
    Trie,
    storage::{TrieFileStorage, TrieStorageConnection, TrieStorageTransaction, TrieIndexProvider}, 
    WriteChainTip, 
    MarfConnection, MarfError, utils::Utils, CursorError, BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, 
    OWN_BLOCK_HEIGHT_KEY, BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, marf_transaction::MarfTransaction, 
    MarfValue, MarfOpenOpts, 
    tries::{
        TrieMerkleProof, TriePtr, TrieCursor, TriePath, TrieLeaf,
        nodes::{TrieNodeType, TrieNodeID, TrieNode256}, 
    }
};

/// Merklized Adaptive-Radix Forest -- a collection of Merklized Adaptive-Radix Tries.
pub struct Marf<TTrieId: MarfTrieId> {
    storage: TrieFileStorage<TTrieId, dyn TrieIndexProvider>,
    open_chain_tip: Option<WriteChainTip<TTrieId>>,
}

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> MarfConnection<TTrieId, TIndex> for Marf<TTrieId> {
    fn with_conn<F, R>(&mut self, exec: F) -> R
    where
        F: FnOnce(&mut TrieStorageConnection<TTrieId, TIndex>) -> R,
    {
        let mut conn = self.storage.connection();
        exec(&mut conn)
    }
    fn sqlite_conn(&self) -> &Connection {
        self.storage.sqlite_conn()
    }
}

// static methods
impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> Marf<TTrieId> {
    #[cfg(test)]
    pub fn from_storage_opened(storage: TrieFileStorage<TTrieId, TIndex>, opened_to: &TTrieId) -> Marf<TTrieId> {
        Marf {
            storage,
            open_chain_tip: Some(WriteChainTip {
                block_hash: opened_to.clone(),
                height: 0,
            }),
        }
    }

    #[cfg(test)]
    pub fn begin(&mut self, chain_tip: &TTrieId, next_chain_tip: &TTrieId) -> Result<(), MarfError> {
        let mut tx = self.begin_tx()?;
        tx.begin(chain_tip, next_chain_tip)?;
        tx.commit_tx();
        Ok(())
    }

    #[cfg(test)]
    pub fn begin_unconfirmed(&mut self, chain_tip: &TTrieId) -> Result<TTrieId, MarfError> {
        let mut tx = self.begin_tx()?;
        let result = tx.begin_unconfirmed(chain_tip)?;
        tx.commit_tx();
        Ok(result)
    }

    #[cfg(test)]
    pub fn seal(&mut self) -> Result<TrieHash, MarfError> {
        let mut tx = self.begin_tx()?;
        let h = tx.seal()?;
        Ok(h)
    }

    // helper method for walking a node's backpr
    fn walk_backptr(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        start_node: &TrieNodeType,
        chr: u8,
        cursor: &mut TrieCursor<TTrieId>,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr, u32), MarfError> {
        if start_node.is_leaf() {
            panic!("Did not get an intermediate node");
        }

        let ptr_opt = start_node.walk(chr);
        match ptr_opt {
            None => {
                // this node never had a child for this chr
                trace!("Failed to walk to '{}' from {:?}", chr, start_node);
                Err(MarfError::BackptrNotFoundError)
            }
            Some(ptr) => {
                trace!(
                    "Walk backptrs for {:?} to {:?} from {:?}",
                    cursor,
                    &ptr, 
                    &start_node
                );

                // this node had a child for this chr at one point
                let (node, node_hash, node_ptr) = Trie::walk_backptr(storage, &ptr, cursor)?;
                Ok((node, node_hash, node_ptr, ptr.back_block))
            }
        }
    }

    fn node_copy_update_ptrs(ptrs: &mut [TriePtr], child_block_id: u32) -> () {
        for pointer in ptrs.iter_mut() {
            // if the node is empty, do nothing, if it's a back pointer,
            if pointer.id() == TrieNodeID::Empty as u8 || Utils::is_backptr(pointer.id()) {
                continue;
            } else {
                // make backptr
                pointer.back_block = child_block_id;
                pointer.id = Utils::set_backptr(pointer.id());
            }
        }
    }

    fn node_copy_update(node: &mut TrieNodeType, child_block_id: u32) -> Result<TrieHash, MarfError> {
        let hash = match node {
            TrieNodeType::Leaf(leaf) => Utils::get_leaf_hash(leaf),
            _ => {
                Marf::<TTrieId, TIndex>::node_copy_update_ptrs(node.ptrs_mut(), child_block_id);
                TrieHash::from_data(&[])
            }
        };

        Ok(hash)
    }

    /// Given a node, and the chr of one of its children, go find the last instance of that child in
    /// the MARF and copy it forward.  Update its ptrs to point to its descendents.
    /// s must point to the block hash in which this node lives, to which the child will be copied.
    fn node_child_copy(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        node: &TrieNodeType,
        chr: u8,
        cursor: &mut TrieCursor<TTrieId>,
    ) -> Result<(TrieNodeType, TrieHash, TriePtr, TTrieId), MarfError> {
        trace!(
            "Copy to {:?} child {:x} of {:?}",
            storage.get_cur_block(),
            chr,
            node
        );

        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        let (mut child_node, _, child_ptr, _) = Marf::walk_backptr(storage, node, chr, cursor)?;
        let child_block_hash = storage.get_cur_block();
        let child_block_identifier = storage.get_cur_block_identifier()?;

        // update child_node with new ptrs and hashes
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_hash = Marf::<TTrieId, TIndex>::node_copy_update(&mut child_node, child_block_identifier)
            .map_err(|e| MarfError::BlockHashMapCorruptionError(Some(Box::new(e))))?;

        // store it in this trie
        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
        let child_disk_ptr = storage.last_ptr()?;
        let child_ptr = TriePtr::new(child_ptr.id(), chr, child_disk_ptr);
        storage.write_nodetype(child_disk_ptr, &child_node, child_hash.clone())?;

        trace!(
            "Copied child 0x{:02x} to {:?}: ptr={:?} child={:?}",
            chr,
            &cur_block_hash,
            &child_ptr,
            &child_node
        );
        Ok((child_node, child_hash, child_ptr, child_block_hash))
    }

    /// Copy the root node from the previous Trie to this Trie, updating its ptrs.
    /// s must point to the target Trie
    fn root_copy(storage: &mut TrieStorageConnection<TTrieId, TIndex>, prev_block_hash: &TTrieId) -> Result<(), MarfError> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();
        storage.open_block(prev_block_hash)?;
        let prev_block_identifier = storage.get_cur_block_identifier().expect(&format!(
            "called open_block on {}, but found no identifier",
            prev_block_hash
        ));

        let (mut prev_root, _) = Trie::read_root(storage)?;
        let new_root_hash = Marf::<TTrieId, TIndex>::node_copy_update(&mut prev_root, prev_block_identifier)?;

        storage.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        let root_ptr = storage.root_ptr();
        storage.write_nodetype(root_ptr, &prev_root, new_root_hash)?;
        Ok(())
    }

    /// create or open a particular Trie.
    /// If the trie doesn't exist, then extend it from the current Trie and create a root node that
    /// has back pointers to its immediate children in the current trie.
    /// On Ok, s will point to new_bhh and will be open for reading.
    /// Returns true/false, based on whether or not the trie will be created (this can return false
    /// if we're resuming work on an unconfirmed trie)
    pub fn extend_trie(storage: &mut TrieStorageTransaction<TTrieId, TIndex>, new_bhh: &TTrieId) -> Result<(), MarfError> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        let (cur_bhh, cur_block_id) = storage.get_cur_block_and_id();
        if storage.num_blocks() == 0 || cur_bhh == TTrieId::sentinel() {
            // brand new storage
            trace!("Brand new storage -- start with {:?}", new_bhh);
            storage.extend_to_block(new_bhh)?;
            let node = TrieNode256::new(&vec![]);
            let hash = Utils::get_node_hash(&node, &vec![], storage.deref_mut());
            let root_ptr = storage.root_ptr();
            storage.write_nodetype(root_ptr, &TrieNodeType::Node256(Box::new(node)), hash)?;
            Ok(())
        } else {
            // existing storage
            match storage.open_block(new_bhh) {
                Ok(_) => {
                    trace!("Switch to Trie {:?}", new_bhh);
                    Ok(())
                }
                Err(e) => {
                    match e {
                        MarfError::NotFoundError => {
                            // bring root forward
                            debug!("Extend {:?} to {:?}", &cur_bhh, new_bhh);
                            storage.open_block_maybe_id(&cur_bhh, cur_block_id)?;
                            storage.extend_to_block(new_bhh)?;
                            Marf::root_copy(storage, &cur_bhh)?;
                            storage.open_block(new_bhh)?;
                            Ok(())
                        }
                        _ => Err(e),
                    }
                }
            }
        }
    }

    /// Walk down this MARF at the given block hash, doing a copy-on-write for intermediate nodes in this block's Trie from any prior Tries.
    /// s must point to the last filled-in Trie -- i.e. block_hash points to the _new_ Trie that is
    /// being filled in.
    fn walk_cow(
        storage: &mut TrieStorageTransaction<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
    ) -> Result<TrieCursor<TTrieId>, MarfError> {
        let block_id = storage.get_block_identifier(block_hash);
        Marf::extend_trie(storage, block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point
        let mut node = Trie::read_root_nohash(storage)?;
        let mut node_ptr = TriePtr::new(0, 0, 0);

        for _ in 0..(cursor.path.len() + 1) {
            match Trie::walk_from_nohash(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((next_node_ptr, next_node)) => {
                            // end of node path.
                            // keep walking.
                            node = next_node;
                            node_ptr = next_node_ptr;
                            continue;
                        }
                        None => {
                            // end of path.  Should have found leaf.
                            if !node.is_leaf()
                                || Utils::clear_backptr(node_ptr.id()) != TrieNodeID::Leaf as u8
                            {
                                error!("Out-of-path but encountered a non-leaf");
                                return Err(MarfError::CorruptionError(
                                    "Non-leaf encountered at end of path".to_string(),
                                ));
                            }

                            trace!(
                                "Out of path in {:?} -- we're done. Node at {:?}",
                                storage.get_cur_block(),
                                &node_ptr
                            );
                            storage.open_block_maybe_id(block_hash, block_id)?;
                            return Ok(cursor);
                        }
                    }
                }
                Err(e) => {
                    match e {
                        MarfError::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  Will need to copy-on-write
                                    // some nodes over.
                                    trace!("Path diverged -- we're done.");
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                }
                                CursorError::ChrNotFound => {
                                    // end-of-node-path but no such child -- not even a backptr.
                                    trace!("ChrNotFound encountered at {:?} -- we're done (node not found)", storage.get_cur_block());
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    return Ok(cursor);
                                }
                                CursorError::BackptrEncountered(ptr) => {
                                    // at intermediate node whose child is not present in this trie.
                                    // bring the child forward and take the step, if possible.
                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                    let (next_node, _, next_node_ptr, next_node_block_hash) =
                                        Marf::node_child_copy(
                                            storage,
                                            &node,
                                            ptr.chr(),
                                            &mut cursor,
                                        )?;

                                    // finish taking the step
                                    cursor.repair_backptr_finish(
                                        &next_node_ptr,
                                        next_node_block_hash,
                                    );

                                    // keep walking
                                    node = next_node;
                                    node_ptr = next_node_ptr;

                                    storage.open_block_maybe_id(block_hash, block_id)?;
                                }
                            }
                        }
                        _ => {
                            // some other error (e.g. I/O error)
                            return Err(e);
                        }
                    }
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(MarfError::CorruptionError("Trie has a cycle".to_string()));
    }

    /// Walk down this MARF at the given block hash, resolving backptrs to previous tries.
    /// Return the cursor and the last node visited.
    /// s will point to the block in which the leaf was found, or the last block visited.
    fn walk(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
    ) -> Result<(TrieCursor<TTrieId>, TrieNodeType), MarfError> {
        storage.open_block(block_hash)?;

        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        // walk to insertion point
        let mut node = Trie::read_root_nohash(storage).map_err(|e| {
            test_debug!("Failed to read root of {:?}: {:?}", block_hash, &e);
            e
        })?;

        for _ in 0..(cursor.path.len() + 1) {
            storage.bench_mut().marf_walk_from_start();
            match Trie::walk_from_nohash(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((_, next_node)) => {
                            // end-of-node-path, and found a child.
                            // keep walking
                            node = next_node;
                            continue;
                        }
                        None => {
                            // end of path.  Must be at a leaf.
                            if Utils::clear_backptr(cursor.ptr().id()) != TrieNodeID::Leaf as u8 {
                                return Err(MarfError::CorruptionError(
                                    "Non-leaf encountered at end of path".to_string(),
                                ));
                            }

                            trace!("Cursor reached leaf {:?}", &node);
                            storage.bench_mut().marf_walk_from_finish();
                            return Ok((cursor, node));
                        }
                    }
                }
                Err(e) => {
                    match e {
                        MarfError::CursorError(cursor_error) => {
                            match cursor_error {
                                CursorError::PathDiverged => {
                                    // we're done -- path diverged.  No backptr-walking can help us.
                                    trace!("Path diverged -- we're done.");
                                    storage.bench_mut().marf_walk_from_finish();
                                    return Err(MarfError::NotFoundError);
                                }
                                CursorError::ChrNotFound => {
                                    // we're done -- end-of-node-path, but no child node.
                                    // Not even a backptr.
                                    trace!("ChrNotFound encountered -- node does not exist");
                                    storage.bench_mut().marf_walk_from_finish();
                                    return Err(MarfError::NotFoundError);
                                }
                                CursorError::BackptrEncountered(ptr) => {
                                    storage.bench_mut().marf_walk_backptr_start();
                                    // at intermediate node whose child is not present in this trie.
                                    // try to shunt to the prior node that has the child itself.
                                    let (next_node, _, next_node_ptr, _) =
                                        Marf::walk_backptr(storage, &node, ptr.chr(), &mut cursor)?;
                                    storage.bench_mut().marf_walk_backptr_finish();

                                    // finish taking the step
                                    cursor.repair_backptr_finish(
                                        &next_node_ptr,
                                        storage.get_cur_block(),
                                    );

                                    // keep going
                                    node = next_node;
                                    continue;
                                }
                            }
                        }
                        _ => {
                            // some other error (e.g. I/O error)
                            storage.bench_mut().marf_walk_from_finish();
                            return Err(e);
                        }
                    }
                }
            }
        }

        trace!("Trie has a cycle");
        return Err(MarfError::CorruptionError("Trie has a cycle".to_string()));
    }

    pub fn format(
        storage: &mut TrieStorageTransaction<TTrieId, TIndex>,
        first_block_hash: &TTrieId,
    ) -> Result<(), MarfError> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        storage.format()?;
        storage.extend_to_block(first_block_hash)?;
        let node = TrieNode256::new(&vec![]);
        let hash = Utils::get_node_hash(&node, &vec![], storage.deref_mut());
        let root_ptr = storage.root_ptr();
        let node_type = TrieNodeType::Node256(Box::new(node));
        storage.write_nodetype(root_ptr, &node_type, hash)
    }

    pub fn get_path(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
    ) -> Result<Option<TrieLeaf>, MarfError> {
        trace!("MARF::get_path({:?}) {:?}", block_hash, path);

        // a NotFoundError _here_ means that a block didn't exist
        storage.open_block(block_hash).map_err(|e| {
            test_debug!("Failed to open block {:?}: {:?}", block_hash, &e);
            e
        })?;

        // a NotFoundError _here_ means that the key doesn't exist in this view
        let (cursor, node) = Marf::walk(storage, block_hash, path).map_err(|e| {
            trace!(
                "Failed to look up key {:?} {:?}: {:?}",
                &block_hash,
                path,
                &e
            );
            e
        })?;

        // both of these get caught by get_by_key and turned into Ok(None)
        //   and a lot of downstream code seems to depend on that behavior, but
        //   should these two different cases be differentiable?

        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("cursor.block_hashes = {:?}", &cursor.block_hashes);
            trace!("cursor.node_ptrs = {:?}", cursor.node_ptrs);
            assert!(false);
        }

        assert!(cursor.eop());

        // out of path and reached the end.
        match node {
            TrieNodeType::Leaf(data) => {
                // found!
                return Ok(Some(data));
            }
            _ => {
                // Trie invariant violation -- a full path reached a non-leaf
                return Err(MarfError::CorruptionError(
                    "Path reached a non-leaf".to_string(),
                ));
            }
        }
    }

    fn do_insert_leaf(
        storage: &mut TrieStorageTransaction<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
        leaf_value: &TrieLeaf,
        update_skiplist: bool,
    ) -> Result<(), MarfError> {
        let mut value = leaf_value.clone();
        let mut cursor = Marf::walk_cow(storage, block_hash, path)?;

        if cursor.block_hashes.len() + 1 != cursor.node_ptrs.len() {
            trace!("c.block_hashes = {:?}", &cursor.block_hashes);
            trace!("c.node_ptrs = {:?}", cursor.node_ptrs);
            assert!(false);
        }

        debug!(
            "MARF Insert in {}: '{}' = '{}' (...{:?})",
            block_hash, path, leaf_value.data, &leaf_value.path
        );

        Trie::add_value(storage, &mut cursor, &mut value)?;

        if update_skiplist {
            Trie::update_root_hash(storage, &cursor)?;
        } else {
            Trie::update_root_node_hash(storage, &cursor)?;
        }
        Ok(())
    }

    pub fn insert_leaf(
        storage: &mut TrieStorageTransaction<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
        value: &TrieLeaf,
    ) -> Result<(), MarfError> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }
        Marf::do_insert_leaf(storage, block_hash, path, value, true)
    }

    // like insert_leaf, but don't update the merkle skiplist
    pub fn insert_leaf_in_batch(
        storage: &mut TrieStorageTransaction<TTrieId, TIndex>,
        block_hash: &TTrieId,
        path: &TriePath,
        value: &TrieLeaf,
    ) -> Result<(), MarfError> {
        if storage.readonly() {
            unreachable!("CORRUPTION: constructed read-only TrieStorageTransaction instance");
        }

        Marf::do_insert_leaf(storage, block_hash, path, value, false)
    }

    /// Instantiate the MARF from a TrieFileStorage instance
    pub fn from_storage(storage: TrieFileStorage<TTrieId, TIndex>) -> Marf<TTrieId> {
        Marf {
            storage: storage,
            open_chain_tip: None,
        }
    }

    /// Instantiate the MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path(path: &str, open_opts: MarfOpenOpts) -> Result<Marf<TTrieId>, MarfError> {
        let file_storage = TrieFileStorage::open(path, open_opts)?;
        Ok(Marf::from_storage(file_storage))
    }

    /// Instantiate an unconfirmed MARF using a TrieFileStorage instance, from the given path on disk.
    /// This will have the side-effect of instantiating a new fork table from the tries encoded on
    /// disk. Performant code should call this method sparingly.
    pub fn from_path_unconfirmed(path: &str, open_opts: MarfOpenOpts) -> Result<Marf<TTrieId>, MarfError> {
        let file_storage = TrieFileStorage::open_unconfirmed(path, open_opts)?;
        Ok(Marf::from_storage(file_storage))
    }

    pub fn get_by_key(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        block_hash: &TTrieId,
        key: &str,
    ) -> Result<Option<MarfValue>, MarfError> {
        let (cur_block_hash, cur_block_id) = storage.get_cur_block_and_id();

        let path = TriePath::from_key(key);

        let result = Marf::get_path(storage, block_hash, &path).or_else(|e| match e {
            MarfError::NotFoundError => Ok(None),
            _ => Err(e),
        });

        // restore
        storage
            .open_block_maybe_id(&cur_block_hash, cur_block_id)
            .map_err(|e| {
                warn!(
                    "Failed to re-open {} {:?}: {:?}",
                    &cur_block_hash, cur_block_id, &e
                );
                warn!("Result of failed key lookup '{}': {:?}", key, &result);
                e
            })?;

        result.map(|option_result| option_result.map(|leaf| leaf.data))
    }

    pub fn get_block_height_miner_tip(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        block_hash: &TTrieId,
        current_block_hash: &TTrieId,
    ) -> Result<Option<u32>, MarfError> {
        let hash_key = format!("{}::{}", BLOCK_HASH_TO_HEIGHT_MAPPING_KEY, block_hash);
        #[cfg(test)]
        {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if storage.test_genesis_block.as_ref() == Some(current_block_hash) {
                return Ok(Some(0));
            }
        }

        let marf_value = if block_hash == current_block_hash {
            Marf::get_by_key(storage, current_block_hash, OWN_BLOCK_HEIGHT_KEY)?
        } else {
            Marf::get_by_key(storage, current_block_hash, &hash_key)?
        };

        Ok(marf_value.map(u32::from))
    }

    pub fn get_block_height(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        block_hash: &TTrieId,
        current_block_hash: &TTrieId,
    ) -> Result<Option<u32>, MarfError> {
        Marf::get_block_height_miner_tip(storage, block_hash, current_block_hash)
    }

    pub fn get_block_at_height(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        height: u32,
        current_block_hash: &TTrieId,
    ) -> Result<Option<TTrieId>, MarfError> {
        #[cfg(test)]
        {
            // used in testing in order to short-circuit block-height lookups
            //   when the trie struct is tested outside of marf.rs usage
            if height == 0 {
                match storage.test_genesis_block {
                    Some(ref s) => return Ok(Some(s.clone())),
                    _ => {}
                }
            }
        }

        let current_block_height =
            match Marf::get_block_height(storage, current_block_hash, current_block_hash)? {
                Some(x) => x,
                None => {
                    error!(
                        "Could not fetch block height for {}, likely not a known block",
                        current_block_hash
                    );
                    return Ok(None);
                }
            };

        if height == current_block_height {
            return Ok(Some(current_block_hash.clone()));
        }

        let height_key = format!("{}::{}", BLOCK_HEIGHT_TO_HASH_MAPPING_KEY, height);

        Marf::get_by_key(storage, current_block_hash, &height_key)
            .map(|option_result| option_result.map(TTrieId::from))
    }

    /// Make an unconfirmed chain tip from an existing chain tip, so that it won't conflict with
    /// the "true" chain tip after the state it represents is later reprocessed and confirmed.
    pub fn make_unconfirmed_chain_tip(chain_tip: &TTrieId) -> TTrieId {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(chain_tip.as_bytes());
        bytes[32..64].copy_from_slice(chain_tip.as_bytes());

        let h = Sha512Trunc256Sum::from_data(&bytes);
        let mut res_bytes = [0u8; 32];
        res_bytes[0..32].copy_from_slice(h.as_bytes());

        TTrieId::from_bytes(res_bytes)
    }

    /// Insert a batch of key/value pairs.  More efficient than inserting them individually, since
    /// the trie root hash will only be calculated once (which is an O(log B) operation).
    fn inner_insert_batch(
        conn: &mut TrieStorageTransaction<TTrieId, TIndex>,
        block_hash: &TTrieId,
        keys: &Vec<String>,
        values: Vec<MarfValue>,
    ) -> Result<(), MarfError> {
        assert_eq!(keys.len(), values.len());

        if keys.len() == 0 {
            return Ok(());
        }

        let (cur_block_hash, cur_block_id) = conn.get_cur_block_and_id();

        let last = keys.len() - 1;
        let mut progress = 0;
        let eta_enabled = keys.len() > 10_000;
        let mut result = keys[0..last]
            .iter()
            .enumerate()
            .zip(values[0..last].iter())
            .try_for_each(|((index, key), value)| {
                let marf_leaf = TrieLeaf::from_value(&vec![], value.clone());
                let path = TriePath::from_key(key);

                if eta_enabled {
                    let updated_progress = 100 * index / last;
                    if updated_progress > progress {
                        progress = updated_progress;
                        info!(
                            "Batching insertions in MARF: {}% ({} out of {})",
                            progress, index, last
                        );
                    }
                }
                Marf::insert_leaf_in_batch(conn, block_hash, &path, &marf_leaf)
            });

        if result.is_ok() {
            // last insert updates the root with the skiplist hash
            let marf_leaf = TrieLeaf::from_value(&vec![], values[last].clone());
            let path = TriePath::from_key(&keys[last]);
            result = Marf::insert_leaf(conn, block_hash, &path, &marf_leaf);
        }

        // restore
        conn.open_block_maybe_id(&cur_block_hash, cur_block_id)?;

        result
    }
}

// instance methods
impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider> Marf<TTrieId> {
    pub fn begin_tx<'a>(&'a mut self) -> Result<MarfTransaction<'a, TTrieId, TIndex>, MarfError> {
        let storage = self.storage.transaction()?;
        Ok(MarfTransaction {
            storage,
            open_chain_tip: &mut self.open_chain_tip,
        })
    }

    /// Target the MARF's storage at a given block.
    pub fn open_block(&mut self, block_hash: &TTrieId) -> Result<(), MarfError> {
        self.storage.connection().open_block(block_hash)
    }

    pub fn get_with_proof(
        &mut self,
        block_hash: &TTrieId,
        key: &str,
    ) -> Result<Option<(MarfValue, TrieMerkleProof<TTrieId>)>, MarfError> {
        let mut conn = self.storage.connection();
        let marf_value = match Marf::get_by_key(&mut conn, block_hash, key)? {
            None => return Ok(None),
            Some(x) => x,
        };
        let proof = TrieMerkleProof::from_raw_entry(&mut conn, key, &marf_value, block_hash)?;
        Ok(Some((marf_value, proof)))
    }

    pub fn get_bhh_at_height(&mut self, block_hash: &TTrieId, height: u32) -> Result<Option<TTrieId>, MarfError> {
        Marf::get_block_at_height(&mut self.storage.connection(), height, block_hash)
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

        let mut tx = self.storage.transaction()?;
        Marf::inner_insert_batch(&mut tx, &block_hash, keys, values)?;
        tx.commit_tx();
        Ok(())
    }

    pub fn insert(&mut self, key: &str, value: MarfValue) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        let marf_leaf = TrieLeaf::from_value(&vec![], value);
        let path = TriePath::from_key(key);
        self.insert_raw(path, marf_leaf)
    }

    /// Insert the given (key, value) pair into the MARF.  Inserting the same key twice silently
    /// overwrites the existing key.  Succeeds if there are no storage errors.
    /// Must be called after a call to .begin() (will fail otherwise)
    pub fn insert_raw(&mut self, path: TriePath, marf_leaf: TrieLeaf) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        match self.open_chain_tip {
            None => Err(MarfError::WriteNotBegunError),
            Some(WriteChainTip { ref block_hash, .. }) => {
                let mut tx = self.storage.transaction()?;
                let (cur_block_hash, cur_block_id) = tx.get_cur_block_and_id();

                let result = Marf::insert_leaf(&mut tx, block_hash, &path, &marf_leaf);

                // restore
                tx.open_block_maybe_id(&cur_block_hash, cur_block_id)?;
                tx.commit_tx();

                result
            }
        }
    }

    /// Drop the current trie from the MARF. This rolls back all
    ///   changes in the block, and closes the current chain tip.
    pub fn drop_current(&mut self) {
        if !self.storage.readonly() {
            let mut tx = self
                .storage
                .transaction()
                .expect("BUG: failed to start transaction to drop trie");
            tx.drop_extending_trie();
            self.open_chain_tip.take();
            tx.open_block(&TTrieId::sentinel())
                .expect("BUG: should never fail to open the block sentinel");
            tx.commit_tx();
        }
    }

    /// Drop the current trie from the MARF, and roll back all unconfirmed state
    pub fn drop_unconfirmed(&mut self) {
        if !self.storage.readonly() && self.storage.unconfirmed() {
            if let Some(tip) = self.open_chain_tip.take() {
                let mut tx = self
                    .storage
                    .transaction()
                    .expect("BUG: failed to start transaction to drop trie");
                tx.drop_unconfirmed_trie(&tip.block_hash);
                tx.open_block(&TTrieId::sentinel())
                    .expect("BUG: should never fail to open the block sentinel");
                tx.commit_tx();
            }
        }
    }

    /// Finish writing the next trie in the MARF.  This persists all changes.
    /// Works for both confirmed and unconfirmed tries
    pub fn commit(&mut self) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush()?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF -- this is used by miners
    ///   to commit the mined block, but write it to the mined_block table,
    ///   rather than out to the marf_data table (this prevents the
    ///   miner's block from getting stepped on after the sortition).
    pub fn commit_mined(&mut self, bhh: &TTrieId) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(MarfError::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_mined(bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    /// Finish writing the next trie in the MARF, but change the hash of the current Trie's
    /// block hash to something other than what we opened it as.  This persists all changes.
    pub fn commit_to(&mut self, real_bhh: &TTrieId) -> Result<(), MarfError> {
        if self.storage.readonly() {
            return Err(MarfError::ReadOnlyError);
        }
        if self.storage.unconfirmed() {
            return Err(MarfError::UnconfirmedError);
        }
        if let Some(_tip) = self.open_chain_tip.take() {
            let mut tx = self.storage.transaction()?;
            tx.flush_to(real_bhh)?;
            tx.commit_tx();
        }
        Ok(())
    }

    // Comes from the marf.
    pub fn get_block_height_of(
        &mut self,
        bhh: &TTrieId,
        current_block_hash: &TTrieId,
    ) -> Result<Option<u32>, MarfError> {
        if Some(bhh) == self.get_open_chain_tip() {
            return Ok(self.get_open_chain_tip_height());
        } else {
            Marf::get_block_height_miner_tip(
                &mut self.storage.connection(),
                bhh,
                current_block_hash,
            )
        }
    }

    /// Get open chain tip
    pub fn get_open_chain_tip(&self) -> Option<&TTrieId> {
        self.open_chain_tip.as_ref().map(|x| &x.block_hash)
    }

    /// Get open chain tip
    pub fn get_open_chain_tip_height(&self) -> Option<u32> {
        self.open_chain_tip.as_ref().map(|x| x.height)
    }

    /// Access internal storage
    #[cfg(test)]
    pub fn borrow_storage_backend(&mut self) -> TrieStorageConnection<TTrieId, TIndex> {
        self.storage.connection()
    }

    #[cfg(test)]
    pub fn borrow_storage_transaction(&mut self) -> TrieStorageTransaction<TTrieId, TIndex> {
        self.storage.transaction().unwrap()
    }

    /// Make a raw transaction to the underlying storage
    pub fn storage_tx<'a>(&'a mut self) -> Result<Transaction<'a>, db_error> {
        self.storage.sqlite_tx()
    }

    /// Reopen storage read-only
    pub fn reopen_storage_readonly(&self) -> Result<TrieFileStorage<TTrieId, TIndex>, MarfError> {
        self.storage.reopen_readonly()
    }

    /// Reopen this MARF with readonly storage.
    ///
    /// Returns Err if:
    ///   1) This class is already in the process of writing.
    ///   2) A new underlying SQLite database connection cannot be established.
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

    /// Get the root trie hash at a particular block
    pub fn get_root_hash_at(&mut self, block_hash: &TTrieId) -> Result<TrieHash, MarfError> {
        self.storage.connection().get_root_hash_at(block_hash)
    }
}