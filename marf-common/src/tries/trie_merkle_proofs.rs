use std::{collections::HashMap, marker::PhantomData};

use stacks_common::{types::chainstate::TrieHash, util::hash::to_hex};

use crate::{MarfTrieId, storage::{TrieStorageConnection, TrieIndexProvider}, MarfValue, MarfError, tries::nodes::TrieNodeID, Trie, utils::Utils, Marf, CursorError};

use super::{TrieLeaf, TriePath, nodes::TrieNodeType, TriePtr, TrieCursor};

#[derive(Clone)]
pub enum TrieMerkleProofType<T> {
    Node4((u8, ProofTrieNode<T>, [TrieHash; 3])),
    Node16((u8, ProofTrieNode<T>, [TrieHash; 15])),
    Node48((u8, ProofTrieNode<T>, [TrieHash; 47])),
    Node256((u8, ProofTrieNode<T>, [TrieHash; 255])),
    Leaf((u8, TrieLeaf)),
    Shunt((i64, Vec<TrieHash>)),
}

#[derive(Debug)]
pub struct TrieMerkleProof<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>>(pub Vec<TrieMerkleProofType<TTrieId>>, PhantomData<TIndex>);


/// Merkle Proof Trie Pointers have a different structure
///   than the runtime representation --- the proof includes
///   the block header hash for back pointers.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofTrieNode<T> {
    pub id: u8,
    pub path: Vec<u8>,
    pub ptrs: Vec<ProofTriePtr<T>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProofTriePtr<T> {
    pub id: u8,
    pub chr: u8,
    pub back_block: T,
}

impl<TTrieId: MarfTrieId, TIndex: TrieIndexProvider<TTrieId>> TrieMerkleProof<TTrieId, TIndex> 
{
    pub fn to_hex(&self) -> String {
        let mut marf_proof = vec![];
        self.consensus_serialize(&mut marf_proof)
            .expect("Write error on memory buffer");
        to_hex(&marf_proof)
    }

    fn make_proof_hashes(
        node: &TrieNodeType,
        all_hashes: &Vec<TrieHash>,
        chr: u8,
    ) -> Result<Vec<TrieHash>, MarfError> {
        let mut hashes = vec![];
        assert!(all_hashes.len() == node.ptrs().len());

        for i in 0..node.ptrs().len() {
            if node.ptrs()[i].id() == TrieNodeID::Empty as u8 {
                hashes.push(TrieHash::from_data(&[]));
            } else if node.ptrs()[i].chr() != chr {
                hashes.push(all_hashes[i].clone());
            }
        }

        if hashes.len() + 1 != node.ptrs().len() {
            trace!(
                "Char 0x{:02x} does not appear in this node: {:?}",
                chr,
                node
            );
            return Err(MarfError::NotFoundError);
        }

        Ok(hashes)
    }

    /// Given a TriePtr to the _currently-visited_ node and the chr of the _previous_ node, calculate a
    /// Merkle proof node.  Include all the children hashes _except_ for the one that corresponds
    /// to the previous node.
    fn ptr_to_segment_proof_node(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        ptr: &TriePtr,
        prev_chr: u8,
    ) -> Result<TrieMerkleProofType<TTrieId>, MarfError> {
        trace!(
            "ptr_to_proof_node: ptr={:?}, prev_chr=0x{:02x}",
            ptr,
            prev_chr
        );
        let (node, _) = storage.read_nodetype(ptr)?;
        let all_hashes = Trie::get_children_hashes(storage, &node)?;

        let hashes = if node.is_leaf() {
            vec![]
        } else {
            TrieMerkleProof::<TTrieId>::make_proof_hashes(&node, &all_hashes, prev_chr)?
        };

        let proof_node = match node {
            TrieNodeType::Leaf(ref data) => TrieMerkleProofType::Leaf((prev_chr, data.clone())),
            TrieNodeType::Node4(ref data) => {
                let mut hash_slice = [TrieHash::from_data(&[]); 3];
                hash_slice.copy_from_slice(&hashes[0..3]);

                TrieMerkleProofType::Node4((
                    prev_chr,
                    ProofTrieNode::try_from_trie_node(data, storage)?,
                    hash_slice,
                ))
            }
            TrieNodeType::Node16(ref data) => {
                let mut hash_slice = [TrieHash::from_data(&[]); 15];
                hash_slice.copy_from_slice(&hashes[0..15]);

                TrieMerkleProofType::Node16((
                    prev_chr,
                    ProofTrieNode::try_from_trie_node(data, storage)?,
                    hash_slice,
                ))
            }
            TrieNodeType::Node48(ref data) => {
                let mut hash_slice = [TrieHash::from_data(&[]); 47];
                hash_slice.copy_from_slice(&hashes[0..47]);

                TrieMerkleProofType::Node48((
                    prev_chr,
                    ProofTrieNode::try_from_trie_node(data.as_ref(), storage)?,
                    hash_slice,
                ))
            }
            TrieNodeType::Node256(ref data) => {
                let mut hash_slice = [TrieHash::from_data(&[]); 255];
                hash_slice.copy_from_slice(&hashes[0..255]);

                TrieMerkleProofType::Node256(
                    // ancestor hashes to be filled in later
                    (
                        prev_chr,
                        ProofTrieNode::try_from_trie_node(data.as_ref(), storage)?,
                        hash_slice,
                    ),
                )
            }
        };
        Ok(proof_node)
    }

    /// Make the initial shunt proof in a MARF merkle proof, for a node that isn't a backptr.
    /// This is a one-item list of a TrieMerkleProofType::Shunt proof entry.
    /// The storage handle must be opened to the block we care about.
    fn make_initial_shunt_proof(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
    ) -> Result<Vec<TrieMerkleProofType<TTrieId>>, MarfError> {
        let backptr_ancestor_hashes = Trie::get_trie_ancestor_hashes_bytes(storage)?;

        trace!(
            "First shunt proof node: (0, {:?})",
            &backptr_ancestor_hashes
        );

        let backptr_proof = TrieMerkleProofType::Shunt((0, backptr_ancestor_hashes));
        Ok(vec![backptr_proof])
    }

    /// Given a node's (non-backptr) ptr, and the node's backptr, make a shunt proof that links
    /// them.  That is, make a proof that the current trie's root node hash and ptr are only reachable from the
    /// corresponding non-backptr root in this trie's ${ptr.back_block()}th ancestor back.
    /// s must point to the block from which we're going to walk back from.
    ///
    /// The first entry of the shunt proof is the set of Trie root hashes _excluding_ the one from
    /// backptr, as well as the index into the list of Trie root hashes into which the backptr hash
    /// should be inserted (this root hash is calculated from the segment proof for that backptr
    /// node).
    ///
    /// The last entry of the shunt proof is the set of root hashes _excluding_ the final root
    /// hash, which will be the root hash for the segment proof for the non-backptr copy of this
    /// node.
    ///
    /// All intermediate shunt proofs will contain all ancestor hashes for each node in-between the
    /// backptr and the non-backptr node.  The intermediate root hashes will be calculated by the verifier.
    fn make_backptr_shunt_proof(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        backptr: &TriePtr,
    ) -> Result<Vec<TrieMerkleProofType<TTrieId>>, MarfError> {
        // the proof is built "backwards" -- starting from the current block all the way back to backptr.
        assert!(Utils::is_backptr(backptr.id()));

        let mut proof = vec![];

        let mut block_header = storage.get_cur_block();

        let ancestor_block_hash = storage
            .get_block_from_local_id(backptr.back_block())?
            .clone();
        storage.open_block(&ancestor_block_hash)?;

        let ancestor_root_hash = Utils::read_root_hash(storage)?;

        let mut found_backptr = false;

        let ancestor_height =
            Marf::get_block_height_miner_tip(storage, &ancestor_block_hash, &block_header)?
                .ok_or_else(|| {
                    MarfError::CorruptionError(format!(
                        "Could not find block height of ancestor block {} from {}",
                        &ancestor_block_hash, &block_header
                    ))
                })?;
        let mut current_height =
            Marf::get_block_height_miner_tip(storage, &block_header, &block_header)?.ok_or_else(
                || {
                    MarfError::CorruptionError(format!(
                        "Could not find block height of current block {} from {}",
                        &block_header, &block_header
                    ))
                },
            )?;

        if current_height == ancestor_height {
            debug!(
                "Already at the ancestor: {} =? {}, heights: {} =? {}",
                &ancestor_block_hash, &block_header, ancestor_height, current_height
            );
        }

        // find last and intermediate entries in the shunt proof -- exclude the root hashes; just
        // include the ancestor hashes.
        while current_height > ancestor_height && !found_backptr {
            storage.open_block(&block_header)?;
            let _cur_root_hash = Utils::read_root_hash(storage)?;
            trace!(
                "Shunt proof: walk heights {}->{} from {:?} ({:?})",
                current_height,
                ancestor_height,
                &block_header,
                &_cur_root_hash
            );

            let ancestor_hashes = Trie::get_trie_ancestor_hashes_bytes(storage)?;

            trace!(
                "Ancestors of {:?} ({:?}): {:?}",
                &block_header,
                &_cur_root_hash,
                &ancestor_hashes
            );

            // did we reach the backptr's root hash?
            found_backptr = ancestor_hashes.contains(&ancestor_root_hash);

            // what's the next block we'll shunt to?
            let mut idx = 0;
            while (1u32 << idx) <= current_height
                && current_height - (1u32 << idx) >= ancestor_height
            {
                idx += 1;
            }
            if idx == 0 {
                panic!("ancestor_height = {}, current_height = {}, but ancestor hash `{}` not found in: [{}]",
                       ancestor_height, current_height, ancestor_root_hash,
                       ancestor_hashes.iter().map(|x| format!("{}", x)).collect::<Vec<_>>().join(", "))
            }
            idx -= 1;

            if found_backptr {
                assert_eq!(&ancestor_hashes[idx], &ancestor_root_hash);
            }

            current_height -= 1u32 << idx;

            block_header = Marf::get_block_at_height(storage, current_height, &block_header)?
                .ok_or_else(|| {
                    MarfError::CorruptionError(format!(
                        "Could not find block at height of {}",
                        current_height
                    ))
                })?
                .clone();

            let mut trimmed_ancestor_hashes = Vec::with_capacity(ancestor_hashes.len() - 1);
            for i in 0..ancestor_hashes.len() {
                if i == idx {
                    continue;
                }
                trimmed_ancestor_hashes.push(ancestor_hashes[i].clone());
            }

            idx += 1;

            // need the target node's root trie ptr, unless this is the first proof (in which case
            // it's a junction proof)
            if proof.len() > 0 {
                let root_ptr = storage.root_trieptr();
                let (root_node, _) = storage.read_nodetype(&root_ptr)?;

                let root_hash = if let TrieNodeType::Node256(ref node256) = root_node {
                    let child_hashes = Trie::get_children_hashes(storage, &root_node)?;
                    let root_hash = Utils::get_node_hash(node256.as_ref(), &child_hashes, storage);
                    root_hash
                } else {
                    return Err(MarfError::CorruptionError(format!(
                        "Root node at {:?} is not a TrieNode256",
                        &block_header
                    )));
                };

                trimmed_ancestor_hashes.insert(0, root_hash);
                idx += 1;

                trace!(
                    "Tail proof: Added intermediate proof node's root data hash is {:?}",
                    &root_hash
                );
            }

            if !found_backptr {
                trace!(
                    "Backptr not found yet: trim ancestor hashes at idx={} from {:?} to {:?}",
                    idx,
                    &ancestor_hashes,
                    &trimmed_ancestor_hashes
                );
                trace!("Backptr not found yet.  Shunt to {:?} and walk to {}; Add shunt proof ({}, {:?})", &block_header, ancestor_height, idx, &trimmed_ancestor_hashes);
            } else {
                trace!(
                    "Backptr found: trim ancestor hashes at idx={} from {:?} to {:?}",
                    idx,
                    &ancestor_hashes,
                    &trimmed_ancestor_hashes
                );
                trace!("Backptr found (ancestor_height = {}, header = {:?}).  Intermediate shunt proof is ({}, {:?})", ancestor_height, &block_header, idx, &trimmed_ancestor_hashes);
            };

            let shunt_proof_node =
                TrieMerkleProofType::Shunt((idx as i64, trimmed_ancestor_hashes));
            proof.push(shunt_proof_node);
        }

        storage.open_block(&block_header)?;
        proof.reverse();

        // put the proof in the right order. we're done!
        Ok(proof)
    }

    fn next_shunt_hash(hash: &TrieHash, idx: i64, hashes: &[TrieHash]) -> Option<TrieHash> {
        let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
        let mut hash_idx = 0;
        for i in 0..hashes.len() + 1 {
            if idx == 0 {
                trace!("Intermediate shunt proof entry must have idx > 0");
                return None;
            }

            if idx - 1 == (i as i64) {
                all_hashes.push(hash.clone());
            } else {
                if hash_idx >= hashes.len() {
                    trace!(
                        "Invalid proof: hash_idx = {}, hashes.len() = {}",
                        hash_idx,
                        hashes.len()
                    );
                    return None;
                }
                all_hashes.push(hashes[hash_idx].clone());
                hash_idx += 1;
            }
        }
        trace!("Shunt proof node: idx={}, all_hashes={:?}", idx, all_hashes);
        let next_hash = TrieHash::from_data_array(&all_hashes);
        Some(next_hash)
    }

    /// Verify the head of a shunt proof
    fn verify_shunt_proof_head(
        node_root_hash: &TrieHash,
        shunt_proof_head: &TrieMerkleProofType<TTrieId>,
    ) -> Option<TrieHash> {
        // ancestor hashes are always the first item
        let hash = match shunt_proof_head {
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                if *idx != 0 {
                    trace!("First shunt proof entry must have idx == 0");
                    return None;
                }

                if hashes.len() == 0 {
                    // special case -- if this shunt proof has no hashes (i.e. this is a leaf from the first
                    // block), then we can safely skip this step
                    trace!(
                        "Special case for a 0-ancestor node: hash is just the trie hash: {:?}",
                        node_root_hash
                    );
                    node_root_hash.clone()
                } else {
                    let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
                    all_hashes.push(node_root_hash.clone());
                    for h in hashes {
                        all_hashes.push(h.clone());
                    }
                    let ret = TrieHash::from_data_array(&all_hashes);
                    trace!(
                        "Shunt proof head: hash = {:?}, all_hashes = {:?}",
                        &ret,
                        &all_hashes
                    );
                    ret
                }
            }
            _ => {
                trace!("Shunt proof head is not a shunt proof node");
                return None;
            }
        };

        Some(hash)
    }

    /// Verify the tail of a shunt proof, given the backptr root hash.
    /// Calculate the root hash of the next segment proof.
    fn verify_shunt_proof_tail(
        initial_hash: &TrieHash,
        shunt_proof: &[TrieMerkleProofType<TTrieId>],
    ) -> Option<TrieHash> {
        let mut hash = initial_hash.clone();

        // walk subsequent legs of a shunt proof, except for the last (since we need the next
        // segment proof for that)
        for i in 0..shunt_proof.len() {
            let proof_node = &shunt_proof[i];
            hash = match proof_node {
                TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                    if *idx == 0 {
                        trace!("Invalid shunt proof tail: idx == 0");
                        return None;
                    }

                    match TrieMerkleProof::<TTrieId>::next_shunt_hash(&hash, *idx, hashes) {
                        Some(h) => h,
                        None => {
                            return None;
                        }
                    }
                }
                _ => {
                    trace!("Shunt proof item is not a shunt proof node");
                    return None;
                }
            };
        }
        Some(hash)
    }

    /// Verify a shunt juncture, where a shunt proof tail and a segment proof meet.
    /// Returns the hash of the root of the junction
    fn verify_shunt_proof_junction(
        node_root_hash: &TrieHash,
        penultimate_trie_hash: &TrieHash,
        shunt_proof_junction: &TrieMerkleProofType<TTrieId>,
    ) -> Option<TrieHash> {
        // at the juncture, we include the node root hash (from the subsequent segment proof) as
        // the first hash, and include the penultimate trie hash in its idx
        let hash = match shunt_proof_junction {
            TrieMerkleProofType::Shunt((ref idx, ref hashes)) => {
                if *idx == 0 {
                    trace!("Shunt proof junction entry must not have idx == 0");
                    return None;
                }

                let mut all_hashes = Vec::with_capacity(hashes.len() + 1);
                let mut hash_idx = 0;

                all_hashes.push(node_root_hash.clone());

                for i in 0..hashes.len() + 1 {
                    if *idx - 1 == (i as i64) {
                        all_hashes.push(penultimate_trie_hash.clone());
                    } else {
                        if hash_idx >= hashes.len() {
                            trace!(
                                "ran out of hashes: hash_idx = {}, hashes.len() = {}",
                                hash_idx,
                                hashes.len()
                            );
                            return None;
                        }

                        all_hashes.push(hashes[hash_idx].clone());
                        hash_idx += 1;
                    }
                }

                trace!(
                    "idx = {}, hashes = {:?}, penultimate = {:?}, node root = {:?}",
                    *idx,
                    hashes,
                    penultimate_trie_hash,
                    node_root_hash
                );
                trace!("Shunt proof junction: all_hashes = {:?}", &all_hashes);
                TrieHash::from_data_array(&all_hashes)
            }
            _ => {
                trace!("Shunt proof junction is not a shunt proof node");
                return None;
            }
        };

        Some(hash)
    }

    /// Given a list of non-backptr ptrs and a root block header hash, calculate a Merkle proof.
    fn make_segment_proof(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        ptrs: &Vec<TriePtr>,
        starting_chr: u8,
    ) -> Result<Vec<TrieMerkleProofType<TTrieId>>, MarfError> {
        trace!("make_segment_proof: ptrs = {:?}", &ptrs);

        assert!(ptrs.len() > 0);
        assert_eq!(ptrs[0], storage.root_trieptr());
        for i in 1..ptrs.len() {
            assert!(!Utils::is_backptr(ptrs[i].id()));
        }

        let mut proof_segment = Vec::with_capacity(ptrs.len());
        let mut prev_chr = starting_chr;

        trace!(
            "make_segment_proof: Trie segment from {:?} starting at {:?}: {:?}",
            &storage.get_cur_block(),
            starting_chr,
            ptrs
        );
        let mut i = ptrs.len() - 1;
        loop {
            let ptr = &ptrs[i];
            let proof_node = TrieMerkleProof::ptr_to_segment_proof_node(storage, &ptr, prev_chr)?;

            trace!(
                "make_segment_proof: Add proof node from {:?} child 0x{:02x}: {:?}",
                &ptr,
                prev_chr,
                &proof_node
            );

            proof_segment.push(proof_node);
            prev_chr = ptr.chr();

            if i == 0 {
                break;
            } else {
                i -= 1;
            }
        }

        Ok(proof_segment)
    }

    /// Given a node in a segment proof, find the hash
    fn get_segment_proof_hash(
        node: &ProofTrieNode<TTrieId>,
        hash: &TrieHash,
        chr: u8,
        hashes: &[TrieHash],
        count: usize,
    ) -> Option<TrieHash> {
        let mut all_hashes = vec![];
        let mut ih = 0;

        assert!(node.ptrs().len() == count);
        assert!(count > 0 && hashes.len() == count - 1);

        for child_ptr in node.ptrs() {
            if child_ptr.id != TrieNodeID::Empty as u8 && child_ptr.chr == chr {
                all_hashes.push(hash.clone());
            } else {
                if ih >= hashes.len() {
                    trace!("verify_get_hash: {} >= {}", ih, hashes.len());
                    return None;
                } else {
                    all_hashes.push(hashes[ih].clone());
                    ih += 1;
                }
            }
        }
        if all_hashes.len() != count {
            trace!("verify_get_hash: {} != {}", all_hashes.len(), count);
            return None;
        }

        Some(Utils::get_node_hash(node, &all_hashes, &mut ()))
    }

    /// Given a segment proof, the deepest node's hash, and the hash of the trie root, verify that
    /// the segment proof is well-formed.
    /// If so, calculate the root hash of the segment and return it.
    fn verify_segment_proof(
        proof: &[TrieMerkleProofType<TTrieId>],
        node_hash: &TrieHash,
    ) -> Option<TrieHash> {
        let mut hash = node_hash.clone();
        for i in 0..proof.len() {
            let hash_opt = match proof[i] {
                TrieMerkleProofType::Leaf((ref _chr, ref node)) => {
                    // special case the leaf hash -- it doesn't
                    //   have any child hashes to check.
                    Some(Utils::get_leaf_hash(node))
                }
                TrieMerkleProofType::Node4((ref chr, ref node, ref hashes)) => {
                    TrieMerkleProof::get_segment_proof_hash(node, &hash, *chr, hashes, 4)
                }
                TrieMerkleProofType::Node16((ref chr, ref node, ref hashes)) => {
                    TrieMerkleProof::get_segment_proof_hash(node, &hash, *chr, hashes, 16)
                }
                TrieMerkleProofType::Node48((ref chr, ref node, ref hashes)) => {
                    TrieMerkleProof::get_segment_proof_hash(node, &hash, *chr, hashes, 48)
                }
                TrieMerkleProofType::Node256((ref chr, ref node, ref hashes)) => {
                    TrieMerkleProof::get_segment_proof_hash(node, &hash, *chr, hashes, 256)
                }
                _ => {
                    trace!("Invalid proof -- encountered a non-node proof type");
                    return None;
                }
            };
            hash = match hash_opt {
                None => {
                    return None;
                }
                Some(h) => h,
            };
        }

        trace!("verify segment: calculated root hash = {:?}", hash);
        Some(hash)
    }

    /// Given a segment proof, extract the path prefix it encodes
    fn get_segment_proof_path_prefix(segment_proof: &[TrieMerkleProofType<TTrieId>]) -> Option<Vec<u8>> {
        let mut path_parts = vec![];
        for proof_node in segment_proof {
            match proof_node {
                TrieMerkleProofType::Leaf((ref _chr, ref node)) => {
                    // path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                }
                TrieMerkleProofType::Node4((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                }
                TrieMerkleProofType::Node16((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                }
                TrieMerkleProofType::Node48((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                }
                TrieMerkleProofType::Node256((ref chr, ref node, _)) => {
                    path_parts.push(vec![*chr]);
                    path_parts.push(node.path.clone());
                }
                _ => {
                    trace!("Not a valid segment proof: got a non-node proof node");
                    return None;
                }
            }
        }

        let mut path = vec![];
        for i in 0..path_parts.len() {
            let idx = path_parts.len() - 1 - i;
            path.extend_from_slice(&path_parts[idx]);
        }
        Some(path)
    }

    /// Verify that a proof is well-formed:
    /// * it must have the same number of segment and shunt proofs
    /// * segment proof i+1 must be a prefix of segment proof i
    /// * segment proof 0 must end in a leaf
    /// * all segment proofs must end in a Node256 (a root)
    fn is_proof_well_formed(proof: &Vec<TrieMerkleProofType<TTrieId>>, expected_path: &TriePath) -> bool {
        if proof.len() == 0 {
            trace!("Proof is empty");
            return false;
        }

        match proof[0] {
            TrieMerkleProofType::Leaf(_) => {}
            _ => {
                trace!("First proof node is not a leaf");
                return false;
            }
        }

        // must be alternating segment and shunt proofs
        let mut i = 0;
        let mut path_bytes = vec![];

        while i < proof.len() {
            // next segment proof
            let mut j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        break;
                    }
                    _ => {
                        j += 1;
                    }
                }
            }

            let segment_proof = &proof[i..j];

            if i == 0 {
                // detect the path
                path_bytes = match TrieMerkleProof::get_segment_proof_path_prefix(segment_proof) {
                    Some(bytes) => bytes,
                    None => {
                        trace!("Failed to get the path from the proof");
                        return false;
                    }
                };

                // first path bytes must be the expected TriePath
                if expected_path.as_bytes().to_vec() != path_bytes {
                    trace!(
                        "Invalid proof -- path bytes {:?} differs from the expected path {:?}",
                        &path_bytes,
                        expected_path
                    );
                    return false;
                }
            } else {
                // make sure that this segment proof is a prefix of the last
                let new_path_bytes =
                    match TrieMerkleProof::get_segment_proof_path_prefix(segment_proof) {
                        Some(bytes) => bytes,
                        None => {
                            trace!("Failed to et the path prefix from the proof");
                            return false;
                        }
                    };

                if path_bytes.len() < new_path_bytes.len() {
                    trace!("Segment proof path is {}, which is longer than the previous segment proof length {}", path_bytes.len(), new_path_bytes.len());
                    trace!("path_bytes: {:?}", &path_bytes);
                    trace!("new path bytes: {:?}", &new_path_bytes);
                    return false;
                }

                for i in 0..new_path_bytes.len() {
                    if path_bytes[i] != new_path_bytes[i] {
                        trace!(
                            "Segment path {:?} is not a prefix of previous segment path {:?}",
                            &new_path_bytes,
                            &path_bytes
                        );
                        return false;
                    }
                }
            }

            // next shunt proof
            i = j;
            if i >= proof.len() {
                trace!("Proof is incomplete -- must end with a shunt proof");
                return false;
            }

            j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        j += 1;
                    }
                    _ => {
                        break;
                    }
                }
            }

            // end of shunt proof
            i = j;
        }

        true
    }

    /// Given a value and the root hash from which this proof was
    /// (supposedly) generated go and verify whether or not it is consistent with the root hash.
    /// For the proof validation to work, the verifier needs to know which Trie roots correspond to
    /// which block headers.  This can be calculated and verified independently from the blockchain
    /// headers.
    /// NOTE: Trie root hashes are globally unique by design, even if they represent the same contents, so the root_to_block map is bijective with high probability.
    pub fn verify_proof(
        proof: &Vec<TrieMerkleProofType<TTrieId>>,
        path: &TriePath,
        value: &MarfValue,
        root_hash: &TrieHash,
        root_to_block: &HashMap<TrieHash, TTrieId>,
    ) -> bool {
        if !TrieMerkleProof::is_proof_well_formed(&proof, path) {
            test_debug!("Invalid proof -- proof is not well-formed");
            return false;
        }

        let (mut node_hash, node_data) = match proof[0] {
            TrieMerkleProofType::Leaf((_, ref node)) => (Utils::get_leaf_hash(node), node.data.clone()),
            _ => unreachable!(),
        };

        // proof must be for this value
        if node_data != *value {
            test_debug!(
                "Invalid proof -- not for value hash {:?}",
                value.to_value_hash()
            );
            return false;
        }

        let mut i = 0;

        // verify the very first segment proof
        let mut j = i + 1;
        while j < proof.len() {
            match proof[j] {
                TrieMerkleProofType::Shunt(_) => {
                    break;
                }
                _ => {
                    j += 1;
                }
            }
        }

        trace!("verify segment proof in range {}..{}", i, j);
        let node_root_hash = match TrieMerkleProof::verify_segment_proof(&proof[i..j], &node_hash) {
            Some(h) => h,
            None => {
                test_debug!("Unable to verify segment proof in range {}...{}", i, j);
                return false;
            }
        };

        i = j;
        if i >= proof.len() {
            test_debug!(
                "Proof is too short -- needed at least one shunt proof for the first segment"
            );
            return false;
        }

        // verify the very first shunt proof head.
        trace!("verify shunt proof head at {}: {:?}", i, &proof[i]);
        let mut trie_hash =
            match TrieMerkleProof::verify_shunt_proof_head(&node_root_hash, &proof[i]) {
                Some(h) => h,
                None => {
                    test_debug!(
                        "Unable to verify shunt proof head at {}: {:?}",
                        i,
                        &proof[i]
                    );
                    return false;
                }
            };
        trace!("shunt proof head hash: {:?}", &trie_hash);

        i += 1;
        if i >= proof.len() {
            // done -- no further shunts
            test_debug!("Verify proof: {:?} =?= {:?}", root_hash, &trie_hash);
            return *root_hash == trie_hash;
        }

        // next node hash is the hash of the block from which its root came
        node_hash = match root_to_block.get(&trie_hash) {
            Some(bhh) => {
                trace!("Block hash for {:?} is {:?}", &trie_hash, bhh);

                // safe because block header hashes are 32 bytes long
                TrieHash(bhh.clone().to_bytes())
            }
            None => {
                test_debug!("Trie hash not found in root-to-block map: {:?}", &trie_hash);
                trace!("root-to-block map: {:?}", &root_to_block);
                return false;
            }
        };

        // next proof item should be part of a segment proof
        match proof[i] {
            TrieMerkleProofType::Shunt(_) => {
                test_debug!("Malformed proof -- exepcted segment proof following first shunt proof head at {}", i);
                return false;
            }
            _ => {}
        }

        while i < proof.len() {
            // find the next segment proof
            j = i + 1;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt(_) => {
                        break;
                    }
                    _ => {
                        j += 1;
                    }
                }
            }

            trace!("verify segment proof in range {}..{}", i, j);
            let next_node_root_hash =
                match TrieMerkleProof::verify_segment_proof(&proof[i..j], &node_hash) {
                    Some(h) => h,
                    None => {
                        test_debug!("Unable to verify segment proof in range {}..{}", i, j);
                        return false;
                    }
                };

            i = j;
            if i >= proof.len() {
                test_debug!("Proof to short -- no shunt proof tail");
                return false;
            }

            // find the tail end
            j = i;
            while j < proof.len() {
                match proof[j] {
                    TrieMerkleProofType::Shunt((ref idx, _)) => {
                        if *idx == 0 {
                            break;
                        }
                        j += 1;
                    }
                    _ => {
                        break;
                    }
                }
            }
            j -= 1;

            if j < i {
                test_debug!("Proof is malformed -- no tail or junction proof");
                return false;
            }

            trace!(
                "verify shunt proof tail in range {}..{} initial hash = {:?}: {:?}",
                i,
                j,
                &trie_hash,
                &proof[i..j]
            );
            let penultimate_trie_hash =
                match TrieMerkleProof::verify_shunt_proof_tail(&trie_hash, &proof[i..j]) {
                    Some(h) => h,
                    None => {
                        test_debug!("Unable to verify shunt proof tail");
                        return false;
                    }
                };
            trace!(
                "verify shunt proof tail in range {}..{}: penultimate trie hash is {:?}",
                i,
                j,
                &penultimate_trie_hash
            );

            i = j;
            if i >= proof.len() {
                test_debug!("Proof to short -- no junction proof");
                return false;
            }

            trace!("verify shunt junction proof at {} next_node_root_hash = {:?} penultimate hash = {:?}: {:?}", i, &next_node_root_hash, &penultimate_trie_hash, &proof[i]);
            let next_trie_hash = match TrieMerkleProof::verify_shunt_proof_junction(
                &next_node_root_hash,
                &penultimate_trie_hash,
                &proof[i],
            ) {
                Some(h) => h,
                None => {
                    test_debug!("Unable to verify shunt junction proof at {} next_node_root_hash = {:?} penultimate hash = {:?}: {:?}", i, &next_node_root_hash, &penultimate_trie_hash, &proof[i]);
                    return false;
                }
            };

            // next node hash is the hash of the block from which its root came
            trie_hash = next_trie_hash;
            node_hash = match root_to_block.get(&trie_hash) {
                Some(bhh) => {
                    trace!("Block hash for {:?} is {:?}", &trie_hash, bhh);

                    // safe because block header hashes are 32 bytes long
                    TrieHash(bhh.clone().to_bytes())
                }
                None => {
                    test_debug!("Trie hash not found in root-to-block map: {:?}", &trie_hash);
                    test_debug!("root-to-block map: {:?}", &root_to_block);
                    return false;
                }
            };

            i += 1;

            if trie_hash == *root_hash {
                trace!(
                    "Appeared to find the root hash early, with the remaining proof:\n{:?}",
                    &proof[i..]
                );
                break;
            }
        }

        test_debug!("Verify proof: {:?} =?= {:?}", root_hash, &trie_hash);
        *root_hash == trie_hash
    }

    /// Verify this proof
    pub fn verify(
        &self,
        path: &TriePath,
        marf_value: &MarfValue,
        root_hash: &TrieHash,
        root_to_block: &HashMap<TrieHash, TTrieId>,
    ) -> bool {
        TrieMerkleProof::<TTrieId>::verify_proof(&self.0, &path, &marf_value, root_hash, root_to_block)
    }

    /// Walk down the trie pointed to by s until we reach a backptr or a leaf
    fn walk_to_leaf_or_backptr(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        path: &TriePath,
    ) -> Result<(TrieCursor<TTrieId>, TrieNodeType, TriePtr), MarfError> {
        trace!(
            "Walk path {:?} from {:?} to the first backptr",
            path,
            &storage.get_cur_block()
        );

        let mut node_ptr = storage.root_trieptr();
        let (mut node, _) = Trie::read_root(storage)?;
        let mut cursor = TrieCursor::new(path, storage.root_trieptr());

        for _ in 0..(cursor.path.len() + 1) {
            match Trie::walk_from(storage, &node, &mut cursor) {
                Ok(node_info_opt) => {
                    match node_info_opt {
                        Some((next_node_ptr, next_node, _)) => {
                            // end-of-node-path.
                            // keep walking.
                            node = next_node;
                            node_ptr = next_node_ptr;
                            continue;
                        }
                        None => {
                            // end of path.
                            trace!("Found leaf {:?}", &node);
                            return Ok((cursor, node, node_ptr));
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
                                    return Err(MarfError::NotFoundError);
                                }
                                CursorError::ChrNotFound => {
                                    // node isn't present
                                    trace!("Failed to walk from {:?}", &node);
                                    return Err(MarfError::NotFoundError);
                                }
                                CursorError::BackptrEncountered(ptr) => {
                                    // expect backptr
                                    if !Utils::is_backptr(ptr.id()) {
                                        return Err(MarfError::CorruptionError(format!(
                                            "Failed to walk 0x{:02x} -- got non-backptr",
                                            ptr.chr()
                                        )));
                                    }

                                    // we're done -- we found a backptr
                                    trace!("Found backptr {:?}", &ptr);
                                    return Ok((cursor, node, ptr));
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

    /// Make a merkle proof of inclusion from a path.
    /// If the path doesn't resolve, return an error (NotFoundError)
    pub fn from_path(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        path: &TriePath,
        expected_value: &MarfValue,
        root_block_header: &TTrieId,
    ) -> Result<TrieMerkleProof<TTrieId, TIndex>, MarfError> {
        // accumulate proofs in reverse order -- each proof will be from an earlier and earlier
        // trie, so we'll reverse them in the end so the proof starts with the latest trie.
        let mut segment_proofs = vec![];
        let mut shunt_proofs = vec![];
        let mut block_header = root_block_header.clone();

        loop {
            storage.open_block(&block_header)?;

            trace!(
                "Walk {:?} path {:?} to leaf or backptr",
                &storage.get_cur_block(),
                path
            );
            let (cursor, reached_node, backptr) =
                TrieMerkleProof::walk_to_leaf_or_backptr(storage, path)?;

            // make a proof to this node
            trace!(
                "Make segment proof at {:?} from {:?}",
                &storage.get_cur_block(),
                &cursor.node_ptrs
            );
            let segment_proof = TrieMerkleProof::make_segment_proof(
                storage,
                &cursor.node_ptrs,
                cursor.chr().unwrap(),
            )?;
            segment_proofs.push(segment_proof);

            // make a shunt proof to this segment proof's root
            trace!(
                "Make shunt proof {:?} back to the block containing {:?} (cursor ptrs = {:?})",
                &storage.get_cur_block(),
                &backptr,
                &cursor.node_ptrs
            );

            if Utils::is_backptr(backptr.id()) {
                // make the shunt proof connecting this block to the next block we'll visit.
                let shunt_proof = TrieMerkleProof::make_backptr_shunt_proof(storage, &backptr)?;
                shunt_proofs.push(shunt_proof);
            } else {
                // make the shunt proof for the block that contains the non-backptr of this leaf.
                let first_shunt_proof = TrieMerkleProof::make_initial_shunt_proof(storage)?;
                shunt_proofs.push(first_shunt_proof);
            }

            if cursor.ptr().id() == TrieNodeID::Leaf as u8 {
                match reached_node {
                    TrieNodeType::Leaf(ref data) => {
                        if data.data != *expected_value {
                            trace!(
                                "Did not find leaf {:?} at {:?} (but got {:?})",
                                expected_value,
                                path,
                                data
                            );

                            // if we're testing, then permit the prover to return an invalid proof
                            // if the test requests it
                            #[cfg(test)]
                            {
                                use std::env;
                                if env::var("BLOCKSTACK_TEST_PROOF_ALLOW_INVALID")
                                    == Ok("1".to_string())
                                {
                                    break;
                                }
                            }
                            return Err(MarfError::NotFoundError);
                        }
                    }
                    _ => {
                        trace!("Did not find leaf at {:?}", path);
                        return Err(MarfError::NotFoundError);
                    }
                }
                break;
            }

            storage.open_block(&block_header)?;

            trace!(
                "Walk back for {:?} from {:?}",
                &backptr,
                &storage.get_cur_block()
            );
            block_header = storage
                .get_block_from_local_id(backptr.back_block())?
                .clone();
        }

        assert_eq!(shunt_proofs.len(), segment_proofs.len());

        // leaf proof needs to be first
        segment_proofs.reverse();
        shunt_proofs.reverse();

        let mut proof = Vec::with_capacity(segment_proofs.len() + shunt_proofs.len());
        for i in 0..shunt_proofs.len() {
            trace!("Append segment proof\n{:?}", &segment_proofs[i]);
            proof.append(&mut segment_proofs[i]);

            trace!("Append shunt proof\n{:?}", &shunt_proofs[i]);
            proof.append(&mut shunt_proofs[i]);
        }

        Ok(TrieMerkleProof(proof, PhantomData))
    }

    /// Make a merkle proof of inclusion from a key/value pair.
    /// If the path doesn't resolve, return an error (NotFoundError)
    pub fn from_entry(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        key: &String,
        value: &String,
        root_block_header: &TTrieId,
    ) -> Result<TrieMerkleProof<TTrieId, TIndex>, MarfError> {
        let marf_value = MarfValue::from_value(value);
        let path = TriePath::from_key(key);
        TrieMerkleProof::from_path(storage, &path, &marf_value, root_block_header)
    }

    pub fn from_raw_entry(
        storage: &mut TrieStorageConnection<TTrieId, TIndex>,
        key: &str,
        value: &MarfValue,
        root_block_header: &TTrieId,
    ) -> Result<TrieMerkleProof<TTrieId, TIndex>, MarfError> {
        let path = TriePath::from_key(key);
        TrieMerkleProof::from_path(storage, &path, value, root_block_header)
    }
}