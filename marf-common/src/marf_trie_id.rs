use crate::{MarfValue, ClarityMarfTrieId};

pub trait MarfTrieId:
    ClarityMarfTrieId
    + rusqlite::types::ToSql
    + rusqlite::types::FromSql
    + stacks_common::codec::StacksMessageCodec
    + std::convert::From<MarfValue>
    + PartialEq
    + Eq
    + std::hash::Hash
    + Copy
{
}