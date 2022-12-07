#[derive(Clone)]
pub struct WriteChainTip<T> {
    pub block_hash: T,
    pub height: u32,
}