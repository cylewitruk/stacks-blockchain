#[derive(Clone)]
pub struct WriteChainTip<T> {
    block_hash: T,
    height: u32,
}