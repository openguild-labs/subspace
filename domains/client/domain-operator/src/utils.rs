use parking_lot::Mutex;
use sc_client_api::{CallExecutorConfig, ExecutorLimits};
use sc_utils::mpsc::{TracingUnboundedReceiver, TracingUnboundedSender};
use sp_consensus_slots::Slot;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::sync::Arc;
use subspace_core_primitives::Randomness;

const EXTRINSIC_STORAGE_LIMIT: u64 = 2048;

/// Data required to produce bundles on executor node.
#[derive(PartialEq, Clone, Debug)]
pub(super) struct OperatorSlotInfo {
    /// Slot
    pub(super) slot: Slot,
    /// Global randomness
    pub(super) global_randomness: Randomness,
}

#[derive(Debug, Clone)]
pub(crate) struct BlockInfo<Block>
where
    Block: BlockT,
{
    /// hash of the block.
    pub hash: Block::Hash,
    /// block's number.
    pub number: NumberFor<Block>,
    /// Is this the new best block.
    pub is_new_best: bool,
}

pub type DomainImportNotificationSinks<Block, CBlock> =
    Arc<Mutex<Vec<TracingUnboundedSender<DomainBlockImportNotification<Block, CBlock>>>>>;

pub type DomainImportNotifications<Block, CBlock> =
    TracingUnboundedReceiver<DomainBlockImportNotification<Block, CBlock>>;

#[derive(Clone, Debug)]
pub struct DomainBlockImportNotification<Block: BlockT, CBlock: BlockT> {
    pub domain_block_hash: Block::Hash,
    pub consensus_block_hash: CBlock::Hash,
}

/// Executor limits implementation.
#[derive(Debug)]
struct ExecutorLimitsImpl;

impl ExecutorLimits for ExecutorLimitsImpl {
    fn storage_limit(&self, method_name: &str) -> Option<u64> {
        if method_name.ends_with("apply_extrinsic") {
            Some(EXTRINSIC_STORAGE_LIMIT)
        } else {
            None
        }
    }
}

/// Builds the executor config.
pub fn executor_config() -> Option<CallExecutorConfig> {
    Some(CallExecutorConfig {
        limits: Arc::new(ExecutorLimitsImpl),
    })
}

/// Builds the executor limits.
pub fn executor_limits() -> Option<Arc<dyn ExecutorLimits>> {
    Some(Arc::new(ExecutorLimitsImpl))
}
