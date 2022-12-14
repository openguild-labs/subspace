use crate::{BlockT, Error, GossipMessageSink, HeaderBackend, HeaderT, Relayer, LOG_TARGET};
use domain_runtime_primitives::RelayerId;
use futures::StreamExt;
use sc_client_api::{AuxStore, BlockchainEvents, ProofProvider};
use sp_api::ProvideRuntimeApi;
use sp_consensus::SyncOracle;
use sp_domain_tracker::DomainTrackerApi;
use sp_messenger::RelayerApi;
use sp_runtime::generic::BlockId;
use sp_runtime::traits::{CheckedAdd, CheckedSub, NumberFor, One, Zero};
use sp_runtime::ArithmeticError;
use std::sync::Arc;

/// Starts relaying system domain messages to other domains.
/// If the node is in major sync, worker waits waits until the sync is finished.
pub async fn relay_system_domain_messages<Client, Block, SO>(
    relayer_id: RelayerId,
    system_domain_client: Arc<Client>,
    system_domain_sync_oracle: SO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    SO: SyncOracle,
{
    let result = relay_domain_messages(
        relayer_id,
        system_domain_client,
        |relayer_id, client, block_id| {
            Relayer::submit_messages_from_system_domain(
                relayer_id,
                client,
                block_id,
                &gossip_message_sink,
            )
        },
        system_domain_sync_oracle,
    )
    .await;

    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for system domain"
        )
    }
}

/// Starts relaying core domain messages to other domains.
/// If the either system domain or core domain node is in major sync,
/// worker waits waits until the sync is finished.
pub async fn relay_core_domain_messages<CDC, SDC, SBlock, Block, SDSO, CDSO>(
    relayer_id: RelayerId,
    core_domain_client: Arc<CDC>,
    system_domain_client: Arc<SDC>,
    system_domain_sync_oracle: SDSO,
    core_domain_sync_oracle: CDSO,
    gossip_message_sink: GossipMessageSink,
) where
    Block: BlockT,
    SBlock: BlockT,
    NumberFor<SBlock>: From<NumberFor<Block>>,
    SBlock::Hash: Into<Block::Hash>,
    CDC: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    CDC::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    SDC: HeaderBackend<SBlock> + ProvideRuntimeApi<SBlock> + ProofProvider<SBlock>,
    SDC::Api: DomainTrackerApi<SBlock, NumberFor<SBlock>>
        + RelayerApi<SBlock, RelayerId, NumberFor<SBlock>>,
    SDSO: SyncOracle + Send,
    CDSO: SyncOracle + Send,
{
    let combined_sync_oracle =
        CombinedSyncOracle::new(system_domain_sync_oracle, core_domain_sync_oracle);

    let result = relay_domain_messages(
        relayer_id,
        core_domain_client,
        |relayer_id, client, block_id| {
            Relayer::submit_messages_from_core_domain(
                relayer_id,
                client,
                &system_domain_client,
                block_id,
                &gossip_message_sink,
            )
        },
        combined_sync_oracle,
    )
    .await;
    if let Err(err) = result {
        tracing::error!(
            target: LOG_TARGET,
            ?err,
            "Failed to start relayer for core domain"
        )
    }
}

async fn relay_domain_messages<Client, Block, MP, SO>(
    relayer_id: RelayerId,
    domain_client: Arc<Client>,
    message_processor: MP,
    sync_oracle: SO,
) -> Result<(), Error>
where
    Block: BlockT,
    Client: BlockchainEvents<Block>
        + HeaderBackend<Block>
        + AuxStore
        + ProofProvider<Block>
        + ProvideRuntimeApi<Block>,
    Client::Api: RelayerApi<Block, RelayerId, NumberFor<Block>>,
    MP: Fn(RelayerId, &Arc<Client>, Block::Hash) -> Result<(), Error>,
    SO: SyncOracle,
{
    let domain_id = Relayer::domain_id(&domain_client)?;
    let relay_confirmation_depth = Relayer::relay_confirmation_depth(&domain_client)?;
    let maybe_last_relayed_block = Relayer::fetch_last_relayed_block(&domain_client, domain_id);
    let mut relay_block_from = match maybe_last_relayed_block {
        None => Zero::zero(),
        Some(last_block_number) => last_block_number
            .checked_add(&One::one())
            .ok_or(ArithmeticError::Overflow)?,
    };

    tracing::info!(
        target: LOG_TARGET,
        "Starting relayer for domain: {:?} from the block: {:?}",
        domain_id,
        relay_block_from,
    );
    let mut domain_block_import = domain_client.import_notification_stream();

    // from the start block, start processing all the messages assigned
    // wait for new block import of system domain,
    // then fetch new messages assigned to to relayer from system domain
    // construct proof of each message to be relayed
    // submit XDM as unsigned extrinsic.
    while let Some(block) = domain_block_import.next().await {
        let block_number = block.header.number();

        // if the client is in major sync, wait until sync is complete
        if sync_oracle.is_major_syncing() {
            tracing::info!(target: LOG_TARGET, "Client is in major sync. Skipping...");
            continue;
        }

        let relay_block_until = match block_number.checked_sub(&relay_confirmation_depth) {
            None => {
                // not enough confirmed blocks.
                tracing::info!(
                    target: LOG_TARGET,
                    "Not enough confirmed blocks for domain: {:?}. Skipping...",
                    domain_id
                );
                continue;
            }
            Some(confirmed_block) => confirmed_block,
        };

        while relay_block_from <= relay_block_until {
            tracing::info!(
                target: LOG_TARGET,
                "Checking messages to be submitted from domain: {:?} at block: {:?}",
                domain_id,
                relay_block_from
            );
            let block_hash = domain_client
                .header(BlockId::Number(relay_block_from))?
                .ok_or(Error::UnableToFetchBlockNumber)?
                .hash();
            if let Err(err) = message_processor(relayer_id.clone(), &domain_client, block_hash) {
                tracing::error!(
                    target: LOG_TARGET,
                    ?err,
                    "Failed to submit messages from the domain {domain_id:?} at the block {relay_block_from:?}"
                );
                break;
            };

            Relayer::store_last_relayed_block(&domain_client, domain_id, relay_block_from)?;
            relay_block_from = relay_block_from
                .checked_add(&One::one())
                .ok_or(ArithmeticError::Overflow)?;
        }
    }

    Ok(())
}

/// Combines both system and core domain sync oracles into one.
struct CombinedSyncOracle<SDSO, CDSO> {
    system_domain_sync_oracle: SDSO,
    core_domain_sync_oracle: CDSO,
}

impl<SDSO, CDSO> SyncOracle for CombinedSyncOracle<SDSO, CDSO>
where
    SDSO: SyncOracle,
    CDSO: SyncOracle,
{
    /// Returns true if either of the domains are in major sync.
    fn is_major_syncing(&self) -> bool {
        self.system_domain_sync_oracle.is_major_syncing()
            || self.core_domain_sync_oracle.is_major_syncing()
    }

    /// Returns true if either of the domains are offline.
    fn is_offline(&self) -> bool {
        self.system_domain_sync_oracle.is_offline() || self.core_domain_sync_oracle.is_offline()
    }
}

impl<SDSO, CDSO> CombinedSyncOracle<SDSO, CDSO> {
    /// Returns a new sync oracle that wraps system domain and core domain sync oracle.
    fn new(system_domain_sync_oracle: SDSO, core_domain_sync_oracle: CDSO) -> Self {
        CombinedSyncOracle {
            system_domain_sync_oracle,
            core_domain_sync_oracle,
        }
    }
}