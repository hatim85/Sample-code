// src/service.rs
extern crate alloc;

use crate::types::{AuthCredentials, ServiceCommand, ServiceState}; // Add AuthCredentials
use alloc::vec::Vec;
use jam_codec::{Decode, Encode};
use jam_pvm_common::{
    accumulate::{get_storage, set_storage},
    declare_service, info, Service,
};
use jam_types::{
    AccumulateItem, CodeHash, Hash, RefineContext, ServiceId, Slot, TransferRecord, WorkOutput,
    WorkPackageHash, WorkPayload
};

// Make STORAGE_KEY public so the authorizer can use it
pub const STORAGE_KEY: &[u8] = b"my_jam_service_state";

pub struct MyJamService;

declare_service!(MyJamService);

impl Service for MyJamService {
    fn refine(
        _id: ServiceId,
        payload: WorkPayload,
        _package_hash: WorkPackageHash,
        _context: RefineContext,
        _auth_code_hash: CodeHash,
    ) -> WorkOutput {
        info!(target = "service::refine", "Executing refine logic.");
        let payload_slice = payload.take();
        let output_data = [b"Refined: ", payload_slice.as_slice()].concat();
        info!(
            target = "service::refine",
            "Produced output of length {}.",
            output_data.len()
        );
        output_data.into()
    }

    fn accumulate(_slot: Slot, _id: ServiceId, items: Vec<AccumulateItem>) -> Option<Hash> {
        info!(
            target = "service::accumulate",
            "Executing accumulate logic with {} item(s).",
            items.len()
        );

        let mut state: ServiceState = get_storage(STORAGE_KEY)
            .and_then(|bytes| ServiceState::decode(&mut bytes.as_slice()).ok())
            .unwrap_or_default();

        if let Some(item) = items.first() {
            // Only update state if the work was successful
            if item.result.is_ok() {
                state.counter += 1;
                state.last_payload_hash = item.payload.0;

                // --- INCREMENT NONCE AFTER SUCCESSFUL EXECUTION ---
                // Decode the AuthParam again to get the public key.
                if let Ok(creds) = AuthCredentials::decode(&mut item.auth_output.0.as_slice()) {
                    let nonce = state.nonces.entry(creds.public_key).or_insert(0);
                    *nonce += 1;
                    info!(
                        target = "service::accumulate",
                        "Nonce for pk {:?} incremented to {}.", creds.public_key, *nonce
                    );
                }
                // --- END NONCE INCREMENT ---
            }
        }

        // --- THIS IS THE FIX ---
        // Use println! for debugging, as it's less likely to be buffered during a panic.
        // println!(
        //     "DEBUG: State before saving: counter = {}",
        //     state.counter,
        // );

         println!(
            "DEBUG: State before saving: counter = {}, nonces = {:?}",
            state.counter,
            state.nonces
        );
        // --- END OF FIX ---

        if set_storage(STORAGE_KEY, &state.encode()).is_err() {
            info!(
                target = "service::accumulate",
                "Error: Failed to set storage."
            );
        } else {
            info!(
                target = "service::accumulate",
                "Successfully wrote new state: counter = {}.", state.counter
            );
        }

        None
    }

    fn on_transfer(_slot: Slot, _id: ServiceId, transfers: Vec<TransferRecord>) {
        info!(
            target = "service::on_transfer",
            "Executing on_transfer logic with {} record(s).",
            transfers.len()
        );

        if transfers.is_empty() {
            return;
        }

        let mut state: ServiceState = get_storage(STORAGE_KEY)
            .and_then(|bytes| ServiceState::decode(&mut bytes.as_slice()).ok())
            .unwrap_or_default();

        info!(
            target = "service::on_transfer",
            "Read initial state: counter = {}.", state.counter
        );

        for transfer in transfers {
            if let Ok(command) = ServiceCommand::decode(&mut &transfer.memo.0[..]) {
                info!(
                    target = "service::on_transfer",
                    "Decoded command: {:?}.", command
                );
                match command {
                    ServiceCommand::IncrementCounter { by } => state.counter += by,
                    ServiceCommand::ResetState => {
                        // ADMIN CHECK
                        if u64::from(transfer.source) == state.admin {
                            state = ServiceState::default();
                            state.admin = u64::from(transfer.source); // Preserve admin on reset
                        } else {
                            info!(
                                target = "service::on_transfer",
                                "ACCESS DENIED: ResetState is admin-only."
                            );
                        }
                    }
                }
            } else {
                info!(
                    target = "service::on_transfer",
                    "Could not decode command from transfer memo."
                );
            }
        }

        // if set_storage(STORAGE_KEY, &state.encode()).is_err() {
        //     info!(
        //         target = "service::on_transfer",
        //         "Error: Failed to set storage."
        //     );
        // } else {
        //     info!(
        //         target = "service::on_transfer",
        //         "Successfully wrote new state: counter = {}.", state.counter
        //     );
        // }
    }
}
