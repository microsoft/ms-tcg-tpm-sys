// Copyright (C) Microsoft Corporation. All rights reserved.

//! Fuzzes booting the TPM on a persisted nvmem blob.
//!
//! A vTPM's nvmem blob lives outside the TPM, in whatever the host uses for
//! persistent storage, so the TPM has to survive being handed one that has been
//! rolled back or tampered with. Each iteration power-cycles onto a
//! corrupted blob and then drives commands against whatever comes up.
//!
//! The blob is installed with `reset`, on a TPM that [`with_tpm`] has just
//! rolled back, rather than with `InitKind::ColdInitWithPersistentState` on a
//! freshly built one. Both take the same path through the platform's nvmem
//! layer and into `_TPM_Init`, but the rollback means an iteration depends only
//! on its own input: leaving the previous iteration's globals in place made
//! most of this target's crashes impossible to replay on their own.
//!
//! The blob always stays the full `NV_MEMORY_SIZE`. The platform now rejects
//! any other size up front - a shorter region let the TPM library address NV
//! memory that wasn't there - so mutating the length here would just bounce off
//! that check and waste the iteration. `tests/nvmem_size.rs` covers it instead.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ms_tcg_tpm_sys_fuzz::Patch;
use ms_tcg_tpm_sys_fuzz::TPM2_STARTUP_CLEAR;
use ms_tcg_tpm_sys_fuzz::baseline_nvmem;
use ms_tcg_tpm_sys_fuzz::split_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_COMMANDS: usize = 8;

#[derive(Arbitrary, Debug)]
struct Input {
    /// Corruption to apply to the nvmem blob.
    patches: Vec<Patch>,
    /// Commands to run against the TPM that comes up on the corrupted blob.
    commands: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let mut nvmem = baseline_nvmem().to_vec();
    Patch::apply_all(&mut nvmem, &input.patches);

    with_tpm(|tpm| {
        // Rejecting a blob outright is a perfectly good outcome.
        if tpm.reset(Some(&nvmem)).is_err() {
            return;
        }

        // Start the TPM up before anything else; that's where the bulk of the
        // nvmem is parsed.
        let mut commands = vec![TPM2_STARTUP_CLEAR.to_vec()];
        commands.append(&mut split_commands(&input.commands, MAX_COMMANDS));

        for command in &mut commands {
            let _ = tpm.execute_command(command);
        }
    });
});
