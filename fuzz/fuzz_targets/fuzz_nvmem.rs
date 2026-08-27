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
use ms_tcg_tpm_sys_fuzz::TPM2_SHUTDOWN_STATE;
use ms_tcg_tpm_sys_fuzz::TPM2_STARTUP_CLEAR;
use ms_tcg_tpm_sys_fuzz::TPM2_STARTUP_STATE;
use ms_tcg_tpm_sys_fuzz::baseline_nvmem;
use ms_tcg_tpm_sys_fuzz::known_commands;
use ms_tcg_tpm_sys_fuzz::split_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_COMMANDS: usize = 8;

/// A command to run against the TPM that came up on the corrupted blob.
#[derive(Arbitrary, Debug)]
enum Command {
    /// One of the harness' well formed commands. This target has no seed
    /// corpus and no dictionary, so without these it rarely gets a command
    /// past the header and never sees what a tampered blob does to a TPM that
    /// is actually running.
    Known(u8),
    /// Fuzzer supplied bytes, split on their declared command sizes.
    Raw(Vec<u8>),
}

#[derive(Arbitrary, Debug)]
struct Input {
    /// Whether to shut down orderly before the power cycle, and come back up
    /// with `TPM_SU_STATE`. Resuming reads far more out of the blob than a
    /// clear start does, but only makes sense against a blob that claims an
    /// orderly shutdown - which the patches below are free to lie about.
    resume: bool,
    /// Corruption to apply to the nvmem blob.
    patches: Vec<Patch>,
    /// Commands to run against the TPM that comes up on the corrupted blob.
    commands: Vec<Command>,
}

fuzz_target!(|input: Input| {
    let mut nvmem = baseline_nvmem().to_vec();
    Patch::apply_all(&mut nvmem, &input.patches);

    with_tpm(|tpm| {
        if input.resume {
            // Has to happen before the power cycle, on the pristine TPM, so
            // that the state being resumed onto is one the TPM really wrote.
            let _ = tpm.execute_command(&mut TPM2_SHUTDOWN_STATE.to_vec());
        }

        // Rejecting a blob outright is a perfectly good outcome.
        if tpm.reset(Some(&nvmem)).is_err() {
            return;
        }

        // Start the TPM up before anything else; that's where the bulk of the
        // nvmem is parsed.
        let startup = if input.resume {
            TPM2_STARTUP_STATE
        } else {
            TPM2_STARTUP_CLEAR
        };

        let mut commands = vec![startup.to_vec()];
        for command in &input.commands {
            match command {
                Command::Known(index) => {
                    let known = known_commands();
                    commands.push(known[*index as usize % known.len()].to_vec());
                }
                Command::Raw(bytes) => {
                    commands.append(&mut split_commands(bytes, MAX_COMMANDS));
                }
            }
            if commands.len() >= MAX_COMMANDS {
                break;
            }
        }

        for command in commands.iter_mut().take(MAX_COMMANDS) {
            let _ = tpm.execute_command(command);
        }
    });
});
