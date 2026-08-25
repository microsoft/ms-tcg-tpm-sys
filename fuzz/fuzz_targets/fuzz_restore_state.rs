// Copyright (C) Microsoft Corporation. All rights reserved.

//! Fuzzes saved-state restore.
//!
//! `MsTpm185Platform::restore_state` parses a blob that, for a vTPM, comes off
//! a save file or a migration stream: it can be truncated, stale, corrupted, or
//! outright hostile. Restoring one must fail cleanly rather than crash, and a
//! blob that does restore must leave the TPM in a state that can keep running.
//!
//! Random bytes never get past the blob's postcard framing, so the interesting
//! mode here is `Patched`, which splices fuzzer controlled bytes into a blob
//! the TPM itself produced.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ms_tcg_tpm_sys_fuzz::Patch;
use ms_tcg_tpm_sys_fuzz::split_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_COMMANDS: usize = 4;

#[derive(Arbitrary, Debug)]
enum Input {
    /// Restore an arbitrary blob.
    Raw {
        /// The blob to restore.
        blob: Vec<u8>,
        /// Commands to run afterwards, if the restore succeeded.
        commands: Vec<u8>,
    },
    /// Restore a corrupted version of a blob the TPM actually saved.
    Patched {
        /// Corruption to apply to the saved state.
        patches: Vec<Patch>,
        /// Commands to run afterwards, if the restore succeeded.
        commands: Vec<u8>,
    },
}

fuzz_target!(|input: Input| {
    with_tpm(|tpm| {
        let (blob, commands) = match &input {
            Input::Raw { blob, commands } => (blob.clone(), commands),
            Input::Patched { patches, commands } => {
                let mut blob = tpm.snapshot().to_vec();
                Patch::apply_all(&mut blob, patches);
                (blob, commands)
            }
        };

        // A rejected blob is the expected outcome for most inputs.
        if tpm.restore_state(blob).is_err() {
            return;
        }

        // The restore claimed the state was good, so the TPM has to be able to
        // keep running on it, and to save it back out.
        for command in &mut split_commands(commands, MAX_COMMANDS) {
            let _ = tpm.execute_command(command);
        }

        let _ = tpm.save_state();
    });
});
