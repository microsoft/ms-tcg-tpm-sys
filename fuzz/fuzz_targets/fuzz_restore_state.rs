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
use ms_tcg_tpm_sys_fuzz::known_commands;
use ms_tcg_tpm_sys_fuzz::split_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_COMMANDS: usize = 4;

/// A command to run against the TPM the blob restored.
#[derive(Arbitrary, Debug)]
enum Command {
    /// One of the harness' well formed commands. Like `fuzz_nvmem`, this
    /// target is driven by `arbitrary` rather than a seed corpus, so raw bytes
    /// alone leave the restored TPM almost untouched.
    Known(u8),
    /// Fuzzer supplied bytes, split on their declared command sizes.
    Raw(Vec<u8>),
}

impl Command {
    fn expand(commands: &[Command]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for command in commands {
            match command {
                Command::Known(index) => {
                    let known = known_commands();
                    out.push(known[*index as usize % known.len()].to_vec());
                }
                Command::Raw(bytes) => out.append(&mut split_commands(bytes, MAX_COMMANDS)),
            }
            if out.len() >= MAX_COMMANDS {
                break;
            }
        }
        out.truncate(MAX_COMMANDS);
        out
    }
}

#[derive(Arbitrary, Debug)]
enum Input {
    /// Restore an arbitrary blob.
    Raw {
        /// The blob to restore.
        blob: Vec<u8>,
        /// Commands to run afterwards, if the restore succeeded.
        commands: Vec<Command>,
    },
    /// Restore a corrupted version of a blob the TPM actually saved.
    Patched {
        /// Corruption to apply to the saved state.
        patches: Vec<Patch>,
        /// Commands to run afterwards, if the restore succeeded.
        commands: Vec<Command>,
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
        for command in &mut Command::expand(commands) {
            let _ = tpm.execute_command(command);
        }

        let _ = tpm.save_state();
    });
});
