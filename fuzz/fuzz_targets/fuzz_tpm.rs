// Copyright (C) Microsoft Corporation. All rights reserved.

//! Fuzzes TPM command dispatch.
//!
//! The input is a raw TPM command stream: it is split into individual commands
//! along the boundaries declared by each command's `commandSize` field, and
//! each one is dispatched through `MsTpm185Platform::execute_command`, which is
//! how a transport (say, a vTPM's MMIO/CRB interface) would hand guest
//! controlled bytes to this crate.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ms_tcg_tpm_sys_fuzz::split_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_COMMANDS: usize = 16;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut commands = split_commands(data, MAX_COMMANDS);

    with_tpm(|tpm| {
        for command in &mut commands {
            // Errors are the crate correctly rejecting a malformed request;
            // it's crashes, hangs, and leaks that this target is looking for.
            let _ = tpm.execute_command(command);
        }
    });
});
