// Copyright (C) Microsoft Corporation. All rights reserved.

//! Fuzzes whole TPM sessions.
//!
//! Where `fuzz_tpm` hammers on a single entry point, this target drives the
//! rest of the crate's surface - power cycles, live save / restore, locality
//! changes and command cancellation - interleaved with commands, looking for
//! bugs that only show up in a particular ordering of platform events.
//!
//! Commands are (mostly) generated with a well formed header, so that the
//! fuzzer spends its time on per-command unmarshaling rather than on the header
//! parsing that `fuzz_tpm` already covers.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use ms_tcg_tpm_sys::Locality;
use ms_tcg_tpm_sys_fuzz::TPM_CC_FIRST;
use ms_tcg_tpm_sys_fuzz::TPM_ST_NO_SESSIONS;
use ms_tcg_tpm_sys_fuzz::TPM_ST_SESSIONS;
use ms_tcg_tpm_sys_fuzz::build_command;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_OPS: usize = 24;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Dispatch a command with a well formed header and a fuzzer controlled
    /// body (handles, authorization area, and parameters).
    Command {
        /// Selects between `TPM_ST_SESSIONS` and `TPM_ST_NO_SESSIONS`.
        sessions: bool,
        /// Offset from `TPM_CC_FIRST`, which covers every implemented command
        /// code, plus a margin of unimplemented ones.
        code_offset: u8,
        /// Everything after the command header.
        body: Vec<u8>,
    },
    /// Dispatch raw bytes, header and all.
    Raw(Vec<u8>),
    /// Dispatch raw bytes through the unchecked entry point, skipping the
    /// wrapper's request size validation.
    RawUnchecked(Vec<u8>),
    /// Round-trip the live state through a save / restore, the way a live
    /// migration would.
    SaveRestore,
    /// Simulate a power cycle.
    Reset,
    /// Assign a locality to subsequent commands. Values that aren't valid
    /// localities are skipped.
    SetLocality(u8),
    /// Set or clear the cancel flag.
    SetCancelFlag(bool),
}

fuzz_target!(|ops: Vec<Op>| {
    if ops.is_empty() {
        return;
    }

    with_tpm(|tpm| {
        for op in ops.iter().take(MAX_OPS) {
            match op {
                Op::Command {
                    sessions,
                    code_offset,
                    body,
                } => {
                    let tag = if *sessions {
                        TPM_ST_SESSIONS
                    } else {
                        TPM_ST_NO_SESSIONS
                    };
                    let code = TPM_CC_FIRST + *code_offset as u32;
                    let mut command = build_command(tag, code, body);
                    let _ = tpm.execute_command(&mut command);
                }
                Op::Raw(bytes) => {
                    let mut command = bytes.clone();
                    let _ = tpm.execute_command(&mut command);
                }
                Op::RawUnchecked(bytes) => {
                    let mut command = bytes.clone();
                    tpm.execute_command_unchecked(&mut command);
                }
                Op::SaveRestore => {
                    let saved = tpm.save_state();
                    tpm.restore_state(saved.clone())
                        .expect("state the TPM just saved should restore");

                    // Restoring a blob and saving it right back out has to
                    // produce that same blob, otherwise state is being dropped
                    // (or invented) on the way through, and a migrated TPM
                    // wouldn't match the one it was migrated from.
                    assert!(
                        tpm.save_state() == saved,
                        "save / restore / save round-trip changed the saved state"
                    );
                }
                Op::Reset => {
                    tpm.reset(None).expect("power cycling should succeed");
                }
                Op::SetLocality(locality) => {
                    if let Ok(locality) = Locality::try_from(*locality) {
                        tpm.set_locality(locality);
                    }
                }
                Op::SetCancelFlag(enabled) => {
                    tpm.set_cancel_flag(*enabled);
                }
            }
        }
    });
});
