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
use ms_tcg_tpm_sys_fuzz::KNOWN_HANDLES;
use ms_tcg_tpm_sys_fuzz::PASSWORD_SESSION;
use ms_tcg_tpm_sys_fuzz::TPM_CC_FIRST;
use ms_tcg_tpm_sys_fuzz::build_structured_command;
use ms_tcg_tpm_sys_fuzz::canned_commands;
use ms_tcg_tpm_sys_fuzz::with_tpm;

/// Caps how much work a single input can ask for, keeping the fuzzer's
/// executions-per-second up.
const MAX_OPS: usize = 24;

/// Caps the handle area. `MAX_HANDLE_NUM` is 3 in this profile, so anything
/// beyond that is parameter bytes rather than a handle.
const MAX_HANDLES: usize = 3;

/// A handle to place in a command's handle area.
#[derive(Arbitrary, Debug)]
enum Handle {
    /// One of the handles that actually names something, selected modulo
    /// [`KNOWN_HANDLES`].
    Known(u8),
    /// An arbitrary handle, for the handle validation itself.
    Raw(u32),
}

impl Handle {
    fn resolve(&self) -> u32 {
        match self {
            Handle::Known(index) => KNOWN_HANDLES[*index as usize % KNOWN_HANDLES.len()],
            Handle::Raw(handle) => *handle,
        }
    }
}

/// The authorization area to attach to a command.
#[derive(Arbitrary, Debug)]
enum Auth {
    /// No authorization area, tagging the command `TPM_ST_NO_SESSIONS`.
    None,
    /// One to three empty password sessions, which is what the great majority
    /// of commands are asking for.
    Password(u8),
    /// A fuzzer supplied authorization area, to exercise the session parser
    /// rather than the command behind it.
    Raw(Vec<u8>),
}

impl Auth {
    fn build(&self) -> Option<Vec<u8>> {
        match self {
            Auth::None => None,
            Auth::Password(count) => {
                let count = 1 + *count as usize % 3;
                Some(PASSWORD_SESSION.repeat(count))
            }
            Auth::Raw(bytes) => Some(bytes.clone()),
        }
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    /// Dispatch a command with a well formed header, a handle area, and an
    /// authorization area, leaving the fuzzer to drive the parameters.
    Command {
        /// Offset from `TPM_CC_FIRST`, which covers every implemented command
        /// code, plus a margin of unimplemented ones.
        code_offset: u8,
        /// The command's handle area.
        handles: Vec<Handle>,
        /// The command's authorization area.
        auth: Auth,
        /// Everything after the authorization area.
        params: Vec<u8>,
    },
    /// Dispatch raw bytes, header and all.
    Raw(Vec<u8>),
    /// Dispatch one of the commands the harness built out of data the TPM
    /// itself produced - a `TPM2_Load` of a real private blob, or a
    /// `TPM2_ContextLoad` of a real saved context. Neither is reachable
    /// otherwise, and a loaded child object is what most of the remaining
    /// object commands are waiting on.
    Canned(u8),
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
    /// Jump the platform clock forward, in minutes.
    AdvanceClock(u16),
    /// Save, probe, restore, probe again. Restoring the state the first probe
    /// ran against has to reproduce its answers, so state the blob fails to
    /// carry shows up as a divergence rather than staying silent.
    RollbackFidelity,
}

fuzz_target!(|ops: Vec<Op>| {
    if ops.is_empty() {
        return;
    }

    with_tpm(|tpm| {
        for op in ops.iter().take(MAX_OPS) {
            match op {
                Op::Command {
                    code_offset,
                    handles,
                    auth,
                    params,
                } => {
                    let handles: Vec<u32> = handles
                        .iter()
                        .take(MAX_HANDLES)
                        .map(Handle::resolve)
                        .collect();
                    let code = TPM_CC_FIRST + *code_offset as u32;
                    let mut command =
                        build_structured_command(code, &handles, auth.build().as_deref(), params);
                    let _ = tpm.execute_command(&mut command);
                }
                Op::Raw(bytes) => {
                    let mut command = bytes.clone();
                    let _ = tpm.execute_command(&mut command);
                }
                Op::Canned(index) => {
                    let canned = canned_commands();
                    let mut command = canned[*index as usize % canned.len()].clone();
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
                Op::AdvanceClock(minutes) => {
                    tpm.advance_clock(u64::from(*minutes) * 60_000);
                }
                Op::RollbackFidelity => {
                    let saved = tpm.save_state();
                    let before = tpm.probe();
                    tpm.restore_state(saved)
                        .expect("state the TPM just saved should restore");
                    let after = tpm.probe();

                    assert!(
                        before == after,
                        "restore did not roll the TPM back: probe responses diverged"
                    );
                }
            }
        }
    });
});
