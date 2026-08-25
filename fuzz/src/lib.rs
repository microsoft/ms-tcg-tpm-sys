// Copyright (C) Microsoft Corporation. All rights reserved.

//! Shared plumbing for the `ms-tcg-tpm-sys` fuzz targets.
//!
//! # Determinism
//!
//! Fuzzing is only useful if a crashing input can be replayed, which means
//! every input the TPM sees other than the fuzzer's own bytes has to be
//! reproducible. [`FuzzPlatformCallbacks`] therefore backs the entropy source
//! with a fixed-seed PRNG and the monotonic timer with a call counter, both of
//! which are reset at the top of every iteration.
//!
//! # The global TPM instance
//!
//! The underlying C library keeps its state in globals, so only one
//! [`MsTpm185Platform`] can be live at a time, and manufacturing one is far too
//! slow to do per iteration. [`with_tpm`] instead manufactures a single TPM per
//! process and restores a pristine post-manufacture snapshot before each
//! iteration, which is both much faster and gives every iteration the same
//! starting state.
//!
//! Note that the snapshot only covers the state the library knows how to
//! save + restore. If a command leaves state behind that isn't part of a
//! saved-state blob, it will bleed into subsequent iterations - which is itself
//! a bug worth finding, since the same bleed-through would break a live
//! migration.

#![warn(missing_docs)]

use arbitrary::Arbitrary;
use ms_tcg_tpm_sys::DynResult;
use ms_tcg_tpm_sys::Error;
use ms_tcg_tpm_sys::InitKind;
use ms_tcg_tpm_sys::Locality;
use ms_tcg_tpm_sys::MsTpm185Platform;
use ms_tcg_tpm_sys::PlatformCallbacks;
use std::cell::RefCell;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

/// `MAX_COMMAND_SIZE` from `TpmProfile_Common.h`.
pub const MAX_COMMAND_SIZE: usize = 8192;

/// `MAX_RESPONSE_SIZE` from `TpmProfile_Common.h`.
///
/// `ExecuteCommand` marshals directly into the caller's response buffer without
/// bounds checking it against the response it is building, so anything smaller
/// than this is a heap overflow waiting to happen. Every response buffer handed
/// to the TPM by this harness is exactly this size.
pub const MAX_RESPONSE_SIZE: usize = 8192;

/// Size of the `tag` + `commandSize` + `commandCode` command header, which is
/// also the size of the `tag` + `responseSize` + `responseCode` response
/// header.
pub const HEADER_SIZE: usize = 10;

/// `TPM_ST_NO_SESSIONS`
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS`
pub const TPM_ST_SESSIONS: u16 = 0x8002;

/// `TPM_CC_FIRST` from `TpmTypes.h`. The last implemented command code is
/// `TPM_CC_LAST` (`0x1aa`).
pub const TPM_CC_FIRST: u32 = 0x0000011f;

/// `TPM_RC_SUCCESS`
pub const TPM_RC_SUCCESS: u32 = 0;

/// `TPM2_Startup(TPM_SU_CLEAR)`
pub const TPM2_STARTUP_CLEAR: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
];

/// `TPM2_SelfTest(fullTest = YES)`
const TPM2_SELF_TEST_FULL: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
];

/// Seed for the entropy PRNG. Any fixed value will do; this one is arbitrary.
const PRNG_SEED: u64 = 0x0123_4567_89ab_cdef;

static PRNG_STATE: AtomicU64 = AtomicU64::new(PRNG_SEED);
static CLOCK_TICKS: AtomicU64 = AtomicU64::new(0);
static COMMITTED_NVMEM: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Rewinds the entropy source and the clock, so that a given sequence of TPM
/// operations always sees the same platform inputs.
///
/// [`with_tpm`] does this for its callers; targets that build their own
/// [`MsTpm185Platform`] have to call it themselves.
pub fn reset_platform_inputs() {
    PRNG_STATE.store(PRNG_SEED, Relaxed);
    CLOCK_TICKS.store(0, Relaxed);
}

/// SplitMix64.
fn next_random() -> u64 {
    const GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

    // `fetch_add` hands back the previous state, so re-apply the step to get
    // the state this draw corresponds to.
    let mut z = PRNG_STATE.fetch_add(GAMMA, Relaxed).wrapping_add(GAMMA);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Deterministic [`PlatformCallbacks`] implementation.
pub struct FuzzPlatformCallbacks;

impl PlatformCallbacks for FuzzPlatformCallbacks {
    fn commit_nv_state(&mut self, state: &[u8]) -> DynResult<()> {
        // Stashed (rather than dropped) so that `baseline_nvmem` can hand a
        // real, TPM-written nvmem blob to the nvmem fuzz target.
        let mut committed = COMMITTED_NVMEM.lock().unwrap();
        committed.clear();
        committed.extend_from_slice(state);
        Ok(())
    }

    fn get_crypt_random(&mut self, buf: &mut [u8]) -> DynResult<usize> {
        // The platform layer runs the FIPS continuous RNG test over
        // consecutive 4 byte blocks, so this must not return a constant.
        for chunk in buf.chunks_mut(size_of::<u64>()) {
            let random = next_random().to_le_bytes();
            chunk.copy_from_slice(&random[..chunk.len()]);
        }
        Ok(buf.len())
    }

    fn monotonic_timer(&mut self) -> Duration {
        // Advance by a fixed step per call, so that time-dependent code (clock
        // updates, lockout self-heal, etc.) makes progress without making the
        // TPM's behavior depend on how fast the fuzzer happens to be running.
        Duration::from_millis(CLOCK_TICKS.fetch_add(1, Relaxed))
    }

    fn get_unique_value(&self) -> &'static [u8] {
        b"ms-tcg-tpm-sys fuzzing platform unique value"
    }
}

thread_local! {
    static TPM: RefCell<Option<FuzzTpm>> = const { RefCell::new(None) };
}

/// Hands `f` a TPM that has been rolled back to its pristine post-manufacture
/// state.
///
/// The TPM is manufactured on first use and reused (via save / restore) by
/// every subsequent call.
pub fn with_tpm<R>(f: impl FnOnce(&mut FuzzTpm) -> R) -> R {
    TPM.with(|tpm| {
        let mut tpm = tpm.borrow_mut();
        let tpm = match &mut *tpm {
            Some(tpm) => {
                tpm.rollback();
                tpm
            }
            slot => slot.insert(FuzzTpm::new()),
        };
        f(tpm)
    })
}

/// An nvmem blob written by a real, freshly manufactured TPM, for fuzz targets
/// that want to mutate a plausible blob rather than start from noise.
///
/// Must not be called while a [`FuzzTpm`] is live, as it briefly manufactures a
/// TPM of its own.
pub fn baseline_nvmem() -> &'static [u8] {
    static BASELINE: OnceLock<Vec<u8>> = OnceLock::new();
    BASELINE.get_or_init(|| {
        // Manufacture a TPM purely for the nvmem it writes on the way up, then
        // hand the platform singleton back for the fuzz target to claim.
        drop(FuzzTpm::new());

        let committed = COMMITTED_NVMEM.lock().unwrap().clone();
        assert!(
            !committed.is_empty(),
            "manufacturing a TPM should have committed an nvmem blob"
        );
        committed
    })
}

/// A manufactured TPM, along with the buffers and pristine snapshot used to
/// drive it.
pub struct FuzzTpm {
    platform: MsTpm185Platform,
    response: Vec<u8>,
    snapshot: Vec<u8>,
}

impl FuzzTpm {
    /// Manufactures a TPM, starts it up, and snapshots the result.
    fn new() -> FuzzTpm {
        reset_platform_inputs();

        let platform =
            MsTpm185Platform::initialize(Box::new(FuzzPlatformCallbacks), InitKind::ColdInit)
                .expect("manufacturing a TPM should succeed");

        let mut tpm = FuzzTpm {
            platform,
            response: vec![0; MAX_RESPONSE_SIZE],
            snapshot: Vec::new(),
        };

        // Start the TPM up, and get the (slow) self tests out of the way once
        // per process, so that iterations start from a state where the bulk of
        // the command surface is reachable.
        tpm.execute_expecting_success(TPM2_STARTUP_CLEAR, "TPM2_Startup");
        tpm.execute_expecting_success(TPM2_SELF_TEST_FULL, "TPM2_SelfTest");

        tpm.snapshot = tpm.platform.save_state();
        tpm
    }

    /// Rolls the TPM back to the state captured by [`FuzzTpm::new`].
    fn rollback(&mut self) {
        reset_platform_inputs();
        self.platform
            .restore_state(self.snapshot.clone())
            .expect("restoring the harness' own snapshot should succeed");
    }

    /// The pristine snapshot that every iteration starts from.
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }

    /// Executes a command through the size-checked entry point, returning the
    /// response on success.
    pub fn execute_command(&mut self, command: &mut [u8]) -> Result<&[u8], Error> {
        let len = self.platform.execute_command(command, &mut self.response)?;
        Ok(check_response(&self.response, len))
    }

    /// Executes a command through the unchecked entry point, returning the
    /// response.
    pub fn execute_command_unchecked(&mut self, command: &mut [u8]) -> &[u8] {
        // SAFETY: `self.response` is `MAX_RESPONSE_SIZE` bytes, which is the
        // largest response the TPM can produce, and the TPM validates the
        // request buffer's size against the size declared in its header.
        let len = unsafe {
            self.platform
                .execute_command_unchecked(command, &mut self.response)
        };
        check_response(&self.response, len)
    }

    /// Executes a command that is expected to succeed, panicking otherwise.
    fn execute_expecting_success(&mut self, command: &[u8], name: &str) {
        let mut command = command.to_vec();
        let response = self
            .execute_command(&mut command)
            .unwrap_or_else(|e| panic!("{name} should be dispatchable: {e}"));
        let code = response_code(response).expect("response should have a header");
        assert_eq!(code, TPM_RC_SUCCESS, "{name} returned {code:#010x}");
    }

    /// Simulates a power cycle, optionally swapping in a new nvmem blob.
    pub fn reset(&mut self, nvmem: Option<&[u8]>) -> Result<(), Error> {
        self.platform.reset(nvmem)
    }

    /// Saves the live state into an opaque blob.
    pub fn save_state(&self) -> Vec<u8> {
        self.platform.save_state()
    }

    /// Restores previously saved state.
    pub fn restore_state(&mut self, state: Vec<u8>) -> Result<(), Error> {
        self.platform.restore_state(state)
    }

    /// Sets the locality subsequent commands run at.
    pub fn set_locality(&mut self, locality: Locality) {
        self.platform.set_locality(locality);
    }

    /// Sets or clears the cancel flag.
    pub fn set_cancel_flag(&mut self, enabled: bool) {
        self.platform.set_cancel_flag(enabled);
    }
}

/// Validates the invariants every TPM response is expected to uphold, and
/// returns the response.
///
/// `len` is the response length the TPM reported, and `buffer` the response
/// buffer it was handed.
pub fn check_response(buffer: &[u8], len: usize) -> &[u8] {
    assert!(
        len <= buffer.len(),
        "TPM reported a {len} byte response, which overruns the {} byte response buffer",
        buffer.len()
    );

    let response = &buffer[..len];

    // A response is either empty (the command was cancelled / dropped) or a
    // well formed header, whose size field covers the whole response.
    if !response.is_empty() {
        assert!(
            response.len() >= HEADER_SIZE,
            "TPM returned a {} byte response, which is too short to hold a header",
            response.len()
        );

        let declared = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
        assert_eq!(
            declared,
            response.len(),
            "response header declares {declared} bytes, but {} bytes were returned",
            response.len()
        );
    }

    response
}

/// Extracts the response code from a response, if it has a header.
pub fn response_code(response: &[u8]) -> Option<u32> {
    let code = response.get(6..HEADER_SIZE)?;
    Some(u32::from_be_bytes(code.try_into().unwrap()))
}

/// Builds a command with a well formed header wrapped around a fuzzer supplied
/// body (handles, authorization area, and parameters).
///
/// Random bytes almost never form a valid header, which would leave the fuzzer
/// stuck at the TPM's front door. This gets it past the header parsing so that
/// it can spend its time on the far more interesting per-command unmarshaling
/// code.
pub fn build_command(tag: u16, command_code: u32, body: &[u8]) -> Vec<u8> {
    let size = (HEADER_SIZE + body.len()) as u32;

    let mut command = Vec::with_capacity(HEADER_SIZE + body.len());
    command.extend_from_slice(&tag.to_be_bytes());
    command.extend_from_slice(&size.to_be_bytes());
    command.extend_from_slice(&command_code.to_be_bytes());
    command.extend_from_slice(body);
    command
}

/// Splits a byte stream into commands along the boundaries declared by each
/// command's own `commandSize` field.
///
/// A stream of concatenated TPM commands splits exactly, so a corpus entry can
/// simply be a capture of a real command stream, while a stream with a bogus
/// size field is handed over as-is to exercise the size validation.
pub fn split_commands(data: &[u8], max_commands: usize) -> Vec<Vec<u8>> {
    let mut commands = Vec::new();
    let mut rest = data;

    while !rest.is_empty() && commands.len() < max_commands {
        let declared = rest
            .get(2..6)
            .map(|size| u32::from_be_bytes(size.try_into().unwrap()) as usize);

        let len = match declared {
            Some(len) if (HEADER_SIZE..=rest.len()).contains(&len) => len,
            _ => rest.len(),
        };

        let (command, tail) = rest.split_at(len);
        commands.push(command.to_vec());
        rest = tail;
    }

    commands
}

/// A fuzzer directed splice into an existing blob.
///
/// Used by the targets that fuzz blobs the TPM itself produced (saved state,
/// nvmem), where starting from random bytes would never get past the blob's
/// header validation.
#[derive(Arbitrary, Debug)]
pub struct Patch {
    /// Offset to splice at, taken modulo the length of the blob.
    pub offset: u32,
    /// Bytes to splice in, truncated to fit.
    pub bytes: Vec<u8>,
}

impl Patch {
    /// Applies a series of patches to `blob`.
    pub fn apply_all(blob: &mut [u8], patches: &[Patch]) {
        if blob.is_empty() {
            return;
        }

        for patch in patches {
            let offset = patch.offset as usize % blob.len();
            let len = patch.bytes.len().min(blob.len() - offset);
            blob[offset..offset + len].copy_from_slice(&patch.bytes[..len]);
        }
    }
}
