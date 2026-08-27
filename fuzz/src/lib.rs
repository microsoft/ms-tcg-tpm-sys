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

/// `TPM2_Startup(TPM_SU_STATE)`
///
/// A substantially different path through a saved nvmem blob than
/// `TPM_SU_CLEAR`: it restores PCRs, sessions and objects out of the state the
/// blob claims was saved, rather than reinitializing them.
pub const TPM2_STARTUP_STATE: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x01,
];

/// `TPM2_Shutdown(TPM_SU_STATE)`
pub const TPM2_SHUTDOWN_STATE: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x45, 0x00, 0x01,
];

/// `TPM2_SelfTest(fullTest = YES)`
const TPM2_SELF_TEST_FULL: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
];

/// `TPM2_ReadPublic(SEEDED_TRANSIENT)`, used to confirm the seeded state
/// survived a rollback.
const TPM2_READ_PUBLIC_SEEDED: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x73, 0x80, 0x00, 0x00, 0x00,
];

/// A `TPM_RS_PW` authorization area holding an empty password.
///
/// This is what the great majority of commands want, and it is the one thing
/// random bytes will essentially never produce: without it every command that
/// takes an authorization is rejected in `ParseSessionBuffer` before its
/// handler is ever entered.
pub const PASSWORD_SESSION: &[u8] = &[
    0x40, 0x00, 0x00, 0x09, // sessionHandle = TPM_RS_PW
    0x00, 0x00, // nonce (empty)
    0x00, // sessionAttributes
    0x00, 0x00, // hmac (empty)
];

/// Transient handle of the primary key [`FuzzTpm::new`] seeds.
pub const SEEDED_TRANSIENT: u32 = 0x8000_0000;
/// Transient handle of the seeded storage key.
///
/// The key at [`SEEDED_TRANSIENT`] is an unrestricted signing key, which
/// cannot be a parent. This one is restricted+decrypt, so `TPM2_Create`,
/// `TPM2_Load` and everything else that needs somewhere to put an object have
/// a parent to name.
///
/// `MAX_LOADED_OBJECTS` is 3 in this profile, so these two are deliberately
/// the only objects seeded: the third slot is left free for the fuzzer to
/// load into, otherwise every `TPM2_Load` would fail with
/// `TPM_RC_OBJECT_MEMORY` and the seeding would cost more coverage than it
/// bought.
pub const SEEDED_STORAGE_PARENT: u32 = 0x8000_0001;
/// Persistent handle the seeded primary key is also evicted to.
pub const SEEDED_PERSISTENT: u32 = 0x8100_0000;
/// Persistent handle of the seeded RSA signing key.
///
/// Persistent rather than transient so that it costs nothing against
/// `MAX_LOADED_OBJECTS`; without it no RSA code runs at all.
pub const SEEDED_RSA: u32 = 0x8100_0001;
/// Persistent handle of the seeded ML-DSA signing key.
pub const SEEDED_MLDSA: u32 = 0x8100_0002;
/// Ordinary NV index [`FuzzTpm::new`] defines and writes.
pub const SEEDED_NV_INDEX: u32 = 0x0100_0001;
/// NV counter index, for `TPM2_NV_Increment`.
pub const SEEDED_NV_COUNTER: u32 = 0x0100_0002;
/// NV bit field index, for `TPM2_NV_SetBits`.
pub const SEEDED_NV_BITS: u32 = 0x0100_0003;
/// NV extend index, for `TPM2_NV_Extend`.
pub const SEEDED_NV_EXTEND: u32 = 0x0100_0004;
/// NV index carrying the `READ_STCLEAR` / `WRITE_STCLEAR` attributes, for
/// `TPM2_NV_ReadLock` and `TPM2_NV_WriteLock`.
pub const SEEDED_NV_LOCKABLE: u32 = 0x0100_0005;
/// Handle of the seeded HMAC session.
pub const SEEDED_HMAC_SESSION: u32 = 0x0200_0000;
/// Handle of the seeded policy session.
///
/// Session slots come from one pool regardless of type, so this is slot 1.
pub const SEEDED_POLICY_SESSION: u32 = 0x0300_0001;

/// Handles a pristine [`FuzzTpm`] actually has live, plus the permanent ones
/// every TPM has.
///
/// Commands are built around these so that the fuzzer spends its time inside
/// command handlers instead of bouncing off handle validation. Guessing a
/// four byte handle that names a live object is not something a mutator will
/// do on its own.
pub const KNOWN_HANDLES: &[u32] = &[
    0x4000_0001, // TPM_RH_OWNER
    0x4000_0007, // TPM_RH_NULL
    0x4000_0009, // TPM_RS_PW
    0x4000_000a, // TPM_RH_LOCKOUT
    0x4000_000b, // TPM_RH_ENDORSEMENT
    0x4000_000c, // TPM_RH_PLATFORM
    0x4000_000d, // TPM_RH_PLATFORM_NV
    SEEDED_TRANSIENT,
    SEEDED_STORAGE_PARENT,
    SEEDED_PERSISTENT,
    SEEDED_RSA,
    SEEDED_MLDSA,
    SEEDED_NV_INDEX,
    SEEDED_NV_COUNTER,
    SEEDED_NV_BITS,
    SEEDED_NV_EXTEND,
    SEEDED_NV_LOCKABLE,
    SEEDED_HMAC_SESSION,
    SEEDED_POLICY_SESSION,
    0x0000_0000, // PCR 0
    0x0000_0007, // PCR 7
];

/// Builds a `TPM2_NV_DefineSpace` under owner authorization, with an empty
/// index authorization value.
#[rustfmt::skip]
const fn nv_define(index: u32, attributes: u32, data_size: u16) -> [u8; 45] {
    let i = index.to_be_bytes();
    let a = attributes.to_be_bytes();
    let d = data_size.to_be_bytes();
    [
        0x80, 0x02, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x01, 0x2a,
        0x40, 0x00, 0x00, 0x01, // authHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // auth (empty)
        0x00, 0x0e, // publicInfo
        i[0], i[1], i[2], i[3], // nvIndex
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        a[0], a[1], a[2], a[3], // attributes
        0x00, 0x00, // authPolicy (empty)
        d[0], d[1], // dataSize
    ]
}

/// Commands run once per process, after startup, to give the pristine state
/// something for the fuzzer to work with: a loaded key, a persistent copy of
/// it, a written NV index, and one session of each type.
///
/// Each entry is a command, and the handle its response is expected to report,
/// so that a drift between these blobs and [`KNOWN_HANDLES`] fails loudly
/// rather than quietly costing coverage.
#[rustfmt::skip]
const SETUP_COMMANDS: &[(&str, &[u8], Option<u32>)] = &[
    // TPM2_CreatePrimary(TPM_RH_OWNER, ECC NIST P-256 signing key). ECC rather
    // than RSA because this runs on every fuzzing process' startup path.
    ("TPM2_CreatePrimary", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x01, 0x31,
        0x40, 0x00, 0x00, 0x01, // primaryHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // inSensitive (empty)
        0x00, 0x16, // inPublic
        0x00, 0x23, // type = TPM_ALG_ECC
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        0x00, 0x04, 0x00, 0x72, // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign
        0x00, 0x00, // authPolicy (empty)
        0x00, 0x10, // symmetric = TPM_ALG_NULL
        0x00, 0x10, // scheme = TPM_ALG_NULL
        0x00, 0x03, // curveID = TPM_ECC_NIST_P256
        0x00, 0x10, // kdf = TPM_ALG_NULL
        0x00, 0x00, 0x00, 0x00, // unique (empty x, y)
        0x00, 0x00, // outsideInfo (empty)
        0x00, 0x00, 0x00, 0x00, // creationPCR (empty)
    ], Some(SEEDED_TRANSIENT)),

    // TPM2_EvictControl, to also reach the key through a persistent handle.
    ("TPM2_EvictControl", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x01, 0x20,
        0x40, 0x00, 0x00, 0x01, // auth = TPM_RH_OWNER
        0x80, 0x00, 0x00, 0x00, // objectHandle
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x00, 0x00, 0x00, // persistentHandle
    ], None),

    // TPM2_NV_DefineSpace, an ordinary 32 byte owner/auth read-write index.
    ("TPM2_NV_DefineSpace", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x01, 0x2a,
        0x40, 0x00, 0x00, 0x01, // authHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, // auth (empty)
        0x00, 0x0e, // publicInfo
        0x01, 0x00, 0x00, 0x01, // nvIndex
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        0x00, 0x06, 0x00, 0x06, // OWNERWRITE|AUTHWRITE|OWNERREAD|AUTHREAD
        0x00, 0x00, // authPolicy (empty)
        0x00, 0x20, // dataSize
    ], None),

    // TPM2_NV_Write, so the index is written and has contents to read back.
    ("TPM2_NV_Write", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x01, 0x37,
        0x40, 0x00, 0x00, 0x01, // authHandle = TPM_RH_OWNER
        0x01, 0x00, 0x00, 0x01, // nvIndex
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, // data
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00, 0x00, // offset
    ], None),

    // TPM2_CreatePrimary again, this time a restricted decryption key, which
    // is what an object needs as a parent. AES-128-CFB is mandatory for a
    // restricted decrypt key; a null symmetric algorithm is rejected.
    ("TPM2_CreatePrimary(storage)", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x01, 0x31,
        0x40, 0x00, 0x00, 0x01, // primaryHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // inSensitive (empty)
        0x00, 0x1a, // inPublic
        0x00, 0x23, // type = TPM_ALG_ECC
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        0x00, 0x03, 0x00, 0x72, // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|restricted|decrypt
        0x00, 0x00, // authPolicy (empty)
        0x00, 0x06, 0x00, 0x80, 0x00, 0x43, // symmetric = AES-128-CFB
        0x00, 0x10, // scheme = TPM_ALG_NULL
        0x00, 0x03, // curveID = TPM_ECC_NIST_P256
        0x00, 0x10, // kdf = TPM_ALG_NULL
        0x00, 0x00, 0x00, 0x00, // unique (empty x, y)
        0x00, 0x00, // outsideInfo (empty)
        0x00, 0x00, 0x00, 0x00, // creationPCR (empty)
    ], Some(SEEDED_STORAGE_PARENT)),

    // TPM2_CreatePrimary a third time, RSA rather than ECC. Nothing else here
    // reaches the RSA code at all - key generation, the prime sieve and
    // Miller-Rabin included - and every RSA operation needs a key to name.
    // 1024 bits because this runs on every process startup and exercises the
    // same generation path a larger modulus would.
    ("TPM2_CreatePrimary(RSA)", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x01, 0x31,
        0x40, 0x00, 0x00, 0x01, // primaryHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // inSensitive (empty)
        0x00, 0x16, // inPublic
        0x00, 0x01, // type = TPM_ALG_RSA
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        // sign and decrypt both, so one key generation covers every RSA
        // operation rather than only signing.
        0x00, 0x06, 0x00, 0x72,
        0x00, 0x00, // authPolicy (empty)
        0x00, 0x10, // symmetric = TPM_ALG_NULL
        0x00, 0x10, // scheme = TPM_ALG_NULL
        0x04, 0x00, // keyBits = 1024
        0x00, 0x00, 0x00, 0x00, // exponent = default
        0x00, 0x00, // unique (empty)
        0x00, 0x00, // outsideInfo (empty)
        0x00, 0x00, 0x00, 0x00, // creationPCR (empty)
    ], Some(0x8000_0002)),

    // Park the RSA key in NV and give the transient slot back. A persistent
    // object costs nothing against `MAX_LOADED_OBJECTS`, so this buys RSA
    // coverage without taking the slot the fuzzer needs for TPM2_Load.
    ("TPM2_EvictControl(RSA)", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x01, 0x20,
        0x40, 0x00, 0x00, 0x01, // auth = TPM_RH_OWNER
        0x80, 0x00, 0x00, 0x02, // objectHandle
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x00, 0x00, 0x01, // persistentHandle
    ], None),

    ("TPM2_FlushContext(RSA)", &[
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x65,
        0x80, 0x00, 0x00, 0x02, // flushHandle, a parameter rather than a handle
    ], None),

    // ML-DSA, same trick again. The streaming signature commands take a
    // `TPM2B_SIGNATURE_CTX`, which is an ML-DSA context: with only ECC and RSA
    // keys around, none of them are reachable and the whole ML-DSA provider is
    // dead code as far as the fuzzer is concerned.
    ("TPM2_CreatePrimary(ML-DSA)", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x01, 0x31,
        0x40, 0x00, 0x00, 0x01, // primaryHandle = TPM_RH_OWNER
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // inSensitive (empty)
        0x00, 0x0f, // inPublic
        0x00, 0xa1, // type = TPM_ALG_MLDSA
        0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
        0x00, 0x04, 0x00, 0x72, // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign
        0x00, 0x00, // authPolicy (empty)
        0x00, 0x01, // parameterSet = ML-DSA-44
        0x00, // allowExternalMu = NO
        0x00, 0x00, // unique (empty)
        0x00, 0x00, // outsideInfo (empty)
        0x00, 0x00, 0x00, 0x00, // creationPCR (empty)
    ], Some(0x8000_0002)),

    ("TPM2_EvictControl(ML-DSA)", &[
        0x80, 0x02, 0x00, 0x00, 0x00, 0x23, 0x00, 0x00, 0x01, 0x20,
        0x40, 0x00, 0x00, 0x01, // auth = TPM_RH_OWNER
        0x80, 0x00, 0x00, 0x02, // objectHandle
        0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x81, 0x00, 0x00, 0x02, // persistentHandle
    ], None),

    ("TPM2_FlushContext(ML-DSA)", &[
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x65,
        0x80, 0x00, 0x00, 0x02,
    ], None),

    // NV indices of each type, so the commands that only work against a
    // particular one have something to name. The type lives in bits 4-7 of
    // TPMA_NV, and fixes the size: counters and bit fields are 8 bytes, an
    // extend index is one digest.
    ("TPM2_NV_DefineSpace(counter)", &nv_define(SEEDED_NV_COUNTER, 0x0006_0016, 8), None),
    ("TPM2_NV_DefineSpace(bits)", &nv_define(SEEDED_NV_BITS, 0x0006_0026, 8), None),
    ("TPM2_NV_DefineSpace(extend)", &nv_define(SEEDED_NV_EXTEND, 0x0006_0046, 32), None),
    // READ_STCLEAR (bit 31) and WRITE_STCLEAR (bit 14), for the lock commands.
    ("TPM2_NV_DefineSpace(lockable)", &nv_define(SEEDED_NV_LOCKABLE, 0x8006_4006, 32), None),

    // TPM2_StartAuthSession, unbound and unsalted, one HMAC and one policy.
    ("TPM2_StartAuthSession(HMAC)", &[
        0x80, 0x01, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x76,
        0x40, 0x00, 0x00, 0x07, // tpmKey = TPM_RH_NULL
        0x40, 0x00, 0x00, 0x07, // bind = TPM_RH_NULL
        0x00, 0x20, // nonceCaller
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x00, 0x00, // encryptedSalt (empty)
        0x00, // sessionType = TPM_SE_HMAC
        0x00, 0x10, // symmetric = TPM_ALG_NULL
        0x00, 0x0b, // authHash = TPM_ALG_SHA256
    ], Some(SEEDED_HMAC_SESSION)),

    ("TPM2_StartAuthSession(policy)", &[
        0x80, 0x01, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x76,
        0x40, 0x00, 0x00, 0x07, // tpmKey = TPM_RH_NULL
        0x40, 0x00, 0x00, 0x07, // bind = TPM_RH_NULL
        0x00, 0x20, // nonceCaller
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x00, 0x00, // encryptedSalt (empty)
        0x01, // sessionType = TPM_SE_POLICY
        0x00, 0x10, // symmetric = TPM_ALG_NULL
        0x00, 0x0b, // authHash = TPM_ALG_SHA256
    ], Some(SEEDED_POLICY_SESSION)),
];

/// `TPM_CC_Load`
const TPM_CC_LOAD: u32 = 0x0000_0157;
/// `TPM_CC_ContextLoad`
const TPM_CC_CONTEXT_LOAD: u32 = 0x0000_0161;

/// `TPM2_Create` of an HMAC key under [`SEEDED_STORAGE_PARENT`].
///
/// Run for its output rather than its effect: the private blob it returns is
/// what makes a `TPM2_Load` possible.
#[rustfmt::skip]
const TPM2_CREATE_KEYEDHASH: &[u8] = &[
    0x80, 0x02, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x01, 0x53,
    0x80, 0x00, 0x00, 0x01, // parentHandle
    0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, // inSensitive (empty)
    0x00, 0x10, // inPublic
    0x00, 0x08, // type = TPM_ALG_KEYEDHASH
    0x00, 0x0b, // nameAlg = TPM_ALG_SHA256
    0x00, 0x04, 0x00, 0x72, // fixedTPM|fixedParent|sensitiveDataOrigin|userWithAuth|sign
    0x00, 0x00, // authPolicy (empty)
    0x00, 0x05, 0x00, 0x0b, // scheme = HMAC-SHA256
    0x00, 0x00, // unique (empty)
    0x00, 0x00, // outsideInfo (empty)
    0x00, 0x00, 0x00, 0x00, // creationPCR (empty)
];

/// `TPM2_ContextSave(SEEDED_TRANSIENT)`, run for the context blob it returns.
const TPM2_CONTEXT_SAVE_SEEDED: &[u8] = &[
    0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x62, 0x80, 0x00, 0x00, 0x00,
];

/// Commands assembled at setup time out of data the TPM itself produced.
///
/// `TPM2_Load` wants a private blob that only the TPM can have generated, and
/// `TPM2_ContextLoad` wants a saved context; a mutator will never invent
/// either, so without this those commands - and everything that needs a loaded
/// child object behind them - are unreachable. Built once per process, before
/// the snapshot, so the blobs stay valid for every iteration that rolls back
/// to it.
static CANNED_COMMANDS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

/// The commands described by [`CANNED_COMMANDS`], empty until a [`FuzzTpm`]
/// has been built.
pub fn canned_commands() -> &'static [Vec<u8>] {
    CANNED_COMMANDS.get().map_or(&[], Vec::as_slice)
}

/// Well formed commands that the targets which don't have a seed corpus can
/// reach for.
///
/// `fuzz_nvmem` and `fuzz_restore_state` take `arbitrary`-encoded input, so
/// unlike `fuzz_tpm` there is no seed corpus and no dictionary to spell a real
/// command out with, and raw bytes almost never clear the header. That wastes
/// the interesting half of what those targets do: not whether a blob is
/// rejected, but what the TPM does while running on one that wasn't.
pub fn known_commands() -> &'static [&'static [u8]] {
    static KNOWN: OnceLock<Vec<&'static [u8]>> = OnceLock::new();
    KNOWN.get_or_init(|| {
        let mut commands: Vec<&'static [u8]> = vec![
            TPM2_STARTUP_CLEAR,
            TPM2_STARTUP_STATE,
            TPM2_SHUTDOWN_STATE,
            TPM2_SELF_TEST_FULL,
            TPM2_READ_PUBLIC_SEEDED,
            TPM2_SIGN_SEEDED,
            TPM2_CREATE_KEYEDHASH,
            TPM2_CONTEXT_SAVE_SEEDED,
        ];
        commands.extend(
            SETUP_COMMANDS
                .iter()
                // Key generation is not something to hand the fuzzer as a
                // command it can call in a loop: the RSA primary alone costs
                // more than everything else here put together, and the keys
                // are seeded already, so replaying these buys nothing and
                // costs most of the execution rate.
                .filter(|(name, _, _)| !name.starts_with("TPM2_CreatePrimary"))
                .map(|(_, command, _)| *command),
        );
        commands
    })
}

/// Splits a `TPM2_Create` response into its `outPrivate` and `outPublic`
/// fields, both keeping the two byte size prefix that `TPM2_Load` wants.
fn split_create_response(response: &[u8]) -> Option<(&[u8], &[u8])> {
    // `TPM2_Create` is authorized, so its response is tagged TPM_ST_SESSIONS
    // and the parameters start after the header's parameterSize.
    let params = response.get(HEADER_SIZE + 4..)?;

    let size_at = |offset: usize| -> Option<usize> {
        let size = params.get(offset..offset + 2)?;
        Some(2 + u16::from_be_bytes(size.try_into().ok()?) as usize)
    };

    let private = size_at(0)?;
    let public = size_at(private)?;
    Some((
        params.get(..private)?,
        params.get(private..private + public)?,
    ))
}

/// `TPM2_Sign(SEEDED_TRANSIENT, ECDSA-SHA256)` over a fixed digest.
///
/// Used to settle the dictionary attack `daUsed` state, and to confirm the
/// seeded key is actually usable.
#[rustfmt::skip]
const TPM2_SIGN_SEEDED: &[u8] = &[
    0x80, 0x02, 0x00, 0x00, 0x00, 0x49, 0x00, 0x00, 0x01, 0x5d,
    0x80, 0x00, 0x00, 0x00, // keyHandle
    0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, // digest
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x18, 0x00, 0x0b, // inScheme = ECDSA, SHA256
    0x80, 0x24, 0x40, 0x00, 0x00, 0x07, 0x00, 0x00, // validation = null ticket
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
/// Must not be called from inside a [`with_tpm`] closure, since it reaches the
/// per-process TPM through [`with_tpm`] itself.
pub fn baseline_nvmem() -> &'static [u8] {
    static BASELINE: OnceLock<Vec<u8>> = OnceLock::new();
    BASELINE.get_or_init(|| {
        // Manufacturing the per-process TPM is what writes the blob, so go
        // through `with_tpm` rather than standing up a throwaway TPM here. Only
        // one TPM can hold the platform singleton at a time, so a throwaway
        // would panic for any caller that got here after the first `with_tpm`.
        with_tpm(|_| ());

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

        for (name, command, expected_handle) in SETUP_COMMANDS {
            let response = tpm.execute_expecting_success(command, name);
            if let Some(expected) = expected_handle {
                let handle = response
                    .get(HEADER_SIZE..HEADER_SIZE + 4)
                    .map(|h| u32::from_be_bytes(h.try_into().unwrap()));
                assert_eq!(
                    handle,
                    Some(*expected),
                    "{name} returned {handle:#x?}, but KNOWN_HANDLES says {expected:#010x}"
                );
            }
        }

        // The first authorization of a dictionary-attack protected object does
        // not run the command: it writes the `daUsed` state to NV and returns
        // TPM_RC_RETRY (SessionProcess.c). Settle that here, or every iteration
        // would spend its first authorized command on it and never reach the
        // handler behind it. The second attempt has to succeed, which also
        // confirms the seeded key works.
        let _ = tpm.execute_command(&mut TPM2_SIGN_SEEDED.to_vec());
        tpm.execute_expecting_success(TPM2_SIGN_SEEDED, "TPM2_Sign");

        // Has to happen before the snapshot: a saved context is only valid
        // against the state it was saved from, which is the state every
        // iteration rolls back to.
        let create = tpm.execute_expecting_success(TPM2_CREATE_KEYEDHASH, "TPM2_Create(keyedhash)");
        let context = tpm.execute_expecting_success(TPM2_CONTEXT_SAVE_SEEDED, "TPM2_ContextSave");

        let mut canned = Vec::new();
        if let Some((private, public)) = split_create_response(&create) {
            let mut blobs = private.to_vec();
            blobs.extend_from_slice(public);
            canned.push(build_structured_command(
                TPM_CC_LOAD,
                &[SEEDED_STORAGE_PARENT],
                Some(PASSWORD_SESSION),
                &blobs,
            ));
        }
        if let Some(context) = context.get(HEADER_SIZE..) {
            canned.push(build_structured_command(
                TPM_CC_CONTEXT_LOAD,
                &[],
                None,
                context,
            ));
        }
        assert_eq!(
            canned.len(),
            2,
            "both canned commands should have been built"
        );
        let _ = CANNED_COMMANDS.set(canned);

        tpm.snapshot = tpm.platform.save_state();

        // Everything above is only worth anything if it survives the rollback
        // that starts every iteration. `s_objects` and `s_sessions` are part of
        // the saved state, so it does - but silently losing the seeded handles
        // would cost most of the reachable command surface, so check rather
        // than assume.
        tpm.rollback();
        tpm.execute_expecting_success(TPM2_READ_PUBLIC_SEEDED, "TPM2_ReadPublic");

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
        // largest response the TPM can produce. The request buffer needs no
        // trimming: `ExecuteCommand` bounds every unmarshal by the
        // `requestSize` it was handed, and rejects a command whose header
        // declares a different size with `TPM_RC_COMMAND_SIZE` (see
        // `commandSize != requestSize` in `ExecCommand.c`), so an oversized
        // declared size can't walk off the end of `command`.
        let len = unsafe {
            self.platform
                .execute_command_unchecked(command, &mut self.response)
        };
        check_response(&self.response, len)
    }

    /// Executes a command that is expected to succeed, returning its response
    /// and panicking otherwise.
    fn execute_expecting_success(&mut self, command: &[u8], name: &str) -> Vec<u8> {
        let mut command = command.to_vec();
        let response = self
            .execute_command(&mut command)
            .unwrap_or_else(|e| panic!("{name} should be dispatchable: {e}"));
        let code = response_code(response).expect("response should have a header");
        assert_eq!(code, TPM_RC_SUCCESS, "{name} returned {code:#010x}");
        response.to_vec()
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

    /// Jumps the platform clock forward.
    ///
    /// The clock otherwise advances a millisecond per read, so anything on a
    /// realistic timeout - lockout self healing, ACT countdowns, the periodic
    /// clock update that forces an NV write - is unreachable in a fuzz run.
    pub fn advance_clock(&mut self, millis: u64) {
        CLOCK_TICKS.fetch_add(millis, Relaxed);
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

/// Builds a command out of its structural pieces: handles, an authorization
/// area, and parameters.
///
/// Getting past a command's front door needs three things a mutator will not
/// invent on its own - a well formed header, handles that name something that
/// exists, and a valid authorization area - and only the parameters are worth
/// spending fuzzing effort on. `auth` picks the tag: `Some` is
/// `TPM_ST_SESSIONS` with `auth` as the authorization area, `None` is
/// `TPM_ST_NO_SESSIONS`.
pub fn build_structured_command(
    command_code: u32,
    handles: &[u32],
    auth: Option<&[u8]>,
    params: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    for handle in handles {
        body.extend_from_slice(&handle.to_be_bytes());
    }

    let tag = match auth {
        Some(auth) => {
            body.extend_from_slice(&(auth.len() as u32).to_be_bytes());
            body.extend_from_slice(auth);
            TPM_ST_SESSIONS
        }
        None => TPM_ST_NO_SESSIONS,
    };

    body.extend_from_slice(params);
    build_command(tag, command_code, &body)
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
