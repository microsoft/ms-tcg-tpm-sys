// Copyright (C) Microsoft Corporation. All rights reserved.

//! Sample binary that uses `ms-tcg-tpm-sys` to initialize a TPM engine, send
//! a few commands to it, and persist state to an on-disk `.nvram` blob.

use ms_tcg_tpm_sys::DynResult;
use ms_tcg_tpm_sys::InitKind;
use ms_tcg_tpm_sys::MsTpm185Platform;
use ms_tcg_tpm_sys::PlatformCallbacks;
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::time::Instant;

/// Minimal callback implementation, returning fake entropy,
pub struct TestPlatformCallbacks {
    file: fs::File,
    time: Instant,
}

impl PlatformCallbacks for TestPlatformCallbacks {
    fn commit_nv_state(&mut self, state: &[u8]) -> DynResult<()> {
        tracing::info!("committing nv state with len {}", state.len());
        self.file.rewind()?;
        self.file.write_all(state)?;
        Ok(())
    }

    fn get_crypt_random(&mut self, buf: &mut [u8]) -> DynResult<usize> {
        tracing::info!("returning dummy entropy into buf of len {}", buf.len());

        if let Some(b) = buf.get_mut(0) {
            *b = 0xff;
        }

        Ok(buf.len())
    }

    fn monotonic_timer(&mut self) -> std::time::Duration {
        self.time.elapsed()
    }

    fn get_unique_value(&self) -> &'static [u8] {
        tracing::info!("fetching unique value from platform");
        b"somebody once told me the world was gonna roll me, I ain't the sharpest tool in the shed"
    }
}

const USAGE: &str = r#"
usage: test-harness <.nvmem file>
"#;
const TPM_RC_SUCCESS: u32 = 0;

fn main() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let file_path = match std::env::args().nth(1) {
        None => {
            eprintln!("{}", USAGE.trim());
            return;
        }
        Some(file_name) => std::path::PathBuf::from(file_name),
    };

    let is_cold_init = !file_path.exists();

    let mut file = if is_cold_init {
        fs::File::create(file_path).unwrap()
    } else {
        fs::OpenOptions::new()
            .write(true)
            .read(true)
            .open(file_path)
            .unwrap()
    };

    let init_kind = if is_cold_init {
        InitKind::ColdInit
    } else {
        let mut blob = Vec::new();
        file.read_to_end(&mut blob).unwrap();
        InitKind::ColdInitWithPersistentState {
            nvmem_blob: blob.into(),
        }
    };

    let mut platform = MsTpm185Platform::initialize(
        Box::new(TestPlatformCallbacks {
            file,
            time: Instant::now(),
        }),
        init_kind,
    )
    .unwrap();

    smoke_test_tpm(&mut platform);
}

fn extract_res(res: &[u8]) -> (u16, u32, String) {
    let tag = u16::from_be_bytes(res[0..2].try_into().unwrap());
    let size = u32::from_be_bytes(res[2..6].try_into().unwrap());
    let code = u32::from_be_bytes(res[6..10].try_into().unwrap());

    let mut res_str = String::new();
    for b in &res[..size as usize] {
        res_str.push_str(&format!("{:02x?}", b));
    }

    (tag, code, res_str)
}

fn send_cmd(platform: &mut MsTpm185Platform, cmd_name: &str, cmd: &mut [u8]) -> Vec<u8> {
    let mut res = vec![0; 4096];

    platform.execute_command(cmd, &mut res).unwrap();

    let (tag, code, res_str) = extract_res(&res);
    eprintln!("{cmd_name} cmd response: ({tag:04x}, {code}, \"{res_str}\")");

    if code != TPM_RC_SUCCESS {
        panic!("{cmd_name} returned non-success response code {code:#010x}");
    }

    res
}

/// Sends a few basic commands to ensure basic TPM engine functionality works.
fn smoke_test_tpm(platform: &mut MsTpm185Platform) {
    // send startup command
    let mut startup_cmd = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    send_cmd(platform, "startup", &mut startup_cmd);

    // send self test command
    let mut self_test_cmd = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x01, 0x43, 0x01,
    ];
    send_cmd(platform, "self test", &mut self_test_cmd);

    // query self-test status
    let mut test_result_cmd = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x7c];
    send_cmd(platform, "get test result", &mut test_result_cmd);

    // request random bytes
    let mut get_random_cmd = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x7b, 0x00, 0x10,
    ];
    send_cmd(platform, "get random", &mut get_random_cmd);

    // quick sanity check
    let state = platform.save_state();
    platform.restore_state(state).unwrap();

    // clear tpm hierarchy control
    let mut clear_cmd = [
        0x80, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x01, 0x21, 0x40, 0x00, 0x00, 0x0c, 0x00,
        0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
        0x0c, 0x00,
    ];
    send_cmd(platform, "clear tpm hierarchy control", &mut clear_cmd);
}
