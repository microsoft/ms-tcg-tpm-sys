// Copyright (C) Microsoft Corporation. All rights reserved.

//! Build script to compile the C TPM reference library.

use std::ffi::OsString;
use std::path::PathBuf;

// corresponds to path within git submodule.
const SRC_PATH: &str = "./TPM/TPMCmd/";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // users can link against pre-built libs if they don't want to use the
    // version included in-tree
    match env("TCG_TPM_LIB_DIR") {
        Some(var) => {
            println!("cargo:rustc-link-search=native={}", var.to_string_lossy());
            println!("cargo:rustc-link-lib=static=run_command");
            println!("cargo:rustc-link-lib=static=Tpm_CoreLib");
            println!("cargo:rustc-link-lib=static=Tpm_CryptoLib_Math_Ossl");
            println!("cargo:rustc-link-lib=static=Tpm_CryptoLib_TpmBigNum");
            return Ok(());
        }
        None => compile_tpm()?,
    }

    Ok(())
}

/// Compile the TPM C codebase to a statically linked `libTpm_CoreLib.a`.
///
/// See `README.md` for additional info regarding supported TPM library versions
/// and crypto backends.
fn compile_tpm() -> Result<(), Box<dyn std::error::Error>> {
    // `RunCommand.c` contains setjmp/longjmp code, and must be compiled in
    // separately. The non-longjmp mode of the TPM is not fully tested, so we
    // rely on the longjmp mode.
    // TODO: enable this in configuration
    cc::Build::new()
        .file("./src/plat/RunCommand.c")
        .compile("run_command");

    // TODO: Inject runtime_state
    let lib_dir = cmake::Config::new(SRC_PATH)
        // We only want the core library
        .define("Tpm_BuildOption_LibOnly", "1")
        // Set crypto backend
        .define("cryptoLib_Symmetric", "Ossl")
        .define("cryptoLib_Hash", "Ossl")
        .define("cryptoLib_BnMath", "Ossl")
        .define("cryptoLib_Math", "TpmBigNum")
        .register_dep("openssl")
        // TODO Create configuration and set user_TpmConfiguration_Dir
        .build();

    // .define("MANUFACTURER", r#""MSFT""#)
    // .define("VENDOR_STRING_1", r#""TPM ""#)
    // .define("VENDOR_STRING_2", r#""Simu""#)
    // .define("VENDOR_STRING_3", r#""lato""#)
    // .define("VENDOR_STRING_4", r#""r   ""#)
    // .define("FIRMWARE_V1", "0x20200312")
    // .define("FIRMWARE_V2", "0x00120003")
    // .define("NV_MEMORY_SIZE", "0x8000")

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::copy(
        lib_dir.join("lib").join("libTpm_CoreLib.a"),
        out_dir.join("libTpm_CoreLib.a"),
    )
    .unwrap();
    std::fs::copy(
        lib_dir.join("lib").join("libTpm_CryptoLib_Math_Ossl.a"),
        out_dir.join("libTpm_CryptoLib_Math_Ossl.a"),
    )
    .unwrap();
    std::fs::copy(
        lib_dir.join("lib").join("libTpm_CryptoLib_TpmBigNum.a"),
        out_dir.join("libTpm_CryptoLib_TpmBigNum.a"),
    )
    .unwrap();

    // Cargo will pick up libTpm_CoreLib and librun_command because we have functions with
    // the `#[link(name = "...")]` attribute. However it won't pick up these automatically.
    println!("cargo:rustc-link-lib=static=Tpm_CryptoLib_Math_Ossl");
    println!("cargo:rustc-link-lib=static=Tpm_CryptoLib_TpmBigNum");

    Ok(())
}

/// Read a environment variable that may / may-not have a target-specific
/// prefix. e.g: `env("FOO")` would first try and read from
/// `X86_64_UNKNOWN_LINUX_GNU_FOO`, and then fall back to just `FOO`.
// yoinked from openssl-sys/build/main.rs
fn env(name: &str) -> Option<OsString> {
    fn env_inner(name: &str) -> Option<OsString> {
        let var = std::env::var_os(name);
        println!("cargo:rerun-if-env-changed={}", name);

        match var {
            Some(ref v) => println!("{} = {}", name, v.to_string_lossy()),
            None => println!("{} unset", name),
        }

        var
    }

    let prefix = std::env::var("TARGET")
        .unwrap()
        .to_uppercase()
        .replace('-', "_");
    let prefixed = format!("{}_{}", prefix, name);
    env_inner(&prefixed).or_else(|| env_inner(name))
}
