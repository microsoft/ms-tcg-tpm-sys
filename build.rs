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

/// Compile the TPM C codebase to a statically linked set of libraries.
///
/// See `README.md` for additional info regarding supported TPM library versions
/// and crypto backends.
fn compile_tpm() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    // `RunCommand.c` contains setjmp/longjmp code, and must be compiled in
    // separately. The non-longjmp mode of the TPM is not fully tested, so we
    // rely on the longjmp mode.
    let run_command_path = manifest_dir.join("src/plat/RunCommand.c");
    cc::Build::new()
        .file(&run_command_path)
        .compile("run_command");

    let tpm_config_dir = manifest_dir.join("overrides/src/TpmConfiguration");
    println!("cargo:rerun-if-changed={}", tpm_config_dir.display());
    println!("cargo:rerun-if-changed={}", SRC_PATH);

    // `runtime_state.c` reads/writes the TPM library's static globals to
    // implement hot save/restore. It must be compiled with the exact same
    // include paths as the core library, so the struct layouts match.
    let tpm_src_root = manifest_dir.join(SRC_PATH).join("tpm");
    let runtime_state_path = manifest_dir.join("overrides/src/runtime_state.c");

    cc::Build::new()
        .file(&runtime_state_path)
        .include(tpm_src_root.join("include"))
        .include(tpm_src_root.join("include/private"))
        .include(tpm_src_root.join("include/private/prototypes"))
        .include(tpm_src_root.join("include/platform_interface/Tpm_Platform_Interface"))
        .include(tpm_src_root.join("include/platform_interface/Tpm_Platform_Interface/prototypes"))
        .include(tpm_src_root.join("cryptolibs/TpmBigNum/include"))
        .include(tpm_src_root.join("cryptolibs/common/include"))
        .include(tpm_src_root.join("cryptolibs/Ossl/include"))
        .include(&tpm_config_dir)
        .define("BN_MATH_LIB", "Ossl")
        .define("HASH_LIB", "Ossl")
        .define("MATH_LIB", "TpmBigNum")
        .define("SYM_LIB", "Ossl")
        .compile("runtime_state");

    // The TPM submodule has a version check for OpenSSL <= 3.6.0, however
    // 3.6.* is compatible with its requirements, so we relax the version check.
    let ossl_compat = manifest_dir.join("overrides/src/ossl_version_compat.h");
    println!("cargo:rerun-if-changed={}", ossl_compat.display());
    let ossl_version_override = if std::env::var("CARGO_CFG_TARGET_ENV").unwrap() == "msvc" {
        format!("/FI{}", ossl_compat.display())
    } else {
        format!("-include {}", ossl_compat.display())
    };

    let lib_dir = cmake::Config::new(SRC_PATH)
        // We only want the core library
        .define("Tpm_BuildOption_LibOnly", "1")
        // Set crypto backend
        .define("cryptoLib_Symmetric", "Ossl")
        .define("cryptoLib_Hash", "Ossl")
        .define("cryptoLib_BnMath", "Ossl")
        .define("cryptoLib_Math", "TpmBigNum")
        .register_dep("openssl")
        .cflag(ossl_version_override)
        .define("user_TpmConfiguration_Dir", tpm_config_dir)
        .build();

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    fs_err::copy(
        lib_dir.join("lib").join("libTpm_CoreLib.a"),
        out_dir.join("libTpm_CoreLib.a"),
    )
    .unwrap();
    fs_err::copy(
        lib_dir.join("lib").join("libTpm_CryptoLib_Math_Ossl.a"),
        out_dir.join("libTpm_CryptoLib_Math_Ossl.a"),
    )
    .unwrap();
    fs_err::copy(
        lib_dir.join("lib").join("libTpm_CryptoLib_TpmBigNum.a"),
        out_dir.join("libTpm_CryptoLib_TpmBigNum.a"),
    )
    .unwrap();

    // Cargo will pick up some static libraries because we have functions with
    // the `#[link(name = "...")]` attribute. However it won't pick up these.
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
