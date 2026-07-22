// Copyright (C) Microsoft Corporation. All rights reserved.

//! Build script to compile the C TPM reference library.

use std::ffi::OsString;
use std::path::PathBuf;

// corresponds to path within git submodule.
const SRC_PATH: &str = "./TPM/TPMCmd/";

const TPM_CRYPTO_LIBRARIES: &[&str] = &[
    "Tpm_CoreLib",
    "Tpm_CryptoLib_BnMath_Ossl",
    "Tpm_CryptoLib_Symmetric_Ossl",
    "Tpm_CryptoLib_Random_RandRef",
    "Tpm_CryptoLib_Kdf_KdfRef",
    "Tpm_CryptoLib_Math_TpmBigNum",
    "Tpm_CryptoLib_RSA_RsaRef",
    "Tpm_CryptoLib_ECC_EccRef",
    "Tpm_CryptoLib_MLKEM_Ossl",
    "Tpm_CryptoLib_MLDSA_Ossl",
    "Tpm_CryptoLib_Common",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // users can link against pre-built libs if they don't want to use the
    // version included in-tree
    match env("TCG_TPM_LIB_DIR") {
        Some(var) => {
            println!("cargo:rustc-link-search=native={}", var.to_string_lossy());
        }
        None => compile_tpm()?,
    }

    for library in TPM_CRYPTO_LIBRARIES {
        println!("cargo:rustc-link-lib=static={library}");
    }

    Ok(())
}

/// Compile the TPM C codebase to a statically linked set of libraries.
///
/// See `README.md` for additional info regarding supported TPM library versions
/// and crypto backends.
fn compile_tpm() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());

    let tpm_config_dir = manifest_dir.join("overrides/src/TpmConfiguration");
    println!("cargo:rerun-if-changed={}", tpm_config_dir.display());
    println!("cargo:rerun-if-changed={}", SRC_PATH);

    // `runtime_state.c` reads/writes the TPM library's static globals to
    // implement hot save/restore. Its compilation is included in the cmake build,
    // but we need to tell cargo to re-run the build script if it changes.
    let runtime_state_path = manifest_dir.join("overrides/src/runtime_state.c");
    println!("cargo:rerun-if-changed={}", runtime_state_path.display());

    let openssl_include_dir = PathBuf::from(
        env("DEP_OPENSSL_INCLUDE").ok_or("openssl-sys did not provide its include directory")?,
    );

    let lib_dir = cmake::Config::new(SRC_PATH)
        // We only want the core library
        .define("Tpm_BuildOption_LibOnly", "1")
        .define("CMAKE_C_STANDARD_INCLUDE_DIRECTORIES", &openssl_include_dir)
        .define("SYMCRYPT_INCLUDE_DIR", "foo")
        .define("SYMCRYPT_LIB_DIR", "foo")
        // Set crypto backend
        .define("cryptoLib_Symmetric", "Ossl")
        .define("cryptoLib_Hash", "Ossl")
        .define("cryptoLib_BnMath", "Ossl")
        .define("cryptoLib_Math", "TpmBigNum")
        .define("cryptoLib_RSA", "RsaRef")
        .define("cryptoLib_ECC", "EccRef")
        .register_dep("openssl")
        .define("user_TpmConfiguration_Dir", &tpm_config_dir)
        .build();

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    for library in TPM_CRYPTO_LIBRARIES {
        let archive = format!("lib{library}.a");
        fs_err::copy(lib_dir.join("lib").join(&archive), out_dir.join(archive))?;
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());

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
