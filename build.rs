// Copyright (C) Microsoft Corporation. All rights reserved.

//! Build script to compile the C TPM reference library.

use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;

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
    validate_openssl_version()?;

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

    // Corresponds to a path within the git submodule.
    let tpm_src_dir = manifest_dir.join("TPM/TPMCmd");
    println!("cargo:rerun-if-changed={}", tpm_src_dir.display());

    let override_dir = manifest_dir.join("overrides");
    println!("cargo:rerun-if-changed={}", override_dir.display());
    let tpm_config_dir = override_dir.join("src/TpmConfiguration");

    let openssl_include_dir = PathBuf::from(
        env("DEP_OPENSSL_INCLUDE").ok_or("openssl-sys did not provide its include directory")?,
    );
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let target = std::env::var("TARGET")?;
    let mut cmake_config = cmake::Config::new(&tpm_src_dir);

    // On Windows, the TPM library's CMake build system expects the OpenSSL include
    // directory to be in a specific location.
    let (archive_prefix, archive_extension) = if target.contains("windows-msvc") {
        let tpm_openssl_include_dir = tpm_src_dir.join("OsslInclude/x64");
        copy_dir(
            &openssl_include_dir.join("openssl"),
            &tpm_openssl_include_dir.join("openssl"),
        )?;

        if std::env::var_os("CARGO_FEATURE_VENDORED").is_some() {
            // MSVC looks beside final link artifacts for the PDB named by OpenSSL's objects.
            let openssl_install_dir = openssl_include_dir
                .parent()
                .ok_or("OpenSSL include directory has no parent")?;
            let profile_dir = out_dir
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or("Cargo OUT_DIR is not inside a profile build directory")?;
            let deps_dir = profile_dir.join("deps");
            fs_err::create_dir_all(&deps_dir)?;
            fs_err::copy(
                openssl_install_dir.join("lib/ossl_static.pdb"),
                deps_dir.join("ossl_static.pdb"),
            )?;
        }

        // Fix CRT mismatch warnings
        cmake_config.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreadedDLL");

        ("", "lib")
    } else {
        ("lib", "a")
    };

    let lib_dir = cmake_config
        // We only want the core library
        .define("Tpm_BuildOption_LibOnly", "1")
        .define("TPM_SOURCE_DIR", &tpm_src_dir)
        .define("OSSL_INCLUDE_SUBDIR", &openssl_include_dir)
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

    for library in TPM_CRYPTO_LIBRARIES {
        let archive = format!("{archive_prefix}{library}.{archive_extension}");
        fs_err::copy(lib_dir.join("lib").join(&archive), out_dir.join(archive))?;
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());

    Ok(())
}

fn copy_dir(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs_err::create_dir_all(destination)?;

    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let destination_path = destination.join(entry.file_name());
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            copy_dir(&entry.path(), &destination_path)?;
        } else if file_type.is_file() {
            fs_err::copy(entry.path(), destination_path)?;
        }
    }
    Ok(())
}

fn validate_openssl_version() -> Result<(), Box<dyn std::error::Error>> {
    const MIN_OPENSSL_VERSION: u64 = 0x3050_0000;
    let openssl_version = env("DEP_OPENSSL_VERSION_NUMBER")
        .and_then(|value| value.into_string().ok())
        .and_then(|value| u64::from_str_radix(&value, 16).ok())
        .ok_or("openssl-sys did not provide a valid OpenSSL version")?;
    if openssl_version < MIN_OPENSSL_VERSION {
        return Err(format!(
            "OpenSSL 3.5 or newer is required by the enabled ML-KEM and ML-DSA profile (found {openssl_version:x})"
        )
        .into());
    }

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
