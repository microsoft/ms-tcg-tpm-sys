// Copyright (C) Microsoft Corporation. All rights reserved.

//! Build script to compile the C TPM reference library.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const SYMBOL_PREFIX: &str = "ms_tcg_tpm_185_";
/// Naming convention for the platform callbacks the TPM library expects.
const PLATFORM_SYMBOL_PREFIX: &str = "_plat";

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
    let source_archives = match env("TCG_TPM_LIB_DIR") {
        Some(var) => {
            let lib_dir = PathBuf::from(var);
            println!("cargo:rerun-if-changed={}", lib_dir.display());
            let source_archives = source_archives(&lib_dir)?;
            for archive in &source_archives {
                println!("cargo:rerun-if-changed={}", archive.display());
            }
            source_archives
        }
        // Archives built in-tree live in `OUT_DIR`, and watching those would
        // make the build script rerun on every build.
        None => source_archives(&compile_tpm()?)?,
    };

    namespace_libraries(&source_archives)?;

    Ok(())
}

/// The archives the TPM build produces, in the same order as
/// [`TPM_CRYPTO_LIBRARIES`].
fn source_archives(lib_dir: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let target = std::env::var("TARGET")?;
    Ok(TPM_CRYPTO_LIBRARIES
        .iter()
        .map(|library| {
            lib_dir.join(if target.contains("windows-msvc") {
                format!("{library}.lib")
            } else {
                format!("lib{library}.a")
            })
        })
        .collect())
}

/// Compile the TPM C codebase to a statically linked set of libraries.
///
/// See `README.md` for additional info regarding supported TPM library versions
/// and crypto backends.
fn compile_tpm() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

    // Corresponds to a path within the git submodule.
    let tpm_src_dir = manifest_dir.join("TPM/TPMCmd");
    println!("cargo:rerun-if-changed={}", tpm_src_dir.display());

    let override_dir = manifest_dir.join("overrides");
    println!("cargo:rerun-if-changed={}", override_dir.display());
    let tpm_config_dir = override_dir.join("src/TpmConfiguration");

    let openssl_include_dir = PathBuf::from(
        env("DEP_OPENSSL_INCLUDE").ok_or("openssl-sys did not provide its include directory")?,
    );
    let target = std::env::var("TARGET")?;
    let mut cmake_config = cmake::Config::new(&tpm_src_dir);

    if target.contains("windows-msvc") {
        // On Windows, the TPM library's CMake build system expects the OpenSSL include
        // directory to be in a specific location.
        let tpm_openssl_include_dir = tpm_src_dir.join("OsslInclude/x64");
        copy_dir(
            &openssl_include_dir.join("openssl"),
            &tpm_openssl_include_dir.join("openssl"),
        )?;

        // MSVC looks beside final link artifacts for the PDB named by OpenSSL's objects.
        if std::env::var_os("CARGO_FEATURE_VENDORED").is_some() {
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
    }

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

    Ok(lib_dir.join("lib"))
}

/// Copy the TPM archives, prefixing every symbol with [`SYMBOL_PREFIX`].
///
/// This lets a binary link this crate alongside another copy of the TPM
/// reference code without the two sets of symbols colliding.
fn namespace_libraries(source_archives: &[PathBuf]) -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let objcopy = env("TCG_TPM_OBJCOPY").unwrap_or_else(|| default_binary_tool("objcopy"));
    let nm = env("TCG_TPM_NM").unwrap_or_else(|| default_binary_tool("nm"));
    println!("cargo:rustc-link-search=native={}", out_dir.display());

    let renames = symbol_renames(&nm, source_archives)?;
    let rename_file = out_dir.join("tpm-symbol-renames.txt");
    fs_err::write(&rename_file, renames)?;

    for (library, source_archive) in TPM_CRYPTO_LIBRARIES.iter().zip(source_archives) {
        let dest_archive = out_dir.join(source_archive.file_name().unwrap());
        let output = Command::new(&objcopy)
            .arg(format!("--redefine-syms={}", rename_file.display()))
            .arg(source_archive)
            .arg(&dest_archive)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(format!(
                "objcopy failed for {}\nstdout: {}\nstderr: {}",
                source_archive.display(),
                stdout,
                stderr
            )
            .into());
        }
        println!("cargo:rustc-link-lib=static={library}");
    }

    Ok(())
}

/// Build an `objcopy --redefine-syms` map covering the symbols the archives
/// define, plus the platform callbacks they expect Rust to provide.
fn symbol_renames(nm: &OsStr, archives: &[PathBuf]) -> Result<String, Box<dyn std::error::Error>> {
    let mut symbols = list_symbols(nm, "--defined-only", archives)?;
    // The platform callbacks are implemented in Rust, so the archives only
    // reference them.
    symbols.extend(
        list_symbols(nm, "--undefined-only", archives)?
            .into_iter()
            .filter(|symbol| symbol.starts_with(PLATFORM_SYMBOL_PREFIX)),
    );
    // Anything that isn't a C identifier is linker metadata that is matched by
    // name, such as MSVC's `@feat.00` or its COMDAT constants.
    symbols.retain(|symbol| is_c_identifier(symbol));

    let mut file = String::new();
    for symbol in symbols {
        writeln!(file, "{symbol} {SYMBOL_PREFIX}{symbol}")?;
    }
    Ok(file)
}

fn is_c_identifier(symbol: &str) -> bool {
    let mut chars = symbol.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// List the globally visible symbols in the given archives that match `filter`.
fn list_symbols(
    nm: &OsStr,
    filter: &str,
    archives: &[PathBuf],
) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let output = Command::new(nm)
        .arg(filter)
        .arg("--extern-only")
        .arg("--format=posix")
        .args(archives)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("nm failed to list TPM symbols\nstderr: {stderr}").into());
    }

    Ok(String::from_utf8(output.stdout)?
        .lines()
        .map(str::trim)
        // `<archive>[<member>]:` headers are interleaved with the symbols
        .filter(|line| !line.ends_with(':'))
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect())
}

fn default_binary_tool(tool: &str) -> OsString {
    let target = std::env::var("TARGET").unwrap();
    if target.ends_with("-msvc") || target.contains("-apple-") {
        OsString::from(format!("llvm-{tool}"))
    } else {
        OsString::from(tool)
    }
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
