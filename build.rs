// Copyright (C) Microsoft Corporation. All rights reserved.

//! Build script to compile the C TPM reference library.

use backend::Backend;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = Backend::from_env()?;
    let libraries = backend.tpm_archives();

    // users can link against pre-built libs if they don't want to use the
    // version included in-tree
    let source_archives = match util::env("TCG_TPM_LIB_DIR") {
        Some(var) => {
            let lib_dir = PathBuf::from(var);
            println!("cargo:rerun-if-changed={}", lib_dir.display());
            let source_archives = tpm::source_archives(&lib_dir, libraries)?;
            for archive in &source_archives {
                println!("cargo:rerun-if-changed={}", archive.display());
            }
            source_archives
        }
        // Archives built in-tree live in `OUT_DIR`, and watching those would
        // make the build script rerun on every build.
        None => {
            let lib_dir = tpm::compile(&backend)?;
            tpm::source_archives(&lib_dir, libraries)?
        }
    };

    symbols::namespace_libraries(libraries, &source_archives)?;

    Ok(())
}

/// Which set of crypto implementations the TPM gets built against.
mod backend {
    use std::path::PathBuf;

    /// The crypto backend the `openssl` / `symcrypt` features select.
    pub(crate) enum Backend {
        OpenSsl,
        /// Where an externally built SymCrypt lives. `scripts/fetch-symcrypt.sh`
        /// stages one that satisfies this.
        SymCrypt {
            include_dir: PathBuf,
            lib_dir: PathBuf,
        },
    }

    impl Backend {
        pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
            let dir = |name: &str, backend: &str| -> Result<PathBuf, Box<dyn std::error::Error>> {
                let dir = PathBuf::from(
                    crate::util::env(name)
                        .ok_or(format!("the `{backend}` feature requires {name} to be set"))?,
                );
                if !dir.is_dir() {
                    return Err(format!("{name} ({}) is not a directory", dir.display()).into());
                }
                Ok(dir)
            };

            let openssl = std::env::var_os("CARGO_FEATURE_OPENSSL").is_some();
            let symcrypt = std::env::var_os("CARGO_FEATURE_SYMCRYPT").is_some();
            match (openssl, symcrypt) {
                (true, true) => {
                    Err("the `openssl` and `symcrypt` features are mutually exclusive".into())
                }
                (false, false) => Err(
                    "exactly one of the `openssl` or `symcrypt` features must be enabled".into(),
                ),
                (true, false) => Ok(Self::OpenSsl),
                (false, true) => Ok(Self::SymCrypt {
                    include_dir: dir("SYMCRYPT_INCLUDE_DIR", "symcrypt")?,
                    lib_dir: dir("SYMCRYPT_LIB_DIR", "symcrypt")?,
                }),
            }
        }

        /// The TPM archives to namespace and link, in link order.
        pub(crate) fn tpm_archives(&self) -> &'static [&'static str] {
            match self {
                Self::OpenSsl => super::openssl::TPM_ARCHIVES,
                Self::SymCrypt { .. } => super::symcrypt::TPM_ARCHIVES,
            }
        }
    }
}

/// The TPM reference codebase's own CMake build.
mod tpm {
    use crate::backend::Backend;
    use crate::util;
    use std::path::Path;
    use std::path::PathBuf;

    /// The archives the TPM build produces, in the same order as `libraries`.
    pub(crate) fn source_archives(
        lib_dir: &Path,
        libraries: &[&str],
    ) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
        libraries
            .iter()
            .map(|library| Ok(lib_dir.join(util::archive_file_name(library)?)))
            .collect()
    }

    /// Compile the TPM C codebase to a statically linked set of libraries.
    ///
    /// See `README.md` for additional info regarding supported TPM library
    /// versions and crypto backends.
    pub(crate) fn compile(backend: &Backend) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
        let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);

        // Corresponds to a path within the git submodule.
        let tpm_src_dir = manifest_dir.join("TPM/TPMCmd");
        println!("cargo:rerun-if-changed={}", tpm_src_dir.display());

        let override_dir = manifest_dir.join("overrides");
        println!("cargo:rerun-if-changed={}", override_dir.display());
        let tpm_config_dir = override_dir.join("src/TpmConfiguration");

        let mut cmake_config = cmake::Config::new(&tpm_src_dir);
        let lib_dir = out_dir.join("lib");
        cmake_config
            // Pin the configuration rather than letting `cmake` infer one from
            // the Cargo profile, so the archive output directory below always
            // matches.
            .profile("RelWithDebInfo")
            // We only want the core library
            .define("Tpm_BuildOption_LibOnly", "1")
            // Building `install` (or `all`) also compiles the crypto providers
            // that weren't selected, which don't necessarily compile against the
            // selected ones. Build just what `Tpm_CoreLib` pulls in, and collect
            // the archives in one place since nothing gets installed.
            .build_target("Tpm_CoreLib")
            .define("CMAKE_ARCHIVE_OUTPUT_DIRECTORY", &lib_dir)
            // Multi-config generators otherwise append the config name.
            .define("CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO", &lib_dir)
            .define("user_TpmConfiguration_Dir", &tpm_config_dir);

        if util::is_windows_msvc()? {
            // Fix CRT mismatch warnings
            cmake_config.define("CMAKE_MSVC_RUNTIME_LIBRARY", "MultiThreadedDLL");
        }

        match backend {
            Backend::OpenSsl => {
                crate::openssl::configure(&mut cmake_config, &tpm_src_dir, &out_dir)?;
            }
            Backend::SymCrypt {
                include_dir,
                lib_dir,
            } => {
                // SymCrypt doesn't cover every role yet, so it layers over the OpenSSL
                // selections instead of replacing them.
                crate::openssl::configure(&mut cmake_config, &tpm_src_dir, &out_dir)?;
                crate::symcrypt::configure(&mut cmake_config, include_dir, lib_dir)?;
            }
        }

        cmake_config.build();

        Ok(lib_dir)
    }
}

/// Everything specific to the OpenSSL crypto backend.
mod openssl {
    use crate::util;
    use std::path::Path;
    use std::path::PathBuf;

    fn validate_version() -> Result<(), Box<dyn std::error::Error>> {
        const MIN_OPENSSL_VERSION: u64 = 0x3050_0000;
        let openssl_version = util::env("DEP_OPENSSL_VERSION_NUMBER")
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

    /// Point the TPM build at the OpenSSL that `openssl-sys` resolved.
    pub(crate) fn configure(
        cmake_config: &mut cmake::Config,
        tpm_src_dir: &Path,
        out_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        validate_version()?;

        let include_dir = PathBuf::from(
            util::env("DEP_OPENSSL_INCLUDE")
                .ok_or("openssl-sys did not provide its include directory")?,
        );

        if util::is_windows_msvc()? {
            // On Windows, the TPM library's CMake build system expects the
            // OpenSSL include directory to be in a specific location.
            util::copy_dir(
                &include_dir.join("openssl"),
                &tpm_src_dir.join("OsslInclude/x64/openssl"),
            )?;

            // MSVC looks beside final link artifacts for the PDB named by OpenSSL's objects.
            if std::env::var_os("CARGO_FEATURE_VENDORED").is_some() {
                let install_dir = include_dir
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
                    install_dir.join("lib/ossl_static.pdb"),
                    deps_dir.join("ossl_static.pdb"),
                )?;
            }
        }

        cmake_config
            .define("OSSL_INCLUDE_SUBDIR", &include_dir)
            .define("CMAKE_C_STANDARD_INCLUDE_DIRECTORIES", &include_dir)
            .define("cryptoLib_Symmetric", "Ossl")
            .define("cryptoLib_Hash", "Ossl")
            .define("cryptoLib_Random", "RandRef")
            .define("cryptoLib_Kdf", "KdfRef")
            .define("cryptoLib_Math", "TpmBigNum")
            .define("cryptoLib_BnMath", "Ossl")
            .define("cryptoLib_RSA", "RsaRef")
            .define("cryptoLib_ECC", "EccRef")
            .define("cryptoLib_MLKEM", "Ossl")
            .define("cryptoLib_MLDSA", "Ossl")
            .register_dep("openssl");

        Ok(())
    }

    /// The TPM archives the OpenSSL backend produces, in link order.
    pub(crate) const TPM_ARCHIVES: &[&str] = &[
        "Tpm_CoreLib",
        "Tpm_CryptoLib_Random_RandRef",
        "Tpm_CryptoLib_Kdf_KdfRef",
        "Tpm_CryptoLib_Math_TpmBigNum",
        "Tpm_CryptoLib_BnMath_Ossl",
        "Tpm_CryptoLib_RSA_RsaRef",
        "Tpm_CryptoLib_ECC_EccRef",
        "Tpm_CryptoLib_MLKEM_Ossl",
        "Tpm_CryptoLib_MLDSA_Ossl",
        "Tpm_CryptoLib_Common",
    ];
}

/// Everything specific to the SymCrypt crypto backend.
mod symcrypt {
    use crate::util;
    use std::path::Path;
    use std::path::PathBuf;

    /// The prebuilt archive `SYMCRYPT_LIB_DIR` is expected to contain.
    pub(crate) fn archive(lib_dir: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        Ok(lib_dir.join(util::archive_file_name("symcrypt")?))
    }

    /// Point the TPM build at the prebuilt SymCrypt.
    pub(crate) fn configure(
        cmake_config: &mut cmake::Config,
        include_dir: &Path,
        lib_dir: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Tell Cargo about the external SymCrypt.
        println!("cargo:rerun-if-changed={}", archive(lib_dir)?.display());
        println!("cargo:rustc-link-search=native={}", lib_dir.display());

        // The TPM's build expects SymCrypt's split `symcrypt_common` /
        // `symcrypt_generic` archives, so pre-seed the cache entries its
        // `find_library` calls populate to accept a single merged archive.
        let archive = archive(lib_dir)?;
        cmake_config
            .define("SYMCRYPT_INCLUDE_DIR", include_dir)
            .define("SYMCRYPT_LIB_DIR", lib_dir)
            .define("SYMCRYPT_COMMON_LIB", &archive)
            .define("cryptoLib_Symmetric", "SymCrypt")
            .define("cryptoLib_Hash", "SymCrypt")
            .define("cryptoLib_Random", "RandRef")
            .define("cryptoLib_Kdf", "KdfRef")
            .define("cryptoLib_Math", "TpmBigNum")
            .define("cryptoLib_BnMath", "SymCrypt")
            .define("cryptoLib_RSA", "SymCrypt")
            .define("cryptoLib_ECC", "EccRef")
            .define("cryptoLib_MLKEM", "Ossl")
            .define("cryptoLib_MLDSA", "Ossl");

        Ok(())
    }

    /// The TPM archives the SymCrypt backend produces, in link order.
    pub(crate) const TPM_ARCHIVES: &[&str] = &[
        "Tpm_CoreLib",
        "Tpm_CryptoLib_Symmetric_SymCrypt",
        "Tpm_CryptoLib_Hash_SymCrypt",
        "Tpm_CryptoLib_Random_RandRef",
        "Tpm_CryptoLib_Kdf_KdfRef",
        "Tpm_CryptoLib_Math_TpmBigNum",
        "Tpm_CryptoLib_BnMath_SymCrypt",
        "Tpm_CryptoLib_RSA_SymCrypt",
        "Tpm_CryptoLib_ECC_EccRef",
        "Tpm_CryptoLib_MLKEM_Ossl",
        "Tpm_CryptoLib_MLDSA_Ossl",
        "Tpm_CryptoLib_SymCrypt_Common",
        "Tpm_CryptoLib_Common",
    ];
}

/// Prefixing the TPM's symbols so a binary can link this crate alongside
/// another copy of the reference code.
mod symbols {
    use crate::util;
    use std::collections::BTreeSet;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::fmt::Write as _;
    use std::path::PathBuf;
    use std::process::Command;

    const SYMBOL_PREFIX: &str = "ms_tcg_tpm_185_";
    /// Naming convention for the platform callbacks the TPM library expects.
    const PLATFORM_SYMBOL_PREFIX: &str = "_plat";

    /// Copy the TPM archives, prefixing every symbol with [`SYMBOL_PREFIX`].
    pub(crate) fn namespace_libraries(
        libraries: &[&str],
        source_archives: &[PathBuf],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
        let objcopy = util::env("TCG_TPM_OBJCOPY").unwrap_or_else(|| default_tool("objcopy"));
        let nm = util::env("TCG_TPM_NM").unwrap_or_else(|| default_tool("nm"));
        println!("cargo:rustc-link-search=native={}", out_dir.display());

        let renames = renames(&nm, source_archives)?;
        let rename_file = out_dir.join("tpm-symbol-renames.txt");
        fs_err::write(&rename_file, renames)?;

        for (library, source_archive) in libraries.iter().zip(source_archives) {
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
    fn renames(nm: &OsStr, archives: &[PathBuf]) -> Result<String, Box<dyn std::error::Error>> {
        let mut symbols = list(nm, "--defined-only", archives)?;
        // The platform callbacks are implemented in Rust, so the archives only
        // reference them.
        symbols.extend(
            list(nm, "--undefined-only", archives)?
                .into_iter()
                .filter(|symbol| symbol.starts_with(PLATFORM_SYMBOL_PREFIX)),
        );
        // Anything that isn't a C identifier is linker metadata that is matched
        // by name, such as MSVC's `@feat.00` or its COMDAT constants.
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

    /// List the globally visible symbols in the given archives that match
    /// `filter`.
    fn list(
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

    fn default_tool(tool: &str) -> OsString {
        let target = std::env::var("TARGET").unwrap();
        if target.ends_with("-msvc") || target.contains("-apple-") {
            OsString::from(format!("llvm-{tool}"))
        } else {
            OsString::from(tool)
        }
    }
}

/// Environment and filesystem odds and ends shared by the rest of the script.
mod util {
    use std::ffi::OsString;
    use std::path::Path;

    pub(crate) fn is_windows_msvc() -> Result<bool, Box<dyn std::error::Error>> {
        Ok(std::env::var("TARGET")?.contains("windows-msvc"))
    }

    /// The file name a static library lands in for the target.
    pub(crate) fn archive_file_name(library: &str) -> Result<String, Box<dyn std::error::Error>> {
        Ok(if is_windows_msvc()? {
            format!("{library}.lib")
        } else {
            format!("lib{library}.a")
        })
    }

    pub(crate) fn copy_dir(
        source: &Path,
        destination: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    /// Read a environment variable that may / may-not have a target-specific
    /// prefix. e.g: `env("FOO")` would first try and read from
    /// `X86_64_UNKNOWN_LINUX_GNU_FOO`, and then fall back to just `FOO`.
    // yoinked from openssl-sys/build/main.rs
    pub(crate) fn env(name: &str) -> Option<OsString> {
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
}
