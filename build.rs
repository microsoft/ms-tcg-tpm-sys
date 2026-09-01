// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

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
            fuzzing::warn_if_prebuilt();
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
    /// The crypto backend the `openssl` / `symcrypt` features select.
    pub(crate) enum Backend {
        OpenSsl,
        /// Where an externally built SymCrypt lives. `scripts/fetch-symcrypt.sh`
        /// stages one that satisfies this.
        SymCrypt,
    }

    impl Backend {
        pub(crate) fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
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
                (false, true) => Ok(Self::SymCrypt),
            }
        }

        /// The TPM archives to namespace and link, in link order.
        pub(crate) fn tpm_archives(&self) -> &'static [&'static str] {
            match self {
                Self::OpenSsl => super::openssl::TPM_ARCHIVES,
                Self::SymCrypt => super::symcrypt::TPM_ARCHIVES,
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

        crate::fuzzing::configure(&mut cmake_config)?;

        match backend {
            Backend::OpenSsl => {
                crate::openssl::configure(&mut cmake_config, &tpm_src_dir, &out_dir)?;
            }
            Backend::SymCrypt => {
                // SymCrypt doesn't cover every role yet, so it layers over the OpenSSL
                // selections instead of replacing them.
                crate::openssl::configure(&mut cmake_config, &tpm_src_dir, &out_dir)?;
                crate::symcrypt::configure(&mut cmake_config)?;
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
        // These two are folded into BnMath_Ossl
        //"Tpm_CryptoLib_Symmetric_Ossl",
        //"Tpm_CryptoLib_Hash_Ossl",
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
    use std::path::PathBuf;

    /// Point the TPM build at the prebuilt SymCrypt.
    pub(crate) fn configure(
        cmake_config: &mut cmake::Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = |name: &str| -> Result<PathBuf, Box<dyn std::error::Error>> {
            util::env_dir(name)?.ok_or_else(|| {
                format!("building the TPM against SymCrypt requires {name} to be set").into()
            })
        };
        let include_dir = dir("SYMCRYPT_INCLUDE_DIR")?;
        let lib_dir = dir("SYMCRYPT_LIB_DIR")?;

        // Tell Cargo about the external SymCrypt.
        let archive = lib_dir.join(util::archive_file_name("symcrypt")?);
        println!("cargo:rerun-if-changed={}", archive.display());
        println!("cargo:rustc-link-search=native={}", lib_dir.display());

        // The TPM's build expects SymCrypt's split `symcrypt_common` /
        // `symcrypt_generic` archives, so pre-seed the cache entries its
        // `find_library` calls populate to accept a single merged archive.
        cmake_config
            .define("SYMCRYPT_INCLUDE_DIR", &include_dir)
            .define("SYMCRYPT_LIB_DIR", &lib_dir)
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

/// Instrumenting the TPM's C code when this crate is built for a fuzzer.
mod fuzzing {
    use crate::util;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;

    /// Whether Cargo is building this crate for a fuzzer.
    ///
    /// `cargo fuzz` puts `--cfg fuzzing` in `RUSTFLAGS`, which Cargo surfaces
    /// to build scripts as this variable.
    fn enabled() -> bool {
        println!("cargo:rerun-if-env-changed=CARGO_CFG_FUZZING");
        std::env::var_os("CARGO_CFG_FUZZING").is_some()
    }

    /// Instrument the TPM build to match how Cargo is building the Rust side.
    ///
    /// Rust's `-Zsanitizer` and libFuzzer's coverage instrumentation only cover
    /// Rust code, which for this crate is a thin wrapper around the C library
    /// that does the actual work. Left uninstrumented, the fuzzer would be
    /// driving the code that parses commands blind, and AddressSanitizer would
    /// only see what its allocator interceptors catch rather than the memory
    /// errors inside that code.
    pub(crate) fn configure(
        cmake_config: &mut cmake::Config,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !enabled() {
            return Ok(());
        }

        // An explicitly empty value opts out of instrumenting the C code.
        let flags = match util::env("TCG_TPM_FUZZ_CFLAGS") {
            Some(flags) => flags,
            None => default_flags(),
        };
        let flags: Vec<&OsStr> = flags
            .to_str()
            .ok_or("TCG_TPM_FUZZ_CFLAGS is not valid UTF-8")?
            .split_whitespace()
            .map(OsStr::new)
            .collect();
        if flags.is_empty() {
            return Ok(());
        }

        if let Some(compiler) = compiler()? {
            drop_stale_cmake_cache(&compiler)?;
            cmake_config.define("CMAKE_C_COMPILER", &compiler);
        }

        for flag in flags {
            cmake_config.cflag(flag);
        }

        Ok(())
    }

    /// CMake refuses to reconfigure an existing build tree with a different
    /// compiler, which would turn something as ordinary as installing a newer
    /// clang into a confusing build failure. Drop the cache so that CMake
    /// configures from scratch instead.
    fn drop_stale_cmake_cache(compiler: &Path) -> Result<(), Box<dyn std::error::Error>> {
        // Where `cmake::Config` puts the build tree, given it inherits `OUT_DIR`.
        let cache = PathBuf::from(std::env::var("OUT_DIR")?).join("build/CMakeCache.txt");
        let Ok(contents) = fs_err::read_to_string(&cache) else {
            return Ok(());
        };

        let cached = contents.lines().find_map(|line| {
            line.strip_prefix("CMAKE_C_COMPILER:")?
                .split_once('=')
                .map(|(_, value)| Path::new(value))
        });

        if cached.is_some_and(|cached| cached != compiler) {
            fs_err::remove_file(&cache)?;
        }

        Ok(())
    }

    /// Warn that `TCG_TPM_LIB_DIR` libraries are used as-is, since whoever
    /// built them is the one who decides whether they're instrumented.
    pub(crate) fn warn_if_prebuilt() {
        if enabled() {
            println!(
                "cargo:warning=fuzzing against the pre-built TPM libraries in TCG_TPM_LIB_DIR; \
                 unless they were built with sanitizer and coverage instrumentation, the fuzzer \
                 will not see inside them"
            );
        }
    }

    /// The instrumentation to build the TPM with, mirroring what `cargo fuzz`
    /// asks `rustc` for.
    fn default_flags() -> OsString {
        // Gives the C code the SanitizerCoverage instrumentation libFuzzer
        // needs, without letting clang link in a `main` of its own.
        let mut flags = String::from("-fsanitize=fuzzer-no-link");

        // `-Zsanitizer=...` reaches build scripts as this variable, already
        // comma-separated the way clang wants it.
        println!("cargo:rerun-if-env-changed=CARGO_CFG_SANITIZE");
        if let Some(sanitizers) = std::env::var_os("CARGO_CFG_SANITIZE")
            && !sanitizers.is_empty()
        {
            flags.push_str(" -fsanitize=");
            flags.push_str(&sanitizers.to_string_lossy());
        }

        flags.into()
    }

    /// The compiler to build the instrumented TPM with, or `None` to keep the
    /// one the build is already configured to use.
    ///
    /// The flags above are clang-only: GCC has no `-fsanitize=fuzzer-no-link`,
    /// and the `-fsanitize-coverage=trace-pc` scheme it does support was
    /// removed from libFuzzer.
    fn compiler() -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
        if let Some(compiler) = util::env("TCG_TPM_FUZZ_CC") {
            return Ok(Some(PathBuf::from(compiler)));
        }

        // Leave an already-clang compiler (and anything the caller pointed `CC`
        // at) alone, so cross-compilation setups keep working.
        if cc::Build::new().try_get_compiler()?.is_like_clang() {
            return Ok(None);
        }

        let clang = find_clang().ok_or(
            "fuzzing needs clang to instrument the TPM's C code, but none was found on PATH. \
             Install clang, or point TCG_TPM_FUZZ_CC at one. To fuzz without instrumenting the \
             C code - which leaves the fuzzer blind to the code that parses TPM commands - set \
             TCG_TPM_FUZZ_CFLAGS to an empty value.",
        )?;

        Ok(Some(clang))
    }

    /// Look for clang on `PATH`.
    fn find_clang() -> Option<PathBuf> {
        // clang-cl is the driver that understands MSVC's command line.
        let stem = if util::is_windows_msvc().ok()? {
            "clang-cl"
        } else {
            "clang"
        };

        let path = std::env::var_os("PATH")?;
        let mut newest: Option<(u32, PathBuf)> = None;

        for dir in std::env::split_paths(&path) {
            let unversioned = dir.join(format!("{stem}{}", std::env::consts::EXE_SUFFIX));
            if unversioned.is_file() {
                return Some(unversioned);
            }

            // Debian and its derivatives only ship versioned binaries unless
            // the `clang` metapackage is installed, so fall back to the newest
            // version that is installed.
            let Ok(entries) = fs_err::read_dir(&dir) else {
                continue;
            };

            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                let name = name
                    .strip_suffix(std::env::consts::EXE_SUFFIX)
                    .unwrap_or(name);

                let Some(version) = name
                    .strip_prefix(stem)
                    .and_then(|version| version.strip_prefix('-'))
                    .and_then(|version| version.parse::<u32>().ok())
                else {
                    continue;
                };

                if newest.as_ref().is_none_or(|(newest, _)| version > *newest) {
                    newest = Some((version, entry.path()));
                }
            }
        }

        newest.map(|(_, path)| path)
    }
}

/// Environment and filesystem odds and ends shared by the rest of the script.
mod util {
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;

    pub(crate) fn is_windows_msvc() -> Result<bool, Box<dyn std::error::Error>> {
        Ok(std::env::var("TARGET")?.contains("windows-msvc"))
    }

    /// Read an environment variable naming a directory that must exist if the
    /// variable is set at all.
    pub(crate) fn env_dir(name: &str) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
        let Some(value) = env(name) else {
            return Ok(None);
        };

        let dir = PathBuf::from(value);
        if !dir.is_dir() {
            return Err(format!("{name} ({}) is not a directory", dir.display()).into());
        }

        Ok(Some(dir))
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
