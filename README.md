# ms-tcg-tpm-sys

Rust bindings to the
[TrustedComputingGroup/TPM](https://github.com/TrustedComputingGroup/TPM) C library.

This crate wraps the upstream C codebase, providing a callback-based "platform"
layer implemented in Rust along with a safe Rust interface for initializing the
TPM, dispatching commands, and saving / restoring runtime state.

It is intended to be used in [OpenVMM](https://github.com/microsoft/openvmm) and
some design decisions have been made with this in mind.

## Features

The following features are enabled by default:

- `openssl` - Include a dependency on `openssl-sys`, and include a link-time
  check that it is present. The currently supported crypto backend requires
  OpenSSL.

The following features are disabled by default:

- `vendored` - Compile OpenSSL from source (corresponds to`openssl-sys/vendored`).

## Building

If no pre-compiled libraries are specified by setting the `TCG_TPM_LIB_DIR`
env-var, this crate will compile `TrustedComputingGroup/TPM` from source via
CMake. So long as you have a C compiler and CMake installed, the build script
should be able to build it without issue.

When `TCG_TPM_LIB_DIR` is set, the build script will instead link against the
following pre-built static libraries from the specified directory:

- `librun_command.a` - thin wrapper around the TPM library's setjmp/longjmp
  based `RunCommand` entrypoint (built from `src/plat/RunCommand.c`).
- `libruntime_state.a` - C hooks for vTPM-style live save/restore (built from
  `overrides/src/runtime_state.c`).
- `libTpm_*.a` - libraries produced by the TPM reference library.

Building OpenSSL may be a bit more tricky. See the `openssl` crate
documentation for instructions on how to build + link against OpenSSL:
<https://docs.rs/openssl/latest/openssl/#building>

The upstream TPM source is vendored as a git submodule under `TPM/`. After
cloning, make sure to initialize submodules:

```sh
git submodule update --init --recursive
```

## Trying it out

The workspace ships with a `test-harness` binary that initializes the TPM,
sends a few commands (`TPM2_Startup`, `TPM2_SelfTest`, `TPM2_ClearControl`),
exercises live save/restore, and persists NV state to an on-disk blob:

```sh
# Cold init - manufactures a fresh nvmem blob on first run.
cargo run -p test-harness -- ./tpm.nvmem

# Subsequent runs reload the existing nvmem blob (warm restart).
cargo run -p test-harness -- ./tpm.nvmem
```

## Workspace layout

- `src/` - The `ms-tcg-tpm-sys` crate itself, containing the Rust platform layer
  and the safe wrapper around the TPM library. The `plat::api` submodule
  implements the C `_plat__*` callbacks the TPM library expects (entropy, NV
  memory, clock, PCR init, locality, physical presence, etc.).
- `src/plat/RunCommand.c` - C entrypoint that wraps the TPM library's
  `RunCommand` with setjmp/longjmp, compiled separately into `librun_command.a`.
- `overrides/src/runtime_state.c` - C hooks used to save / restore the live
  global state of the TPM library (used for vTPM-style live save/restore).
- `overrides/src/TpmConfiguration/` - Header overrides (`TpmBuildSwitches.h`,
  `TpmProfile_*.h`, `VendorCommands/`) passed to the upstream CMake build via
  `user_TpmConfiguration_Dir` to customize the TPM feature set, command list,
  and platform profile.
- `build.rs` - Build script that compiles the TPM C codebase via CMake (or
  links against pre-built libraries when `TCG_TPM_LIB_DIR` is set). The
  upstream C `Platform/` library is replaced by the Rust platform layer in
  `src/plat/`.
- `TPM/` - Git submodule pointing at upstream `TrustedComputingGroup/TPM`.
- `test-harness/` - A small sample binary that initializes the TPM, sends a
  few commands, and persists state to an on-disk `.nvmem` blob.

## Relationship to `tpm-rs`

This crate is NOT associated with the <https://github.com/tpm-rs> project.

This crate wraps the existing C-based TCG TPM codebase, only implementing the
generic "platform" layer in Rust, without porting the underlying "engine" to
Rust.

For a pure Rust implementation of the TPM 2.0 specification, see (and support!)
the effort over at <https://github.com/tpm-rs/tpm-rs>.

## Versioning

### Supported TCG TPM versions

At this time, the only supported version of `TrustedComputingGroup/TPM` that
this crate can compile + link against is v1.85 (pinned via the `TPM/`
submodule).

In the future, this crate may be updated to support compiling + linking against
alternate versions of `TrustedComputingGroup/TPM`, though at this time, there
is no concrete roadmap as to when that is going to happen.

If you are interested in extending `ms-tcg-tpm-sys` to work with multiple
alternate versions of `TrustedComputingGroup/TPM`, please feel free to reach
out by opening a GitHub Issue.

### Supported crypto backends

While the underlying `TrustedComputingGroup/TPM` library does support multiple
different crypto backends, at this time, the only supported crypto backend is
OpenSSL 3.x.

This particular backend was selected in order to seamlessly integrate
`ms-tcg-tpm-sys` into a larger codebase that was already using OpenSSL 3.x.

In the future, this crate may be updated to support linking against alternate
crypto backends, though at this time, there is no concrete roadmap as to when
that is going to happen.

If you are interested in extending `ms-tcg-tpm-sys` to work with alternate crypto
backends, please feel free to reach out by opening a GitHub Issue.

### Saved-state compatibility

`TrustedComputingGroup/TPM` makes no guarantees as to the stability of its
saved state across revisions. This applies to both volatile (in-memory), and
non-volatile (nvram) state.

As such, `ms-tcg-tpm-sys` makes the exact same guarantees wrt. saved state.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require
you to agree to a Contributor License Agreement (CLA) declaring that you have
the right to, and actually do, grant us the rights to use your contribution. For
details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether
you need to provide a CLA and decorate the PR appropriately (e.g., status check,
comment). Simply follow the instructions provided by the bot. You will only need
to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of
Conduct](https://opensource.microsoft.com/codeofconduct/). For more information
see the [Code of Conduct
FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact
[opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional
questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or
services. Authorized use of Microsoft trademarks or logos is subject to and must
follow [Microsoft's Trademark & Brand
Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must
not cause confusion or imply Microsoft sponsorship. Any use of third-party
trademarks or logos are subject to those third-party's policies.
