# Fuzzing `ms-tcg-tpm-sys`

[`cargo-fuzz`](https://rust-fuzz.github.io/book/cargo-fuzz.html) targets for the
crate's untrusted-input boundaries: the TPM command stream, saved-state blobs,
and persisted nvmem blobs.

## Running

```sh
cargo install cargo-fuzz
rustup toolchain install nightly

# Fuzz until interrupted.
cargo +nightly fuzz run fuzz_tpm

# Anything after `--` goes to libFuzzer.
cargo +nightly fuzz run fuzz_tpm -- -max_total_time=600 -dict=fuzz/tpm.dict
cargo +nightly fuzz run fuzz_tpm_session -- -runs=100000
```

The `fuzz_tpm` seed corpus is checked in, and `cargo fuzz` doesn't pick it up on
its own, so pass it as a second, read-only corpus to start from real commands
rather than random bytes. libFuzzer writes new inputs to the first directory it
is given and requires it to already exist:

```sh
mkdir -p fuzz/corpus/fuzz_tpm
cargo +nightly fuzz run fuzz_tpm fuzz/corpus/fuzz_tpm fuzz/seed_corpus/fuzz_tpm \
    -- -dict=fuzz/tpm.dict
```

The other three targets take `arbitrary`-encoded structures rather than raw
bytes, so there's nothing meaningful to hand-write a seed for; they build their
corpus from scratch.

Reproducing and minimizing a crash works as usual:

```sh
cargo +nightly fuzz run fuzz_tpm fuzz/artifacts/fuzz_tpm/crash-<hash>
cargo +nightly fuzz tmin fuzz_tpm fuzz/artifacts/fuzz_tpm/crash-<hash>
```

The `symcrypt` backend can be fuzzed with `--no-default-features --features
symcrypt` (after `./scripts/fetch-symcrypt.sh`).

## Targets

| Target | Input | What it covers |
| --- | --- | --- |
| `fuzz_tpm` | A raw TPM command stream | `execute_command`: header validation, command unmarshaling, and dispatch - the bytes a guest controls |
| `fuzz_tpm_session` | A sequence of platform operations | Commands interleaved with power cycles, live save / restore, locality changes, and cancellation |
| `fuzz_restore_state` | A saved-state blob | `restore_state`, plus running the TPM on whatever the blob restored |
| `fuzz_nvmem` | A persisted nvmem blob | Booting on a corrupted, truncated, or hostile nvmem blob |

`fuzz_tpm` takes plain bytes: the input is split into commands along the
boundaries declared by each command's own `commandSize` field, so a corpus
entry can be a capture of a real command stream, and
[`seed_corpus/fuzz_tpm/`](seed_corpus/fuzz_tpm) holds hand-built commands to
start from.

The other three take
[`arbitrary`](https://docs.rs/arbitrary)-derived structures. `fuzz_restore_state`
and `fuzz_nvmem` mostly work by splicing fuzzer controlled bytes into a blob the
TPM itself produced, since random bytes never survive a blob's framing and
header validation.

## Oracles

Beyond the crashes, hangs, and leaks that libFuzzer and the sanitizers find on
their own, the targets assert that:

- a reported response length fits in the response buffer that was handed to the
  TPM,
- a non-empty response is at least a header long, and its `responseSize` field
  matches the number of bytes actually returned,
- a save / restore / save round-trip reproduces the blob it started from -
  otherwise state is being dropped or invented in transit, and a migrated TPM
  wouldn't match the one it was migrated from,
- restoring a blob the TPM just saved always succeeds, and
- an `initialize` that fails leaves the platform singleton free to be claimed
  again.

## Determinism

Replaying a crash has to reproduce it, so every input the TPM sees other than
the fuzzer's bytes is fixed: entropy comes from a fixed-seed PRNG, and the
monotonic timer advances by a fixed step per call. Both are rewound at the start
of every iteration.

Manufacturing a TPM is far too slow to do per iteration, so every target
manufactures one per process and rolls it back to a pristine snapshot before
each iteration. State that a command leaves behind but that isn't part of a
saved-state blob will therefore bleed into subsequent iterations, which can make
a crash depend on the inputs that ran before it. That's worth chasing rather
than papering over: the same bleed-through would break a live migration.

This matters in practice. `fuzz_nvmem` originally booted a fresh TPM per
iteration via `InitKind::ColdInitWithPersistentState` instead of rolling one
back, and 50 of the 61 artifacts a campaign produced could not be replayed on
their own. Installing the blob with `reset` on a rolled-back TPM fixed that.
Note that residual nondeterminism in a replay is itself a signal: the TPM
library reads uninitialized stack memory when an NV read fails, so what a
corrupt blob does can genuinely depend on what ran before it.

## Instrumenting the C library

Rust's `-Zsanitizer=address` and libFuzzer's coverage instrumentation only apply
to Rust code. Since essentially all of the interesting code here is the vendored
C TPM library, the C build has to be instrumented as well, which requires clang.

[`build.rs`](../build.rs) handles this: `cargo fuzz` puts `--cfg fuzzing` in
`RUSTFLAGS`, which Cargo passes to build scripts as `CARGO_CFG_FUZZING`, so the
build script knows to build the TPM with clang, `-fsanitize=fuzzer-no-link`, and
whatever `-Zsanitizer` Cargo reported in `CARGO_CFG_SANITIZE`. Nothing needs to
be set by hand, and normal (non-fuzzing) builds are untouched.

It's worth it: on a short run of `fuzz_tpm`, instrumenting the C code took
coverage from ~550 edges (the Rust wrapper alone) to ~2300, and it's what lets
ASan catch memory errors inside the TPM library - such as a read past the end of
a global - rather than only the ones its allocator interceptors see.

Two env-vars adjust this, both accepting the target-prefixed forms the crate's
other env-vars do:

- `TCG_TPM_FUZZ_CC` - the compiler to build the instrumented TPM with. Set this
  when cross-compiling, or when the clang to use isn't the newest one on `PATH`.
  If the build is already configured to use a clang (via `CC`, say), that one is
  kept and this isn't needed.
- `TCG_TPM_FUZZ_CFLAGS` - replaces the instrumentation flags entirely. Setting
  it to an empty value fuzzes without instrumenting the C code, which leaves the
  fuzzer blind to the code that parses TPM commands.

The build script fails rather than silently producing an uninstrumented fuzzer
if it can't find a clang.

GCC can't be used for this - it has no `-fsanitize=fuzzer-no-link`, and the
`-fsanitize-coverage=trace-pc` scheme it does support was removed from libFuzzer.

OpenSSL is deliberately left uninstrumented: it's a dependency of the code under
test rather than the target, and instrumenting it slows the build down and
spends the fuzzer's energy inside crypto primitives it can't steer. ASan's
allocator interceptors still cover heap errors there.

## Corpus layout

- `corpus/<target>/` - the working corpus libFuzzer grows as it runs
  (git-ignored).
- `seed_corpus/fuzz_tpm/` - checked-in starting inputs.
- `artifacts/<target>/` - crashing inputs (git-ignored).
- `tpm.dict` - TPM wire-format constants (tags, command codes, handles,
  algorithm ids) for libFuzzer's `-dict`.
