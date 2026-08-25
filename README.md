# Artifact Evaluation Guide

This repository contains a Rust implementation of a multiparty Schnorr / EdDSA signing protocol, including an **Associated Data** binding for Ed25519 signatures.

You do **not** need prior Rust experience. Follow the two steps below in order.

## Requirements

- A computer with **macOS** or **Linux**
- Internet access (to download the Rust toolchain and crate dependencies)
- About **10–20 minutes** for the first build (later runs are much faster)

## Step 1 — Install Rust (one command)

Open a terminal in this repository directory and run:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88 && . "$HOME/.cargo/env"
```

What this does:

1. Installs the Rust toolchain manager (`rustup`)
2. Installs Rust **1.88** (the version required by this project)
3. Loads the toolchain into your current terminal session

If you open a **new** terminal later, run `. "$HOME/.cargo/env"` once (or restart the terminal) so `cargo` is found.

Optional check:

```bash
rustc --version
cargo --version
```

## Step 2 — Run the Associated Data protocol test (one command)

From the repository root, run:

```bash
cargo test --release --features "eddsa,ad,test-support" sign_2_3_with_auth_data -- --nocapture
```

What this does:

1. Compiles the library with EdDSA signing and the Associated Data (`ad`) feature
2. Runs the automated test `sign_2_3_with_auth_data`
3. That test performs a **2-of-3** threshold key generation, then a threshold EdDSA signing session that binds **associated data**, and finally checks that the associated-data proof verifies

A successful run ends with output similar to:

```text
test sign::eddsa::tests::sign_2_3_with_auth_data ... ok
```

The first run downloads dependencies and compiles; this can take several minutes. Later runs reuse the build cache.

## Optional: micro-benchmark

To measure associated-data prove/verify overhead (ignored by default):

```bash
cargo test --release --features "eddsa,ad,test-support" bench_associated_data_1000 -- --ignored --nocapture
```

## Troubleshooting

| Problem | What to try |
| :--- | :--- |
| `cargo: command not found` | Run `. "$HOME/.cargo/env"`, then retry Step 2 |
| Build fails on Linux with linker / `cc` errors | Install a C toolchain, e.g. `sudo apt-get update && sudo apt-get install -y build-essential`, then retry Step 2 |
| Slow first build | Expected; wait for compilation to finish |
| Wrong Rust version | Re-run Step 1, or `rustup default 1.88` |

## Notes for reviewers

- This package provides the **cryptographic protocol only** (no networking).
- The Associated Data path is enabled with the Cargo feature `ad` and is exercised by the test named above.
- No special configuration files are required beyond the commands in this guide.
