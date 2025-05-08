<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Introduction](#introduction)
- [Features](#features)
- [Installing, Testing, Benchmarks](#installing-testing-benchmarks)
  - [Building](#building)
  - [Running Tests](#running-tests)
  - [Examples](#examples)
- [Implementation Details](#implementation-details)
  - [Feature Flags](#feature-flags)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction
This is a high-performance threshold EdDSA/Schnorr signing protocol based on the paper [Simple Three-Round Multiparty Schnorr Signing with Full Simulatability](https://eprint.iacr.org/2022/374.pdf).


This is a production-ready, audited implementation  and has undergone a comprehensive [security audit](./docs/Hashcloak-SilenceLaboratories_2025_04_09.pdf) by HashCloak.

## Features

- Distributed Key Generation (DKG)
- Distributed Signature Generation (DSG)
- Key refresh
- Quorum Change: change dynamically the set of participants adding or removing



## Installing, Testing, Benchmarks
### Building
```bash
cargo build
```
### Running Tests
```bash
cargo test
```


### Examples
Under <a href="./examples/">`/examples/`</a> directory there are examples on how to perform keygen, sign and refresh.

Running the examples:
```bash
cargo run --example keygen
cargo run --example sign
cargo run --example refresh
```




## Implementation Details

- This library provides Distributed Key Generation generic over any elliptic curve group that implements the `Group` trait from the `elliptic-curve` crate.
  We currently support threshold Schnorr signing with random nonce over curve25519 and Bitcoin Taproot Schnorr over the secp256k1 curve.








**The library does not support**:
- This library contains only the cryptographic protocol and does not provide any networking functions.
- The parties in the protocol do not authenticate themselves and do not establish e2e secure channels



### Feature Flags

| Feature            | Default? | Description |
| :---               |  :---:   | :---        |
| `eddsa`            |    ✓     | Enables signing over curve25519 with edd25519-dalek signing objects compatibility|
| `taproot`          |        | Enables Bitcoin Taproot Schnorr signing over secp256k1 |


## Security

If you discover a vulnerability, please follow the instructions in [SECURITY](SECURITY.md).

## Security Audit

HashCloak has performed a security audit in April, 2025 on the following commit:
- `146d4a57a82c62cf8d24fbd6b713d9bfc7cd534c` 

and the report is available here: [security audit](./docs/Hashcloak-SilenceLaboratories_2025_04_09.pdf)


## Contributing

Please refer to [CONTRIBUTING](CONTRIBUTING.md).

## Reach out to us
Don't hesitate to contact us if you need any assistance.

info@silencelaboratories.com
security@silencelaboratories.com

**Happy signing!**