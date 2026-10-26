# Constitutive Action Kernel — vendored library

This directory supplies the Kernel used by TGC-Demo. It contains the library source, Cargo metadata and licence; the standalone repository contains the documentation, tests and runnable examples.

- [Kernel repository](https://github.com/endonym/constitutive-action-kernel)
- [Local snapshot fingerprints and original baseline](../kernel-source.json)
- [Generative Commons License](LICENSE)
- [Kernel control disclosure](https://github.com/endonym/constitutive-action-kernel/blob/main/MANIFEST.md)

The implementation matches the Kernel revision recorded in [kernel-source.json](../kernel-source.json). This README describes the vendored subset and intentionally differs from the standalone README.

Run the demo's workspace tests from the TGC-Demo root with `cargo test --workspace --locked --all-targets`. Run Kernel examples and its independent suite from a full Kernel checkout.
