# Local evidence capture

This tooling captures Rust executions and checks their evidence. Choose the workflow you need:

- Use `prepare` → `collect` → `check_evidence.py` to create and check an evidence collection.
- Use `tools/verify.py` to capture tests, examples and formatting checks together with a local archive of their source inputs. See [Validation](../../docs/validation.md).

## Capture and check

`prepare` runs the scenarios and tests. `collect` verifies the captured results and
assembles the evidence files.

From TGC-Demo, with the sibling ConstitutiveActionKernel checkout and locked Rust
dependencies available locally:

```sh
python3 tools/dx/evidence.py prepare --runs /tmp/tgc-runs-UNIQUE
python3 tools/dx/evidence.py collect --runs /tmp/tgc-runs-UNIQUE --out /tmp/tgc-evidence-UNIQUE
python3 tools/dx/check_evidence.py /tmp/tgc-evidence-UNIQUE
```

Use new, separate directories for prepared runs and collected evidence. Existing
output directories are never overwritten. If a command fails, any partial output
remains available for inspection; use a new directory when retrying.

Preparation captures twelve scenario branches, six examples with assertions, workspace
and overlapping standalone Kernel tests, and two actual process-crash recoveries.
Preparation records hashes of the source, tooling, executables and outputs.
Collection checks these before and after processing and verifies each scenario
journal. Changed inputs or outputs require fresh preparation.

The collected directory contains individual run records, examples, host cases,
Kernel demonstration output, test transcripts, a manifest and regression records
under `evidence/`. `evidence-index.json` lists paths relative to `evidence/` and
their SHA-256 hashes.
JSON regression records remain byte-identical; diagnostic workspace paths are
normalised. Private issuer material and input archives are excluded.

The checker verifies branch hashes, whether recorded events match their decisions,
whether payloads and evidence match their recorded bindings, and whether receipts
refer to the correct attempts. It also checks crash recovery, transcript counts
and hashes, and the expected regression records.

To capture tests, formatting checks and examples together with a local archive of
their source inputs, use
`python3 tools/verify.py --out /tmp/tgc-verification-UNIQUE`.
See [Validation](../../docs/validation.md) and
[Deployment architecture](../../MANIFEST.md).

## Tooling regression tests

```sh
python3 -B -m unittest discover -s tools/dx -p 'test_*.py'
python3 -O -B -m unittest discover -s tools/dx -p 'test_*.py'
```
