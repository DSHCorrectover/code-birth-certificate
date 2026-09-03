# Code Birth Certificate

[![self-anchor workflow](https://github.com/DSHCorrectover/code-birth-certificate/actions/workflows/self-anchor.yml/badge.svg)](https://github.com/DSHCorrectover/code-birth-certificate/actions/workflows/self-anchor.yml)
[![Rekor genesis entry](https://img.shields.io/badge/Rekor%20genesis%20entry-logIndex%202694324795-1455A3)](https://search.sigstore.dev/?logIndex=2694324795)
[![DOI genesis bundle](https://zenodo.org/badge/DOI/10.5281/zenodo.22266162.svg)](https://doi.org/10.5281/zenodo.22266162)

**Publicly verifiable evidence of existence and timestamp for any code
snapshot: a content-addressed manifest, a signed receipt, and a Sigstore Rekor
transparency-log anchor — with an optional Zenodo DOI — in one GitHub Action.**

When your workflow runs, this action snapshots your repository, builds a
content-addressed manifest of every file (per-file SHA-256, canonicalized with
JCS / [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)), signs an identity
receipt with Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)), and
anchors the manifest digest in the public **Sigstore Rekor** transparency log
(a `hashedrekord` entry with an inclusion proof). The Rekor anchor needs **no
tokens, no accounts, no registration** — the log is public and free to write
and read.

Anyone, any time, without trusting Correctover or running any Correctover
service, can confirm: *this exact set of file bytes existed at or before this
time, and the receipt was signed by this key.*

> **What this is:** evidence of existence and timestamp for a specific code
> snapshot (a specific set of file hashes), signed by a specific key at a
> specific time, anchored in a public transparency log.
>
> **What this is not:** a copyright registration, a legal opinion, or a
> statement about authorship rights. Cryptographic hashes prove **byte
> identity** of a snapshot; they do not judge semantic similarity between
> codebases. That question is a higher-layer capability.

---

## Quickstart — 3 steps

**1.** Add this file at `.github/workflows/birth-certificate.yml`:

```yaml
name: code-birth-certificate
on:
  push:
    tags: ['v*']          # anchor every release tag
  workflow_dispatch:      # and allow manual runs
permissions:
  contents: read
jobs:
  anchor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: DSHCorrectover/code-birth-certificate@main
        id: cbc
      - run: echo "Rekor log index: ${{ steps.cbc.outputs.rekor-log-index }}"
```

**2.** Push a tag (or run the workflow manually from the Actions tab).

**3.** Open the **Rekor log viewer** link printed in the run summary — your
snapshot is anchored in the public transparency log. The full proof bundle
(manifest, receipt, anchor record) is attached as a workflow artifact.

That is the whole setup. No secrets are required. After the action is tagged,
pin to a major version (`@v1`) instead of `@main`.

### Optional: also mint a Zenodo DOI

Pass a Zenodo personal access token (`deposit:write` scope) as a secret, and
the proof bundle is additionally archived with a persistent DOI:

```yaml
      - uses: DSHCorrectover/code-birth-certificate@main
        with:
          zenodo-token: ${{ secrets.ZENODO_TOKEN }}
```

Without the token, the Rekor anchor still runs and the DOI step is skipped.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `path` | no | `.` | Code directory to anchor, relative to the repository root. |
| `name` | no | repository name | Snapshot name used in the receipt and proof bundle. |
| `zenodo-token` | no | _(empty)_ | Optional Zenodo PAT (`deposit:write`). Empty = Rekor-only anchoring. |

## Outputs

| Output | Description |
|---|---|
| `manifest-digest` | SHA-256 digest of the JCS-canonical (RFC 8785) content-addressed manifest. |
| `rekor-log-index` | Sigstore Rekor transparency-log entry index. |
| `rekor-url` | Public Sigstore log viewer URL (`https://search.sigstore.dev/?logIndex=…`). |
| `zenodo-doi` | Zenodo DOI of the proof bundle; empty when no token was provided. |

The run also gets a **job summary** (digest, log index, links, signer) and an
artifact named `code-birth-certificate-bundle`.

---

## Verify independently — no Correctover service involved

Every claim below is checkable with public infrastructure only.

### 1. Check the transparency log entry directly

```bash
# Replace <UUID> with the entry UUID printed in the run summary / anchor record.
curl -s "https://rekor.sigstore.dev/api/v1/log/entries/<UUID>"
```

Decode the base64 `body`; `spec.data.hash.value` is the anchored SHA-256
digest, and `verification.inclusionProof` proves the entry is included in the
log's signed tree. Or open the viewer link in a browser:
`https://search.sigstore.dev/?logIndex=<index>`.

### 2. Re-verify the full proof bundle end-to-end

Download the `code-birth-certificate-bundle` artifact and run:

```bash
pip install jcs cryptography
python provenance.py verify <bundle-dir>
```

This recomputes every file hash, re-derives the JCS manifest digest, verifies
the Ed25519 receipt signature with the public key embedded in the receipt,
fetches the Rekor entry over HTTPS, and checks that the on-log digest matches.
It contacts only `rekor.sigstore.dev` — never any Correctover service.

### Genesis anchor — real and public

The first birth certificate ever minted by this toolchain covers the public
package `correctover-scan` v1.4.0 (commit `13a3caa`), manifest digest
`b0366186a5063a091148ffdc6b042d36e8cfa8e2d675e05b6c598e096b3ca75f`:

- Rekor transparency log: [logIndex 2694324795](https://search.sigstore.dev/?logIndex=2694324795)
  — the on-log digest is the hash above and the entry carries an inclusion proof.
- Zenodo archive of the proof bundle: [DOI 10.5281/zenodo.22266162](https://doi.org/10.5281/zenodo.22266162).

This repository anchors **itself** on every push to `main` via
[`.github/workflows/self-anchor.yml`](.github/workflows/self-anchor.yml) — the
status badge at the top shows the latest run, and each run summary contains
the repo's own latest birth certificate.

---

## How it works

```
code snapshot
  → content-addressed manifest   (per-file SHA-256; JCS canonicalization, RFC 8785)
  → identity receipt             (Ed25519 signature, RFC 8032; public key embedded)
  → transparency-log anchor      (Sigstore Rekor hashedrekord entry + inclusion proof)
  → optional persistent archive  (Zenodo deposit with a DOI for the proof bundle)
```

- **Content-addressed manifest (JCS, RFC 8785).** Every file's POSIX-relative
  path and SHA-256 hash is recorded, canonicalized deterministically with JCS
  (JSON Canonicalization Scheme), and hashed again to produce one manifest
  digest. Change one byte anywhere and the digest changes.
- **Signed identity receipt (Ed25519, RFC 8032).** The receipt binds the
  manifest digest, the signer identity, and a timestamp. It is signed with
  Ed25519; the public key is embedded in the receipt itself, so verification
  needs no external key distribution.
- **Transparency anchor (Sigstore Rekor).** The manifest digest is submitted
  as a `hashedrekord` v0.0.1 entry to the public Rekor log, which returns an
  entry with an inclusion proof. Rekor is an append-only, publicly auditable
  log operated by the Sigstore community — writing an entry requires no
  credentials.
- **Why ECDSA P-256 for the Rekor anchor (one sentence):** Rekor's
  `hashedrekord` entry type verifies detached signatures against the
  artifact's SHA-256 hash, which the Ed25519ph verifier rejects (it accepts
  only SHA-512), so the interoperable Sigstore default — **ECDSA P-256 over
  SHA-256** — signs the transparency anchor, while the identity receipt
  remains Ed25519 (RFC 8032); both keys belong to the same subject. Full
  detail is in `anchor-record.json → rekor.note`.
- **Optional Zenodo DOI.** With a token, the proof bundle (manifest, receipt,
  anchor record, readme) is deposited to Zenodo and cross-references the Rekor
  entry, giving the evidence a persistent, citable identifier. A pre-publish
  credential scan fails closed if any token-like pattern appears in the
  bundle, and Git remote URLs are sanitized of credentials before they enter
  any record.

## CLI usage (without GitHub Actions)

```bash
pip install jcs cryptography

python provenance.py keygen                       # once; local keys, 0600
python provenance.py anchor ./path/to/repo --name my-project --strict
ZENODO_TOKEN=… python provenance.py anchor ./path/to/repo   # with optional DOI
python provenance.py verify output/<bundle-dir>  # independent verification
```

Environment variables: `ZENODO_TOKEN` (optional), `REKOR_API` (optional Rekor
base URL), `CBC_SUBJECT_NAME` / `CBC_SUBJECT_EMAIL` / `CBC_SUBJECT_ORG`
(signer identity; the GitHub Action fills these from the repository owner).

## Boundaries and honesty

- This tool produces **evidence of existence and timestamp**. It does not
  register copyright, establish authorship in law, or give legal advice.
- Hashes bind a **specific byte-level snapshot**. They say nothing about
  whether another codebase is semantically similar, derived, or copied —
  semantic similarity is a separate, higher-layer analysis.
- In GitHub Actions the signing keys are generated fresh for each run on the
  runner and never leave it; only public keys are published in the receipt and
  in the Rekor entry. The signer identity recorded by the action is the
  repository owner (the workflow run itself is publicly attributable).
- Nothing about the action contacts or depends on a Correctover service for
  anchoring or verification.

## License

[MIT](LICENSE) © 2026 Correctover. Proof bundles deposited to Zenodo are
released under CC0-1.0.
