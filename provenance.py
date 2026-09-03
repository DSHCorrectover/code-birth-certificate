#!/usr/bin/env python3
"""Code Birth Certificate - one-command code provenance CLI.

A single command takes a snapshot of a code directory and produces
independent, publicly checkable **evidence of existence and timestamp**
for it:

    code snapshot -> content-addressed manifest (JCS/RFC 8785)
                  -> Ed25519 identity receipt (RFC 8032)
                  -> Sigstore Rekor transparency-log anchor (hashedrekord)
                  -> (optional) Zenodo DOI of the proof bundle

The proof bundle is self-contained: verification re-hashes every file,
checks the Ed25519 signature against the embedded public key, and reads
the public Rekor entry directly. No Correctover service is involved.

This is evidence of existence and timestamp only. It is not a copyright
registration, not a legal opinion, and not a statement about authorship
rights. Hashes prove byte identity of a snapshot; they do not judge
semantic similarity.

Usage:
    python provenance.py keygen [--keys-dir DIR]
    python provenance.py anchor <path> [--name NAME] [--keys-dir DIR]
                              [--output-dir DIR] [--strict]
    python provenance.py verify <bundle-dir>

Credentials are read ONLY from environment variables; nothing is
hard-coded:
    ZENODO_TOKEN          - Zenodo personal access token (deposit:write).
                            If unset, the Rekor anchor still runs and the
                            DOI step is skipped.
    REKOR_API             - optional, defaults to https://rekor.sigstore.dev
    CBC_SUBJECT_NAME / CBC_SUBJECT_EMAIL / CBC_SUBJECT_ORG
                          - signer identity (the identity receipt carries
                            the signer identity; in GitHub Actions the
                            action fills these from the repo owner).
"""
from __future__ import annotations

import argparse
import base64
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import jcs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECEIPT_VERSION = "code-birth-certificate/1.0"
MANIFEST_SPEC = "cbc-manifest/1.0"
ANCHOR_SPEC = "cbc-anchor/1.0"

DEFAULT_REKOR = os.environ.get("REKOR_API", "https://rekor.sigstore.dev").rstrip("/")
ZENODO_API = "https://zenodo.org"

# Directories never snapshotted.
DEFAULT_EXCLUDES = {".git", "node_modules", "__pycache__", ".DS_Store", ".venv", "venv"}
# Top-level dot-directories that ARE snapshotted (CI workflows live here).
INCLUDED_DOT_DIRS = {".github"}

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def utcnow() -> tuple[float, str]:
    ts = _dt.datetime.now(_dt.timezone.utc)
    return ts.timestamp(), ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical_bytes(obj: Any) -> bytes:
    """JCS canonical JSON (RFC 8785)."""
    return jcs.canonicalize(obj)


def write_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=False, ensure_ascii=False) + "\n",
                    encoding="utf-8")


def http_json(url: str, *, method: str = "GET", body: Any = None,
              headers: dict | None = None, raw_body: bytes | None = None,
              timeout: int = 60) -> tuple[int, Any]:
    hdr = {"Accept": "application/json"}
    if headers:
        hdr.update(headers)
    data = None
    if raw_body is not None:
        data = raw_body
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        hdr.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode("utf-8", "replace")


def resolve_subject() -> dict:
    """Signer identity.

    In GitHub Actions the action sets CBC_SUBJECT_* from the repository
    context (the run itself is publicly attributable to the workflow run,
    so the signer identity matches whoever triggered it). On the CLI,
    identity comes from the same environment variables; a generic default
    is used if none are set - change it via the env vars when you run
    your own anchors.
    """
    # Fall back to git identity when available.
    git_name = git_email = None
    try:
        r1 = subprocess.run(["git", "config", "--get", "user.name"],
                            capture_output=True, text=True, timeout=10)
        if r1.returncode == 0:
            git_name = r1.stdout.strip() or None
        r2 = subprocess.run(["git", "config", "--get", "user.email"],
                            capture_output=True, text=True, timeout=10)
        if r2.returncode == 0:
            git_email = r2.stdout.strip() or None
    except Exception:
        pass
    name = os.environ.get("CBC_SUBJECT_NAME") or git_name or "Code Birth Certificate user"
    email = os.environ.get("CBC_SUBJECT_EMAIL") or git_email or "example@example.invalid"
    org = os.environ.get("CBC_SUBJECT_ORG") or ""
    subject = {"name": name, "email": email}
    if org:
        subject["organization"] = org
    return subject


# ---------------------------------------------------------------------------
# Keys
# ---------------------------------------------------------------------------

def keygen(keys_dir: Path) -> None:
    """Create the local identity keys (once). Private keys stay local."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    ed_priv_path = keys_dir / "provenance_ed25519.pem"
    ec_priv_path = keys_dir / "anchor_ecdsap256.pem"
    if ed_priv_path.exists() and ec_priv_path.exists():
        print(f"keys already exist in {keys_dir} (not overwritten)")
        return
    ed_key = ed25519.Ed25519PrivateKey.generate()
    ec_key = ec.generate_private_key(ec.SECP256R1())
    ed_priv_path.write_bytes(ed_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ec_priv_path.write_bytes(ec_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    os.chmod(ed_priv_path, 0o600)
    os.chmod(ec_priv_path, 0o600)
    ed_pub = ed_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("generated keys:")
    print(f"  {ed_priv_path}  (Ed25519 identity receipt key)")
    print(f"  {ec_priv_path}  (ECDSA P-256 Rekor anchor key)")
    print(f"  Ed25519 fingerprint (sha256/16): {sha256_bytes(ed_pub)[:16]}")


def load_keys(keys_dir: Path):
    ed_priv_path = keys_dir / "provenance_ed25519.pem"
    ec_priv_path = keys_dir / "anchor_ecdsap256.pem"
    if not ed_priv_path.exists() or not ec_priv_path.exists():
        print(f"ERROR: keys not found in {keys_dir}. Run:  "
              f"python provenance.py keygen", file=sys.stderr)
        sys.exit(2)
    ed_key = serialization.load_pem_private_key(ed_priv_path.read_bytes(), password=None)
    ec_key = serialization.load_pem_private_key(ec_priv_path.read_bytes(), password=None)
    return ed_key, ec_key


# ---------------------------------------------------------------------------
# Step 1: snapshot + content-addressed manifest
# ---------------------------------------------------------------------------

def _sanitize_remote(url: str) -> str:
    """Strip any credentials (user:token@) from a Git remote URL."""
    return re.sub(r"^(https?://)[^/@]*@", r"\1", url)


def git_info(target: Path) -> dict:
    info: dict[str, Any] = {}
    try:
        commit = subprocess.run(["git", "-C", str(target), "rev-parse", "HEAD"],
                                capture_output=True, text=True, timeout=20)
        if commit.returncode == 0:
            info["git_commit"] = commit.stdout.strip()
        remote = subprocess.run(["git", "-C", str(target), "config", "--get",
                                 "remote.origin.url"],
                                capture_output=True, text=True, timeout=20)
        if remote.returncode == 0 and remote.stdout.strip():
            info["git_remote"] = _sanitize_remote(remote.stdout.strip())
        short = subprocess.run(["git", "-C", str(target), "rev-parse", "--short", "HEAD"],
                               capture_output=True, text=True, timeout=20)
        if short.returncode == 0:
            info["git_commit_short"] = short.stdout.strip()
    except Exception:
        pass
    return info


def package_version(target: Path) -> str | None:
    for name in ("package.json", "pyproject.toml"):
        p = target / name
        if p.exists():
            txt = p.read_text(encoding="utf-8", errors="replace")
            if name == "package.json":
                try:
                    data = json.loads(txt)
                    if data.get("version"):
                        return f"{data.get('name', 'package')}@{data['version']}"
                except Exception:
                    pass
            else:
                m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', txt, re.M)
                if m:
                    return f"{target.name}@{m.group(1)}"
    return None


def build_manifest(target: Path, name: str, output_dir: Path) -> dict:
    target = target.resolve()
    out_resolved = output_dir.resolve()
    files: dict[str, str] = {}
    for root, dirs, fnames in os.walk(target):
        kept_dirs = []
        for d in dirs:
            p = (Path(root) / d).resolve()
            if p == out_resolved or str(p).startswith(str(out_resolved) + os.sep):
                continue
            if d in DEFAULT_EXCLUDES:
                continue
            if d.startswith(".") and d not in INCLUDED_DOT_DIRS:
                continue
            kept_dirs.append(d)
        dirs[:] = sorted(kept_dirs)
        for fname in sorted(fnames):
            if fname in DEFAULT_EXCLUDES or fname.startswith("."):
                continue
            fpath = Path(root) / fname
            if fpath.resolve() == out_resolved:
                continue
            rel = fpath.relative_to(target).as_posix()
            files[rel] = sha256_file(fpath)
    _, iso = utcnow()
    manifest = {
        "spec": MANIFEST_SPEC,
        "snapshot_name": name,
        "canonicalization": "JCS (RFC 8785)",
        "file_hash_algorithm": "sha256",
        "excludes": sorted(DEFAULT_EXCLUDES),
        "included_dotdirs": sorted(INCLUDED_DOT_DIRS),
        "generated_at": iso,
        "file_count": len(files),
        "files": dict(sorted(files.items())),
    }
    return manifest


# ---------------------------------------------------------------------------
# Step 2: Ed25519 identity receipt
# ---------------------------------------------------------------------------

def build_receipt(ed_key, subject: dict, manifest: dict,
                  manifest_digest: str, snapshot: dict) -> dict:
    epoch, iso = utcnow()
    pub = ed_key.public_key()
    pub_raw = pub.public_bytes(serialization.Encoding.Raw,
                               serialization.PublicFormat.Raw)
    pub_pem = pub.public_bytes(serialization.Encoding.PEM,
                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    receipt = {
        "receipt_version": RECEIPT_VERSION,
        "receipt_type": "code-snapshot-provenance",
        "issuer": "Code Birth Certificate",
        "subject": subject,
        "snapshot": snapshot,
        "manifest": {
            "spec": manifest["spec"],
            "canonicalization": manifest["canonicalization"],
            "file_hash_algorithm": manifest["file_hash_algorithm"],
            "file_count": manifest["file_count"],
            "manifest_digest_sha256": manifest_digest,
        },
        "issued_at_epoch": round(epoch, 3),
        "issued_at": iso,
        "signing_algorithm": "Ed25519 (RFC 8032)",
        "public_key": {
            "algorithm": "Ed25519",
            "raw_base64": base64.b64encode(pub_raw).decode("ascii"),
            "pem": pub_pem,
        },
        "public_key_fingerprint_sha256_16": sha256_bytes(pub_raw)[:16],
        "signature": None,
    }
    # Sign the JCS-canonical receipt with 'signature' excluded.
    signed = {k: v for k, v in receipt.items() if k != "signature"}
    sig = ed_key.sign(canonical_bytes(signed))
    receipt["signature"] = base64.b64encode(sig).decode("ascii")
    return receipt


# ---------------------------------------------------------------------------
# Step 3: Rekor transparency-log anchor (hashedrekord v0.0.1)
# ---------------------------------------------------------------------------

REKOR_ED25519_NOTE = (
    "Rekor hashedrekord v0.0.1 parses every detached signature as Ed25519ph "
    "(RFC 8032 prehashed) but passes the artifact hash algorithm (SHA-256) "
    "into verification; the Ed25519ph verifier accepts only SHA-512, so "
    "Ed25519 hashedrekord entries are rejected by the public log "
    "('unsupported hash algorithm: SHA-256 not in [SHA-512]'). ECDSA P-256 "
    "over SHA-256 is the default, interoperable combination used across the "
    "Sigstore ecosystem (cosign, sigstore-python, sigstore-js) and is used "
    "for the transparency anchor. The identity receipt itself is signed with "
    "Ed25519 (RFC 8032); both keys belong to the same subject."
)


def rekor_anchor(ec_key, digest_hex: str) -> dict:
    # ECDSA signature over the 32-byte SHA-256 digest (ASN.1 DER), Prehashed.
    digest = bytes.fromhex(digest_hex)
    sig_der = ec_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    pub_pem = ec_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    body = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "signature": {
                "content": base64.b64encode(sig_der).decode("ascii"),
                "publicKey": {"content": base64.b64encode(pub_pem.encode()).decode()},
            },
            "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
        },
    }
    code, resp = http_json(f"{DEFAULT_REKOR}/api/v1/log/entries", method="POST", body=body)
    if code != 201 or not isinstance(resp, dict):
        raise RuntimeError(f"Rekor POST failed: HTTP {code}: {resp}")
    uuid = next(iter(resp.keys()))
    entry = resp[uuid]
    log_index = entry.get("logIndex")
    record = {
        "transparency_log": "Sigstore Rekor",
        "api_base": DEFAULT_REKOR,
        "entry_kind": "hashedrekord v0.0.1",
        "entry_uuid": uuid,
        "log_index": log_index,
        "entry_url_api": f"{DEFAULT_REKOR}/api/v1/log/entries/{uuid}",
        "entry_url_search": f"https://search.sigstore.dev/?logIndex={log_index}",
        "anchored_digest_sha256": digest_hex,
        "anchor_signature_algorithm": "ECDSA P-256 (secp256r1) over SHA-256, ASN.1 DER",
        "anchor_public_key_pem": pub_pem,
        "inclusion_proof_present": bool(entry.get("verification", {}).get("inclusionProof")),
        "note": REKOR_ED25519_NOTE,
    }
    # Confirm the entry is publicly retrievable.
    code2, fetch = http_json(record["entry_url_api"])
    record["public_fetch_http"] = code2
    if code2 == 200 and isinstance(fetch, dict) and uuid in fetch:
        record["publicly_verified"] = True
    else:
        record["publicly_verified"] = False
    return record


# ---------------------------------------------------------------------------
# Step 4: Zenodo DOI of the proof bundle (optional)
# ---------------------------------------------------------------------------

def _guard_no_credentials(bundle: Path) -> None:
    """Fail closed if any bundle file contains an embedded secret pattern."""
    patterns = [
        (re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"), "GitHub token"),
        (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private key PEM"),
        (re.compile(r"zenodo\.org/api/deposit[^\s\"']*"), "Zenodo API URL"),
    ]
    offenders = []
    for fp in bundle.glob("*"):
        if not fp.is_file() or fp.suffix not in (".json", ".md", ".txt", ".env"):
            continue
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for pat, label in patterns:
            if pat.search(txt):
                offenders.append(f"{fp.name}: {label}")
    if offenders:
        raise RuntimeError("REFUSING to publish: credential pattern(s) found in bundle: "
                           + "; ".join(offenders))


def zenodo_publish(token: str, bundle: Path, rekor_rec: dict,
                   manifest_digest: str, name: str, subject: dict) -> dict:
    H = {"Authorization": f"Bearer {token}"}
    _guard_no_credentials(bundle)

    # 1) create deposition
    code, dep = http_json(f"{ZENODO_API}/api/deposit/depositions",
                          method="POST", body={}, headers=H)
    if code not in (200, 201):
        raise RuntimeError(f"Zenodo create deposition failed: HTTP {code}: {dep}")
    dep_id = dep["id"]
    bucket_url = dep["links"]["bucket"]

    # 2) upload bundle files
    for fname in ("manifest.json", "receipt.json", "anchor-record.json", "bundle-readme.md"):
        fp = bundle / fname
        if not fp.exists():
            continue
        raw = fp.read_bytes()
        req = urllib.request.Request(
            f"{bucket_url}/{fname}", data=raw, method="PUT",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/octet-stream"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                r.read()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"Zenodo upload {fname} failed: HTTP {e.code}: "
                               f"{e.read().decode('utf-8','replace')[:300]}")

    # 3) metadata
    rekor_search = rekor_rec["entry_url_search"]
    rekor_api = rekor_rec["entry_url_api"]
    description = (
        "<p>Code Birth Certificate - evidence of existence and timestamp for a "
        "specific code snapshot. This record contains the content-addressed "
        "manifest (per-file SHA-256 hashes, JCS/RFC 8785 canonicalization) and "
        "the signed identity receipt for the snapshot.</p>"
        f"<p>The manifest digest <code>{manifest_digest}</code> is anchored in "
        "the public Sigstore Rekor transparency log (hashedrekord entry), which "
        "provides an independently observable, append-only timestamp. The Rekor "
        f"entry and this DOI cross-reference each other:</p>"
        f"<ul><li>Rekor entry (search UI): <a href=\"{rekor_search}\">{rekor_search}</a></li>"
        f"<li>Rekor entry (API): <a href=\"{rekor_api}\">{rekor_api}</a></li></ul>"
        f"<p>Snapshot: <strong>{name}</strong>. Signer: {subject['name']} "
        f"({subject['email']}).</p>"
        "<p>Files: <code>manifest.json</code> (content-addressed file list), "
        "<code>receipt.json</code> (Ed25519-signed identity receipt, RFC 8032), "
        "<code>anchor-record.json</code> (Rekor UUID / log index / Zenodo DOI "
        "cross-reference), <code>bundle-readme.md</code> (how to verify).</p>"
        "<p>This deposit is evidence of existence and timestamp only; it is not "
        "a legal claim and not a copyright registration. Released under CC0-1.0.</p>"
    )
    metadata = {
        "metadata": {
            "title": f"Code Birth Certificate: {name} - code snapshot existence and timestamp evidence",
            "upload_type": "software",
            "creators": [{"name": subject["name"],
                          "affiliation": subject.get("organization", "Code Birth Certificate")}],
            "description": description,
            "license": "CC0-1.0",
            "access_right": "open",
            "keywords": ["code provenance", "sigstore", "rekor",
                         "transparency log", "content-addressed manifest",
                         "Ed25519", "code birth certificate"],
            "notes": f"Rekor log index {rekor_rec['log_index']}; manifest digest {manifest_digest}",
        }
    }
    code, _ = http_json(f"{ZENODO_API}/api/deposit/depositions/{dep_id}",
                        method="PUT", body=metadata, headers=H)
    if code not in (200, 201):
        raise RuntimeError(f"Zenodo metadata failed: HTTP {code}")

    # 4) publish
    code, pub = http_json(f"{ZENODO_API}/api/deposit/depositions/{dep_id}/actions/publish",
                          method="POST", headers=H)
    if code not in (200, 202):
        raise RuntimeError(f"Zenodo publish failed: HTTP {code}: {pub}")
    doi = pub.get("doi") or pub.get("metadata", {}).get("doi")
    record = {
        "repository": "Zenodo",
        "deposition_id": dep_id,
        "doi": doi,
        "doi_url": f"https://doi.org/{doi}" if doi else None,
        "record_url": pub.get("links", {}).get("record_html")
                      or f"https://zenodo.org/records/{dep_id}",
        "license": "CC0-1.0",
    }
    return record


# ---------------------------------------------------------------------------
# Badges + bundle README + machine outputs
# ---------------------------------------------------------------------------

def badges_md(rekor_rec: dict, zenodo_rec: dict | None = None) -> str:
    li = rekor_rec.get("log_index", "")
    lines = [
        f"[![Rekor transparency log](https://img.shields.io/badge/Rekor%20transparency%20log-entry%20{li}-1455A3)]({rekor_rec.get('entry_url_search','')})",
    ]
    if zenodo_rec and zenodo_rec.get("doi"):
        doi = zenodo_rec["doi"]
        lines.insert(0, f"[![DOI](https://zenodo.org/badge/DOI/{doi}.svg)]({zenodo_rec.get('doi_url','')})")
    return "\n".join(lines) + "\n"


def write_bundle_readme(bundle: Path, subject: dict, manifest: dict, snapshot: dict,
                        manifest_digest: str) -> None:
    txt = f"""# Code Birth Certificate - proof bundle

This bundle is **evidence of existence and timestamp** for a specific code
snapshot. It records that a snapshot with this content-addressed manifest hash
was signed by the identified subject at a given time and anchored in a public
transparency log (and, optionally, deposited with a DOI).

It is **not** a legal claim, **not** a copyright registration, and **not** a
legal opinion. Hashes prove byte identity of the snapshot; they do not judge
semantic similarity between codebases.

## What is in this bundle

| File | Meaning |
|---|---|
| `manifest.json` | Content-addressed manifest: every file's relative path and SHA-256 hash, canonicalized with JCS (RFC 8785). The whole canonical manifest is hashed to produce the manifest digest. |
| `receipt.json` | Identity receipt signed with Ed25519 (RFC 8032) by {subject['name']} <{subject['email']}>. Contains the public key, the manifest digest, and the timestamp. |
| `anchor-record.json` | Transparency-log anchor (Sigstore Rekor hashedrekord: entry UUID, log index, public URLs) and - when minted - the Zenodo DOI, cross-referencing each other. |
| `bundle-readme.md` | This file. |

## Snapshot

- Name: `{snapshot.get('snapshot_name')}`
- Files covered: {manifest['file_count']}
- Manifest digest (SHA-256 of JCS-canonical manifest): `{manifest_digest}`
- Git commit: `{snapshot.get('git_commit', 'n/a')}`
- Git remote: `{snapshot.get('git_remote', 'n/a')}`

## How to verify independently

1. Recompute the manifest digest from the snapshot: walk the directory, hash
   each file with SHA-256, build the same `files` map (excluding
   {', '.join(sorted(DEFAULT_EXCLUDES))}; including {', '.join(sorted(INCLUDED_DOT_DIRS))}),
   canonicalize with JCS (RFC 8785), hash with SHA-256. It must equal the
   manifest digest above.
2. Verify `receipt.json`: take the receipt without its `signature` field,
   canonicalize with JCS, and verify the Ed25519 signature with the embedded
   public key. The signed digest must equal the manifest digest.
3. Open the Rekor entry URL in `anchor-record.json`. The on-log
   `spec.data.hash.value` (sha256) must equal the manifest digest. The Rekor
   entry carries an inclusion proof. No Correctover service is contacted.
4. If a DOI is present, open the DOI URL in `anchor-record.json` to retrieve
   this bundle from Zenodo.

Or run:

```bash
pip install jcs cryptography
python provenance.py verify <this-bundle-dir>
```

## Transparency anchor key note

Rekor's `hashedrekord` v0.0.1 entry type parses detached signatures as
Ed25519ph but verifies them with the artifact's SHA-256 hash algorithm, which
the Ed25519ph verifier rejects (it accepts only SHA-512). The interoperable
Sigstore default - ECDSA P-256 over SHA-256 - is therefore used for the
transparency anchor. The identity receipt remains Ed25519 (RFC 8032); both
keys belong to the same subject. See `anchor-record.json` for the anchor
public key and full note.
"""
    (bundle / "bundle-readme.md").write_text(txt, encoding="utf-8")


def write_result_env(path: Path, fields: dict) -> None:
    """Single-line KEY=VALUE file for CI consumption."""
    lines = []
    for k, v in fields.items():
        v = str(v if v is not None else "").replace("\n", " ").replace("\r", " ")
        lines.append(f"{k}={v}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_step_summary(path: Path, subject: dict, name: str, manifest_digest: str,
                       rekor_rec: dict, zenodo_rec: dict, bundle: Path) -> None:
    li = rekor_rec.get("log_index", "FAILED")
    search = rekor_rec.get("entry_url_search", "")
    api = rekor_rec.get("entry_url_api", "")
    lines = [
        "## :certificate: Code Birth Certificate",
        "",
        f"Snapshot **{name}** - evidence of existence and timestamp, anchored in "
        "the public Sigstore Rekor transparency log.",
        "",
        f"- **Manifest digest (SHA-256):** `{manifest_digest}`",
        f"- **Rekor log index:** [{li}]({search})",
        f"- **Rekor entry (API):** {api}",
        f"- **Inclusion proof:** {rekor_rec.get('inclusion_proof_present', False)}",
        f"- **Public fetch verified:** {rekor_rec.get('publicly_verified', False)}",
        f"- **Signed by:** {subject['name']} <{subject['email']}> (Ed25519, RFC 8032)",
    ]
    if zenodo_rec and zenodo_rec.get("doi"):
        lines += [
            f"- **Zenodo DOI:** [{zenodo_rec['doi']}]({zenodo_rec.get('doi_url','')})",
        ]
    lines += [
        "",
        "Verify independently (no Correctover service involved):",
        "",
        "```bash",
        f'curl -s "{api}" ',
        "# on-log spec.data.hash.value must equal the manifest digest above",
        "```",
        "",
        f"The full proof bundle is attached as artifact `code-birth-certificate-bundle` "
        f"({bundle.name}/).",
        "",
        "> Evidence of existence and timestamp only - not a copyright registration "
        "and not a legal opinion. Hashes prove byte identity, not semantic similarity.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# anchor command
# ---------------------------------------------------------------------------

def cmd_anchor(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"ERROR: target not found: {target}", file=sys.stderr)
        return 2
    keys_dir = Path(args.keys_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    name = args.name or target.name
    _, date_iso = utcnow()
    date = date_iso[:10]
    bundle = output_dir / f"{name}-{date}"
    bundle.mkdir(parents=True, exist_ok=True)

    subject = resolve_subject()
    ed_key, ec_key = load_keys(keys_dir)

    # 1) snapshot + manifest
    print(f"[1/5] snapshotting {target} ...")
    gi = git_info(target)
    pv = package_version(target)
    manifest = build_manifest(target, name, output_dir)
    manifest_digest = sha256_bytes(canonical_bytes(manifest))
    write_json(bundle / "manifest.json", manifest)
    print(f"      files: {manifest['file_count']}  manifest digest: {manifest_digest}")

    snapshot = {"snapshot_name": name, "source_path": str(target.resolve())}
    if pv:
        snapshot["package"] = pv
    snapshot.update(gi)

    # 2) Ed25519 receipt
    print("[2/5] signing Ed25519 identity receipt ...")
    receipt = build_receipt(ed_key, subject, manifest, manifest_digest, snapshot)
    write_json(bundle / "receipt.json", receipt)
    print(f"      receipt signed by {receipt['public_key_fingerprint_sha256_16']} "
          f"at {receipt['issued_at']} ({subject['name']})")

    # 3) Rekor anchor (the zero-credential core)
    print("[3/5] anchoring to Sigstore Rekor transparency log ...")
    rekor_rec: dict
    try:
        rekor_rec = rekor_anchor(ec_key, manifest_digest)
        print(f"      Rekor log index: {rekor_rec['log_index']}")
        print(f"      {rekor_rec['entry_url_search']}")
        print(f"      public fetch: HTTP {rekor_rec['public_fetch_http']} "
              f"(verified={rekor_rec['publicly_verified']})")
    except Exception as e:
        print(f"      REKOR FAILED: {e}", file=sys.stderr)
        rekor_rec = {"error": str(e), "anchored_digest_sha256": manifest_digest,
                     "publicly_verified": False, "inclusion_proof_present": False}

    # 4) write anchor record (pre-publish) + bundle readme
    anchor_record = {
        "spec": ANCHOR_SPEC,
        "anchored_at": utcnow()[1],
        "anchor_digest_sha256": manifest_digest,
        "subject": subject,
        "snapshot": snapshot,
        "rekor": rekor_rec,
        "zenodo": {"status": "pending"},
    }
    write_json(bundle / "anchor-record.json", anchor_record)
    write_bundle_readme(bundle, subject, manifest, snapshot, manifest_digest)

    # 5) Zenodo DOI (optional; skipped silently without a token)
    token = os.environ.get("ZENODO_TOKEN")
    zenodo_rec: dict
    if not token:
        print("[4/5] ZENODO_TOKEN not set - skipping DOI mint (Rekor anchor done).",
              file=sys.stderr)
        zenodo_rec = {"status": "skipped", "reason": "ZENODO_TOKEN not set"}
    else:
        print("[4/5] minting Zenodo DOI (create -> upload -> publish) ...")
        try:
            zrec = zenodo_publish(token, bundle, rekor_rec, manifest_digest, name, subject)
            zrec["status"] = "published"
            zenodo_rec = zrec
            print(f"      DOI: {zenodo_rec['doi']}  {zenodo_rec['doi_url']}")
        except Exception as e:
            print(f"      ZENODO FAILED: {e}", file=sys.stderr)
            zenodo_rec = {"status": "failed", "error": str(e)}

    # 6) finalize
    print("[5/5] writing proof bundle ...")
    anchor_record["zenodo"] = zenodo_rec
    if "log_index" in rekor_rec:
        anchor_record["badges_markdown"] = badges_md(
            rekor_rec, zenodo_rec if zenodo_rec.get("doi") else None)
    write_json(bundle / "anchor-record.json", anchor_record)
    if anchor_record.get("badges_markdown"):
        (bundle / "badges.md").write_text(anchor_record["badges_markdown"],
                                          encoding="utf-8")

    # Machine-readable outputs for the GitHub Action.
    write_result_env(output_dir / "result.env", {
        "MANIFEST_DIGEST": manifest_digest,
        "REKOR_LOG_INDEX": rekor_rec.get("log_index", ""),
        "REKOR_URL": rekor_rec.get("entry_url_search", ""),
        "REKOR_API_URL": rekor_rec.get("entry_url_api", ""),
        "REKOR_UUID": rekor_rec.get("entry_uuid", ""),
        "ZENODO_DOI": zenodo_rec.get("doi", ""),
        "ZENODO_DOI_URL": zenodo_rec.get("doi_url", ""),
        "BUNDLE_DIR": str(bundle),
        "BUNDLE_NAME": bundle.name,
        "REKOR_PUBLICLY_VERIFIED": str(rekor_rec.get("publicly_verified", False)),
    })
    write_step_summary(output_dir / "summary.md", subject, name,
                       manifest_digest, rekor_rec,
                       zenodo_rec if zenodo_rec.get("doi") else None, bundle)

    print(f"\nproof bundle: {bundle}")
    print(f"results:       {output_dir / 'result.env'}")
    print("done.")

    if args.strict:
        ok = bool(rekor_rec.get("publicly_verified")) and "log_index" in rekor_rec
        if token:
            ok = ok and bool(zenodo_rec.get("doi"))
        if not ok:
            print("STRICT MODE: anchor verification failed.", file=sys.stderr)
            return 1
    return 0


# ---------------------------------------------------------------------------
# verify command (independent; only public material + public log)
# ---------------------------------------------------------------------------

def cmd_verify(args: argparse.Namespace) -> int:
    bundle = Path(args.bundle).resolve()
    ok = True

    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    receipt = json.loads((bundle / "receipt.json").read_text(encoding="utf-8"))
    anchor = json.loads((bundle / "anchor-record.json").read_text(encoding="utf-8"))

    # 1) manifest digest
    md = sha256_bytes(canonical_bytes(manifest))
    print(f"manifest digest recomputed: {md}")
    print(f"  receipt says           : {receipt['manifest']['manifest_digest_sha256']}")
    match1 = (md == receipt["manifest"]["manifest_digest_sha256"])
    print(f"  match receipt: {match1}")
    ok &= match1

    # 2) Ed25519 receipt signature
    pk_b64 = receipt["public_key"]["raw_base64"]
    pub = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pk_b64))
    signed = {k: v for k, v in receipt.items() if k != "signature"}
    try:
        pub.verify(base64.b64decode(receipt["signature"]), canonical_bytes(signed))
        print("Ed25519 receipt signature: VALID")
    except InvalidSignature:
        print("Ed25519 receipt signature: INVALID")
        ok = False

    # 3) Rekor on-log hash consistency
    rekor = anchor.get("rekor", {})
    if rekor.get("entry_uuid"):
        url = rekor["entry_url_api"]
        code, resp = http_json(url)
        if code == 200 and isinstance(resp, dict):
            entry = resp.get(rekor["entry_uuid"])
            if entry:
                body = json.loads(base64.b64decode(entry["body"]))
                on_log_hash = body["spec"]["data"]["hash"]["value"]
                print(f"Rekor on-log digest: {on_log_hash}")
                match3 = (on_log_hash == md)
                print(f"  matches manifest digest: {match3}")
                inclusion = bool(entry.get("verification", {}).get("inclusionProof"))
                print(f"  inclusion proof present: {inclusion}")
                print(f"  log index: {entry.get('logIndex')}")
                ok &= match3 and inclusion
        else:
            print(f"Rekor fetch failed: HTTP {code}")
            ok = False
    else:
        print(f"Rekor: no entry ({rekor.get('error', 'n/a')})")

    # 4) DOI present
    z = anchor.get("zenodo", {})
    if z.get("doi"):
        print(f"Zenodo DOI: {z['doi']}  {z.get('doi_url')}")
    else:
        print(f"Zenodo: {z.get('status', 'missing')} {z.get('error','')}")

    print(f"\nVERIFICATION: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Code Birth Certificate CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate local identity keys")
    k.add_argument("--keys-dir", default=os.environ.get("CBC_KEYS_DIR", str(HERE / "keys")))
    a = sub.add_parser("anchor", help="snapshot -> manifest -> sign -> Rekor -> (optional DOI)")
    a.add_argument("target", help="code directory or repo path")
    a.add_argument("--name", help="snapshot name (default: directory name)")
    a.add_argument("--keys-dir", default=os.environ.get("CBC_KEYS_DIR", str(HERE / "keys")))
    a.add_argument("--output-dir", default=os.environ.get("CBC_OUTPUT_DIR", str(HERE / "output")))
    a.add_argument("--strict", action="store_true",
                   help="exit non-zero if the Rekor anchor (or DOI with token) fails")
    v = sub.add_parser("verify", help="independently verify a proof bundle")
    v.add_argument("bundle", help="proof bundle directory")
    args = ap.parse_args()
    if args.cmd == "keygen":
        keygen(Path(args.keys_dir))
        return 0
    if args.cmd == "anchor":
        return cmd_anchor(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())
