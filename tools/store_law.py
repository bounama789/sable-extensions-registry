#!/usr/bin/env python3
"""The store's verification law, ported 1:1 from the app's Kotlin (ext-store).

The app verifies with StoreSigning/StoreCatalogParser at install. This module
must agree with them byte-for-byte. tools/conformance vectors are the proof:
the same fixtures are checked by this script and by the Kotlin tests; if they
ever disagree, CI fails. Do not "fix" a mismatch here without also fixing the
Kotlin law and re-running the shared vectors.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile

# ---- canonical JSON (StoreSigning.canonicalPayload / canonical / quote) ----

def _quote(s: str) -> str:
    out = ['"']
    for c in s:
        if c == '"': out.append('\\"')
        elif c == '\\': out.append('\\\\')
        elif c == '\n': out.append('\\n')
        elif c == '\r': out.append('\\r')
        elif c == '\t': out.append('\\t')
        elif c == '\b': out.append('\\b')
        elif c == '\f': out.append('\\f')
        elif ord(c) < 0x20: out.append('\\u%04x' % ord(c))
        else: out.append(c)
    out.append('"')
    return ''.join(out)

def _num(value) -> str:
    # org.json parses integers as Int/Long and floats as Double; Kotlin's
    # Number.toString() must match. Catalog fields are ints only; be strict.
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value == int(value):
            return str(int(value)) + '.0'  # Kotlin Double.toString()
        return repr(value)
    raise ValueError('unsupported JSON number: %r' % (value,))

def canonical(value) -> str:
    if isinstance(value, dict):
        return '{' + ','.join(
            _quote(k) + ':' + canonical(value[k]) for k in sorted(value.keys())
        ) + '}'
    if isinstance(value, list):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return _num(value)
    if value is None:
        return 'null'
    raise ValueError('unsupported JSON value: %r' % (value,))

def canonical_payload(obj: dict) -> bytes:
    body = {k: v for k, v in obj.items() if k != 'signature'}
    return canonical(body).encode('utf-8')

# ---- signatures (StoreSigning.verifyRoot / verifyPack) ----

def _b64decode(s: str) -> bytes:
    return base64.b64decode(s, validate=True)

def verify_signature(sig_b64: str, data: bytes, pub_b64: str) -> bool:
    """ECDSA SHA256withECDSA, P-256, X.509 SPKI key. openssl CLI, no deps."""
    try:
        with tempfile.TemporaryDirectory() as d:
            pub = os.path.join(d, 'pub.der')
            sig = os.path.join(d, 'sig')
            msg = os.path.join(d, 'msg')
            open(pub, 'wb').write(_b64decode(pub_b64))
            open(sig, 'wb').write(_b64decode(sig_b64))
            open(msg, 'wb').write(data)
            # Convert DER SPKI -> PEM for openssl dgst.
            pem = os.path.join(d, 'pub.pem')
            subprocess.run(
                ['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', pub, '-out', pem],
                check=True, capture_output=True,
            )
            r = subprocess.run(
                ['openssl', 'dgst', '-sha256', '-verify', pem, '-signature', sig, msg],
                capture_output=True,
            )
            return r.returncode == 0 and b'Verified OK' in r.stdout
    except Exception:
        return False

# ---- pack digest (StoreSigning.packDigest) ----

def pack_digest(files: dict) -> bytes:
    """dict of rel-path -> bytes; SHA-256 over length-framed, path-sorted files."""
    h = hashlib.sha256()
    for path in sorted(files.keys()):
        p = path.encode('utf-8')
        b = files[path]
        h.update(p)
        h.update(b'\x00')
        h.update(len(p).to_bytes(4, 'big') + len(b).to_bytes(4, 'big'))
        h.update(b)
    return h.digest()

# ---- catalog schema (StoreCatalogParser) ----

SHA = __import__('re').compile(r'^[0-9a-fA-F]{64}$')
REF = __import__('re').compile(r'^[0-9a-f]{40}$')
REPO = __import__('re').compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$')
KNOWN_PERMS = {
    'process.exec', 'net.download', 'pkg.install', 'workspace.read',
    'workspace.write', 'editor.read', 'editor.edit', 'fs.outside',
    'terminal.run', 'agent.invoke', 'secrets.own', 'toolchains', 'events',
    'ui', 'tasks.run', 'agent.context', 'agent.policy', 'storage.own',
}
KNOWN_KINDS = {'language', 'theme', 'command', 'provider', 'hook'}
PART = __import__('re').compile(r'^[a-z][a-z0-9-]*$')

class Reject(Exception):
    pass

def parse_catalog(raw: bytes, root_pub_b64: str) -> dict:
    """Parse + verify a signed catalog. Returns parsed catalog or raises Reject."""
    try:
        obj = json.loads(raw.decode('utf-8'))
    except Exception as e:
        raise Reject('malformed JSON: %s' % e)
    if obj.get('schema') != 1:
        raise Reject('unsupported catalog schema')

    keys = obj.get('publisherKeys')
    if not isinstance(keys, dict) or not keys:
        raise Reject('no publisher keys')
    for name, key in keys.items():
        if not PART.match(name):
            raise Reject('malformed publisher key name')
        if not _is_p256_pub(key):
            raise Reject('publisher %s has no P-256 public key' % name)

    sig = obj.get('signature')
    if not isinstance(sig, str):
        raise Reject('root signature missing')
    try:
        _b64decode(sig)
    except Exception:
        raise Reject('root signature not base64')

    exts = obj.get('extensions')
    if not isinstance(exts, list):
        raise Reject('extensions missing')
    seen = set()
    for e in exts:
        ext_id = e.get('id', '')
        parts = ext_id.split('.')
        if len(parts) != 2 or not all(PART.match(p) for p in parts):
            raise Reject('bad id %s' % ext_id)
        pub = e.get('publisher')
        if pub != parts[0]:
            raise Reject('id publisher mismatch')
        if pub not in keys:
            raise Reject('no key for publisher %s' % pub)
        if ext_id in seen:
            raise Reject('duplicate id')
        seen.add(ext_id)
        if not str(e.get('name', '')).strip() or not str(e.get('summary', '')).strip():
            raise Reject('blank name or summary')
        kinds = e.get('kinds', [])
        if not kinds or any(k not in KNOWN_KINDS for k in kinds):
            raise Reject('bad kinds')
        versions = e.get('versions', [])
        if not versions:
            raise Reject('no versions')
        prev = None
        semvers = []
        for v in versions:
            text = v.get('version', '')
            sv = _semver(text)
            if sv is None:
                raise Reject('bad version %s' % text)
            semvers.append(sv)
            if not REF.match(v.get('ref', '')):
                raise Reject('ref must be 40-hex SHA')
            if not REPO.match(v.get('repo', '')):
                raise Reject('repo must be owner/name')
            sha = v.get('sha256', '')
            if not SHA.match(sha):
                raise Reject('sha256 must be 64 hex')
            try:
                _b64decode(v.get('signature', ''))
            except Exception:
                raise Reject('signature not base64')
            perms = v.get('permissions', [])
            if not perms or any(p not in KNOWN_PERMS for p in perms):
                raise Reject('bad permissions')
            if v.get('minApi', 0) < 26:
                raise Reject('minApi below 26')
            if v.get('size', -1) < 0:
                raise Reject('negative size')
        if len(set(semvers)) != len(semvers):
            raise Reject('duplicate version')
        if semvers != sorted(semvers, reverse=True):
            raise Reject('versions not newest-first')

    if not verify_signature(sig, canonical_payload(obj), root_pub_b64):
        raise Reject('root signature refused')
    return obj

def _semver(text: str):
    import re
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.\-]+)?$', text.strip())
    if not m: return None
    if (int(m.group(1)), int(m.group(2)), int(m.group(3))) == (0, 0, 0):
        return None
    pre = m.group(4)[1:] if m.group(4) else None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre or '')

def is_upgrade(installed: str, candidate: str) -> bool:
    a, b = _semver(installed), _semver(candidate)
    return a is not None and b is not None and b > a

def _is_p256_pub(key_b64: str) -> bool:
    try:
        with tempfile.TemporaryDirectory() as d:
            pub = os.path.join(d, 'pub.der')
            open(pub, 'wb').write(_b64decode(key_b64))
            r = subprocess.run(
                ['openssl', 'pkey', '-pubin', '-inform', 'DER', '-in', pub,
                 '-text', '-noout'], capture_output=True,
            )
            if r.returncode != 0: return False
            text = r.stdout.decode()
            return 'prime256v1' in text or 'secp256r1' in text or 'P-256' in text
    except Exception:
        return False

# ---- zip unpacking safety (PackFetcher.unzip) ----

def check_zip(data: bytes, version: dict, pub_b64: str) -> bool:
    """Verify a pack zip: no traversal, declared digest + publisher signature."""
    files = {}
    try:
        with zipfile.ZipFile(__import__('io').BytesIO(data)) as z:
            names = z.namelist()
            for name in names:
                if name.startswith('/') or name.startswith('\\') or '..' in name:
                    return False
                if len(names) > 2000: return False
                if not name.endswith('/'):
                    files[name] = z.read(name)
    except Exception:
        return False
    # Strip single top-level dir like PackFetcher (codeload repo-sha/).
    top_dirs = set(n.split('/')[0] for n in files if '/' in n)
    top_files = [n for n in files if '/' not in n]
    if not top_files and len(top_dirs) == 1:
        prefix = next(iter(top_dirs)) + '/'
        files = {n[len(prefix):]: v for n, v in files.items() if n.startswith(prefix)}
    digest = pack_digest(files)
    declared = version.get('sha256', '')
    if declared.lower() != digest.hex():
        return False
    return verify_signature(version.get('signature', ''), digest, pub_b64)
