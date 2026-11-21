#!/usr/bin/env python3
"""Publisher-side tool: build an entry file for YOUR extension.

Run this from your own machine against your own extension repo and YOUR
publisher private key. It never touches registry secrets. The output is a
self-contained entries/<id>.json you submit by PR to the registry.

Usage:
  SABLE_PUB_KEY=/path/to/your/private.pem python3 make-entry.py \
      --dir /path/to/pack --id sable.lang-python --repo owner/sable-ext-python \
      --ref <commit-sha> --version 1.0.0 --name Python --summary "..." \
      --kinds language --out entries/sable.lang-python.json
"""
import argparse, base64, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L
from publish import derive_pub_der_b64, sign

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dir', required=True, help='local pack directory (root = extension files)')
    ap.add_argument('--id', required=True)
    ap.add_argument('--repo', required=True, help='owner/name of the extension repo')
    ap.add_argument('--ref', required=True, help='immutable commit SHA the pack is published at')
    ap.add_argument('--version', required=True)
    ap.add_argument('--name', required=True)
    ap.add_argument('--summary', required=True)
    ap.add_argument('--kinds', required=True, help='comma-separated: language,theme,...')
    ap.add_argument('--permissions', default='workspace.read', help='comma-separated')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    key = os.environ['SABLE_PUB_KEY']  # publisher's own private key
    pub = derive_pub_der_b64(key, 'publisher', '/tmp/sable-entry')

    files = {}
    for root, _, fs in os.walk(a.dir):
        if '.git' in root.split(os.sep):
            continue
        for f in fs:
            p = os.path.join(root, f)
            rel = os.path.relpath(p, a.dir).replace(os.sep, '/')
            files[rel] = open(p, 'rb').read()
    digest = L.pack_digest(files)
    signature = sign(digest, key, a.id.replace('.', '_'), '/tmp/sable-entry')

    entry = {
        'id': a.id, 'publisher': a.id.split('.')[0],
        'name': a.name, 'summary': a.summary,
        'kinds': [k.strip() for k in a.kinds.split(',')],
        'publisherPublicKey': pub,
        'versions': [{
            'version': a.version, 'ref': a.ref, 'repo': a.repo,
            'sha256': digest.hex(), 'signature': signature,
            'permissions': [p.strip() for p in a.permissions.split(',')],
            'minApi': 26, 'size': sum(len(v) for v in files.values()),
        }],
    }
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    open(a.out, 'w').write(json.dumps(entry, indent=2) + '\n')
    print(f'wrote {a.out} ({len(files)} files, digest {digest.hex()[:12]}...)')

if __name__ == '__main__':
    main()
