#!/usr/bin/env python3
"""CI verification of submitted entries + the conformance vectors.

The registry is neutral: it knows no publisher's private key. A submission is
a self-contained entries/<id>.json carrying the publisher's public key and a
signature over the declared digest. This script verifies the law on every
entry: valid id/schema, repo@SHA format, digest, signature, permissions, and
the shared conformance vectors. Anything failing is a refused PR.
"""
import base64, glob, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L

REG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRIES = os.path.join(REG, 'entries')

def check_vectors():
    v = json.load(open(os.path.join(REG, 'conformance', 'vectors.json')))
    root = v['rootPublicKey']; pub = v['publisherPublicKey']
    cat = base64.b64decode(v['validCatalog'])
    parsed = L.parse_catalog(cat, root)
    assert parsed['extensions'][0]['id'] == 'sable.lang-python'
    ver = parsed['extensions'][0]['versions'][0]
    bad = json.loads(cat); bad['extensions'][0]['summary'] = 'EVIL'
    try:
        L.parse_catalog(json.dumps(bad).encode(), root); assert False, 'tampered catalog accepted'
    except L.Reject:
        pass
    assert L.check_zip(base64.b64decode(v['validPack']), ver, pub)
    assert not L.is_upgrade('2.0.0', '1.0.0')
    print('conformance vectors OK')

def check_entries():
    files = sorted(glob.glob(os.path.join(ENTRIES, '*.json')))
    if not files:
        print('no submitted entries yet (registry is empty)')
        return
    seen = set()
    for path in files:
        e = json.load(open(path))
        eid = e.get('id', '')
        # Identity law.
        parts = eid.split('.')
        assert len(parts) == 2 and all(L.PART.match(p) for p in parts), f'{path}: bad id'
        assert e.get('publisher') == parts[0], f'{path}: publisher mismatch'
        assert eid not in seen, f'{path}: duplicate id'
        seen.add(eid)
        pubkey = e.get('publisherPublicKey', '')
        assert L._is_p256_pub(pubkey), f'{path}: bad publisher public key'
        assert e.get('name', '').strip() and e.get('summary', '').strip(), f'{path}: blank fields'
        kinds = e.get('kinds', [])
        assert kinds and all(k in L.KNOWN_KINDS for k in kinds), f'{path}: bad kinds'
        versions = e.get('versions', [])
        assert versions, f'{path}: no versions'
        semvers = []
        for v in versions:
            sv = L._semver(v.get('version', ''))
            assert sv is not None, f'{path}: bad version'
            semvers.append(sv)
            assert L.REF.match(v.get('ref', '')), f'{path}: ref must be 40-hex SHA'
            assert L.REPO.match(v.get('repo', '')), f'{path}: repo must be owner/name'
            sha = v.get('sha256', '')
            assert L.SHA.match(sha), f'{path}: sha256 must be 64 hex'
            assert v.get('minApi', 0) >= 26, f'{path}: minApi too low'
            perms = v.get('permissions', [])
            assert perms and all(p in L.KNOWN_PERMS for p in perms), f'{path}: bad permissions'
            # A submission may include a publisher signature over the digest.
            # If present, it must verify with the submitted public key.
            sig = v.get('signature')
            if sig:
                try:
                    data = bytes.fromhex(sha)
                except ValueError:
                    raise AssertionError(f'{path}: bad digest hex')
                assert L.verify_signature(sig, data, pubkey), f'{path}: signature refused'
        assert semvers == sorted(semvers, reverse=True), f'{path}: versions not newest-first'
        print(f'entry OK: {eid}')

def main():
    check_vectors()
    check_entries()
    print('VERIFY OK')

if __name__ == '__main__':
    main()
