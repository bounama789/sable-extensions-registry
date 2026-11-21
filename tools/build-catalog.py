#!/usr/bin/env python3
"""Assemble accepted submissions into catalog.json, signed by the root key.

The registry's only signing act is the CATALOG, using SABLE_ROOT_KEY (CI secret).
It never signs a publisher's pack — that signature comes from the publisher and
is carried in the entry. Public keys are aggregated from the entries themselves.
"""
import glob, json, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L
from publish import derive_pub_der_b64, sign

REG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENTRIES = os.path.join(REG, 'entries')

def main():
    root_key = os.environ['SABLE_ROOT_KEY']
    work = os.environ.get('SABLE_WORK', '/tmp/sable-catalog')
    root_pub = derive_pub_der_b64(root_key, 'root', work)

    entries = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(ENTRIES, '*.json')))]
    publisher_keys = {}
    extension_rows = []
    for e in entries:
        publisher_keys[e['publisher']] = e['publisherPublicKey']
        extension_rows.append({
            'id': e['id'], 'publisher': e['publisher'], 'name': e['name'],
            'summary': e['summary'], 'kinds': e['kinds'], 'versions': e['versions'],
        })
    catalog = {'schema': 1, 'publisherKeys': publisher_keys, 'extensions': extension_rows}
    catalog['signature'] = sign(L.canonical_payload(catalog), root_key, 'catalog', work)
    path = os.path.join(REG, 'catalog.json')
    open(path, 'w').write(json.dumps(catalog, separators=(',', ':')) + '\n')
    print(f'wrote {path}: {len(extension_rows)} extensions, root public key {root_pub[:24]}...')

if __name__ == '__main__':
    main()
