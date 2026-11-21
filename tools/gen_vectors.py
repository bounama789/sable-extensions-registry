#!/usr/bin/env python3
"""Generate conformance vectors: signed catalog + pack, and expected verdicts.

The vector file is checked by BOTH the Python CI verifier and the app's Kotlin
tests. If the two implementations ever disagree on a vector, that is a bug in
one of them and CI fails. Private keys are never written to the vector file —
only the signatures and public keys needed to verify.
"""
import base64, io, json, os, subprocess, sys, tempfile, zipfile
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L

def keypair(d):
    os.makedirs(d, exist_ok=True)
    subprocess.run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',d+'/k.pem'],check=True,capture_output=True)
    subprocess.run(['openssl','ec','-in',d+'/k.pem','-pubout','-outform','DER','-out',d+'/k.der'],check=True,capture_output=True)
    return d+'/k.pem', base64.b64encode(open(d+'/k.der','rb').read()).decode()

def sign(data, priv, d):
    os.makedirs(d, exist_ok=True)
    open(d+'/msg','wb').write(data)
    subprocess.run(['openssl','dgst','-sha256','-sign',priv,'-out',d+'/sig',d+'/msg'],check=True,capture_output=True)
    return base64.b64encode(open(d+'/sig','rb').read()).decode()

def b64(b): return base64.b64encode(b).decode()

def main():
    with tempfile.TemporaryDirectory() as d:
        root_priv, root_pub = keypair(d+'/root')
        pub_priv, pub_pub = keypair(d+'/pub')

        files = {
            'extension.json': b'{"schemaVersion":1,"id":"sable.lang-python","name":"Python","version":"1.0.0","publisher":"sable","description":"Python support","license":"MIT","engines":{"api":"^1.0"}}',
            'scripts/main.js': b'// conformance fixture\n',
        }
        digest = L.pack_digest(files)
        v = {'version':'1.0.0','ref':'0'*40,'repo':'sable-ide/ext-python',
             'sha256':digest.hex(),'signature':sign(digest, pub_priv, d+'/pub'),
             'permissions':['workspace.read'],'minApi':26,'size':10}
        catalog = {'schema':1,'publisherKeys':{'sable':pub_pub},
                   'extensions':[{'id':'sable.lang-python','publisher':'sable','name':'Python',
                                  'summary':'Python support','kinds':['language'],'versions':[v]}]}
        catalog['signature'] = sign(L.canonical_payload(catalog), root_priv, d+'/root')
        cat_bytes = json.dumps(catalog, separators=(',',':')).encode()

        # Valid pack zip (single top-level codeload dir).
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            for name, body in files.items(): z.writestr('ext-python-'+'0'*7+'/'+name, body)
        pack = buf.getvalue()

        vectors = {
            'rootPublicKey': root_pub,
            'publisherPublicKey': pub_pub,
            'validCatalog': b64(cat_bytes),
            'validPack': b64(pack),
            'expected': {
                'valid_catalog_accepts': True,
                'tampered_catalog_rejects': True,
                'valid_pack_verifies': True,
                'tampered_pack_rejects': True,
                'traversal_pack_rejects': True,
                'downgrade_refused': True,
            },
        }
        out = os.path.join(os.path.dirname(__file__), '..', 'conformance', 'vectors.json')
        os.makedirs(os.path.dirname(out), exist_ok=True)
        open(out,'w').write(json.dumps(vectors, indent=2)+'\n')
        print('wrote', out)

if __name__ == '__main__': main()
