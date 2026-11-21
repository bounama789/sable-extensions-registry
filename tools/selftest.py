#!/usr/bin/env python3
"""Self-test: generate a valid signed catalog + pack, verify with store_law."""
import base64, io, json, os, subprocess, sys, tempfile, zipfile
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L

def gen_key(d):
    os.makedirs(d, exist_ok=True)
    subprocess.run(['openssl','ecparam','-name','prime256v1','-genkey','-noout','-out',d+'/k.pem'],check=True,capture_output=True)
    subprocess.run(['openssl','ec','-in',d+'/k.pem','-pubout','-outform','DER','-out',d+'/k.der'],check=True,capture_output=True)
    return d+'/k.pem', base64.b64encode(open(d+'/k.der','rb').read()).decode()

def sign(data, priv, d):
    open(d+'/msg','wb').write(data)
    r = subprocess.run(['openssl','dgst','-sha256','-sign',priv,'-out',d+'/sig',d+'/msg'],capture_output=True)
    if r.returncode != 0: raise RuntimeError('openssl sign failed: ' + r.stderr.decode())
    return base64.b64encode(open(d+'/sig','rb').read()).decode()

def main():
    with tempfile.TemporaryDirectory() as d:
        root_priv, root_pub = gen_key(d+'/root')
        pub_priv, pub_pub = gen_key(d+'/pub')

        # A pack with extension.json + a script, signed by the publisher.
        files = {'extension.json': b'{"schemaVersion":1,"id":"sable.lang-python","name":"Python","version":"1.0.0","publisher":"sable","description":"d","license":"MIT","engines":{"api":"^1.0"}}',
                 'scripts/main.js': b'// hi'}
        digest = L.pack_digest(files)
        sig = sign(digest, pub_priv, d+'/pub')

        v = {'version':'1.0.0','ref':'0'*40,'repo':'sable-ide/ext-python',
             'sha256':digest.hex(),'signature':sig,'permissions':['workspace.read'],
             'minApi':26,'size':10}
        catalog = {'schema':1,'publisherKeys':{'sable':pub_pub},
                   'extensions':[{'id':'sable.lang-python','publisher':'sable','name':'Python',
                                  'summary':'Python support','kinds':['language'],'versions':[v]}]}
        cat_sig = sign(L.canonical_payload(catalog), root_priv, d+'/root')
        catalog['signature'] = cat_sig

        # Parse + verify catalog.
        parsed = L.parse_catalog(json.dumps(catalog).encode(), root_pub)
        assert parsed['extensions'][0]['id'] == 'sable.lang-python'

        # Pack zip (single top-level dir like codeload).
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,'w') as z:
            for name, body in files.items(): z.writestr('ext-python-abc/'+name, body)
        assert L.check_zip(buf.getvalue(), v, pub_pub), 'valid pack must pass'

        # Tampered catalog (change a field) must fail.
        bad = json.loads(json.dumps(catalog)); bad['extensions'][0]['summary']='EVIL'
        try:
            L.parse_catalog(json.dumps(bad).encode(), root_pub)
            assert False, 'tampered catalog accepted'
        except L.Reject:
            pass

        # Tampered pack must fail.
        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2,'w') as z:
            for name, body in files.items():
                z.writestr('ext-python-abc/'+name, b'EVIL' if name=='scripts/main.js' else body)
        assert not L.check_zip(buf2.getvalue(), v, pub_pub), 'tampered pack accepted'
        print('SELFTEST OK')

if __name__ == '__main__': main()
