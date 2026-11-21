#!/usr/bin/env python3
"""Build the signed catalog from pack repos. Config = packs.json; keys = env.

Two modes:
  --seed   one-time: create each pack repo and push its content from
           SABLE_APP_PACKS (local, needs write access to GitHub).
  default  CI: clone each pack repo at its default branch, digest the files,
           sign with SABLE_PUB_KEY / SABLE_ROOT_KEY (CI secrets), write
           catalog.json. Public keys are DERIVED from the private secrets —
           no separate public-key config to drift.
"""
import base64, json, os, shutil, subprocess, sys
sys.path.insert(0, os.path.dirname(__file__))
import store_law as L

REG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(REG, 'packs.json')

def run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, **kw)

def out(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, **kw)
    return r.stdout.decode().strip()

def keyfile(value, tag, work):
    """Accept a path OR inline PEM content (GH secret) and return a real path."""
    if not value:
        raise SystemExit('key value is empty')
    if value.lstrip().startswith('-----BEGIN'):
        os.makedirs(work, exist_ok=True)
        path = os.path.join(work, tag + '.key.pem')
        open(path, 'w').write(value if value.endswith('\n') else value + '\n')
        return path
    return value

def derive_pub_der_b64(priv, tag, work):
    os.makedirs(work, exist_ok=True)
    der = os.path.join(work, tag+'.pub.der')
    run(['openssl','pkey','-in',keyfile(priv,tag+'_pub',work),'-pubout','-outform','DER','-out',der])
    return base64.b64encode(open(der,'rb').read()).decode()

def sign(data, priv, tag, work):
    os.makedirs(work, exist_ok=True)
    m = os.path.join(work, tag+'.msg'); s = os.path.join(work, tag+'.sig')
    open(m,'wb').write(data)
    run(['openssl','dgst','-sha256','-sign',keyfile(priv,tag+'_sign',work),'-out',s,m])
    return base64.b64encode(open(s,'rb').read()).decode()

def load_config():
    return json.load(open(CONFIG))

def seed(cfg, owner):
    """One-time: create pack repos and push content from SABLE_APP_PACKS."""
    src_root = os.environ.get('SABLE_APP_PACKS')
    if not src_root: raise SystemExit('SABLE_APP_PACKS required for --seed')
    work = os.environ.get('SABLE_WORK','/tmp/sable-publish')
    for p in cfg['packs']:
        full=f'{owner}/{p["repo"]}'
        if subprocess.run(['gh','repo','view',full],capture_output=True).returncode!=0:
            run(['gh','repo','create',full,'--public','-y','--description',f'Sable extension: {p["name"]}'])
        clone=os.path.join(work,p['repo']+'-clone')
        if os.path.isdir(clone): shutil.rmtree(clone)
        run(['gh','repo','clone',full,clone])
        has=subprocess.run(['git','rev-parse','HEAD'],cwd=clone,capture_output=True).returncode==0
        if not has:
            src=os.path.join(src_root,p['source'])
            for f in os.listdir(src):
                s=os.path.join(src,f); t=os.path.join(clone,f)
                shutil.copytree(s,t,dirs_exist_ok=True) if os.path.isdir(s) else shutil.copy2(s,t)
            subprocess.run(['git','add','-A'],cwd=clone,check=True)
            subprocess.run(['git','-c','user.email=ci@sable.local','-c','user.name=Sable CI','commit','-qm','publish'],cwd=clone,check=True)
            run(['git','push','-u','origin','HEAD:main'],cwd=clone)
        print(f'seeded {full}')

def build(cfg, owner, work):
    root_key=os.environ['SABLE_ROOT_KEY']
    pub_key=os.environ['SABLE_PUB_KEY']
    root_pub=derive_pub_der_b64(root_key,'root',work)
    pub_pub=derive_pub_der_b64(pub_key,'pub',work)
    versions=[]
    for i,p in enumerate(cfg['packs']):
        full=f'{owner}/{p["repo"]}'
        clone=os.path.join(work,p['repo']+'-clone')
        if not os.path.isdir(os.path.join(clone,'.git')):
            run(['gh','repo','clone',full,clone])
        sha=out(['git','rev-parse','HEAD'],cwd=clone)
        files={}
        for root,_,fs in os.walk(clone):
            if '.git' in root.split(os.sep): continue
            for f in fs:
                path=os.path.join(root,f)
                rel=os.path.relpath(path,clone).replace(os.sep,'/')
                files[rel]=open(path,'rb').read()
        digest=L.pack_digest(files)
        sig=sign(digest,pub_key,p['id'].replace('.','_'),work)
        versions.append({
            'version':p['version'],'ref':sha,'repo':full,'sha256':digest.hex(),
            'signature':sig,'permissions':['workspace.read'],'minApi':26,
            'size':sum(len(v) for v in files.values()),
        })
        print(f'{p["id"]} @ {sha[:12]} ({len(files)} files)')
    catalog={
        'schema':1,'publisherKeys':{'sable':pub_pub},
        'extensions':[
            {'id':p['id'],'publisher':'sable','name':p['name'],'summary':p['summary'],
             'kinds':p['kinds'],'versions':[versions[i]]}
            for i,p in enumerate(cfg['packs'])
        ],
    }
    catalog['signature']=sign(L.canonical_payload(catalog),root_key,'catalog',work)
    path=os.path.join(REG,cfg['catalogPath'])
    open(path,'w').write(json.dumps(catalog,separators=(',',':'))+'\n')
    print('wrote',path,'root public key:',root_pub)

def main():
    cfg=load_config(); owner=cfg['owner']
    work=os.environ.get('SABLE_WORK','/tmp/sable-publish')
    if '--seed' in sys.argv: seed(cfg,owner)
    else: build(cfg,owner,work)

if __name__=='__main__': main()
