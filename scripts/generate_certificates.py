#!/usr/bin/env python3
"""Generate laboratory-only private-CA hierarchies with OpenSSL."""
from pathlib import Path
import subprocess, json, hashlib
ROOT=Path(__file__).resolve().parents[1]
def cmd(*args):
 p=subprocess.run(['openssl',*map(str,args)],capture_output=True,text=True)
 if p.returncode:raise RuntimeError(p.stderr)
 return p.stdout

def main():
 manifest=[]
 for name,alg in [('ecdsa','EC'),('mldsa44','ML-DSA-44'),('mldsa65','ML-DSA-65'),('mldsa87','ML-DSA-87')]:
  d=ROOT/'certificates'/name;d.mkdir(parents=True,exist_ok=True)
  ca='basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
  leaf='basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n'
  (d/'ca.cnf').write_text(ca);(d/'leaf.cnf').write_text(leaf)
  for part in ['root','intermediate','leaf']:
   opts=['genpkey','-algorithm',alg,'-out',d/f'{part}.key']
   if alg=='EC':opts+=['-pkeyopt','ec_paramgen_curve:P-256']
   cmd(*opts)
   cmd('req','-new','-key',d/f'{part}.key','-out',d/f'{part}.csr','-subj',f'/CN=QUIC {part}/O=Transport Experiment')
  cmd('req','-new','-x509','-key',d/'root.key','-out',d/'root.pem','-days','3650','-set_serial','1','-subj','/CN=QUIC Root/O=Transport Experiment','-addext','basicConstraints=critical,CA:true','-addext','keyUsage=critical,keyCertSign,cRLSign')
  for part,issuer,serial in [('intermediate','root','2'),('leaf','intermediate','3')]:
   cmd('x509','-req','-in',d/f'{part}.csr','-CA',d/f'{issuer}.pem','-CAkey',d/f'{issuer}.key','-set_serial',serial,'-days','3650','-extfile',d/('leaf.cnf' if part=='leaf' else 'ca.cnf'),'-out',d/f'{part}.pem')
  (d/'chain.pem').write_bytes((d/'leaf.pem').read_bytes()+(d/'intermediate.pem').read_bytes())
  (d/'trust_cached.pem').write_bytes((d/'root.pem').read_bytes()+(d/'intermediate.pem').read_bytes())
  rec={'id':name,'algorithm':alg}
  for part in ['root','intermediate','leaf']:
   cmd('x509','-in',d/f'{part}.pem','-outform','DER','-out',d/f'{part}.der')
   data=(d/f'{part}.der').read_bytes();rec[part+'_bytes']=len(data);rec[part+'_sha256']=hashlib.sha256(data).hexdigest()
  rec['verification']=cmd('verify','-CAfile',d/'root.pem','-untrusted',d/'intermediate.pem','-verify_hostname','localhost',d/'leaf.pem').strip()
  manifest.append(rec)
 (ROOT/'certificates'/'manifest.json').write_text(json.dumps({'openssl':cmd('version'),'certificates':manifest},indent=2))
 print(json.dumps(manifest,indent=2))
if __name__=='__main__':main()
