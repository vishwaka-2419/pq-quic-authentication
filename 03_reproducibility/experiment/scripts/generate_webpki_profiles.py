#!/usr/bin/env python3
"""Generate WebPKI-like laboratory leaf certificates for Block C.

The profile adds two SANs, AIA, OCSP, CRL distribution, certificate policies,
and a deterministic non-critical SCT-sized fixture extension. The fixture is
used only to reproduce certificate-size pressure; no claim is made that it is
a production CT proof or a browser-accepted SCT list.
"""
from pathlib import Path
import subprocess, hashlib, json, shutil
ROOT=Path(__file__).resolve().parents[1]

def cmd(*args):
 p=subprocess.run(['openssl',*map(str,args)],capture_output=True,text=True)
 if p.returncode: raise RuntimeError(p.stderr)
 return p.stdout

def main():
 out=[]
 # Valid DER OCTET STRING containing 242 deterministic bytes: 245 raw DER bytes.
 payload=bytes((i*73+19)%256 for i in range(242))
 sct_der=bytes([0x04,0x81,0xF2])+payload
 sct_hex=':'.join(f'{b:02X}' for b in sct_der)
 for alg in ['mldsa44','mldsa65']:
  src=ROOT/'certificates'/alg; dst=ROOT/'certificates_webpki'/alg
  dst.mkdir(parents=True,exist_ok=True)
  for name in ['root.pem','root.key','intermediate.pem','intermediate.key','leaf.key']:
   shutil.copy2(src/name,dst/name)
  conf=f'''basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:www.example.test
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=caIssuers;URI:http://ca.example.test/intermediate.der,OCSP;URI:http://ocsp.example.test/
crlDistributionPoints=URI:http://crl.example.test/root.crl
certificatePolicies=1.3.6.1.4.1.55555.1.1
1.3.6.1.4.1.11129.2.4.2=DER:{sct_hex}
'''
  (dst/'leaf_webpki.cnf').write_text(conf)
  cmd('req','-new','-key',dst/'leaf.key','-out',dst/'leaf.csr','-subj','/CN=localhost/O=Transport Experiment/C=CH')
  cmd('x509','-req','-in',dst/'leaf.csr','-CA',dst/'intermediate.pem','-CAkey',dst/'intermediate.key',
      '-set_serial','103','-days','3650','-extfile',dst/'leaf_webpki.cnf','-out',dst/'leaf.pem')
  (dst/'chain.pem').write_bytes((dst/'leaf.pem').read_bytes()+(dst/'intermediate.pem').read_bytes())
  (dst/'trust_cached.pem').write_bytes((dst/'root.pem').read_bytes()+(dst/'intermediate.pem').read_bytes())
  cmd('x509','-in',dst/'leaf.pem','-outform','DER','-out',dst/'leaf.der')
  leaf=(dst/'leaf.der').read_bytes()
  verify=cmd('verify','-CAfile',dst/'root.pem','-untrusted',dst/'intermediate.pem','-verify_hostname','localhost',dst/'leaf.pem').strip()
  out.append({'algorithm':alg,'leaf_der_bytes':len(leaf),'leaf_sha256':hashlib.sha256(leaf).hexdigest(),
              'verification':verify,'fixture_extension_oid':'1.3.6.1.4.1.11129.2.4.2',
              'fixture_raw_der_bytes':len(sct_der),'profile':'WebPKI-like laboratory profile'})
 (ROOT/'certificates_webpki'/'manifest.json').write_text(json.dumps(out,indent=2))
 print(json.dumps(out,indent=2))
if __name__=='__main__':main()
