#!/usr/bin/env python3
"""Serialize and verify laboratory RFC 6962 v1 SCT lists, offline only.

Private log keys and private-CA certificates are used. These are not browser-
trusted SCTs. No transparency acceptance or MTC QUIC implementation is claimed.
"""
from pathlib import Path
from hashlib import sha256
import json,zlib,base64
import pandas as pd
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'raw/transparency';OUT.mkdir(exist_ok=True)
def u16(n):return int(n).to_bytes(2,'big')
def u24(n):return int(n).to_bytes(3,'big')
def main():
 keys=[ec.generate_private_key(ec.SECP256R1()) for _ in range(2)];rows=[]
 for i,key in enumerate(keys):
  (OUT/f'log{i}.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 for alg in ['ecdsa','mldsa44','mldsa65','mldsa87']:
  leaf=(ROOT/'certificates'/alg/'leaf.der').read_bytes();inter=(ROOT/'certificates'/alg/'intermediate.der').read_bytes();scts=[]
  for i,key in enumerate(keys):
   timestamp=(1789905600000+i).to_bytes(8,'big')
   signed=b'\0\0'+timestamp+u16(0)+u24(len(leaf))+leaf+u16(0)
   sig=key.sign(signed,ec.ECDSA(hashes.SHA256()));key.public_key().verify(sig,signed,ec.ECDSA(hashes.SHA256()))
   spki=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
   sct=b'\0'+sha256(spki).digest()+timestamp+u16(0)+bytes([4,3])+u16(len(sig))+sig
   scts.append(u16(len(sct))+sct)
  blob=b''.join(scts);sctlist=u16(len(blob))+blob;ext=u16(18)+u16(len(sctlist))+sctlist
  for cached in [False,True]:
   for with_sct in [False,True]:
    e=ext if with_sct else b''
    entries=u24(len(leaf))+leaf+u16(len(e))+e
    if not cached:entries+=u24(len(inter))+inter+u16(0)
    body=b'\0'+u24(len(entries))+entries;message=bytes([11])+u24(len(body))+body
    name=f'{alg}_{"cached" if cached else "full"}_{"sct" if with_sct else "plain"}'
    (OUT/f'{name}.bin').write_bytes(message)
    compressed=zlib.compress(body)
    rows.append({'algorithm':alg,'cached':cached,'sct_count':2 if with_sct else 0,'certificate_message_bytes':len(message),'compressed_certificate_message_bytes':12+len(compressed),'sct_list_bytes':len(sctlist) if with_sct else 0,'sct_signature_verification':True,'scope':'offline RFC6962 v1 X509-entry encoding; private logs; not sent in native QUIC'})
  (OUT/f'{alg}_sctlist.bin').write_bytes(sctlist)
 pd.DataFrame(rows).to_csv(ROOT/'analysis/transparency_costs.csv',index=False)
 (OUT/'manifest.json').write_text(json.dumps(rows,indent=2));print(pd.DataFrame(rows).to_string(index=False))
if __name__=='__main__':main()
