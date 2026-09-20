#!/usr/bin/env python3
"""Local negative certificate-validation controls; no external hosts contacted."""
from pathlib import Path
import subprocess, socket, os, json, base64
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'raw/security_controls';OUT.mkdir(exist_ok=True)
def port():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p

def main():
 cert=ROOT/'certificates/mldsa44';bad=bytearray((cert/'leaf.der').read_bytes());bad[-1]^=1
 der=base64.b64encode(bad).decode();pem='-----BEGIN CERTIFICATE-----\n'+'\n'.join(der[i:i+64] for i in range(0,len(der),64))+'\n-----END CERTIFICATE-----\n'
 (OUT/'bad_signature_chain.pem').write_text(pem+(cert/'intermediate.pem').read_text())
 rows=[]
 cases=[('valid_full',cert/'chain.pem',cert/'root.pem',True),('valid_cached',cert/'leaf.pem',cert/'trust_cached.pem',True),('missing_intermediate',cert/'leaf.pem',cert/'root.pem',False),('unknown_root',cert/'chain.pem',ROOT/'certificates/mldsa65/root.pem',False),('modified_certificate_signature',OUT/'bad_signature_chain.pem',cert/'root.pem',False)]
 for name,chain,trust,expected in cases:
  d=OUT/name;d.mkdir(exist_ok=True);p=port();env=os.environ.copy();env['QUIC_RETRY']='0';env['QUIC_COMPRESS']='0'
  sf=open(d/'server.err','w');server=subprocess.Popen([str(ROOT/'bin/quic_probe'),'server',str(p),str(chain),str(cert/'leaf.key'),str(trust),'X25519MLKEM768','0',str(d/'server')],stdout=subprocess.PIPE,stderr=sf,env=env,text=True)
  ready=server.stdout.readline();(d/'server.out').write_text(ready)
  try:
   client=subprocess.run([str(ROOT/'bin/quic_probe'),'client',str(p),str(chain),str(cert/'leaf.key'),str(trust),'X25519MLKEM768','0',str(d/'client')],capture_output=True,text=True,env=env,timeout=5)
   (d/'client.out').write_text(client.stdout);(d/'client.err').write_text(client.stderr)
   actual=client.returncode==0;rows.append({'case':name,'expected_success':expected,'actual_success':actual,'passed':actual==expected,'client_returncode':client.returncode,'diagnostic':client.stderr})
  finally:
   if server.poll() is None:server.terminate()
   server.wait(timeout=2);sf.close()
 (OUT/'results.json').write_text(json.dumps(rows,indent=2));print(json.dumps([{k:v for k,v in x.items() if k!='diagnostic'}for x in rows],indent=2))
 if not all(x['passed'] for x in rows):raise SystemExit('negative controls failed')
if __name__=='__main__':main()
