#!/usr/bin/env python3
from pathlib import Path
import json, math, hashlib
import numpy as np, pandas as pd
from scipy.stats import norm
ROOT=Path(__file__).resolve().parents[1]; raw=ROOT/'raw'/'block_c'; out=ROOT/'analysis'; out.mkdir(exist_ok=True)
def wilson(k,n):
 z=norm.ppf(.975);p=k/n;d=1+z*z/n;c=(p+z*z/(2*n))/d;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d;return c-h,c+h
rows=[]
for p in sorted(raw.glob('*/result.json')):
 r=json.loads(p.read_text());c=json.loads((p.parent/'configuration.json').read_text());r.update({k:v for k,v in c.items() if k not in r})
 dg=[]
 for line in (p.parent/'datagrams.jsonl').read_text().splitlines():
  e=json.loads(line)
  if e.get('event')=='observed': dg.append(e)
 r['client_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='cs')
 r['server_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='sc')
 r['client_datagrams']=sum(e['direction']=='cs' for e in dg)
 r['server_datagrams']=sum(e['direction']=='sc' for e in dg)
 tls=[]
 for line in (p.parent/'server.tls.jsonl').read_text().splitlines():
  e=json.loads(line)
  if e.get('write')==1:tls.append(e)
 r['server_tls_bytes']=sum(e['length'] for e in tls)
 rows.append(r)
df=pd.DataFrame(rows).sort_values('run_order');df.to_csv(out/'block_C_trials.csv',index=False)
rng=np.random.default_rng(20261103);summ=[]
for (alg,ci,ce),g in df.groupby(['algorithm','cached','enlargement_bytes']):
 n=len(g);k=int(g.first_band.sum());lo,hi=wilson(k,n);x=g.latency_ms.to_numpy();sims=np.median(rng.choice(x,(20000,n),replace=True),axis=1);mlo,mhi=np.quantile(sims,[.025,.975])
 summ.append(dict(algorithm=alg,profile='webpki-like',cached=ci,enlargement_bytes=ce,n=n,successes=int(g.success.sum()),first_band=k,first_band_rate=k/n,wilson_low=lo,wilson_high=hi,median_ms=float(np.median(x)),median_ci_low_ms=mlo,median_ci_high_ms=mhi,server_tls_bytes_median=float(g.server_tls_bytes.median()),client_udp_bytes_median=float(g.client_udp_bytes.median()),server_udp_bytes_median=float(g.server_udp_bytes.median()),client_datagrams_median=float(g.client_datagrams.median()),server_datagrams_median=float(g.server_datagrams.median())))
s=pd.DataFrame(summ);s.to_csv(out/'block_C_summary.csv',index=False)
checks={'n_trials':len(df),'n_success':int(df.success.sum()),'n_failures':int((~df.success).sum()),'all_verify_zero':bool((df.verify_result==0).all()),'all_hybrid_group':bool((df.group=='X25519MLKEM768').all()),'all_not_resumed':bool((df.resumed==0).all()),'trials_sha256':hashlib.sha256((out/'block_C_trials.csv').read_bytes()).hexdigest()}
(out/'block_C_quality_checks.json').write_text(json.dumps(checks,indent=2))
# compare with Block A matching cells
A=pd.read_csv(out/'block_A_summary.csv'); merged=s.merge(A,on=['algorithm','cached','enlargement_bytes'],suffixes=('_web','_lab'))
merged['delta_tls_bytes']=merged.server_tls_bytes_median_web-merged.server_tls_bytes_median_lab
merged['delta_median_ms']=merged.median_ms_web-merged.median_ms_lab
merged.to_csv(out/'block_C_vs_A.csv',index=False)
print(s.to_string(index=False));print('\nComparison\n',merged[['algorithm','cached','enlargement_bytes','first_band_web','first_band_lab','server_tls_bytes_median_web','server_tls_bytes_median_lab','delta_tls_bytes','median_ms_web','median_ms_lab','delta_median_ms']].to_string(index=False));print('\n',json.dumps(checks,indent=2))
