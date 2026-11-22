#!/usr/bin/env python3
from pathlib import Path
import json, hashlib
import numpy as np, pandas as pd
ROOT=Path(__file__).resolve().parents[1]; raw=ROOT/'raw'/'block_f'; out=ROOT/'analysis'
rows=[]
for p in sorted(raw.glob('*/result.json')):
 r=json.loads(p.read_text()); c=json.loads((p.parent/'configuration.json').read_text()); r.update({k:v for k,v in c.items() if k not in r})
 dg=[]
 for line in (p.parent/'datagrams.jsonl').read_text().splitlines():
  e=json.loads(line)
  if e.get('event')=='observed':dg.append(e)
 r['client_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='cs')
 r['server_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='sc')
 rows.append(r)
df=pd.DataFrame(rows).sort_values('run_order');df.to_csv(out/'block_F_trials.csv',index=False)
rng=np.random.default_rng(20261102); summ=[]
for (alg,group),g in df.groupby(['algorithm','group']):
 x=g.latency_ms.to_numpy(); sims=np.median(rng.choice(x,(20000,len(x)),replace=True),axis=1); lo,hi=np.quantile(sims,[.025,.975])
 summ.append(dict(algorithm=alg,group=group,n=len(g),successes=int(g.success.sum()),median_ms=float(np.median(x)),ci_low_ms=lo,ci_high_ms=hi,p95_ms=float(np.quantile(x,.95)),client_udp_bytes_median=float(g.client_udp_bytes.median()),server_udp_bytes_median=float(g.server_udp_bytes.median())))
s=pd.DataFrame(summ);s.to_csv(out/'block_F_summary.csv',index=False)
checks={'n_trials':len(df),'n_success':int(df.success.sum()),'all_verify_zero':bool((df.verify_result==0).all()),'all_not_resumed':bool((df.resumed==0).all()),'trials_sha256':hashlib.sha256((out/'block_F_trials.csv').read_bytes()).hexdigest()}
(out/'block_F_quality_checks.json').write_text(json.dumps(checks,indent=2))
print(s.to_string(index=False));print(json.dumps(checks,indent=2))
