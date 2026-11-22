#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import json, math, hashlib
import numpy as np
import pandas as pd
from scipy.stats import fisher_exact
from scipy.stats import norm

ROOT=Path(__file__).resolve().parents[1]
RAW=ROOT/'raw'/'block_a'
OUT=ROOT/'analysis'
OUT.mkdir(exist_ok=True)
SEED=20261101

def wilson(k,n,alpha=.05):
    if n==0:return (math.nan,math.nan)
    z=norm.ppf(1-alpha/2); p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d
    h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return c-h,c+h

def bootstrap_median(x,reps=20000,seed=SEED):
    x=np.asarray(x,float); rng=np.random.default_rng(seed)
    sims=np.median(rng.choice(x,(reps,len(x)),replace=True),axis=1)
    return np.quantile(sims,[.025,.975])

def round_class(ms,rtt=60):
    if ms < 1.5*rtt:return 1
    if ms < 2.5*rtt:return 2
    return 3

rows=[]
for p in sorted(RAW.glob('*/result.json')):
    rec=json.loads(p.read_text()); cfg=json.loads((p.parent/'configuration.json').read_text())
    rec.update({k:v for k,v in cfg.items() if k not in rec})
    # derive datagram/TLS quantities from the retained raw files
    dg=[]
    for line in (p.parent/'datagrams.jsonl').read_text().splitlines():
        e=json.loads(line)
        if e.get('event')=='observed':dg.append(e)
    rec['client_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='cs')
    rec['server_udp_bytes']=sum(e['bytes'] for e in dg if e['direction']=='sc')
    rec['client_datagrams']=sum(1 for e in dg if e['direction']=='cs')
    rec['server_datagrams']=sum(1 for e in dg if e['direction']=='sc')
    tls=[]
    tf=p.parent/'server.tls.jsonl'
    if tf.exists():
        for line in tf.read_text().splitlines():
            e=json.loads(line)
            if e.get('write')==1:tls.append(e)
    rec['server_tls_bytes']=sum(e['length'] for e in tls)
    rec['rounds']=round_class(rec['latency_ms']) if rec.get('success') else None
    rows.append(rec)

df=pd.DataFrame(rows).sort_values('run_order')
df.to_csv(OUT/'block_A_trials.csv',index=False)

summ=[]
for keys,g in df.groupby(['algorithm','cached','enlargement_bytes'],sort=True):
    alg,ci,ce=keys;n=len(g);k=int(g['first_band'].sum());lo,hi=wilson(k,n)
    med=float(g['latency_ms'].median());mlo,mhi=bootstrap_median(g['latency_ms'],seed=SEED+len(summ))
    rc=g['rounds'].value_counts().to_dict()
    summ.append(dict(algorithm=alg,cached=ci,enlargement_bytes=ce,n=n,successes=int(g['success'].sum()),
                     first_band=k,first_band_rate=k/n,wilson_low=lo,wilson_high=hi,
                     median_ms=med,median_ci_low_ms=mlo,median_ci_high_ms=mhi,
                     rounds_1=int(rc.get(1,0)),rounds_2=int(rc.get(2,0)),rounds_3=int(rc.get(3,0)),
                     client_udp_bytes_median=float(g['client_udp_bytes'].median()),
                     server_udp_bytes_median=float(g['server_udp_bytes'].median()),
                     server_tls_bytes_median=float(g['server_tls_bytes'].median()),
                     client_datagrams_median=float(g['client_datagrams'].median()),
                     server_datagrams_median=float(g['server_datagrams'].median())))
s=pd.DataFrame(summ)
s.to_csv(OUT/'block_A_summary.csv',index=False)

# exact one-sided contrasts for the pre-specified ML-DSA-44 and -65 hypotheses
contr=[]
for alg in ['mldsa44','mldsa65']:
    cells={(bool(r.cached),int(r.enlargement_bytes)):r for _,r in s[s.algorithm==alg].iterrows()}
    both=cells[(True,2400)]
    for label,key in [('CI+CE_vs_CI',(True,0)),('CI+CE_vs_CE',(False,2400))]:
        comp=cells[key]
        table=[[int(both.first_band),int(both.n-both.first_band)],
               [int(comp.first_band),int(comp.n-comp.first_band)]]
        odds,p=fisher_exact(table,alternative='greater')
        contr.append(dict(algorithm=alg,contrast=label,odds_ratio=odds,p_raw=p))
c=pd.DataFrame(contr)
# Holm across the two algorithms within each contrast family
c['p_holm']=np.nan
for label,idx in c.groupby('contrast').groups.items():
    idx=list(idx); vals=c.loc[idx,'p_raw'].to_numpy(); order=np.argsort(vals)
    adjusted=np.empty_like(vals)
    running=0.0
    for rank,pos in enumerate(order):
        val=min(1.0,(len(vals)-rank)*vals[pos]); running=max(running,val); adjusted[pos]=running
    c.loc[idx,'p_holm']=adjusted
c.to_csv(OUT/'block_A_fisher_tests.csv',index=False)

# additive interaction contrasts with stratified nonparametric bootstrap
ints=[]
for alg in ['mldsa44','mldsa65']:
    sub=df[df.algorithm==alg]
    cell_arrays={}
    for ci in [False,True]:
      for ce in [0,2400]:
        cell_arrays[(ci,ce)]=sub[(sub.cached==ci)&(sub.enlargement_bytes==ce)]['first_band'].astype(int).to_numpy()
    point=cell_arrays[(True,2400)].mean()-cell_arrays[(True,0)].mean()-cell_arrays[(False,2400)].mean()+cell_arrays[(False,0)].mean()
    rng=np.random.default_rng(SEED+(44 if alg=='mldsa44' else 65)); sims=np.empty(100000)
    for i in range(len(sims)):
      means={k:rng.choice(v,len(v),replace=True).mean() for k,v in cell_arrays.items()}
      sims[i]=means[(True,2400)]-means[(True,0)]-means[(False,2400)]+means[(False,0)]
    lo,hi=np.quantile(sims,[.025,.975])
    ints.append(dict(algorithm=alg,interaction_contrast=point,ci_low=lo,ci_high=hi,bootstrap_reps=len(sims)))
pd.DataFrame(ints).to_csv(OUT/'block_A_interaction.csv',index=False)

# protocol checks
checks={
 'n_trials':int(len(df)),
 'n_success':int(df.success.sum()),
 'n_failures':int((~df.success).sum()),
 'all_verify_zero':bool((df.verify_result==0).all()),
 'all_hybrid_group':bool((df.group=='X25519MLKEM768').all()),
 'all_not_resumed':bool((df.resumed==0).all()),
 'unique_ids':bool(df.id.is_unique),
 'run_orders_complete':bool(sorted(df.run_order.tolist())==list(range(480))),
 'preregistration_sha256':json.loads((OUT/'preregistration_block_A.json').read_text())['sha256'],
 'trials_sha256':hashlib.sha256((OUT/'block_A_trials.csv').read_bytes()).hexdigest(),
}
(OUT/'block_A_quality_checks.json').write_text(json.dumps(checks,indent=2))

print(s.to_string(index=False))
print('\nFisher tests\n',c.to_string(index=False))
print('\nInteraction\n',pd.DataFrame(ints).to_string(index=False))
print('\nChecks\n',json.dumps(checks,indent=2))
