#!/usr/bin/env python3
"""Generate manuscript tables directly from archived analysis outputs."""
from pathlib import Path
import pandas as pd
R=Path(__file__).resolve().parents[1];O=R/'paper/generated';O.mkdir(exist_ok=True)
s=pd.read_csv(R/'analysis/summary.csv');d=pd.read_csv(R/'analysis/trials.csv')
algs=['mldsa44','mldsa65','mldsa87'];names={'ecdsa':'ECDSA','mldsa44':'ML-DSA-44','mldsa65':'ML-DSA-65','mldsa87':'ML-DSA-87'}
q=d[(d.loss==0)&(d.rtt_ms==60)&(d.condition=='plain')&(d.up_mbps==100)]
rows=[]
for a,g in [('ecdsa','X25519'),('ecdsa','X25519MLKEM768')]+[(a,'X25519MLKEM768')for a in algs]:
 z=q[(q.algorithm==a)&(q.group==g)]
 vals=[z[c].median()for c in ['client_hello_bytes','certificate_bytes','certificate_verify_bytes','tls_server_bytes','authentication_udp_bytes']]
 rows.append(names[a]+(' / X'if g=='X25519'else' / H')+' & '+' & '.join(f'{v:,.0f}'for v in vals)+r' \\')
(O/'sizes.tex').write_text('\n'.join(rows)+'\n')
q=s[(s.loss==0)&(s.rtt_ms==60)&(s.up_mbps==100)&(s.group=='X25519MLKEM768')]
rows=[]
conds=['plain','compressed','cached','padding','cached_padding','cached_compressed_padding']
labels=['Full chain','Certificate compression','Cached intermediate','ClientHello enlargement','Cache + enlargement','Cache + compression + enlargement']
for cond,lab in zip(conds,labels):
 vals=[]
 for a in algs:
  z=q[(q.algorithm==a)&(q.condition==cond)].iloc[0]
  vals.append(f'{z.median_ms:.2f} [{z.ci_low_ms:.2f}, {z.ci_high_ms:.2f}]')
 rows.append(lab+' & '+' & '.join(vals)+r' \\')
(O/'interventions.tex').write_text('\n'.join(rows)+'\n')
rows=[]
for _,z in s[s.loss>0].iterrows():
 rows.append(f"{names[z.algorithm]} & {'Full' if z.condition=='plain' else 'Cached'} & {100*z.loss:.0f} & {'Burst' if z.burst else 'Independent'} & {z.successes}/{z.n} & {z.median_ms:.2f} & {z.p95_success_ms:.2f}"+r' \\')
(O/'loss.tex').write_text('\n'.join(rows)+'\n')
rows=[]
for _,z in s[(s.loss==0)&(s.condition.isin(['plain','retry']))&(s.up_mbps==100)].iterrows():
 rows.append(f"{names[z.algorithm]} & {'X' if z.group=='X25519' else 'H'} & {z.condition.capitalize()} & {z.rtt_ms:.0f} & {z.n} & {z.median_ms:.2f} & [{z.ci_low_ms:.2f}, {z.ci_high_ms:.2f}]"+r' \\')
(O/'baseline.tex').write_text('\n'.join(rows)+'\n')
rows=[]
q=d[(d.algorithm=='mldsa65')&(d.condition.isin(['cached_padding','cached_padding900']))&(d.loss==0)&(d.up_mbps==100)]
for keys,z in q.groupby(['condition','rtt_ms','padded_ack_datagrams_before_crypto']):
 cond,rtt,ack=keys
 rows.append(f"{900 if cond.endswith('900') else 2400} & {rtt:.0f} & {ack:.0f} & {len(z)} & {(z.latency_ms<1.5*z.rtt_ms).sum()} & {z.latency_ms.median():.2f}"+r' \\')
(O/'ack_counts.tex').write_text('\n'.join(rows)+'\n')
print('Generated five tables.')

# Update only explicitly delimited generated table bodies in the LaTeX sources.
import re
for manuscript in ['manuscript.tex','supplement.tex']:
    p=R/'paper'/manuscript
    if not p.exists(): continue
    text=p.read_text()
    for table in ['sizes','interventions','baseline','loss','ack_counts']:
        pattern=r'% BEGIN GENERATED '+table+r'\n.*?\n% END GENERATED '+table
        replacement='% BEGIN GENERATED '+table+'\n'+(O/(table+'.tex')).read_text().rstrip()+'\n% END GENERATED '+table
        text=re.sub(pattern,lambda match:replacement,text,flags=re.S)
    p.write_text(text)
