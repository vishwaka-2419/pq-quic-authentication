#!/usr/bin/env python3
"""Publication figures from archived measurements and explicitly identified models."""
from pathlib import Path
import json,sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.colors import ListedColormap
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'paper/figures';OUT.mkdir(exist_ok=True)
plt.rcParams.update({'font.family':'serif','font.serif':['DejaVu Serif'],'font.size':9,'axes.labelsize':9,'xtick.labelsize':8,'ytick.labelsize':8,'legend.fontsize':8,'pdf.fonttype':42,'ps.fonttype':42,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':.7,'lines.linewidth':1.5,'savefig.dpi':450})
COL=['#0072B2','#D55E00','#009E73','#CC79A7','#E69F00']
ALG=['mldsa44','mldsa65','mldsa87'];LAB={'ecdsa':'ECDSA','mldsa44':'ML-DSA-44','mldsa65':'ML-DSA-65','mldsa87':'ML-DSA-87'}
S=pd.read_csv(ROOT/'analysis/summary.csv');D=pd.read_csv(ROOT/'analysis/trials.csv')
B=S[(S.loss==0)&(S.up_mbps==100)&(S.down_mbps==100)&(S.group=='X25519MLKEM768')]
records={}
def setup(w=3.42,h=3.1):
 f,a=plt.subplots(figsize=(w,h));a.set_axisbelow(True);a.grid(axis='y',color='#E5E5E5',linewidth=.5);return f,a

def save(f,name,ids=None):
 f.savefig(OUT/(name+'.pdf'),bbox_inches='tight',pad_inches=.04)
 f.savefig(OUT/(name+'.png'),bbox_inches='tight',pad_inches=.04)
 f.savefig(OUT/(name+'.eps'),bbox_inches='tight',pad_inches=.04)
 plt.close(f);records[name]=ids if ids is not None else 'See figure caption and script filters'

def error(a,x,g,color,label,marker='o'):
 a.errorbar(x,g.median_ms,yerr=[g.median_ms-g.ci_low_ms,g.ci_high_ms-g.median_ms],fmt=marker+'-',color=color,label=label,markersize=4,capsize=2,elinewidth=.9)
# 1. Measured TLS message composition.
f,a=setup();sub=D[(D.loss==0)&(D.rtt_ms==60)&(D.up_mbps==100)&(D.condition=='plain')]
configs=[('ecdsa','X25519'),('ecdsa','X25519MLKEM768')]+[(x,'X25519MLKEM768') for x in ALG]
x=np.arange(5);bottom=np.zeros(5)
for col,label,color in [('certificate_bytes','Certificate',COL[0]),('certificate_verify_bytes','CertificateVerify',COL[1]),('server_hello_bytes','ServerHello',COL[2])]:
 v=np.array([sub[(sub.algorithm==alg)&(sub.group==group)][col].median() for alg,group in configs])/1000
 a.bar(x,v,bottom=bottom,width=.65,color=color,label=label);bottom+=v
v=np.array([(sub[(sub.algorithm==alg)&(sub.group==group)].encrypted_extensions_bytes+sub[(sub.algorithm==alg)&(sub.group==group)].finished_bytes).median() for alg,group in configs])/1000
a.bar(x,v,bottom=bottom,width=.65,color=COL[3],label='Other TLS')
a.set_xticks(x,['EC\nX','EC\nH','44\nH','65\nH','87\nH']);a.set_ylabel('Server TLS handshake bytes (kB)');a.set_ylim(0,23)
a.legend(loc='lower center',bbox_to_anchor=(.5,1.02),ncol=2,frameon=False,columnspacing=.8,handlelength=1.1);save(f,'Fig1')
# 2. Latency versus configured RTT.
f,a=setup()
for i,alg in enumerate(['ecdsa']+ALG):
 g=B[(B.algorithm==alg)&(B.condition=='plain')].sort_values('rtt_ms');error(a,g.rtt_ms,g,COL[i],LAB[alg],['s','o','^','D'][i])
a.set(xlabel='Configured round-trip time (ms)',ylabel='Client handshake completion (ms)',xlim=(12,128));a.set_xticks([20,60,120]);a.legend(loc='lower center',bbox_to_anchor=(.5,1.02),ncol=2,frameon=False,columnspacing=.8);save(f,'Fig2')
# 3. Individual and joint interventions.
f,a=setup(6.85,3.05);conds=['plain','compressed','cached','padding','cached_padding','cached_compressed_padding'];x=np.arange(len(conds))
for i,alg in enumerate(ALG):
 g=B[(B.algorithm==alg)&(B.rtt_ms==60)].set_index('condition').loc[conds];xp=x+(i-1)*.23
 a.bar(xp,g.median_ms,width=.215,color=COL[i],label=LAB[alg]);a.errorbar(xp,g.median_ms,yerr=[g.median_ms-g.ci_low_ms,g.ci_high_ms-g.median_ms],fmt='none',ecolor='#333333',capsize=2,elinewidth=.7)
a.set_xticks(x,['Full chain','zlib','Cached\nintermediate','Client\npadding','Cache +\npadding','Cache + zlib\n+ padding']);a.set_ylabel('Client handshake completion (ms)');a.set_ylim(0,215);a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=3,frameon=False);save(f,'Fig3')
# 4. Padding dose, including all individual observations in supplementary data.
f,a=setup(3.42,3.05)
for i,(alg,cached) in enumerate([('mldsa44',True),('mldsa65',True),('mldsa87',False)]):
 xs=[];med=[];low=[];high=[]
 for p in [0,800,900,1600,2400,3200]:
  cond=('cached' if cached else 'plain') if p==0 else ('cached_' if cached else '')+('padding' if p==2400 else f'padding{p}')
  g=B[(B.algorithm==alg)&(B.rtt_ms==60)&(B.condition==cond)]
  if g.empty:continue
  r=g.iloc[0];xs.append(p);med.append(r.median_ms);low.append(r.median_ms-r.ci_low_ms);high.append(r.ci_high_ms-r.median_ms)
 a.errorbar(xs,med,yerr=[low,high],fmt=['o-','s--','^-'][i],color=COL[i],label=LAB[alg]+(' with cache' if cached else ', full chain'),capsize=3,markersize=4)
a.set(xlabel='Additional ClientHello extension payload (bytes)',ylabel='Client handshake completion (ms)',xlim=(-70,3300),ylim=(45,210));a.set_xticks([0,800,1600,2400,3200]);a.legend(loc='lower center',bbox_to_anchor=(.5,1.02),ncol=1,frameon=False,handlelength=1.5);save(f,'Fig4')
# 5. Representative real traces chosen nearest to the corresponding median.
f,a=setup(3.42,3.05);chosen=[]
for i,cond in enumerate(['plain','cached','padding']):
 g=D[(D.algorithm=='mldsa87')&(D.group=='X25519MLKEM768')&(D.rtt_ms==60)&(D.loss==0)&(D.up_mbps==100)&(D.down_mbps==100)&(D.condition==cond)]
 r=g.loc[(g.latency_ms-g.latency_ms.median()).abs().idxmin()];chosen.append(r.id)
 es=[json.loads(x) for x in (ROOT/'raw/measurements'/r.id/'datagrams.jsonl').read_text().splitlines()];t0=next(e['t'] for e in es if e['event']=='observed' and e['direction']=='cs')
 sc=[e for e in es if e['event']=='observed' and e['direction']=='sc' and e['t']<=r.client_complete]
 times=[0]+[1000*(e['t']-t0) for e in sc]+[r.latency_ms];vol=[0]+list(np.cumsum([e['bytes'] for e in sc])/1000);vol+=[vol[-1]]
 a.step(times,vol,where='post',color=COL[i],label={'plain':'Full chain','cached':'Cached intermediate','padding':'Extra client bytes'}[cond],linestyle=['-','--','-.'][i])
a.axhline(7.2,color='#666666',linestyle=':',linewidth=.9,label='Unpadded initial credit');a.set(xlabel='Time from first client datagram (ms)',ylabel='Cumulative server UDP payload (kB)',xlim=(0,202),ylim=(0,24));a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=1,frameon=False);save(f,'Fig5',chosen)
# 6. Subdistribution function, retaining failure/censoring mass.
f,a=setup(3.42,3.05)
for i,(cond,burst) in enumerate([('plain',False),('cached',False),('plain',True),('cached',True)]):
 g=D[(D.algorithm=='mldsa87')&(D.loss==.05)&(D.burst==burst)&(D.condition==cond)];v=np.sort(g.loc[g.success,'latency_ms']);xs=np.r_[60,v,5000];ys=np.r_[0,np.arange(1,len(v)+1)/len(g),len(v)/len(g)]
 a.step(xs,ys,where='post',color=COL[i],linestyle=['-','--','-.',':'][i],label=('Full' if cond=='plain' else 'Cached')+', '+('burst loss' if burst else 'independent loss'))
a.set_xscale('log');a.set_xticks([60,100,200,500,1000,5000],labels=['60','100','200','500','1000','5000']);a.set(xlabel='Client completion deadline (ms)',ylabel='Fraction of all trials completed',ylim=(0,1.03),xlim=(60,5100));a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=1,frameon=False);save(f,'Fig6')
# 7. Conditional feasibility map, not a latency prediction.
f,a=setup(3.42,3.2);c=np.linspace(1.2,9.6,169);b=np.linspace(1,25,241);C,V=np.meshgrid(c,b);A=V>3*C;W=V>12;Z=A.astype(int)+2*W.astype(int)
a.pcolormesh(c,b,Z,cmap=ListedColormap(['#D5EEE3','#F9DFC6','#D3E7F5','#EADCEB']),vmin=-.5,vmax=3.5,shading='nearest',rasterized=True)
a.plot([1.2,8.33],[3.6,25],color=COL[1],linewidth=1);a.axhline(12,color=COL[0],linewidth=1)
a.set(xlabel='Initial client UDP payload (kB)',ylabel='Server flight UDP payload (kB)',xlim=(1.2,9.6),ylim=(1,25));a.legend(handles=[Patch(facecolor=x,label=l) for x,l in zip(['#D5EEE3','#F9DFC6','#D3E7F5','#EADCEB'],['Feasible','Amplification','Congestion','Both'])],loc='lower center',bbox_to_anchor=(.5,1.01),ncol=2,frameon=False);save(f,'Fig7')
# 8. Uplink asymmetry, fixed 10 Mbit/s downlink and 60 ms RTT.
f,a=setup(3.42,3.05);pos=np.arange(4)
for i,cond in enumerate(['plain','padding','cached']):
 med=[];lo=[];hi=[]
 for alg,up in [('mldsa44',1),('mldsa44',10),('mldsa87',1),('mldsa87',10)]:
  r=S[(S.algorithm==alg)&(S.condition==cond)&(S.loss==0)&(S.up_mbps==up)&(S.down_mbps==10)].iloc[0];med.append(r.median_ms);lo.append(r.median_ms-r.ci_low_ms);hi.append(r.ci_high_ms-r.median_ms)
 a.errorbar(pos+(i-1)*.12,med,yerr=[lo,hi],fmt=['o','s','^'][i],color=COL[i],label={'plain':'Full chain','padding':'Extra client bytes','cached':'Cached intermediate'}[cond],capsize=3,markersize=5)
a.set_xticks(pos,['ML-DSA-44\n1 Mbit/s','ML-DSA-44\n10 Mbit/s','ML-DSA-87\n1 Mbit/s','ML-DSA-87\n10 Mbit/s']);a.set_ylabel('Client handshake completion (ms)');a.set_ylim(115,232);a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=1,frameon=False);save(f,'Fig8')
# S1. Retry outcomes under native packetization.
f,a=setup(6.85,3.0)
for i,(alg,group) in enumerate([('ecdsa','X25519'),('ecdsa','X25519MLKEM768'),('mldsa44','X25519MLKEM768'),('mldsa87','X25519MLKEM768')]):
 g=S[(S.algorithm==alg)&(S.group==group)&(S.condition=='retry')].sort_values('rtt_ms');error(a,g.rtt_ms,g,COL[i],LAB[alg]+(' / X25519' if group=='X25519' else ' / hybrid'),['o','s','^','D'][i])
a.set(xlabel='Configured round-trip time (ms)',ylabel='Client handshake completion (ms)');a.set_xticks([20,60,120]);a.legend(loc='lower center',bbox_to_anchor=(.5,1.02),ncol=2,frameon=False);save(f,'FigS1')
# S2. Retrospective disagreement count.
f,a=setup(6.85,2.6);m=json.loads((ROOT/'analysis/models.json').read_text())['classification'];vals=[m[k]['mismatches'] for k in m]
a.barh([2,1,0],vals,color=COL[:3],height=.55);a.set_yticks([2,1,0],['TLS-byte\nbudget','UDP-byte\nbudget','Two\nbudgets']);a.set_xlabel('Disagreements in 1740 loss-free traces');a.set_xlim(0,250)
for y,v in zip([2,1,0],vals):a.text(v+4,y,str(v),va='center',fontsize=9)
save(f,'FigS2')
# S3. Conditional cache-state simulation with independent Monte Carlo sample check.
f,a=setup(6.85,2.9);m=pd.read_csv(ROOT/'analysis/state_simulation.csv');m=m[m.algorithm=='mldsa44']
for i,p in enumerate([0,60,120]):
 g=m[m.cold_penalty_ms==p];a.plot(g.hit_probability,g.analytic_mean_ms,color=COL[i],label=f'Cold-state penalty {p} ms');a.plot(g.hit_probability[::4],g.mean_ms[::4],linestyle='none',marker=['o','s','^'][i],markersize=4,color=COL[i])
a.set(xlabel='Warm-state probability (assumed)',ylabel='Mean client completion (ms)',xlim=(0,1));a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=3,frameon=False);save(f,'FigS3')
# S4. Offline transparency encoding, same private-chain structures.
f,a=setup(6.85,2.9);m=pd.read_csv(ROOT/'analysis/transparency_costs.csv');x=np.arange(4)
for i,(sct,comp) in enumerate([(0,False),(0,True),(2,False),(2,True)]):
 vals=[]
 for alg in ['ecdsa']+ALG:
  r=m[(m.algorithm==alg)&(~m.cached)&(m.sct_count==sct)].iloc[0];vals.append(r['compressed_certificate_message_bytes' if comp else 'certificate_message_bytes']/1000)
 a.bar(x+(i-1.5)*.2,vals,width=.19,color=COL[i],label=('Two SCTs' if sct else 'No SCTs')+(' / zlib' if comp else ' / uncompressed'))
a.set_xticks(x,[LAB[z] for z in ['ecdsa']+ALG]);a.set_ylabel('Certificate message size (kB)');a.legend(loc='lower center',bbox_to_anchor=(.5,1.01),ncol=2,frameon=False);save(f,'FigS4')
(OUT/'provenance.json').write_text(json.dumps(records,indent=2));print('Created',len(records),'figures in PDF, EPS and PNG formats.')
