#!/usr/bin/env python3
"""Conditional transport and certificate-state simulations.

These models do not replace native QUIC and do not predict unobserved native
scheduling or recovery. Inputs, conditional assumptions and random seeds are
written next to every generated result.
"""
from __future__ import annotations
from dataclasses import dataclass
from math import ceil
from pathlib import Path
import hashlib, json, zlib, gzip, csv
import numpy as np
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]

@dataclass(frozen=True)
class Prefix:
    server_sent: int
    client_received: int
    validated: bool=False

def minimum_credit(schedule:list[Prefix])->int:
    if any(min(e.server_sent,e.client_received)<0 for e in schedule):raise ValueError('negative byte count')
    return max(0,max((ceil((e.server_sent-3*e.client_received)/3) for e in schedule if not e.validated),default=0))

def feasibility(auth_udp:int,early_padded_ack:int,client_credit:int,cwnd:int)->str:
    """A feedback-free model where every included packet counts as in flight."""
    if min(auth_udp,early_padded_ack,client_credit,cwnd)<0:raise ValueError('negative byte count')
    load=auth_udp+early_padded_ack
    amp=load>3*client_credit;cong=load>cwnd
    return 'both' if amp and cong else ('amplification' if amp else ('congestion' if cong else 'feasible'))

def merkle_root(leaves:list[bytes])->bytes:
    if not leaves or len(leaves)&(len(leaves)-1):raise ValueError('power-of-two leaf count required')
    layer=[hashlib.sha256(b'\0'+v).digest() for v in leaves]
    while len(layer)>1:layer=[hashlib.sha256(b'\1'+layer[i]+layer[i+1]).digest() for i in range(0,len(layer),2)]
    return layer[0]

def merkle_path(leaves:list[bytes],index:int)->list[bytes]:
    if index<0 or index>=len(leaves):raise ValueError('bad leaf index')
    layer=[hashlib.sha256(b'\0'+v).digest() for v in leaves];path=[]
    while len(layer)>1:
        path.append(layer[index^1]);index//=2
        layer=[hashlib.sha256(b'\1'+layer[i]+layer[i+1]).digest() for i in range(0,len(layer),2)]
    return path

def verify_path(leaf:bytes,index:int,path:list[bytes],root:bytes)->bool:
    v=hashlib.sha256(b'\0'+leaf).digest()
    for sibling in path:
        v=hashlib.sha256(b'\1'+(sibling+v if index&1 else v+sibling)).digest();index//=2
    return v==root

def simulate():
    out=ROOT/'analysis';out.mkdir(exist_ok=True)
    # Full grid of necessary feedback-free conditions, not RTT predictions.
    rows=[]
    for b in range(1000,25001,100):
        for c in range(1200,9601,100):
            for a in [0,1200,2400,3600]:
                rows.append((b,c,a,12000,feasibility(b,a,c,12000)))
    pd.DataFrame(rows,columns=['authentication_udp_bytes','client_credit_bytes','early_padded_ack_bytes','cwnd_bytes','regime']).to_csv(out/'feasibility_grid.csv',index=False)
    # Measured warm-cache and full-chain timing pools, with an explicit cold-state penalty.
    df=pd.read_csv(out/'trials.csv');sel=df[(df.rtt_ms==60)&(df.loss==0)&(df.up_mbps==100)&(df.group=='X25519MLKEM768')&df.success]
    rng=np.random.default_rng(20260921);mix=[]
    rawdir=ROOT/'raw/simulations';rawdir.mkdir(parents=True,exist_ok=True)
    rawfile=gzip.open(rawdir/'state_draws.csv.gz','wt',newline='')
    writer=csv.writer(rawfile);writer.writerow(['algorithm','cold_penalty_ms','warm_probability','draw','warm_state','completion_ms'])
    for alg in ['mldsa44','mldsa65','mldsa87']:
        warm=sel[(sel.algorithm==alg)&(sel.condition=='cached_padding')].latency_ms.to_numpy()
        cold=sel[(sel.algorithm==alg)&(sel.condition=='padding')].latency_ms.to_numpy()
        for penalty in [0.,60.,120.]:
            for hit in np.linspace(0,1,21):
                n=10000;states=rng.random(n)<hit
                draws=np.where(states,rng.choice(warm,n),rng.choice(cold,n)+penalty)
                writer.writerows((alg,penalty,float(hit),i,int(states[i]),format(float(value),'.12g')) for i,value in enumerate(draws))
                expectation=hit*warm.mean()+(1-hit)*(cold.mean()+penalty)
                mix.append((alg,penalty,hit,n,draws.mean(),draws.std(ddof=1)/np.sqrt(n),expectation,np.quantile(draws,.95)))
    rawfile.close()
    pd.DataFrame(mix,columns=['algorithm','cold_penalty_ms','hit_probability','draws','mean_ms','mc_standard_error_ms','analytic_mean_ms','p95_ms']).to_csv(out/'state_simulation.csv',index=False)
    # Lower-bound Merkle proof arithmetic, NOT an MTC serializer or deployment estimate.
    reps=[]
    sizes={'mldsa44':(1312,2420),'mldsa65':(1952,3309),'mldsa87':(2592,4627)}
    for alg,(pk,sig) in sizes.items():
        for metadata in [128,256,512]:
            for depth in [10,16,20,23]:
                proof=32*depth
                # framing assumes a single TLS Certificate entry; signature CV is retained.
                # Full trusted-checkpoint and certificate metadata encodings are not claimed.
                warm=1178+92+36+8+pk+metadata+proof+sig+8
                for cosigners in [1,2]:
                    cold=warm+cosigners*(sig+32)
                    reps.append((alg,metadata,depth,proof,cosigners,warm,cold))
    pd.DataFrame(reps,columns=['algorithm','assumed_metadata_bytes','tree_depth','proof_bytes','checkpoint_signers','warm_tls_lower_bound','standalone_tls_lower_bound']).to_csv(out/'merkle_cost_bounds.csv',index=False)
    # Retrospective feasibility classification uses observed complete-flight UDP sizes.
    native=df[(df.loss==0)&(df.up_mbps==100)&(~df.retry)&df.success].copy()
    native['static_tls_feasible']=native.tls_server_bytes<=3*native.initial_client_flight_bytes
    native['udp_amp_feasible']=native.authentication_udp_bytes<=3*native.initial_client_flight_bytes
    native['two_budget_feasible']=native.udp_amp_feasible&(native.authentication_udp_bytes<=12000)
    native['observed_fast']=native.latency_ms<1.5*native.rtt_ms
    native.to_csv(out/'retrospective_classification.csv',index=False)
    comparisons={}
    for c in ['static_tls_feasible','udp_amp_feasible','two_budget_feasible']:
        comparisons[c]={'n':len(native),'mismatches':int((native[c]!=native.observed_fast).sum()),'false_feasible':int((native[c]&~native.observed_fast).sum()),'false_infeasible':int((~native[c]&native.observed_fast).sum())}
    manifest={'feasibility_cells':len(rows),'state_simulated_draws':len(mix)*10000,'state_rng_seed':20260921,'representation_cases':len(reps),'classification':comparisons,'interpretation':'Retrospective model uses observed packetization. It is not an independent latency predictor. State hit probabilities and cold penalties are hypothetical; no MTC handshake is implemented.'}
    (out/'models.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest,indent=2))
if __name__=='__main__':simulate()
