#!/usr/bin/env python3
"""Reconcile native TLS and UDP traces and aggregate without discarding failures."""
from pathlib import Path
import json, hashlib, platform, subprocess, zlib
import numpy as np
import pandas as pd
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'analysis';OUT.mkdir(exist_ok=True)

def json_lines(path):
    if not path.exists():return []
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]

def qlog(path):
    events=[];bad=0;tm=0
    for i,chunk in enumerate(path.read_text().split('\x1e')):
        if not chunk.strip():continue
        try:e=json.loads(chunk)
        except json.JSONDecodeError:bad+=1;continue
        if 'time' in e:tm+=e['time']
        e['absolute_ms']=tm;events.append(e)
    return events,bad

def bootstrap(x,seed=271828,n=4000):
    x=np.asarray(x,dtype=float)
    if not len(x):return np.nan,np.nan
    r=np.random.default_rng(seed)
    med=np.median(r.choice(x,(n,len(x)),replace=True),axis=1)
    return tuple(np.percentile(med,[2.5,97.5]))

def wilson(k,n):
    z=1.959963984540054;p=k/n;a=1+z*z/n
    h=z*np.sqrt(p*(1-p)/n+z*z/(4*n*n))/a;c=(p+z*z/(2*n))/a
    return c-h,c+h

def collect():
    rows=[];messages=[];issues=[];delay=[]
    for d in sorted((ROOT/'raw/measurements').iterdir()):
        if not d.is_dir() or not (d/'result.json').exists():continue
        cfg=json.loads((d/'configuration.json').read_text());res=json.loads((d/'result.json').read_text())
        rec=dict(cfg);rec.update(res);rec['negotiated_group']=res.get('group');rec['group']=cfg['group']
        rec['stage']=2 if ('cached_padding' in cfg['condition'] or 'cached_compressed_padding' in cfg['condition'] or any(c.isdigit() for c in cfg['condition'])) else 1
        rec['failure_kind']='none'
        if not res['success']:
            err=(d/'client.err').read_text()
            rec['failure_kind']='crypto_buffer_exceeded' if 'CRYPTO_BUFFER_EXCEEDED' in err else ('deadline' if 'TimeoutError' in res.get('error','') else 'other')
        ss=json_lines(d/'server.tls.jsonl');cc=json_lines(d/'client.tls.jsonl')
        for m in ss:
            if m['write'] and m['type'] in [2,8,11,15,20,25]:
                messages.append({'id':cfg['id'],'algorithm':cfg['algorithm'],'group':cfg['group'],'condition':cfg['condition'],'type':m['type'],'bytes':m['length']})
        out=[m for m in ss if m['write'] and m['type'] in [2,8,11,15,20,25]]
        rec['tls_server_bytes']=sum(m['length'] for m in out)
        for typ,name in [(2,'server_hello'),(8,'encrypted_extensions'),(11,'certificate'),(15,'certificate_verify'),(20,'finished'),(25,'compressed_certificate')]:
            rec[name+'_bytes']=sum(m['length'] for m in out if m['type']==typ)
        ch=[m for m in cc if m['write'] and m['type']==1]
        rec['client_hello_bytes']=ch[0]['length'] if ch else np.nan
        cv=[m for m in out if m['type']==15]
        rec['signature_scheme']=int(cv[0]['hex'][8:12],16) if cv else np.nan
        cm=[m for m in out if m['type']==25]
        if cm:
            b=bytes.fromhex(cm[0]['hex']);u=int.from_bytes(b[6:9],'big');comp=int.from_bytes(b[9:12],'big')
            try:
                plain=zlib.decompress(b[12:]);assert len(plain)==u and comp==len(b)-12 and int.from_bytes(b[4:6],'big')==1
                rec['compression_verified']=True;rec['uncompressed_certificate_body_bytes']=u
            except (ValueError,zlib.error,AssertionError):
                rec['compression_verified']=False;issues.append(cfg['id']+': compression reconciliation failed')
        else:rec['compression_verified']=None
        ev=json_lines(d/'datagrams.jsonl');obs=[e for e in ev if e['event']=='observed'];delv=[e for e in ev if e['event']=='delivered']
        sc=[e for e in obs if e['direction']=='sc'];cs=[e for e in obs if e['direction']=='cs']
        t0=cs[0]['t'] if cs else 0;tend=res.get('client_complete') or t0+5
        rec['sent_client_bytes']=sum(e['bytes'] for e in cs if e['t']<=tend)
        rec['sent_server_bytes']=sum(e['bytes'] for e in sc if e['t']<=tend)
        rec['dropped_datagrams']=sum(e['drop'] for e in obs if e['t']<=tend)
        rec['attempted_datagrams']=sum(e['t']<=tend for e in obs)
        rec['actual_loss_fraction']=rec['dropped_datagrams']/max(1,rec['attempted_datagrams'])
        first_sc=sc[0]['t'] if sc else np.inf
        rec['client_bytes_before_first_server_datagram']=sum(e['bytes'] for e in delv if e['direction']=='cs' and e['t']<first_sc)
        # Earliest flight ends when feedback following a server datagram can return.
        first=next((e for e in sc if ((bytes.fromhex(e['hex'])[0]>>4)&3)!=3),None)
        rec['initial_client_flight_bytes']=sum(e['bytes'] for e in cs if e['t']<t0+cfg['rtt_ms']/2000)
        rec['initial_client_datagrams']=sum(e['t']<t0+cfg['rtt_ms']/2000 for e in cs)
        rec['max_udp_payload']=max((e['bytes'] for e in obs),default=0)
        dl=[1000*(e['t']-e['due']) for e in delv if e['t']<=tend];delay.extend(dl)
        rec['delivery_lateness_p50_ms']=np.median(dl) if dl else np.nan
        rec['delivery_lateness_p99_ms']=np.quantile(dl,.99) if dl else np.nan
        rec['padded_ack_datagrams_before_crypto']=0
        rec['qlog_partial_records']=0
        for f in (d/'qlogs').glob('*.sqlog'):
            events,bad=qlog(f);rec['qlog_partial_records']+=bad
            if f.name.endswith('_server.sqlog'):
                sent=[e for e in events if e.get('name')=='transport:packet_sent']
                seen_crypto=False;dg=set()
                for e in sent:
                    fs=e['data'].get('frames',[])
                    if any(x['frame_type']=='crypto' for x in fs):seen_crypto=True
                    if not seen_crypto and any(x['frame_type']=='padding' for x in fs):dg.add(e['data']['datagram_id'])
                rec['padded_ack_datagrams_before_crypto']=len(dg)
                # Entire server authentication flight, unique datagrams carrying CRYPTO,
                # plus preceding Initial ACK/PADDING datagrams. No application traffic.
                used=set();last=-1
                for e in sent:
                    if any(x['frame_type']=='crypto' for x in e['data'].get('frames',[])):last=max(last,e['data']['datagram_id'])
                if not cfg['retry'] and cfg['loss']==0:
                    rec['authentication_udp_bytes']=sum(x['bytes'] for i,x in enumerate(sc) if i<=last)
        if res['success'] and (res.get('verify_result')!=0 or res.get('resumed')!=0 or str(res.get('group')).lower()!=cfg['group'].lower()):issues.append(cfg['id']+': negotiation/verification mismatch')
        if res['success'] and bool(cm)!=cfg['compress']:issues.append(cfg['id']+': compression negotiation mismatch')
        rows.append(rec)
    df=pd.DataFrame(rows);df.to_csv(OUT/'trials.csv',index=False)
    pd.DataFrame(messages).to_csv(OUT/'tls_messages.csv',index=False)
    group=['algorithm','group','rtt_ms','condition','loss','burst','up_mbps','down_mbps','stage']
    agg=[]
    for key,g in df.groupby(group,dropna=False,sort=True):
        v=g.loc[g.success,'latency_ms'].to_numpy();lo,hi=bootstrap(v);wl,wh=wilson(int(g.success.sum()),len(g))
        rec=dict(zip(group,key));rec.update(n=len(g),successes=int(g.success.sum()),failures=int((~g.success).sum()),median_ms=np.median(v) if len(v) else np.nan,ci_low_ms=lo,ci_high_ms=hi,success_ci_low=wl,success_ci_high=wh,p95_success_ms=np.quantile(v,.95) if len(v) else np.nan)
        for c in ['client_hello_bytes','tls_server_bytes','initial_client_flight_bytes','authentication_udp_bytes','padded_ack_datagrams_before_crypto']:
            if c in g:rec[c+'_median']=g[c].median() if g[c].notna().any() else np.nan
        agg.append(rec)
    pd.DataFrame(agg).to_csv(OUT/'summary.csv',index=False)
    df.loc[~df.success].to_csv(OUT/'failures.csv',index=False)
    ds=np.asarray(delay)
    report={'trials':len(df),'successful':int(df.success.sum()),'failures':df.failure_kind.value_counts().to_dict(),'integrity_issues':issues,'qlog_partial_records':int(df.qlog_partial_records.sum()),'delivery_lateness_ms':{str(p):float(np.quantile(ds,p))for p in [.5,.9,.95,.99,1]},'openssl':subprocess.check_output(['openssl','version'],text=True).strip(),'platform':platform.platform(),'python':platform.python_version()}
    (OUT/'audit.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
if __name__=='__main__':collect()
