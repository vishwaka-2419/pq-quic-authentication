#!/usr/bin/env python3
from pathlib import Path
import json, csv
from extract_wave_accounting import server_qlog
HERE=Path(__file__).resolve(); ROOT=HERE.parents[2]
EXP=ROOT/'03_reproducibility'/'experiment'/'raw'
OUT=ROOT/'03_reproducibility'/'data'/'new_qlog_features.csv'

def read_events(path):
    for raw in path.read_bytes().split(b'\x1e'):
        raw=raw.strip()
        if not raw: continue
        try: yield json.loads(raw)
        except json.JSONDecodeError: continue

def feature(trial, block):
    cfg=json.loads((trial/'configuration.json').read_text())
    result=json.loads((trial/'result.json').read_text())
    q=server_qlog(trial)
    pre=0; pads=0; first_crypto_time=None
    if q is not None:
        for e in read_events(q):
            if e.get('name')!='transport:packet_sent': continue
            frames=e.get('data',{}).get('frames',[])
            if any(f.get('frame_type')=='crypto' for f in frames):
                first_crypto_time=e.get('time'); break
            types={f.get('frame_type') for f in frames}
            if frames and types.issubset({'ack','padding'}):
                pre+=1
                pads+=sum(int(f.get('payload_length',0)) for f in frames if f.get('frame_type')=='padding')
    return {
      'block':block,'id':cfg.get('id',trial.name),'algorithm':cfg.get('algorithm'),
      'cached':cfg.get('cached'),'enlargement_bytes':cfg.get('enlargement_bytes',cfg.get('padding')),
      'replicate':cfg.get('replicate'),'success':result.get('success'),
      'latency_ms':result.get('latency_ms'),'first_band':result.get('first_band'),
      'pre_crypto_ack_padding_datagrams':pre,'pre_crypto_padding_payload_bytes':pads,
      'first_server_crypto_qlog_time':first_crypto_time
    }
rows=[]
for block,sub in [('A','block_a'),('C','block_c'),('F','block_f'),('G','block_g'),('Gc','block_gc')]:
    d=EXP/sub
    if not d.exists(): continue
    for trial in sorted(p for p in d.iterdir() if p.is_dir() and (p/'result.json').exists()):
        rows.append(feature(trial,block))
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
print('wrote',OUT,len(rows))
