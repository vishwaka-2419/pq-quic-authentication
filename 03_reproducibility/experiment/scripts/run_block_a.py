#!/usr/bin/env python3
"""Prospectively specified interleaved 2x2 replication (Block A).

This script uses the public OpenSSL QUIC APIs and a loopback UDP proxy.
The 16 cells (4 authentication algorithms x cache on/off x 0/2400-byte
ClientHello enlargement) are randomized into one sequence, one connection
at a time. Server, client, and proxy are pinned to separate CPUs.
"""
from __future__ import annotations
import argparse, asyncio, hashlib, json, os, random, socket, time, resource
from pathlib import Path
from typing import Any
ROOT=Path(__file__).resolve().parents[1]

class Link(asyncio.DatagramProtocol):
    def __init__(self, server_addr, rtt_ms, log, up_mbps=100.0, down_mbps=100.0):
        self.server_addr=server_addr; self.client_addr=None; self.rtt=rtt_ms/1000.0
        self.log=log; self.seq=0; self.pending=set(); self.closed=False
        self.last={'cs':0.0,'sc':0.0}; self.rates={'cs':up_mbps*1e6,'sc':down_mbps*1e6}
    def connection_made(self, transport): self.transport=transport
    def datagram_received(self, data, addr):
        t=time.monotonic(); direction='sc' if addr==self.server_addr else 'cs'
        if direction=='cs': self.client_addr=addr; target=self.server_addr
        else: target=self.client_addr
        if target is None: return
        i=self.seq; self.seq+=1
        finish=max(t,self.last[direction])+8*len(data)/self.rates[direction]
        self.last[direction]=finish; due=finish+self.rtt/2
        self.log.write(json.dumps({'event':'observed','i':i,'t':t,'direction':direction,
                                   'bytes':len(data),'drop':False,'due':due,'hex':data.hex()})+'\n')
        self.log.flush()
        h=asyncio.get_running_loop().call_later(max(0,due-time.monotonic()),
                                                 self.deliver,i,data,target,direction,due)
        self.pending.add(h)
    def deliver(self,i,data,target,direction,due):
        if self.closed: return
        self.transport.sendto(data,target)
        self.log.write(json.dumps({'event':'delivered','i':i,'t':time.monotonic(),
                                   'direction':direction,'bytes':len(data),'due':due})+'\n')
        self.log.flush()
    def finish(self):
        self.closed=True
        for h in self.pending: h.cancel()
        self.transport.close()

def free_port():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0))
    p=s.getsockname()[1]; s.close(); return p

def pin(cpu: int):
    def _pin(): os.sched_setaffinity(0,{cpu})
    return _pin

def make_design() -> list[dict[str,Any]]:
    auths=['ecdsa','mldsa44','mldsa65','mldsa87']
    rows=[]
    for alg in auths:
        for cached in [False,True]:
            for enlargement in [0,2400]:
                for replicate in range(30):
                    cell=f'{alg}_ci{int(cached)}_ce{enlargement}'
                    key=f'blockA_{cell}_r{replicate:02d}'
                    seed=int.from_bytes(hashlib.sha256(('BLOCK-A-20261101/'+key).encode()).digest()[:8],'big')
                    rows.append(dict(id=key,block='A',algorithm=alg,group='X25519MLKEM768',
                                     cached=cached,enlargement_bytes=enlargement,rtt_ms=60,
                                     up_mbps=100.0,down_mbps=100.0,loss=0.0,retry=False,
                                     replicate=replicate,seed=seed,first_band_threshold_ms=90.0))
    random.Random(20261101).shuffle(rows)
    for order,row in enumerate(rows): row['run_order']=order
    return rows

async def trial(rec, base):
    d=base/rec['id']; d.mkdir(parents=True,exist_ok=True); q=d/'qlogs'; q.mkdir(exist_ok=True)
    (d/'configuration.json').write_text(json.dumps(rec,indent=2,sort_keys=True))
    env=os.environ.copy(); env['QLOGDIR']=str(q); env['QUIC_RETRY']='0'; env['QUIC_COMPRESS']='0'
    cert=ROOT/'certificates'/rec['algorithm']; sp=free_port()
    chain=cert/('leaf.pem' if rec['cached'] else 'chain.pem')
    trust=cert/('trust_cached.pem' if rec['cached'] else 'root.pem')
    common=[str(chain),str(cert/'leaf.key'),str(trust),rec['group'],str(rec['enlargement_bytes'])]
    sf=open(d/'server.err','w'); cf=open(d/'client.err','w'); dg=open(d/'datagrams.jsonl','w')
    server=client=None; link=None
    result={'id':rec['id'],'success':False,'run_order':rec['run_order'],
            'loadavg_before':os.getloadavg(),'proxy_cpu':2,'server_cpu':0,'client_cpu':1}
    try:
        server=await asyncio.create_subprocess_exec(str(ROOT/'bin/quic_probe'),'server',str(sp),*common,str(d/'server'),
                  env=env,stdout=asyncio.subprocess.PIPE,stderr=sf,preexec_fn=pin(0))
        ready=await asyncio.wait_for(server.stdout.readline(),2.0)
        (d/'server.out').write_bytes(ready)
        if not ready: raise RuntimeError('server did not initialize')
        transport,link=await asyncio.get_running_loop().create_datagram_endpoint(
            lambda:Link(('127.0.0.1',sp),rec['rtt_ms'],dg,rec['up_mbps'],rec['down_mbps']),
            local_addr=('127.0.0.1',0))
        pp=transport.get_extra_info('sockname')[1]
        client=await asyncio.create_subprocess_exec(str(ROOT/'bin/quic_probe'),'client',str(pp),*common,str(d/'client'),
                  env=env,stdout=asyncio.subprocess.PIPE,stderr=cf,preexec_fn=pin(1))
        out=[]; tstart=tend=None; until=time.monotonic()+5.0
        while time.monotonic()<until:
            line=await asyncio.wait_for(client.stdout.readline(),max(.001,until-time.monotonic()))
            if not line: break
            out.append(line); e=json.loads(line)
            if e['event']=='start': tstart=e['t']
            if e['event']=='complete':
                tend=e['t']; result.update(e); result['success']=True; break
        (d/'client.out').write_bytes(b''.join(out))
        if tend is not None and tstart is not None:
            result['latency_ms']=1000*(tend-tstart)
            result['first_band']=result['latency_ms'] < rec['first_band_threshold_ms']
            try:
                sout=await asyncio.wait_for(server.stdout.read(),.7)
                with open(d/'server.out','ab') as f: f.write(sout)
            except asyncio.TimeoutError: result['server_drain_timeout']=True
    except (asyncio.TimeoutError,RuntimeError,ValueError) as exc:
        result['error']=type(exc).__name__+': '+str(exc)
    finally:
        if link: link.finish()
        for p in [client,server]:
            if p is not None and p.returncode is None:
                p.terminate()
                try: await asyncio.wait_for(p.wait(),1)
                except asyncio.TimeoutError: p.kill(); await p.wait()
        for f in [sf,cf,dg]: f.close()
        result['loadavg_after']=os.getloadavg()
        result['maxrss_kb']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        (d/'result.json').write_text(json.dumps(result,indent=2,sort_keys=True))
    return result

async def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path,default=ROOT/'raw'/'block_a')
    args=ap.parse_args(); base=args.output.resolve(); base.mkdir(parents=True,exist_ok=True)
    os.sched_setaffinity(0,{2})
    design=make_design(); (base/'design.json').write_text(json.dumps(design,indent=2,sort_keys=True))
    progress=base/'progress.jsonl'
    for idx,rec in enumerate(design,1):
        result_path=base/rec['id']/'result.json'
        if result_path.exists(): continue
        res=await trial(rec,base)
        with progress.open('a') as f: f.write(json.dumps(res,sort_keys=True)+'\n')
        if idx%20==0 or not res['success']:
            print(f'{idx}/{len(design)} {rec["id"]} success={res["success"]} latency={res.get("latency_ms")}')
    print('completed',len(design))
if __name__=='__main__': asyncio.run(main())
