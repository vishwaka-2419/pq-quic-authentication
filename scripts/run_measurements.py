#!/usr/bin/env python3
"""Run verified native QUIC through a controlled loopback UDP link.

Only 127.0.0.1 is used. Each trial has an independent seeded loss process.
The proxy logs exact UDP payloads and requested/actual delivery times.
No simulated TLS or QUIC packets are substituted for implementation output.
"""
import argparse, asyncio, json, os, random, socket, time, hashlib, re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class Link(asyncio.DatagramProtocol):
 def __init__(self,server_addr,rtt_ms,loss,seed,log,up_mbps=100,down_mbps=100,burst=False):
  self.server_addr=server_addr;self.client_addr=None;self.rtt=rtt_ms/1000;self.loss=loss
  self.rng=random.Random(seed);self.log=log;self.seq=0;self.pending=set()
  self.last={'cs':0.,'sc':0.};self.rates={'cs':up_mbps*1e6,'sc':down_mbps*1e6}
  self.burst=burst;self.bad={'cs':False,'sc':False};self.closed=False
 def connection_made(self,transport):self.transport=transport
 def datagram_received(self,data,addr):
  t=time.monotonic();direction='sc' if addr==self.server_addr else 'cs'
  if direction=='cs':self.client_addr=addr;target=self.server_addr
  else:target=self.client_addr
  if target is None:return
  i=self.seq;self.seq+=1
  # Gilbert two-state loss process with stationary loss p and mean loss burst 3.
  if self.burst:
   q=1/3;a=self.loss*q/(1-self.loss)
   self.bad[direction]=self.rng.random()<(1-q if self.bad[direction] else a)
   drop=self.bad[direction]
  else:drop=self.rng.random()<self.loss
  finish=max(t,self.last[direction])+8*len(data)/self.rates[direction]
  self.last[direction]=finish;due=finish+self.rtt/2
  self.log.write(json.dumps({'event':'observed','i':i,'t':t,'direction':direction,'bytes':len(data),'drop':drop,'due':due,'hex':data.hex()})+'\n')
  if not drop:
   h=asyncio.get_running_loop().call_later(max(0,due-time.monotonic()),self.deliver,i,data,target,direction,due)
   self.pending.add(h)
 def deliver(self,i,data,target,direction,due):
  if self.closed:return
  self.transport.sendto(data,target)
  self.log.write(json.dumps({'event':'delivered','i':i,'t':time.monotonic(),'direction':direction,'bytes':len(data),'due':due})+'\n')
 def finish(self):
  self.closed=True
  for h in self.pending:h.cancel()
  self.transport.close()

def free_port():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));p=s.getsockname()[1];s.close();return p

async def trial(rec,base):
 d=base/rec['id'];d.mkdir(parents=True,exist_ok=True);q=d/'qlogs';q.mkdir(exist_ok=True)
 (d/'configuration.json').write_text(json.dumps(rec,indent=2))
 env=os.environ.copy();env['QLOGDIR']=str(q);env['QUIC_RETRY']=str(int(rec['retry']));env['QUIC_COMPRESS']=str(int(rec['compress']))
 cert=ROOT/'certificates'/rec['algorithm'];group=rec['group'];sp=free_port()
 chain=cert/('leaf.pem' if rec['cached'] else 'chain.pem');trust=cert/('trust_cached.pem' if rec['cached'] else 'root.pem')
 common=[str(chain),str(cert/'leaf.key'),str(trust),group,str(rec['padding'])]
 sf=open(d/'server.err','w');cf=open(d/'client.err','w');dg=open(d/'datagrams.jsonl','w')
 server=client=None;link=None;result={'id':rec['id'],'success':False}
 try:
  server=await asyncio.create_subprocess_exec(str(ROOT/'bin/quic_probe'),'server',str(sp),*common,str(d/'server'),env=env,stdout=asyncio.subprocess.PIPE,stderr=sf)
  ready=await asyncio.wait_for(server.stdout.readline(),1.5)
  (d/'server.out').write_bytes(ready)
  if not ready:raise RuntimeError('server did not initialize')
  transport,link=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Link(('127.0.0.1',sp),rec['rtt_ms'],rec['loss'],rec['seed'],dg,rec['up_mbps'],rec['down_mbps'],rec['burst']),local_addr=('127.0.0.1',0))
  pp=transport.get_extra_info('sockname')[1]
  client=await asyncio.create_subprocess_exec(str(ROOT/'bin/quic_probe'),'client',str(pp),*common,str(d/'client'),env=env,stdout=asyncio.subprocess.PIPE,stderr=cf)
  out=[];tstart=None;tend=None
  until=time.monotonic()+5.0
  while time.monotonic()<until:
   line=await asyncio.wait_for(client.stdout.readline(),max(.001,until-time.monotonic()))
   if not line:break
   out.append(line)
   e=json.loads(line)
   if e['event']=='start':tstart=e['t']
   if e['event']=='complete':
    tend=e['t'];result.update(e);result['success']=True;break
  (d/'client.out').write_bytes(b''.join(out))
  if tend is not None:
   result['latency_ms']=1000*(tend-tstart)
   # Allow server completion while client services final ACKs; do not include drain in latency.
   try:
    sout=await asyncio.wait_for(server.stdout.read(),.7)
    with open(d/'server.out','ab') as f:f.write(sout)
   except asyncio.TimeoutError:result['server_drain_timeout']=True
  result['client_complete']=tend
 except (asyncio.TimeoutError,RuntimeError,ValueError) as exc:result['error']=type(exc).__name__+': '+str(exc)
 finally:
  if link:link.finish()
  for p in [client,server]:
   if p is not None and p.returncode is None:
    p.terminate()
    try:await asyncio.wait_for(p.wait(),1)
    except asyncio.TimeoutError:p.kill();await p.wait()
  for f in [sf,cf,dg]:f.close()
  (d/'result.json').write_text(json.dumps(result,indent=2))
 return result

def build_design(small=False):
 configs=[('ecdsa','X25519'),('ecdsa','X25519MLKEM768'),('mldsa44','X25519MLKEM768'),('mldsa65','X25519MLKEM768'),('mldsa87','X25519MLKEM768')]
 out=[]
 def add(alg,group,rtt,condition,rep,loss=0.,burst=False,up=100.,down=100.):
  retry=condition=='retry';compress='compressed' in condition;cached='cached' in condition
  match=re.search(r'padding(\d+)$',condition)
  padding=int(match.group(1)) if match else (2400 if 'padding' in condition else 0)
  key=f'{alg}_{"x" if group=="X25519" else "h"}_{rtt}_{condition}_{loss}_{int(burst)}_{up}_{down}_{rep}'
  out.append(dict(id=key,algorithm=alg,group=group,rtt_ms=rtt,condition=condition,retry=retry,compress=compress,cached=cached,padding=padding,loss=loss,burst=burst,up_mbps=up,down_mbps=down,replicate=rep,seed=int.from_bytes(hashlib.sha256(('QUIC20260920/'+key).encode()).digest()[:8],'big')))
 if small:
  for alg,group in configs:
   for cond in ['plain','retry','compressed','cached','padding']:
    add(alg,group,60,cond,0)
 else:
  for alg,group in configs:
   for rtt in [20,60,120]:
    for cond in ['plain','retry']:
     for rep in range(30):add(alg,group,rtt,cond,rep)
  for alg in ['mldsa44','mldsa65','mldsa87']:
   for rtt in [20,60,120]:
    for cond in ['compressed','cached','padding','cached_compressed']:
     for rep in range(20):add(alg,'X25519MLKEM768',rtt,cond,rep)
  for alg in ['ecdsa','mldsa44','mldsa87']:
   for cond in ['plain','cached']:
    for loss in [.01,.05]:
     for burst in [False,True]:
      for rep in range(50):add(alg,'X25519MLKEM768',60,cond,rep,loss,burst)
  for alg in ['mldsa44','mldsa87']:
   for cond in ['plain','padding','cached']:
    for up in [1.,10.]:
     for rep in range(20):add(alg,'X25519MLKEM768',60,cond,rep,up=up,down=10.)
  # Exploratory stage 2: jointly relieve the independently observed constraints.
  for alg in ['mldsa44','mldsa65','mldsa87']:
   for rtt in [20,60,120]:
    for cond in ['cached_padding','cached_compressed_padding']:
     for rep in range(20):add(alg,'X25519MLKEM768',rtt,cond,rep)
   for cond in ['padding800','padding900','padding1600','padding3200','cached_padding800','cached_padding900','cached_padding1600']:
    for rep in range(10):add(alg,'X25519MLKEM768',60,cond,rep)
 random.Random(20260920).shuffle(out);return out

async def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pilot',action='store_true');ap.add_argument('--concurrency',type=int,default=2);ap.add_argument('--output',type=Path,help='New output directory; existing completed trials are skipped');args=ap.parse_args()
 base=args.output.resolve() if args.output else ROOT/'raw'/('pilot' if args.pilot else 'measurements');base.mkdir(parents=True,exist_ok=True)
 design=build_design(args.pilot);(base/'design.json').write_text(json.dumps(design,indent=2));sem=asyncio.Semaphore(args.concurrency);n=0
 async def worker(rec):
  nonlocal n
  async with sem:
   if (base/rec['id']/'result.json').exists():return
   res=await trial(rec,base);n+=1
   if n%20==0 or not res['success']:print(n,'/',len(design),rec['id'],res['success'],res.get('latency_ms',res.get('error')),flush=True)
 await asyncio.gather(*(worker(rec) for rec in design))
 print('completed',len(design),flush=True)
if __name__=='__main__':asyncio.run(main())
