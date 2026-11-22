#!/usr/bin/env python3
"""Block G: implementation-version replication of Block A on a second OpenSSL release.

The design is *identical* to Block A (``run_block_a.make_design``): the same 16 cells
(4 authentication algorithms x cached intermediate on/off x 0/2,400-byte ClientHello
enlargement), 30 replicates per cell, the same pseudo-random interleaving and run order,
the same certificates, the same 60 ms loopback RTT and 100 Mbit/s link model, and the
same 5 s per-trial budget.  Only three things differ, and all three are recorded:

* the probe binary is linked against a different OpenSSL release (``--probe``,
  ``--libdir``); Block G used OpenSSL 3.5.9 (29 Sep 2026), which contains the fix for
  CVE-2026-35191 (unvalidated amplification credit counted once per packet instead of
  once per datagram);
* the CPU mapping is configurable (``--cpus server,client,proxy``) because the Block G
  host exposed two CPUs; ``proxy`` may be ``-`` for "not pinned";
* an environment record (``environment.json``) is written next to ``design.json``.

Trial identifiers are ``blockG_<cell>_r<NN>``; ``configuration.json`` keeps the matching
Block A identifier in ``block_a_id`` so the two campaigns can be joined trial by trial.

A same-host control (``--block-label Gc``, probe linked against OpenSSL 3.5.5 built from
source with the same options) was added after the 3.5.9 results to separate the library
version from the host; it was not part of the prospective specification.
"""
from __future__ import annotations
import argparse, asyncio, json, os, platform, resource, socket, subprocess, sys, time, hashlib
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE.parent))
from run_block_a import Link, free_port, make_design  # noqa: E402  (identical design + link model)


def pin(cpus):
    def _pin():
        if cpus:
            os.sched_setaffinity(0, set(cpus))
    return _pin


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def make_design_g(block_label: str = 'G'):
    rows = make_design()
    for r in rows:
        r['block_a_id'] = r['id']
        r['id'] = r['id'].replace('blockA_', f'block{block_label}_', 1)
        r['block'] = block_label
    return rows


def environment_record(probe: Path, libdir: Path | None, cpus) -> dict:
    env = dict(os.environ)
    if libdir:
        env['LD_LIBRARY_PATH'] = str(libdir) + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    rec = {
        'generated_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'uname': ' '.join(platform.uname()),
        'python': sys.version.split()[0],
        'probe': str(probe), 'probe_sha256': sha256(probe),
        'libdir': str(libdir) if libdir else None,
        'cpus': {'server': cpus[0], 'client': cpus[1], 'proxy': cpus[2]},
        'nproc': os.cpu_count(),
    }
    if libdir:
        for lib in ('libssl.so.3', 'libcrypto.so.3'):
            p = libdir / lib
            if p.exists():
                rec[lib + '_sha256'] = sha256(p)
    openssl_bin = (libdir.parent / 'bin' / 'openssl') if libdir else Path('openssl')
    try:
        rec['openssl_version_a'] = subprocess.run([str(openssl_bin), 'version', '-a'], capture_output=True,
                                                  text=True, env=env, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        rec['openssl_version_a'] = f'unavailable: {exc}'
    try:
        rec['lscpu'] = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        rec['lscpu'] = None
    return rec


async def trial(rec, base, probe: Path, cpus, libdir: Path | None):
    d = base / rec['id']; d.mkdir(parents=True, exist_ok=True); q = d / 'qlogs'; q.mkdir(exist_ok=True)
    (d / 'configuration.json').write_text(json.dumps(rec, indent=2, sort_keys=True))
    env = os.environ.copy(); env['QLOGDIR'] = str(q); env['QUIC_RETRY'] = '0'; env['QUIC_COMPRESS'] = '0'
    if libdir:
        env['LD_LIBRARY_PATH'] = str(libdir) + (':' + env['LD_LIBRARY_PATH'] if env.get('LD_LIBRARY_PATH') else '')
    cert = ROOT / 'certificates' / rec['algorithm']; sp = free_port()
    chain = cert / ('leaf.pem' if rec['cached'] else 'chain.pem')
    trust = cert / ('trust_cached.pem' if rec['cached'] else 'root.pem')
    common = [str(chain), str(cert / 'leaf.key'), str(trust), rec['group'], str(rec['enlargement_bytes'])]
    sf = open(d / 'server.err', 'w'); cf = open(d / 'client.err', 'w'); dg = open(d / 'datagrams.jsonl', 'w')
    server = client = None; link = None
    result = {'id': rec['id'], 'success': False, 'run_order': rec['run_order'],
              'loadavg_before': os.getloadavg(), 'proxy_cpu': cpus[2], 'server_cpu': cpus[0], 'client_cpu': cpus[1],
              'openssl_build': rec.get('openssl_build')}
    try:
        server = await asyncio.create_subprocess_exec(str(probe), 'server', str(sp), *common, str(d / 'server'),
                                                      env=env, stdout=asyncio.subprocess.PIPE, stderr=sf,
                                                      preexec_fn=pin([cpus[0]] if cpus[0] is not None else None))
        ready = await asyncio.wait_for(server.stdout.readline(), 2.0)
        (d / 'server.out').write_bytes(ready)
        if not ready:
            raise RuntimeError('server did not initialize')
        transport, link = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Link(('127.0.0.1', sp), rec['rtt_ms'], dg, rec['up_mbps'], rec['down_mbps']),
            local_addr=('127.0.0.1', 0))
        pp = transport.get_extra_info('sockname')[1]
        client = await asyncio.create_subprocess_exec(str(probe), 'client', str(pp), *common, str(d / 'client'),
                                                      env=env, stdout=asyncio.subprocess.PIPE, stderr=cf,
                                                      preexec_fn=pin([cpus[1]] if cpus[1] is not None else None))
        out = []; tstart = tend = None; until = time.monotonic() + 5.0
        while time.monotonic() < until:
            line = await asyncio.wait_for(client.stdout.readline(), max(.001, until - time.monotonic()))
            if not line:
                break
            out.append(line); e = json.loads(line)
            if e['event'] == 'start':
                tstart = e['t']
            if e['event'] == 'complete':
                tend = e['t']; result.update(e); result['success'] = True; break
        (d / 'client.out').write_bytes(b''.join(out))
        if tend is not None and tstart is not None:
            result['latency_ms'] = 1000 * (tend - tstart)
            result['first_band'] = result['latency_ms'] < rec['first_band_threshold_ms']
            try:
                sout = await asyncio.wait_for(server.stdout.read(), .7)
                with open(d / 'server.out', 'ab') as f:
                    f.write(sout)
            except asyncio.TimeoutError:
                result['server_drain_timeout'] = True
    except (asyncio.TimeoutError, RuntimeError, ValueError) as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if link:
            link.finish()
        for p in [client, server]:
            if p is not None and p.returncode is None:
                p.terminate()
                try:
                    await asyncio.wait_for(p.wait(), 1)
                except asyncio.TimeoutError:
                    p.kill(); await p.wait()
        for f in [sf, cf, dg]:
            f.close()
        result['loadavg_after'] = os.getloadavg()
        result['maxrss_kb'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        (d / 'result.json').write_text(json.dumps(result, indent=2, sort_keys=True))
    return result


def parse_cpus(text: str):
    parts = text.split(',')
    if len(parts) != 3:
        raise argparse.ArgumentTypeError('expected server,client,proxy')
    return tuple(None if p.strip() in ('-', '') else int(p) for p in parts)


async def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, default=ROOT / 'raw' / 'block_g')
    ap.add_argument('--probe', type=Path, default=ROOT / 'bin' / 'quic_probe_3.5.9')
    ap.add_argument('--libdir', type=Path, default=None, help='directory holding libssl.so.3/libcrypto.so.3 to preload')
    ap.add_argument('--cpus', type=parse_cpus, default=(0, 1, None), help='server,client,proxy CPU ids ("-" = unpinned)')
    ap.add_argument('--openssl-build', default='OpenSSL 3.5.9', help='free-text label recorded in every configuration.json')
    ap.add_argument('--block-label', default='G', help="block label used in ids and configuration.json ('G' = 3.5.9 run, 'Gc' = same-host 3.5.5 control)")
    args = ap.parse_args(); base = args.output.resolve(); base.mkdir(parents=True, exist_ok=True)
    probe = args.probe.resolve(); libdir = args.libdir.resolve() if args.libdir else None
    if args.cpus[2] is not None:
        os.sched_setaffinity(0, {args.cpus[2]})
    design = make_design_g(args.block_label)
    for r in design:
        r['openssl_build'] = args.openssl_build
    (base / 'design.json').write_text(json.dumps(design, indent=2, sort_keys=True))
    (base / 'environment.json').write_text(json.dumps(environment_record(probe, libdir, args.cpus), indent=2))
    progress = base / 'progress.jsonl'
    t0 = time.monotonic()
    for idx, rec in enumerate(design, 1):
        result_path = base / rec['id'] / 'result.json'
        if result_path.exists():
            continue
        res = await trial(rec, base, probe, args.cpus, libdir)
        with progress.open('a') as f:
            f.write(json.dumps(res, sort_keys=True) + '\n')
        if idx % 20 == 0 or not res['success']:
            print(f'{idx}/{len(design)} {rec["id"]} success={res["success"]} latency={res.get("latency_ms")} '
                  f'elapsed={time.monotonic() - t0:.0f}s', flush=True)
    print('completed', len(design))


if __name__ == '__main__':
    asyncio.run(main())
