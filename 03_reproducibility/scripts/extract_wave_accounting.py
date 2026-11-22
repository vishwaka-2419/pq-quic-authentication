#!/usr/bin/env python3
"""Wave-level byte accounting for every retained raw trial (Blocks A, C, F, G, Gc).

For each trial directory the script reads ``configuration.json``, ``result.json``,
``datagrams.jsonl`` and the server qlog, and derives:

* ``c0``: client UDP payload bytes observed before the first server datagram
  (the credit that creates the pre-validation amplification allowance 3*c0);
* ``first_wave_bytes``: server UDP payload sent before any further client datagram
  (the feedback-free first wave that the two byte limits bound);
* ``wave_bytes``: the complete sequence of server bursts separated by client datagrams;
* ``pre_crypto_pads``: ACK+PADDING-only Initial packets emitted before the first
  server CRYPTO-bearing packet (from the server qlog);
* ``auth_flight_bytes``: server UDP payload of the authentication flight
  (ServerHello..Finished datagrams), i.e. total server bytes minus the padded
  ACK-only Initials and minus the post-handshake bytes sent after the client's
  last datagram (HANDSHAKE_DONE);
* ``flight_bytes``: ``auth_flight_bytes + pad_bytes`` -- the quantity that must fit
  both the amplification allowance and the initial congestion window for the
  handshake to complete without feedback;
* ``rounds``: 1/2/3 using cut points at 1.5 and 2.5 configured RTTs.

Outputs ``data/new_wave_accounting.csv`` (one row per trial) and
``data/new_wave_summary.csv`` (one row per cell).  Only the standard library is used.
"""
from pathlib import Path
import csv
import json
import statistics
import sys

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
RAW = ROOT / '03_reproducibility' / 'experiment' / 'raw'
OUT_DIR = ROOT / '03_reproducibility' / 'data'
OUT_TRIALS = OUT_DIR / 'new_wave_accounting.csv'
OUT_SUMMARY = OUT_DIR / 'new_wave_summary.csv'


def read_qlog_events(path):
    for raw in path.read_bytes().split(b'\x1e'):
        raw = raw.strip()
        if not raw:
            continue
        try:
            yield json.loads(raw)
        except json.JSONDecodeError:
            continue


def first_client_dcid(trial):
    """Destination connection ID of the first client datagram (QUIC long header), as lower-case hex."""
    for line in (trial / 'datagrams.jsonl').open():
        e = json.loads(line)
        if e.get('event') == 'observed' and e.get('direction') == 'cs':
            b = bytes.fromhex(e['hex'])
            if len(b) > 6 and b[0] & 0x80:
                dcil = b[5]
                return b[6:6 + dcil].hex()
            return None
    return None


def server_qlog(trial):
    """The server qlog of the logged connection: the file named after the original DCID of the first client
    datagram; falls back to the largest *_server.sqlog (a few Block A/C directories hold a stray, truncated
    qlog pair of an unlogged connection)."""
    qfiles = sorted((trial / 'qlogs').glob('*_server.sqlog'))
    if not qfiles:
        return None
    dcid = first_client_dcid(trial)
    for q in qfiles:
        if dcid and q.name.startswith(dcid):
            return q
    return max(qfiles, key=lambda q: q.stat().st_size)


def pre_crypto_pads(trial):
    """Count ACK+PADDING-only packets sent by the server before its first CRYPTO packet."""
    q = server_qlog(trial)
    if q is None:
        return None
    pads = 0
    for e in read_qlog_events(q):
        if e.get('name') != 'transport:packet_sent':
            continue
        frames = e.get('data', {}).get('frames', [])
        types = {f.get('frame_type') for f in frames}
        if 'crypto' in types:
            break
        if frames and types.issubset({'ack', 'padding'}):
            pads += 1
    return pads


def analyse(trial, block):
    cfg = json.loads((trial / 'configuration.json').read_text())
    res = json.loads((trial / 'result.json').read_text())
    obs = []
    for line in (trial / 'datagrams.jsonl').read_text().splitlines():
        e = json.loads(line)
        if e.get('event') == 'observed':
            obs.append((e['t'], e['direction'], int(e['bytes'])))
    obs.sort()
    # client credit before the first server datagram
    first_sc = next((i for i, o in enumerate(obs) if o[1] == 'sc'), None)
    c0 = sum(o[2] for o in obs[:first_sc]) if first_sc is not None else 0
    # server bursts separated by client datagrams
    waves, cur = [], None
    for t, d, b in obs:
        if d == 'sc':
            if cur is None:
                cur = [0, 0]
            cur[0] += b
            cur[1] += 1
        elif cur is not None:
            waves.append(cur)
            cur = None
    if cur is not None:
        waves.append(cur)
    total_sc = sum(o[2] for o in obs if o[1] == 'sc')
    total_cs = sum(o[2] for o in obs if o[1] == 'cs')
    last_cs_t = max((o[0] for o in obs if o[1] == 'cs'), default=0.0)
    post = sum(o[2] for o in obs if o[1] == 'sc' and o[0] > last_cs_t)
    pads = pre_crypto_pads(trial)
    pad_bytes = 1200 * pads if pads is not None else None
    auth = total_sc - post - pad_bytes if pad_bytes is not None else None
    flight = total_sc - post
    rtt = float(cfg.get('rtt_ms', 0))
    lat = float(res['latency_ms'])
    if rtt > 0:
        rounds = 1 if lat < 1.5 * rtt else (2 if lat < 2.5 * rtt else 3)
        first_band = lat < 1.5 * rtt
        predicted = (flight <= 3 * c0) and (flight <= 12000)
    else:
        # configured RTT 0 (Block F): no round bands exist, so the band-related columns are left undefined
        rounds, first_band, predicted = '', '', ''
    return {
        'block': block,
        'id': cfg['id'],
        'algorithm': cfg['algorithm'],
        'profile': cfg.get('profile', 'laboratory' if block != 'C' else 'webpki-like'),
        'group': cfg.get('group', ''),
        'cached': cfg.get('cached', False),
        'enlargement_bytes': cfg.get('enlargement_bytes', 0),
        'rtt_ms': rtt,
        'run_order': res.get('run_order', cfg.get('run_order')),
        'success': res.get('success'),
        'latency_ms': lat,
        'first_band': first_band,
        'rounds': rounds,
        'c0_bytes': c0,
        'allowance_bytes': 3 * c0,
        'first_wave_bytes': waves[0][0] if waves else 0,
        'first_wave_datagrams': waves[0][1] if waves else 0,
        'n_waves': len(waves),
        'wave_bytes': ';'.join(str(w[0]) for w in waves),
        'pre_crypto_pads': pads,
        'pad_bytes': pad_bytes,
        'auth_flight_bytes': auth,
        'flight_bytes': flight,
        'post_handshake_bytes': post,
        'total_server_udp_bytes': total_sc,
        'total_client_udp_bytes': total_cs,
        'fits_allowance': flight <= 3 * c0,
        'fits_window': flight <= 12000,
        'predicted_one_round': predicted,
    }


def main():
    rows = []
    for block, sub in [('A', 'block_a'), ('C', 'block_c'), ('F', 'block_f'), ('G', 'block_g'), ('Gc', 'block_gc')]:
        d = RAW / sub
        if not d.exists():
            continue
        for trial in sorted(p for p in d.iterdir() if p.is_dir() and (p / 'result.json').exists()):
            rows.append(analyse(trial, block))
    if not rows:
        sys.exit('no trials found')
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with OUT_TRIALS.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    # per-cell summary
    cells = {}
    for r in rows:
        key = (r['block'], r['algorithm'], r['profile'], r['group'], r['cached'], r['enlargement_bytes'])
        cells.setdefault(key, []).append(r)
    summ = []
    for key in sorted(cells, key=str):
        c = cells[key]
        fw = [r['first_wave_bytes'] for r in c]
        fl = [r['flight_bytes'] for r in c]
        pads = [r['pre_crypto_pads'] for r in c if r['pre_crypto_pads'] is not None]
        pred = [r['predicted_one_round'] for r in c]
        obs1 = [r['rounds'] == 1 for r in c] if c[0]['rounds'] != '' else []
        agree = sum(1 for p, o in zip(pred, obs1) if p == o) if obs1 else ''
        pred_count = sum(1 for p in pred if p is True) if obs1 else ''
        summ.append({
            'block': key[0], 'algorithm': key[1], 'profile': key[2], 'group': key[3],
            'cached': key[4], 'enlargement_bytes': key[5], 'n': len(c),
            'c0_bytes': c[0]['c0_bytes'], 'allowance_bytes': 3 * c[0]['c0_bytes'],
            'auth_flight_bytes_mode': statistics.mode([r['auth_flight_bytes'] for r in c if r['auth_flight_bytes'] is not None]),
            'flight_bytes_min': min(fl), 'flight_bytes_max': max(fl),
            'first_wave_bytes_min': min(fw), 'first_wave_bytes_max': max(fw),
            'first_wave_values': ';'.join(f'{v}:{fw.count(v)}' for v in sorted(set(fw))),
            'pads_0': pads.count(0), 'pads_1': pads.count(1), 'pads_2': pads.count(2),
            'rounds_1': sum(1 for r in c if r['rounds'] == 1),
            'rounds_2': sum(1 for r in c if r['rounds'] == 2),
            'rounds_3': sum(1 for r in c if r['rounds'] == 3),
            'predicted_one_round': pred_count,
            'prediction_agrees_with_observed': agree,
            'median_latency_ms': statistics.median(r['latency_ms'] for r in c),
        })
    with OUT_SUMMARY.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(summ[0]))
        w.writeheader()
        w.writerows(summ)
    print('wrote', OUT_TRIALS, len(rows), 'trials;', OUT_SUMMARY, len(summ), 'cells')
    for s in summ:
        print(s['block'], s['algorithm'], s['profile'], 'CI' if s['cached'] else '--', s['enlargement_bytes'],
              'allow', s['allowance_bytes'], 'auth', s['auth_flight_bytes_mode'], 'flight', s['flight_bytes_min'], '-', s['flight_bytes_max'],
              'wave', s['first_wave_values'], 'rounds', s['rounds_1'], s['rounds_2'], s['rounds_3'],
              'pred1', s['predicted_one_round'], 'agree', s['prediction_agrees_with_observed'])


if __name__ == '__main__':
    main()
