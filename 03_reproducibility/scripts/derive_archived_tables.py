#!/usr/bin/env python3
"""Re-derive archived-campaign numerical summaries from the
normalized trial ledger of the pinned public repository
(vishwaka-2419/pq-quic-authentication, commit 46206c98..., ``analysis/trials.csv``
and ``analysis/retrospective_classification.csv``).

The ledgers are vendored in ``05_upstream_archive/normalized/`` with SHA-256 sums so
that the derivation works without network access.  Outputs are written to
``03_reproducibility/data/archived_*.csv``.  Standard library only.
"""
from pathlib import Path
import csv
import statistics
from collections import Counter, defaultdict

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / '05_upstream_archive' / 'normalized'
OUT = ROOT / '03_reproducibility' / 'data'

ALG = {'ecdsa': 'ECDSA', 'mldsa44': 'ML-DSA-44', 'mldsa65': 'ML-DSA-65', 'mldsa87': 'ML-DSA-87'}


def load(name):
    with (SRC / name).open(newline='') as f:
        return list(csv.DictReader(f))


def sel(rows, **kw):
    out = []
    for r in rows:
        if all(r[k] == v for k, v in kw.items()):
            out.append(r)
    return out


def med(rows, key='latency_ms'):
    return round(statistics.median(float(r[key]) for r in rows), 2)


def write(name, rows, fields):
    with (OUT / name).open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print('wrote', name, len(rows), 'rows')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    tr = load('trials.csv')
    rc = load('retrospective_classification.csv')
    base = dict(retry='False', loss='0.0', burst='False', up_mbps='100.0', down_mbps='100.0')

    # 1. classifier comparison on the 1,740 eligible traces, recomputed from the ledger.
    #    C0 is the complete client Initial flight (all ClientHello datagrams); the observed
    #    one-round label is completion below 1.5 configured RTTs.  The vendored
    #    retrospective_classification.csv (repository output) must agree exactly.
    elig = sel(tr, success='True', **base)
    assert len(elig) == len(rc) == 1740, (len(elig), len(rc))
    rules = {
        'Amplification on TLS bytes': lambda r: float(r['tls_server_bytes']) <= 3 * float(r['initial_client_flight_bytes']),
        'Amplification on UDP bytes': lambda r: float(r['authentication_udp_bytes']) <= 3 * float(r['initial_client_flight_bytes']),
        'Amplification and 12 kB window on UDP bytes': lambda r: (float(r['authentication_udp_bytes']) <= 3 * float(r['initial_client_flight_bytes'])
                                                                  and float(r['authentication_udp_bytes']) <= 12000),
    }
    repo_cols = ['static_tls_feasible', 'udp_amp_feasible', 'two_budget_feasible']
    repo = {r['id']: r for r in rc}
    rows = []
    for (label, fn), col in zip(rules.items(), repo_cols):
        dis = ff = fi = repo_dis = 0
        for r in elig:
            obs = float(r['latency_ms']) < 1.5 * float(r['rtt_ms'])
            p = fn(r)
            if p != obs:
                dis += 1
                ff += p and not obs
                fi += (not p) and obs
            if (repo[r['id']][col] == 'True') != p:
                repo_dis += 1
        assert repo_dis == 0, (label, repo_dis)
        rows.append(dict(rule=label, disagreements=dis, false_feasible=ff, false_infeasible=fi,
                         eligible_traces=len(elig), rate_pct=round(100 * dis / len(elig), 2)))
    write('archived_classifier_comparison.csv', rows, list(rows[0]))

    # 2. baseline medians by RTT (full chain, hybrid group)
    rows = []
    for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
        for rtt in ['20', '60', '120']:
            s = sel(tr, algorithm=alg, group='X25519MLKEM768', rtt_ms=rtt, condition='plain', success='True', **base)
            rows.append(dict(configuration=('ecdsa_h' if alg == 'ecdsa' else alg), rtt_ms=int(rtt), n=len(s),
                             median_ms=med(s), source='archived_3630_campaign'))
    write('archived_baseline_rtt.csv', rows, list(rows[0]))

    # 3. full-chain message and datagram sizes at 60 ms (modal values)
    rows = []
    for alg, grp, label in [('ecdsa', 'X25519', 'ECDSA/X25519'), ('ecdsa', 'X25519MLKEM768', 'ECDSA/X25519MLKEM768'),
                            ('mldsa44', 'X25519MLKEM768', 'ML-DSA-44/X25519MLKEM768'),
                            ('mldsa65', 'X25519MLKEM768', 'ML-DSA-65/X25519MLKEM768'),
                            ('mldsa87', 'X25519MLKEM768', 'ML-DSA-87/X25519MLKEM768')]:
        s = sel(tr, algorithm=alg, group=grp, rtt_ms='60', condition='plain', success='True', **base)
        nopad = [r for r in s if r['padded_ack_datagrams_before_crypto'] == '0'] or s
        mode = lambda k, rr: Counter(int(float(r[k])) for r in rr).most_common(1)[0][0]
        rows.append(dict(configuration=label, n=len(s), client_hello_bytes=mode('client_hello_bytes', s),
                         certificate_bytes=mode('certificate_bytes', s), certificate_verify_bytes=mode('certificate_verify_bytes', s),
                         server_tls_bytes=mode('tls_server_bytes', s), server_udp_bytes=mode('authentication_udp_bytes', nopad)))
    write('archived_full_chain_sizes.csv', rows, list(rows[0]))

    # 4. interventions at 60 ms, hybrid group, 100 Mbit/s, no loss, no Retry
    conds = [('plain', 'Full chain'), ('compressed', 'CC'), ('cached', 'CI'), ('padding', 'CE'),
             ('cached_padding', 'CI+CE'), ('cached_compressed_padding', 'CI+CC+CE')]
    rows = []
    for alg in ['mldsa44', 'mldsa65', 'mldsa87']:
        for cond, label in conds:
            s = sel(tr, algorithm=alg, group='X25519MLKEM768', rtt_ms='60', condition=cond, success='True', **base)
            fb = sum(1 for r in s if float(r['latency_ms']) < 90)
            rows.append(dict(algorithm=alg, condition=label, n=len(s), first_band=fb, median_ms=med(s), rtt_ms=60,
                             server_tls_bytes=Counter(int(r['tls_server_bytes']) for r in s).most_common(1)[0][0],
                             source='archived_3630_campaign'))
    write('archived_interventions_60ms.csv', rows, list(rows[0]))

    # 5. client-credit threshold cells (ClientHello enlargement 0/800/900/1600/2400/3200 bytes)
    rows = []
    for alg in ['mldsa44', 'mldsa65', 'mldsa87']:
        for cached, label in [('False', 'full chain'), ('True', 'CI')]:
            for pad in ['0', '800', '900', '1600', '2400', '3200']:
                s = [r for r in sel(tr, algorithm=alg, group='X25519MLKEM768', rtt_ms='60', cached=cached, padding=pad,
                                     compress='False', success='True', **base)]
                if not s:
                    continue
                fb = sum(1 for r in s if float(r['latency_ms']) < 90)
                dg = Counter(int(float(r['initial_client_datagrams'])) for r in s).most_common(1)[0][0]
                c0 = Counter(int(float(r['client_bytes_before_first_server_datagram'])) for r in s).most_common(1)[0][0]
                auth = Counter(int(float(r['authentication_udp_bytes'])) for r in s if r['padded_ack_datagrams_before_crypto'] == '0')
                auth_nopad = auth.most_common(1)[0][0] if auth else ''
                pads = Counter(int(r['padded_ack_datagrams_before_crypto']) for r in s)
                rows.append(dict(algorithm=alg, chain=label, enlargement_bytes=int(pad),
                                 client_hello_bytes=Counter(int(float(r['client_hello_bytes'])) for r in s).most_common(1)[0][0],
                                 client_initial_datagrams=dg, c0_bytes=c0, allowance_bytes=3 * c0,
                                 auth_flight_udp_bytes=auth_nopad, n=len(s), first_band=fb,
                                 pads_0=pads.get(0, 0), pads_1=pads.get(1, 0), pads_2=pads.get(2, 0),
                                 pads_3plus=sum(v for k, v in pads.items() if k >= 3), median_ms=med(s)))
    write('archived_credit_threshold.csv', rows, list(rows[0]))

    # 6. robustness core: Retry, loss, uplink
    rows = []
    for alg, grp, label in [('ecdsa', 'X25519', 'ECDSA/X25519'), ('ecdsa', 'X25519MLKEM768', 'ECDSA/hybrid'),
                            ('mldsa44', 'X25519MLKEM768', 'ML-DSA-44'), ('mldsa65', 'X25519MLKEM768', 'ML-DSA-65'),
                            ('mldsa87', 'X25519MLKEM768', 'ML-DSA-87')]:
        b = sel(tr, algorithm=alg, group=grp, rtt_ms='60', condition='plain', success='True', **base)
        s = sel(tr, algorithm=alg, group=grp, rtt_ms='60', condition='retry', success='True', loss='0.0', burst='False', up_mbps='100.0', down_mbps='100.0')
        rows.append(dict(scenario='Retry', configuration=label, baseline_ms=med(b), condition_ms=med(s),
                         delta_ms=round(med(s) - med(b), 2), attempts=len(s), successes=len(s), median_success_ms=med(s)))
    for cond, label in [('plain', 'ML-DSA-87 full'), ('cached', 'ML-DSA-87 cached')]:
        for loss, burst, name in [('0.01', 'False', '1% independent loss'), ('0.01', 'True', '1% burst loss'),
                                  ('0.05', 'False', '5% independent loss'), ('0.05', 'True', '5% burst loss')]:
            s = sel(tr, algorithm='mldsa87', group='X25519MLKEM768', rtt_ms='60', condition=cond, loss=loss, burst=burst)
            ok = [r for r in s if r['success'] == 'True']
            rows.append(dict(scenario=name, configuration=label, baseline_ms='', condition_ms='', delta_ms='',
                             attempts=len(s), successes=len(ok), median_success_ms=med(ok)))
    for alg, label in [('mldsa44', 'ML-DSA-44'), ('mldsa87', 'ML-DSA-87')]:
        for cond, cl in [('plain', 'full'), ('padding', 'CE'), ('cached', 'CI')]:
            for up in ['1.0', '10.0']:
                s = sel(tr, algorithm=alg, group='X25519MLKEM768', rtt_ms='60', condition=cond, up_mbps=up, down_mbps='10.0', success='True')
                rows.append(dict(scenario=f'{up.rstrip("0").rstrip(".")} Mbit/s uplink', configuration=f'{label} {cl}', baseline_ms='',
                                 condition_ms=med(s), delta_ms='', attempts=len(s), successes=len(s), median_success_ms=med(s)))
    write('archived_robustness_core.csv', rows, list(rows[0]))

    # 7. failures ledger
    fails = [r for r in tr if r['success'] != 'True']
    rows = [dict(id=r['id'], algorithm=r['algorithm'], condition=r['condition'], rtt_ms=r['rtt_ms'], loss=r['loss'], burst=r['burst'],
                 failure_kind=r['failure_kind']) for r in fails]
    write('archived_failures.csv', rows, list(rows[0]))

    # 8. campaign structure summary
    cells = Counter((r['algorithm'], r['group'], r['rtt_ms'], r['condition'], r['retry'], r['compress'], r['cached'], r['padding'],
                     r['loss'], r['burst'], r['up_mbps'], r['down_mbps']) for r in tr)
    elig = sel(tr, success='True', **base)
    print('attempts', len(tr), 'cells', len(cells), 'successes', sum(1 for r in tr if r['success'] == 'True'),
          'eligible loss-free no-Retry 100 Mbit/s', len(elig), 'failures', Counter(r['failure_kind'] for r in fails))


if __name__ == '__main__':
    main()
