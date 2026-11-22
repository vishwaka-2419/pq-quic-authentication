#!/usr/bin/env python3
"""Validate numerical results, raw-file completeness, and protocol digests.

Run from any directory after installing the dataset beside the code:
    python3 03_reproducibility/tests/check_headlines.py

For a dataset at another root:
    python3 03_reproducibility/tests/check_headlines.py --root /path/to/dataset

The root must contain 03_reproducibility/ and 06_experiment_protocols/.
Only Python's standard library is required. No TeX source, compiled document,
figure, or presentation table is read. Exit code 0 means all checks passed.
"""
from pathlib import Path
import argparse
import hashlib
import csv
import json
import sys
from collections import Counter

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    '--root', type=Path, default=Path(__file__).resolve().parents[2],
    help='root containing the extracted dataset and protocol files',
)
ROOT = parser.parse_args().root.resolve()
D = ROOT / '03_reproducibility' / 'data'
RAW = ROOT / '03_reproducibility' / 'experiment' / 'raw'


def read(name):
    with (D / name).open(newline='') as f:
        return list(csv.DictReader(f))


def b(x):
    return x == 'True'


failures = []
checks_run = 0


def check(cond, msg):
    global checks_run
    checks_run += 1
    if not cond:
        failures.append(msg)
        print('FAIL', msg)
    else:
        print('ok  ', msg)


A = read('block_A_summary.csv'); At = read('block_A_trials.csv')
C = read('block_C_summary.csv'); Ct = read('block_C_trials.csv')
F = read('block_F_summary.csv'); Ft = read('block_F_trials.csv')
G = read('block_G_summary.csv'); Gt = read('block_G_trials.csv')      # OpenSSL 3.5.9, host 2
GC = read('block_Gc_summary.csv'); GCt = read('block_Gc_trials.csv')  # OpenSSL 3.5.5, host 2 (control)
GQ = json.loads((D / 'block_G_quality_checks.json').read_text())
Q = read('new_qlog_features.csv')
W = read('new_wave_accounting.csv')
WS = read('new_wave_summary.csv')
CL = read('archived_classifier_comparison.csv')
TH = read('archived_credit_threshold.csv')
RB = read('archived_robustness_core.csv')
SZ = read('archived_full_chain_sizes.csv')
IV = read('archived_interventions_60ms.csv')
FI = read('block_A_fisher_tests.csv')


def cell(df, alg, ci, ce):
    x = [r for r in df if r['algorithm'] == alg and b(r['cached']) == ci and int(r['enlargement_bytes']) == ce]
    assert len(x) == 1, (alg, ci, ce, len(x))
    return x[0]


# --- trial counts and integrity
check(len(At) == 480 and all(b(r['success']) for r in At), 'Block A: 480/480 successful trials')
check(len(Ct) == 240 and all(b(r['success']) for r in Ct), 'Block C: 240/240 successful trials')
check(len(Ft) == 150 and all(b(r['success']) for r in Ft), 'Block F: 150/150 successful trials')
check(len(Gt) == 480 and all(b(r['success']) for r in Gt), 'Block G (3.5.9): 480/480 successful trials')
check(len(GCt) == 480 and all(b(r['success']) for r in GCt), 'Block G control (3.5.5, same host): 480/480 successful trials')
check(len(Q) == 1830 and len(W) == 1830, 'qlog features and wave accounting cover 1,830 trials')

# --- Block A results
for alg in ['mldsa44', 'mldsa65']:
    check(int(cell(A, alg, True, 2400)['first_band']) == 30, f'{alg} CI+CE 30/30 one round')
    for ci, ce in [(True, 0), (False, 2400), (False, 0)]:
        check(int(cell(A, alg, ci, ce)['first_band']) == 0, f'{alg} ci={ci} ce={ce} 0/30 one round')
check(int(cell(A, 'mldsa87', True, 2400)['first_band']) == 0, 'mldsa87 CI+CE 0/30')
check((int(cell(A, 'mldsa87', False, 0)['rounds_2']), int(cell(A, 'mldsa87', False, 0)['rounds_3'])) == (6, 24), 'mldsa87 full chain 6 two-round / 24 three-round')
for alg in ['ecdsa']:
    for ci, ce in [(False, 0), (True, 0), (False, 2400), (True, 2400)]:
        check(int(cell(A, alg, ci, ce)['first_band']) == 30, f'ecdsa ci={ci} ce={ce} 30/30')
check(abs(float(cell(A, 'mldsa44', True, 2400)['median_ms']) - 65.80) < 0.01, 'mldsa44 CI+CE median 65.80 ms')
check(abs(float(cell(A, 'mldsa65', True, 2400)['median_ms']) - 66.47) < 0.01, 'mldsa65 CI+CE median 66.47 ms')
check(all(abs(float(r['p_raw']) - 8.4556e-18) < 1e-21 and abs(float(r['p_holm']) - 1.6911e-17) < 1e-20 for r in FI), 'Fisher raw 8.46e-18, Holm 1.69e-17')

# --- observed first-wave stops (wave accounting)
def wcell(block, alg, ci, ce, profile=None):
    return [r for r in W if r['block'] == block and r['algorithm'] == alg and b(r['cached']) == ci and int(r['enlargement_bytes']) == ce
            and (profile is None or r['profile'] == profile)]

for alg in ['mldsa44', 'mldsa65', 'mldsa87']:
    for ci in [False, True]:
        fw = Counter(int(r['first_wave_bytes']) for r in wcell('A', alg, ci, 0))
        check(fw == Counter({7199: 30}), f'Block A {alg} ci={ci} no CE: first wave 7,199 B in 30/30')
for alg, ci in [('mldsa44', False), ('mldsa65', False), ('mldsa87', False), ('mldsa87', True)]:
    fw = Counter(int(r['first_wave_bytes']) for r in wcell('A', alg, ci, 2400))
    check(fw == Counter({11999: 30}), f'Block A {alg} ci={ci} CE: first wave 11,999 B in 30/30')
check(Counter(int(r['first_wave_bytes']) for r in wcell('A', 'mldsa44', True, 2400)) == Counter({9376: 29, 10576: 1}), 'mldsa44 CI+CE first wave 9,376 (29) / 10,576 (1)')
check(Counter(int(r['first_wave_bytes']) for r in wcell('A', 'mldsa65', True, 2400)) == Counter({11878: 30}), 'mldsa65 CI+CE first wave 11,878 B in 30/30 (122 B margin)')
check(all(r['predicted_one_round'] == str(int(r['rounds']) == 1) for r in W if r['block'] in ('A', 'C')), 'trial-level two-limit rule matches all 720 Block A/C outcomes')
check(all(r['predicted_one_round'] == str(int(r['rounds']) == 1) for r in W if r['block'] in ('G', 'Gc')), 'trial-level two-limit rule matches all 960 Block G outcomes')
check(all(r['predicted_one_round'] == str(int(r['rounds']) == 1) for r in W if r['block'] in ('A', 'C', 'G', 'Gc')), 'trial-level two-limit rule matches all 1,680 new trials')
auth = {(r['block'], r['algorithm'], b(r['cached'])): int(r['auth_flight_bytes_mode']) for r in WS if r['block'] in ('A', 'C', 'G', 'Gc')}
check(auth[('A', 'mldsa44', False)] == 12397 and auth[('A', 'mldsa44', True)] == 8176, 'ML-DSA-44 authentication flight 12,397 / 8,176 B')
check(auth[('A', 'mldsa65', False)] == 16470 and auth[('A', 'mldsa65', True)] == 10678, 'ML-DSA-65 authentication flight 16,470 / 10,678 B')
check(auth[('A', 'mldsa87', False)] == 21920 and auth[('A', 'mldsa87', True)] == 14080, 'ML-DSA-87 authentication flight 21,920 / 14,080 B')
check(auth[('C', 'mldsa65', True)] == 11201 and auth[('C', 'mldsa44', True)] == 8699, 'WebPKI-like reduced flights 11,201 / 8,699 B')

# --- Block C results
check(int(cell(C, 'mldsa44', True, 2400)['first_band']) == 30, 'Block C mldsa44 CI+CE 30/30')
check(int(cell(C, 'mldsa65', True, 2400)['first_band']) == 1, 'Block C mldsa65 CI+CE 1/30')
check(round(float(cell(C, 'mldsa65', True, 2400)['server_tls_bytes_median']) - float(cell(A, 'mldsa65', True, 2400)['server_tls_bytes_median'])) == 481, 'WebPKI-like profile adds 481 TLS bytes')
q = [r for r in Q if r['block'] == 'C' and r['algorithm'] == 'mldsa65' and b(r['cached']) and int(r['enlargement_bytes']) == 2400]
check(Counter(int(r['pre_crypto_ack_padding_datagrams']) for r in q) == Counter({1: 28, 0: 1, 2: 1}), 'Block C mldsa65 CI+CE padded Initials 0:1, 1:28, 2:1')
check(Counter((int(r['flight_bytes']), int(r['rounds'])) for r in wcell('C', 'mldsa65', True, 2400)) == Counter({(12401, 2): 28, (11201, 1): 1, (13601, 2): 1}), 'Block C mldsa65 CI+CE flights 11,201 (1 round) / 12,401 / 13,601 (2 rounds)')
padsA = sum(1 for r in W if r['block'] == 'A' and int(r['pre_crypto_pads']) >= 1)
check(padsA == 436, 'Block A: 436/480 trials with a padded ACK-only Initial')

# --- Block F
med = {(r['algorithm'], str(r['group'])): float(r['median_ms']) for r in F}
check(abs(med[('ecdsa', 'X25519MLKEM768')] - 3.88) < 0.01 and abs(med[('ecdsa', 'x25519')] - 4.79) < 0.01, 'Block F ECDSA medians 3.88 / 4.79 ms')
check(abs(med[('mldsa44', 'X25519MLKEM768')] - 5.36) < 0.01 and abs(med[('mldsa65', 'X25519MLKEM768')] - 6.54) < 0.01 and abs(med[('mldsa87', 'X25519MLKEM768')] - 7.44) < 0.01, 'Block F ML-DSA medians 5.36 / 6.54 / 7.44 ms')

# --- archived campaign
check([int(r['disagreements']) for r in CL] == [220, 123, 0] and all(int(r['eligible_traces']) == 1740 for r in CL), 'archived classifier 220 / 123 / 0 of 1,740')
check(all(int(r['false_infeasible']) == 0 for r in CL), 'all archived disagreements are false feasibility verdicts')
sz = {r['configuration']: r for r in SZ}
check(int(sz['ML-DSA-44/X25519MLKEM768']['server_tls_bytes']) == 11890 and int(sz['ML-DSA-44/X25519MLKEM768']['server_udp_bytes']) == 12397, 'ML-DSA-44 11,890 TLS / 12,397 UDP bytes')
th = {(r['algorithm'], r['chain'], r['enlargement_bytes']): r for r in TH}
check(th[('mldsa44', 'CI', '800')]['first_band'] == '0' and th[('mldsa44', 'CI', '900')]['first_band'] == '10', 'credit step: +800 B 0/10, +900 B 10/10 for ML-DSA-44 CI')
check(th[('mldsa65', 'CI', '900')]['first_band'] == '7' and th[('mldsa65', 'CI', '2400')]['first_band'] == '18', 'ML-DSA-65 CI +900 B 7/10, +2,400 B 18/20')
rb = {(r['scenario'], r['configuration']): r for r in RB}
check(abs(float(rb[('Retry', 'ML-DSA-44')]['delta_ms']) - 123.68) < 0.01 and abs(float(rb[('Retry', 'ML-DSA-87')]['delta_ms']) - 63.80) < 0.01, 'Retry overhead +123.68 (ML-DSA-44) / +63.80 ms (ML-DSA-87)')
check(rb[('5% independent loss', 'ML-DSA-87 full')]['successes'] == '45' and rb[('5% independent loss', 'ML-DSA-87 cached')]['successes'] == '50', '5% loss: 45/50 full, 50/50 cached')
check(abs(float(rb[('1 Mbit/s uplink', 'ML-DSA-44 CE')]['condition_ms']) - 177.90) < 0.01, '1 Mbit/s uplink ML-DSA-44 CE 177.90 ms')
iv = {(r['algorithm'], r['condition']): r for r in IV}
check(abs(float(iv[('mldsa44', 'CC')]['median_ms']) - 127.01) < 0.01 and abs(float(iv[('mldsa87', 'CI')]['median_ms']) - 128.43) < 0.01, 'archived interventions medians (CC 127.01, ML-DSA-87 CI 128.43)')

# --- Block G: implementation-version and host replication
for blk, S, lab in [('G', G, '3.5.9/host 2'), ('Gc', GC, '3.5.5/host 2')]:
    same = all(int(cell(S, r['algorithm'], b(r['cached']), int(r['enlargement_bytes']))['first_band']) == int(r['first_band']) for r in A)
    check(same, f'Block {blk} ({lab}): one-round counts identical to Block A in all 16 cells')
    for alg in ['mldsa44', 'mldsa65', 'mldsa87']:
        for ci, ce in [(False, 0), (True, 0)]:
            check(Counter(int(r['first_wave_bytes']) for r in wcell(blk, alg, ci, ce)) == Counter({7199: 30}), f'Block {blk} {alg} ci={ci} ce={ce}: first wave 7,199 B in 30/30')
        bound_ce = [(False, 2400)] + ([(True, 2400)] if alg == 'mldsa87' else [])
        for ci, ce in bound_ce:
            check(Counter(int(r['first_wave_bytes']) for r in wcell(blk, alg, ci, ce)) == Counter({11999: 30}), f'Block {blk} {alg} ci={ci} ce={ce}: first wave 11,999 B in 30/30')
    for alg, full, red in [('mldsa44', 12397, 8176), ('mldsa65', 16470, 10678), ('mldsa87', 21920, 14080)]:
        check(auth[(blk, alg, False)] == full and auth[(blk, alg, True)] == red, f'Block {blk} {alg} authentication flight {full:,} / {red:,} B (as Block A)')
    tls_same = all(Counter(int(float(r['server_tls_bytes'])) for r in t if r['algorithm'] == alg and b(r['cached']) == ci) .keys()
                   == Counter(int(float(r['server_tls_bytes'])) for r in At if r['algorithm'] == alg and b(r['cached']) == ci).keys()
                   for t in [Gt if blk == 'G' else GCt] for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87'] for ci in [False, True])
    check(tls_same, f'Block {blk}: server TLS byte values identical to Block A in every cell')
padsG = sum(1 for r in W if r['block'] == 'G' and r['pre_crypto_pads'] and int(r['pre_crypto_pads']) >= 1)
padsGc = sum(1 for r in W if r['block'] == 'Gc' and r['pre_crypto_pads'] and int(r['pre_crypto_pads']) >= 1)
check(padsG == 13 and padsGc == 10, 'Block G padded ACK-only Initials: 13/480 (3.5.9) and 10/480 (3.5.5 control)')
check(int(cell(G, 'mldsa87', False, 0)['rounds_3']) == 30 and int(cell(GC, 'mldsa87', False, 0)['rounds_3']) == 30, 'Block G full-chain ML-DSA-87 three rounds in 30/30 and 30/30')
check(int(cell(GC, 'mldsa87', True, 2400)['rounds_3']) == 1, 'Block G control ML-DSA-87 CI+CE: one 161-ms trial in the third band')
check(GQ['all_cells_fisher_p_equal_1_G_vs_A'] and GQ['all_cells_fisher_p_equal_1_Gc_vs_A'] and GQ['all_cells_fisher_p_equal_1_G_vs_Gc'], 'Block G: two-sided Fisher p = 1 in every cell for every pair of runs')
check(GQ['max_abs_median_diff_G_minus_A_ms'] < 2.0 and GQ['max_abs_median_diff_Gc_minus_A_ms'] < 2.0, 'Block G: cell medians within 2 ms of Block A')
check(abs(float(cell(G, 'mldsa44', True, 2400)['median_ms']) - 65.54) < 0.01 and abs(float(cell(G, 'mldsa65', True, 2400)['median_ms']) - 65.89) < 0.01, 'Block G (3.5.9) CI+CE medians 65.54 / 65.89 ms')

# --- raw directories
req = {'configuration.json', 'result.json', 'datagrams.jsonl', 'client.tls.jsonl', 'server.tls.jsonl', 'client.keys', 'server.keys', 'client.out', 'server.out', 'client.err', 'server.err'}
for block, n in [('block_a', 480), ('block_c', 240), ('block_f', 150), ('block_g', 480), ('block_gc', 480)]:
    dirs = [p for p in (RAW / block).iterdir() if p.is_dir()]
    ok = len(dirs) == n
    for p in dirs:
        missing = req - {x.name for x in p.iterdir() if x.is_file()}
        ok = ok and not missing and (p / 'qlogs').is_dir() and any((p / 'qlogs').iterdir())
    check(ok, f'{block}: {n} complete raw trial directories')

# --- protocol files match their original recorded SHA-256 digests
check(json.loads((ROOT / '03_reproducibility' / 'data' / 'preregistration_block_A.json').read_text())['sha256'] == hashlib.sha256((ROOT / '06_experiment_protocols' / 'Block_A_completed_protocol.md').read_bytes()).hexdigest(), 'Block A protocol file matches its registered digest')
check(json.loads((ROOT / '03_reproducibility' / 'data' / 'preregistration_block_G.json').read_text())['sha256'] == hashlib.sha256((ROOT / '06_experiment_protocols' / 'Block_G_completed_protocol.md').read_bytes()).hexdigest(), 'Block G protocol file matches its registered digest')
th3200 = next(r for r in TH if r['algorithm'] == 'mldsa44' and r['chain'] == 'full chain' and r['enlargement_bytes'] == '3200')
check(int(th3200['n']) - int(th3200['pads_0']) == 10 and th3200.get('pads_3plus') == '1', 'threshold +3,200 B ML-DSA-44 full: 10/10 trials with k>=1 (one with k=3)')
check(all(r['rounds'] == '' and r['predicted_one_round'] == '' for r in W if r['block'] == 'F'), 'Block F rows carry no round band or two-limit verdict (RTT 0)')

if failures:
    print(f'{len(failures)} check(s) failed')
    sys.exit(1)
print(f'All {checks_run} numerical, raw-file, and protocol-integrity checks passed.')
