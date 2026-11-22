#!/usr/bin/env python3
"""Generate compact and complete LaTeX table fragments from derived data.

Inputs: CSV files in 03_reproducibility/data, produced by the analysis scripts.
Outputs: .tex fragments in results/tables. The files contain table rows rather
than standalone documents; no LaTeX installation is needed to generate them.
Generated outputs are local, untracked files. Uses the Python standard library.
"""
from pathlib import Path
import csv
import statistics
from collections import Counter

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / '03_reproducibility' / 'data'
OUT = ROOT / 'results' / 'tables'
OUT.mkdir(parents=True, exist_ok=True)

ALG = {'ecdsa': 'ECDSA', 'mldsa44': r'ML\nbh{}DSA\nbh{}44', 'mldsa65': r'ML\nbh{}DSA\nbh{}65', 'mldsa87': r'ML\nbh{}DSA\nbh{}87'}
COND = {(False, 0): 'none', (True, 0): r'\CI', (False, 2400): r'\CE', (True, 2400): r'\CI+\CE'}
ORDER = [(False, 0), (True, 0), (False, 2400), (True, 2400)]


def read(name):
    with (DATA / name).open(newline='') as f:
        return list(csv.DictReader(f))


def b(x):
    return x == 'True'


def n(x):
    return f'{int(round(float(x))):,}'


def pct(x):
    return f'{100 * float(x):.1f}'


def write(path, text):
    path.write_text(text)
    print('wrote', path.relative_to(ROOT))


W = read('new_wave_accounting.csv')
for r in W:
    r['cached_b'] = b(r['cached'])
    r['ce'] = int(r['enlargement_bytes'])
    r['lat'] = float(r['latency_ms'])
    r['fw'] = int(r['first_wave_bytes'])
    r['fl'] = int(r['flight_bytes'])
    r['k'] = int(r['pre_crypto_pads']) if r['pre_crypto_pads'] else -1
    r['rd'] = int(r['rounds']) if r['rounds'] else 0

A = read('block_A_summary.csv')
C = read('block_C_summary.csv')
F = read('block_F_summary.csv')
G = read('block_G_summary.csv')     # OpenSSL 3.5.9, host 2
GC = read('block_Gc_summary.csv')   # OpenSSL 3.5.5, host 2 (same-host control)


def cell(block, alg, ci, ce):
    return [r for r in W if r['block'] == block and r['algorithm'] == alg and r['cached_b'] == ci and r['ce'] == ce]


def wave_str(c):
    cnt = Counter(r['fw'] for r in c)
    vals = sorted(cnt)
    if len(vals) > 2:
        return f'{vals[0]:,}--{vals[-1]:,} (all)'
    return ', '.join(f'{v:,} ({cnt[v]})' for v in vals)


def flight_mode(c):
    return statistics.mode([r['fl'] for r in c])


def summary_row(S, alg, ci, ce):
    return next(r for r in S if r['algorithm'] == alg and b(r['cached']) == ci and int(r['enlargement_bytes']) == ce)


# ---------------------------------------------------------------- Block A (compact)
rows = []
for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
    for ci, ce in ORDER:
        s = summary_row(A, alg, ci, ce)
        c = cell('A', alg, ci, ce)
        rows.append(f"{ALG[alg]} & {COND[(ci, ce)]} & {s['first_band']}/30 & {pct(s['first_band_rate'])} [{pct(s['wilson_low'])}, {pct(s['wilson_high'])}] & "
                    f"{float(s['median_ms']):.2f} [{float(s['median_ci_low_ms']):.2f}, {float(s['median_ci_high_ms']):.2f}] & "
                    f"{s['rounds_1']}/{s['rounds_2']}/{s['rounds_3']} & {flight_mode(c):,} & {wave_str(c)} \\tabularnewline")
write(OUT / 'table_blockA.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- profiles (compact): one row per (profile, k)
rows = []
for alg in ['mldsa44', 'mldsa65']:
    for blk, S, prof in [('A', A, 'laboratory'), ('C', C, 'WebPKI-like')]:
        s = summary_row(S, alg, True, 2400)
        c = cell(blk, alg, True, 2400)
        auth = statistics.mode([int(r['auth_flight_bytes']) for r in c])
        ks = sorted(set(r['k'] for r in c))
        for i, k in enumerate(ks):
            sub = [r for r in c if r['k'] == k]
            fl = statistics.mode([r['fl'] for r in sub])
            margin = 12000 - fl
            mg = f'{margin:,}' if margin >= 0 else f'$-${-margin:,}'
            one = sum(1 for r in sub if r['rd'] == 1)
            head = f"{ALG[alg]} & {prof} & {n(s['server_tls_bytes_median'])} & {auth:,}" if i == 0 else " & & &"
            rows.append(f"{head} & {k} & {len(sub)} & {fl:,} & {mg} & {one}/{len(sub)} \\\\")
        rows[-1] = rows[-1]  # keep
    rows.append('\\addlinespace[2pt]')
rows = rows[:-1]
write(OUT / 'table_profiles.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- credit threshold (selected rows)
T = read('archived_credit_threshold.csv')
sel = [('mldsa44', 'CI', '0'), ('mldsa44', 'CI', '800'), ('mldsa44', 'CI', '900'), ('mldsa44', 'CI', '1600'), ('mldsa44', 'CI', '2400'),
       ('mldsa65', 'CI', '0'), ('mldsa65', 'CI', '800'), ('mldsa65', 'CI', '900'), ('mldsa65', 'CI', '1600'), ('mldsa65', 'CI', '2400'),
       ('mldsa44', 'full chain', '3200'), ('mldsa87', 'CI', '2400')]
rows = []
for alg, chain, pad in sel:
    r = next(r for r in T if r['algorithm'] == alg and r['chain'] == chain and r['enlargement_bytes'] == pad)
    lab = f"{ALG[alg]} {'\\CI' if chain == 'CI' else 'full'}"
    k1 = int(r['n']) - int(r['pads_0'])   # trials with at least one padded ACK-only Initial (k >= 1, any k)
    auth = r['auth_flight_udp_bytes'] or next(x for x in T if x['algorithm'] == alg and x['chain'] == chain and x['enlargement_bytes'] == '0')['auth_flight_udp_bytes']
    rows.append(f"{lab} & {n(pad)} & {r['client_initial_datagrams']} & {n(r['allowance_bytes'])} & {n(auth)} & {r['first_band']}/{r['n']} & {k1} \\\\")
write(OUT / 'table_threshold.tex', '\n'.join(rows) + '\n')

# full threshold table (complete)
rows = []
for r in T:
    lab = f"{ALG[r['algorithm']]} {'\\CI' if r['chain'] == 'CI' else 'full'}"
    rows.append(f"{lab} & {n(r['enlargement_bytes'])} & {n(r['client_hello_bytes'])} & {r['client_initial_datagrams']} & {n(r['allowance_bytes'])} & "
                f"{n(r['auth_flight_udp_bytes']) if r['auth_flight_udp_bytes'] else '--'} & {r['first_band']}/{r['n']} & {r['pads_0']}/{r['pads_1']}/{r['pads_2']}/{r.get('pads_3plus', 0)} & {float(r['median_ms']):.2f} \\\\")
write(OUT / 'supp_threshold_full.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- classifier (compact)
CL = read('archived_classifier_comparison.csv')
labels = ['Amplification, TLS-message bytes', 'Amplification, observed UDP flight', 'Amplification and 12,000-B window, UDP flight']
rows = [f"{lab} & {r['disagreements']} & {float(r['rate_pct']):.2f}\\% \\\\" for lab, r in zip(labels, CL)]
write(OUT / 'table_classifier.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- zero RTT (compact and complete)
order = [('ecdsa', 'x25519', 'ECDSA / X25519'), ('ecdsa', 'X25519MLKEM768', 'ECDSA / hybrid'), ('mldsa44', 'X25519MLKEM768', 'ML-DSA-44 / hybrid'),
         ('mldsa65', 'X25519MLKEM768', 'ML-DSA-65 / hybrid'), ('mldsa87', 'X25519MLKEM768', 'ML-DSA-87 / hybrid')]
rows = []; rows_s = []
for a, g, lab in order:
    r = next(r for r in F if r['algorithm'] == a and r['group'] == g)
    rows.append(f"{lab} & {float(r['median_ms']):.2f} [{float(r['ci_low_ms']):.2f}, {float(r['ci_high_ms']):.2f}] & {float(r['p95_ms']):.2f} \\tabularnewline")
    rows_s.append(f"{lab} & {r['n']} & {float(r['median_ms']):.2f} [{float(r['ci_low_ms']):.2f}, {float(r['ci_high_ms']):.2f}] & {float(r['p95_ms']):.2f} & {n(r['client_udp_bytes_median'])} & {n(r['server_udp_bytes_median'])} \\\\")
write(OUT / 'table_zero_rtt.tex', '\n'.join(rows) + '\n')
write(OUT / 'supp_blockF.tex', '\n'.join(rows_s) + '\n')

# ---------------------------------------------------------------- robustness (compact)
RB = read('archived_robustness_core.csv')
def rb(scn, cfg):
    return next(r for r in RB if r['scenario'] == scn and r['configuration'] == cfg)
rows = []
for cfg, lab in [('ECDSA/X25519', 'ECDSA / X25519'), ('ECDSA/hybrid', 'ECDSA / hybrid'), ('ML-DSA-44', 'ML-DSA-44'), ('ML-DSA-65', 'ML-DSA-65'), ('ML-DSA-87', 'ML-DSA-87')]:
    r = rb('Retry', cfg)
    rows.append(f"Retry & {lab} & {float(r['condition_ms']):.2f} ms; $+${float(r['delta_ms']):.2f} ms \\tabularnewline")
for scn in ['5% independent loss', '5% burst loss']:
    for cfg, lab in [('ML-DSA-87 full', 'ML-DSA-87 full'), ('ML-DSA-87 cached', 'ML-DSA-87 \\CI')]:
        r = rb(scn, cfg)
        rows.append(f"{scn.replace('%', '\\%').replace('independent', 'indep.')} & {lab} & {r['successes']}/{r['attempts']}; {float(r['median_success_ms']):.2f} ms \\tabularnewline")
for alg in ['ML-DSA-44', 'ML-DSA-87']:
    v = [float(rb('1 Mbit/s uplink', f'{alg} {c}')['condition_ms']) for c in ['full', 'CE', 'CI']]
    rows.append(f"1 Mbit/s uplink & {alg} full/\\CE/\\CI & {v[0]:.2f}/{v[1]:.2f}/{v[2]:.2f} ms \\tabularnewline")
write(OUT / 'table_robustness.tex', '\n'.join(rows) + '\n')

# full robustness (complete)
rows = [f"{r['scenario'].replace('%', '\\%')} & {r['configuration'].replace('cached', '\\CI').replace(' CE', ' \\CE').replace(' CI', ' \\CI')} & "
        f"{r['baseline_ms'] or '--'} & {r['condition_ms'] or '--'} & {r['delta_ms'] or '--'} & {r['attempts']} & {r['successes']} & {r['median_success_ms']} \\\\" for r in RB]
write(OUT / 'supp_robustness_full.tex', '\n'.join(rows) + '\n')

# failures ledger (complete)
FL = read('archived_failures.csv')
rows = [f"\\texttt{{{r['id'].replace('_', '\\_')}}} & {ALG[r['algorithm']]} & {r['condition'].replace('_', '\\_')} & {float(r['loss']) * 100:.0f}\\% {'burst' if r['burst'] == 'True' else 'independent'} & {r['failure_kind'].replace('_', '\\_')} \\\\" for r in FL]
write(OUT / 'supp_failures.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- Block A complete (complete) incl. bytes
rows = []
for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
    for ci, ce in ORDER:
        s = summary_row(A, alg, ci, ce)
        c = cell('A', alg, ci, ce)
        pads = Counter(r['k'] for r in c)
        auth = statistics.mode([int(r['auth_flight_bytes']) for r in c])
        rows.append(f"{ALG[alg]} & {COND[(ci, ce)]} & {s['first_band']}/30 & {float(s['median_ms']):.2f} [{float(s['median_ci_low_ms']):.2f}, {float(s['median_ci_high_ms']):.2f}] & "
                    f"{s['rounds_1']}/{s['rounds_2']}/{s['rounds_3']} & {n(s['server_tls_bytes_median'])} & {auth:,} & {n(c[0]['allowance_bytes'])} & {pads.get(0, 0)}/{pads.get(1, 0)}/{pads.get(2, 0)} & {wave_str(c)} & {n(s['server_udp_bytes_median'])} \\\\")
write(OUT / 'supp_blockA_full.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- Block C complete (complete)
rows = []
for alg in ['mldsa44', 'mldsa65']:
    for ci, ce in ORDER:
        s = summary_row(C, alg, ci, ce)
        c = cell('C', alg, ci, ce)
        pads = Counter(r['k'] for r in c)
        auth = statistics.mode([int(r['auth_flight_bytes']) for r in c])
        rows.append(f"{ALG[alg]} & {COND[(ci, ce)]} & {s['first_band']}/30 & {pct(s['wilson_low'])}--{pct(s['wilson_high'])} & {float(s['median_ms']):.2f} [{float(s['median_ci_low_ms']):.2f}, {float(s['median_ci_high_ms']):.2f}] & "
                    f"{n(s['server_tls_bytes_median'])} & {auth:,} & {n(c[0]['allowance_bytes'])} & {pads.get(0, 0)}/{pads.get(1, 0)}/{pads.get(2, 0)} & {wave_str(c)} & {n(s['server_udp_bytes_median'])} \\\\")
write(OUT / 'supp_blockC_full.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- ML-DSA-87 second wave (complete)
c = cell('A', 'mldsa87', False, 0)
cnt = Counter()
for r in c:
    waves = [int(v) for v in r['wave_bytes'].split(';')]
    cnt[(r['k'], r['rd'], tuple(waves[:3]))] += 1
rows = []
for (k, rd, waves), m in sorted(cnt.items(), key=lambda kv: (kv[0][1], kv[0][0], kv[0][2])):
    rows.append(f"{k} & {rd} & {' / '.join(f'{w:,}' for w in waves)} & {m} \\\\")
write(OUT / 'supp_waves87.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- padded ACK frequency per cell (complete)
rows = []
for blk in ['A', 'C', 'F', 'Gc', 'G']:
    for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
        for ci, ce in ORDER:
            c = [r for r in W if r['block'] == blk and r['algorithm'] == alg and r['cached_b'] == ci and r['ce'] == ce]
            if not c:
                continue
            groups = sorted(set(r['group'] for r in c))
            for g in groups:
                cc = [r for r in c if r['group'] == g]
                pads = Counter(r['k'] for r in cc)
                lab = ALG[alg] + (' / X25519' if g.lower() == 'x25519' else '')
                rows.append(f"{blk} & {lab} & {COND[(ci, ce)]} & {len(cc)} & {pads.get(0, 0)} & {pads.get(1, 0)} & {pads.get(2, 0)} \\\\")
write(OUT / 'supp_pads.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- Block G (compact): three runs side by side
# Columns: Authentication & Condition & one round A/Gc/G & median A & median Gc & median G & rounds A & Gc & G & first wave (B) & padded trials A/Gc/G
rows = []
for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
    for ci, ce in ORDER:
        sa, sgc, sg = summary_row(A, alg, ci, ce), summary_row(GC, alg, ci, ce), summary_row(G, alg, ci, ce)
        ca, cgc, cg = cell('A', alg, ci, ce), cell('Gc', alg, ci, ce), cell('G', alg, ci, ce)
        def padded(c):
            return sum(1 for r in c if r['k'] >= 1)
        # first-wave values: identical modal value across runs is the expected case; print the union with counts per run if they differ
        fwa, fwgc, fwg = Counter(r['fw'] for r in ca), Counter(r['fw'] for r in cgc), Counter(r['fw'] for r in cg)
        if set(fwa) == set(fwgc) == set(fwg) and len(fwa) == 1:
            fw = f'{next(iter(fwa)):,} (all)'
        else:
            modes = [statistics.mode([r['fw'] for r in c]) for c in (ca, cgc, cg)]
            fw = ' / '.join(f'{m:,}' for m in modes)
        rows.append(f"{ALG[alg]} & {COND[(ci, ce)]} & {sa['first_band']}/{sgc['first_band']}/{sg['first_band']} & "
                    f"{float(sa['median_ms']):.2f} & {float(sgc['median_ms']):.2f} & {float(sg['median_ms']):.2f} & "
                    f"{sa['rounds_1']}/{sa['rounds_2']}/{sa['rounds_3']} & {sgc['rounds_1']}/{sgc['rounds_2']}/{sgc['rounds_3']} & {sg['rounds_1']}/{sg['rounds_2']}/{sg['rounds_3']} & "
                    f"{fw} & {padded(ca)}/{padded(cgc)}/{padded(cg)} \\tabularnewline")
write(OUT / 'table_blockG.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- Block G complete (complete), one table per run
for blk, S in [('Gc', GC), ('G', G)]:
    rows = []
    for alg in ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']:
        for ci, ce in ORDER:
            s_ = summary_row(S, alg, ci, ce)
            c = cell(blk, alg, ci, ce)
            pads = Counter(r['k'] for r in c)
            auth = statistics.mode([int(r['auth_flight_bytes']) for r in c])
            rows.append(f"{ALG[alg]} & {COND[(ci, ce)]} & {s_['first_band']}/30 & {float(s_['median_ms']):.2f} [{float(s_['median_ci_low_ms']):.2f}, {float(s_['median_ci_high_ms']):.2f}] & "
                        f"{s_['rounds_1']}/{s_['rounds_2']}/{s_['rounds_3']} & {n(s_['server_tls_bytes_median'])} & {auth:,} & {n(c[0]['allowance_bytes'])} & {pads.get(0, 0)}/{pads.get(1, 0)}/{pads.get(2, 0)} & {wave_str(c)} & {n(s_['server_udp_bytes_median'])} \\\\")
    write(OUT / f'supp_block{blk}_full.tex', '\n'.join(rows) + '\n')

# ---------------------------------------------------------------- ML-DSA-87 second wave, all three runs (complete)
rows = []
for blk, lab in [('A', 'A (3.5.5, host 1)'), ('Gc', 'G control (3.5.5, host 2)'), ('G', 'G (3.5.9, host 2)')]:
    c = cell(blk, 'mldsa87', False, 0)
    cnt = Counter()
    for r in c:
        waves = [int(v) for v in r['wave_bytes'].split(';')]
        cnt[(r['k'], r['rd'], tuple(waves[:3]))] += 1
    first = True
    for (k, rd, waves), m in sorted(cnt.items(), key=lambda kv: (kv[0][1], kv[0][0], kv[0][2])):
        rows.append(f"{lab if first else ''} & {k} & {rd} & {' / '.join(f'{w:,}' for w in waves)} & {m} \\\\")
        first = False
write(OUT / 'supp_waves87_runs.tex', '\n'.join(rows) + '\n')
