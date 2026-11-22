#!/usr/bin/env python3
"""Block G analysis: the Block A design re-executed on a second host with two OpenSSL releases.

Runs analysed (raw/):
  block_g    OpenSSL 3.5.9, host 2  (label 'G'; prospectively specified)
  block_gc   OpenSSL 3.5.5, host 2  (label 'Gc'; same-host control added after the 3.5.9 results)

Outputs (experiment/analysis/):
  block_G_trials.csv, block_G_summary.csv, block_Gc_trials.csv, block_Gc_summary.csv
      -- same columns as block_A_trials.csv / block_A_summary.csv (+ openssl_build)
  block_G_comparison.csv
      -- one row per cell: first-band counts and medians for A, Gc and G; two-sided Fisher exact
         p-values for G vs A, Gc vs A and G vs Gc; round distributions; TLS-byte support equality
  block_G_quality_checks.json
      -- protocol checks for both runs and the pre-specified predictions 1-4 of the Block G protocol
"""
from __future__ import annotations
from pathlib import Path
import json, math, hashlib
import numpy as np
import pandas as pd
from scipy.stats import fisher_exact, norm

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis'
OUT.mkdir(exist_ok=True)
SEED = 20261107
RUNS = [('G', ROOT / 'raw' / 'block_g'), ('Gc', ROOT / 'raw' / 'block_gc')]
PRED_ONE_ROUND = {('ecdsa', False, 0), ('ecdsa', False, 2400), ('ecdsa', True, 0), ('ecdsa', True, 2400),
                  ('mldsa44', True, 2400), ('mldsa65', True, 2400)}


def wilson(k, n, alpha=.05):
    if n == 0:
        return (math.nan, math.nan)
    z = norm.ppf(1 - alpha / 2); p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h


def bootstrap_median(x, reps=20000, seed=SEED):
    x = np.asarray(x, float); rng = np.random.default_rng(seed)
    sims = np.median(rng.choice(x, (reps, len(x)), replace=True), axis=1)
    return np.quantile(sims, [.025, .975])


def round_class(ms, rtt=60):
    if ms < 1.5 * rtt:
        return 1
    if ms < 2.5 * rtt:
        return 2
    return 3


def load_trials(raw: Path) -> pd.DataFrame:
    rows = []
    for p in sorted(raw.glob('*/result.json')):
        rec = json.loads(p.read_text()); cfg = json.loads((p.parent / 'configuration.json').read_text())
        rec.update({k: v for k, v in cfg.items() if k not in rec})
        dg = []
        for line in (p.parent / 'datagrams.jsonl').read_text().splitlines():
            e = json.loads(line)
            if e.get('event') == 'observed':
                dg.append(e)
        rec['client_udp_bytes'] = sum(e['bytes'] for e in dg if e['direction'] == 'cs')
        rec['server_udp_bytes'] = sum(e['bytes'] for e in dg if e['direction'] == 'sc')
        rec['client_datagrams'] = sum(1 for e in dg if e['direction'] == 'cs')
        rec['server_datagrams'] = sum(1 for e in dg if e['direction'] == 'sc')
        tls = []
        tf = p.parent / 'server.tls.jsonl'
        if tf.exists():
            for line in tf.read_text().splitlines():
                e = json.loads(line)
                if e.get('write') == 1:
                    tls.append(e)
        rec['server_tls_bytes'] = sum(e['length'] for e in tls)
        rec['rounds'] = round_class(rec['latency_ms']) if rec.get('success') else None
        rows.append(rec)
    return pd.DataFrame(rows).sort_values('run_order')


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    summ = []
    for keys, g in df.groupby(['algorithm', 'cached', 'enlargement_bytes'], sort=True):
        alg, ci, ce = keys; n = len(g); k = int(g['first_band'].sum()); lo, hi = wilson(k, n)
        med = float(g['latency_ms'].median()); mlo, mhi = bootstrap_median(g['latency_ms'], seed=SEED + len(summ))
        rc = g['rounds'].value_counts().to_dict()
        summ.append(dict(algorithm=alg, cached=ci, enlargement_bytes=ce, n=n, successes=int(g['success'].sum()),
                         first_band=k, first_band_rate=k / n, wilson_low=lo, wilson_high=hi,
                         median_ms=med, median_ci_low_ms=mlo, median_ci_high_ms=mhi,
                         rounds_1=int(rc.get(1, 0)), rounds_2=int(rc.get(2, 0)), rounds_3=int(rc.get(3, 0)),
                         client_udp_bytes_median=float(g['client_udp_bytes'].median()),
                         server_udp_bytes_median=float(g['server_udp_bytes'].median()),
                         server_tls_bytes_median=float(g['server_tls_bytes'].median()),
                         client_datagrams_median=float(g['client_datagrams'].median()),
                         server_datagrams_median=float(g['server_datagrams'].median())))
    return pd.DataFrame(summ)


def checks_for(label: str, df: pd.DataFrame, s: pd.DataFrame) -> dict:
    pattern_ok = all((int(r.first_band) == 30) == ((r.algorithm, bool(r.cached), int(r.enlargement_bytes)) in PRED_ONE_ROUND)
                     and int(r.first_band) in (0, 30) for _, r in s.iterrows())
    thresholds = all((int(r.first_band) >= 27) if (r.algorithm, bool(r.cached), int(r.enlargement_bytes)) in PRED_ONE_ROUND
                     else (int(r.first_band) <= 3) for _, r in s.iterrows())
    return {
        'n_trials': int(len(df)), 'n_success': int(df.success.sum()), 'n_failures': int((~df.success).sum()),
        'all_verify_zero': bool((df.verify_result == 0).all()),
        'all_hybrid_group': bool((df.group == 'X25519MLKEM768').all()),
        'all_not_resumed': bool((df.resumed == 0).all()),
        'unique_ids': bool(df.id.is_unique),
        'run_orders_complete': bool(sorted(df.run_order.tolist()) == list(range(480))),
        'openssl_build': str(df.openssl_build.iloc[0]),
        'prediction_1_band_pattern_identical_to_block_A': bool(pattern_ok),
        'prediction_1_absolute_thresholds_met': bool(thresholds),
        'trials_sha256': hashlib.sha256((OUT / f'block_{label}_trials.csv').read_bytes()).hexdigest(),
    }


def main():
    a_s = pd.read_csv(OUT / 'block_A_summary.csv')
    a_t = pd.read_csv(OUT / 'block_A_trials.csv')
    frames, summaries, checks = {'A': a_t}, {'A': a_s}, {}
    for label, raw in RUNS:
        df = load_trials(raw)
        df.to_csv(OUT / f'block_{label}_trials.csv', index=False)
        s = summarise(df)
        s.to_csv(OUT / f'block_{label}_summary.csv', index=False)
        frames[label], summaries[label] = df, s
        checks[label] = checks_for(label, df, s)

    def cellrow(s, alg, ci, ce):
        return s[(s.algorithm == alg) & (s.cached == ci) & (s.enlargement_bytes == ce)].iloc[0]

    def celltrials(t, alg, ci, ce):
        return t[(t.algorithm == alg) & (t.cached == ci) & (t.enlargement_bytes == ce)]

    comp = []
    for _, g in summaries['G'].iterrows():
        alg, ci, ce = g.algorithm, bool(g.cached), int(g.enlargement_bytes)
        r = {lab: cellrow(summaries[lab], alg, ci, ce) for lab in ('A', 'Gc', 'G')}
        t = {lab: celltrials(frames[lab], alg, ci, ce) for lab in ('A', 'Gc', 'G')}

        def fisher(x, y):
            return fisher_exact([[int(r[x].first_band), int(r[x].n - r[x].first_band)],
                                 [int(r[y].first_band), int(r[y].n - r[y].first_band)]], alternative='two-sided')[1]
        row = dict(algorithm=alg, cached=ci, enlargement_bytes=ce, n=int(g.n))
        for lab in ('A', 'Gc', 'G'):
            row[f'first_band_{lab}'] = int(r[lab].first_band)
            row[f'median_ms_{lab}'] = float(r[lab].median_ms)
            row[f'median_ci_{lab}'] = f"{r[lab].median_ci_low_ms:.2f}-{r[lab].median_ci_high_ms:.2f}"
            row[f'rounds_{lab}'] = f"{int(r[lab].rounds_1)}/{int(r[lab].rounds_2)}/{int(r[lab].rounds_3)}"
            row[f'server_tls_bytes_values_{lab}'] = ';'.join(str(v) for v in sorted(t[lab].server_tls_bytes.unique()))
        row['fisher_p_G_vs_A'] = fisher('G', 'A')
        row['fisher_p_Gc_vs_A'] = fisher('Gc', 'A')
        row['fisher_p_G_vs_Gc'] = fisher('G', 'Gc')
        row['tls_bytes_support_identical_A_Gc_G'] = bool(set(t['A'].server_tls_bytes.unique()) == set(t['Gc'].server_tls_bytes.unique())
                                                         == set(t['G'].server_tls_bytes.unique()))
        row['median_diff_G_minus_A_ms'] = float(r['G'].median_ms - r['A'].median_ms)
        row['median_diff_Gc_minus_A_ms'] = float(r['Gc'].median_ms - r['A'].median_ms)
        row['median_diff_G_minus_Gc_ms'] = float(r['G'].median_ms - r['Gc'].median_ms)
        comp.append(row)
    c = pd.DataFrame(comp)
    c.to_csv(OUT / 'block_G_comparison.csv', index=False)

    prereg = json.loads((OUT / 'preregistration_block_G.json').read_text())
    summary_checks = {
        'runs': checks,
        'prediction_3_tls_bytes_support_identical_every_cell': bool(c.tls_bytes_support_identical_A_Gc_G.all()),
        'all_cells_fisher_p_equal_1_G_vs_A': bool((c.fisher_p_G_vs_A >= 0.999).all()),
        'all_cells_fisher_p_equal_1_Gc_vs_A': bool((c.fisher_p_Gc_vs_A >= 0.999).all()),
        'all_cells_fisher_p_equal_1_G_vs_Gc': bool((c.fisher_p_G_vs_Gc >= 0.999).all()),
        'max_abs_median_diff_G_minus_A_ms': float(c.median_diff_G_minus_A_ms.abs().max()),
        'max_abs_median_diff_Gc_minus_A_ms': float(c.median_diff_Gc_minus_A_ms.abs().max()),
        'max_abs_median_diff_G_minus_Gc_ms': float(c.median_diff_G_minus_Gc_ms.abs().max()),
        'preregistration_sha256': prereg['sha256'],
        'preregistration_runner_sha256_at_registration': prereg['runner_sha256'],
        'note': 'Predictions 2 and 4 (first-wave stops, rule agreement) are evaluated by scripts/extract_wave_accounting.py '
                'and tests/check_headlines.py from the datagram logs; the Gc run was added post hoc as a same-host control.',
    }
    (OUT / 'block_G_quality_checks.json').write_text(json.dumps(summary_checks, indent=2))
    pd.set_option('display.width', 250)
    for lab in ('Gc', 'G'):
        print(f'\n== block {lab} ==')
        print(summaries[lab][['algorithm', 'cached', 'enlargement_bytes', 'first_band', 'median_ms', 'rounds_1', 'rounds_2', 'rounds_3',
                              'server_udp_bytes_median', 'server_tls_bytes_median']].to_string(index=False))
    print('\n== comparison ==')
    print(c[['algorithm', 'cached', 'enlargement_bytes', 'first_band_A', 'first_band_Gc', 'first_band_G', 'median_ms_A', 'median_ms_Gc',
             'median_ms_G', 'rounds_A', 'rounds_Gc', 'rounds_G', 'fisher_p_G_vs_A', 'tls_bytes_support_identical_A_Gc_G']].to_string(index=False))
    print('\n== checks ==')
    print(json.dumps(summary_checks, indent=2))


if __name__ == '__main__':
    main()
