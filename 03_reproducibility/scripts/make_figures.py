#!/usr/bin/env python3
"""Generate reproducible plots from the derived experiment data.

Inputs: CSV files in 03_reproducibility/data, produced by the analysis scripts.
Outputs: vector PDF and 300-dpi PNG files in results/figures.
The generators retain the measured values and rendering calculations from the
original experiment analysis. Generated outputs are local, untracked files.
Requires NumPy and Matplotlib; a noninteractive rendering backend is used.
"""
from __future__ import annotations
from pathlib import Path
import csv
import glob
import statistics

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
from matplotlib.patches import FancyArrowPatch, Rectangle
from matplotlib.lines import Line2D

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / '03_reproducibility' / 'data'
OUT = ROOT / 'results' / 'figures'
OUT.mkdir(parents=True, exist_ok=True)

# ----------------------------------------------------------------------------- style
# A TrueType face is embedded as Type 42, which PDF checkers accept without font-type warnings.
FONT = 'Liberation Sans' if any(x.name == 'Liberation Sans' for x in fm.fontManager.ttflist) else 'DejaVu Sans'
INK = '#1a1a1a'       # primary ink
INK2 = '#6e6e6e'      # secondary ink (muted)
GRID = '#d9d9d9'
LIGHT = '#bfbfbf'     # light grey marks
ACC = '#1f4e79'       # single accent hue (deep blue)
ACC_L = '#9dbbd9'     # light tint of the accent
plt.rcParams.update({
    'font.family': FONT, 'font.size': 8, 'axes.titlesize': 8.5, 'axes.labelsize': 8,
    'legend.fontsize': 7.5, 'xtick.labelsize': 7.5, 'ytick.labelsize': 7.5,
    'axes.edgecolor': INK, 'axes.linewidth': 0.6, 'xtick.color': INK, 'ytick.color': INK,
    'axes.titleweight': 'bold', 'axes.titlelocation': 'left',
    'axes.spines.top': False, 'axes.spines.right': False,
    'axes.grid': True, 'grid.color': GRID, 'grid.linewidth': 0.5, 'grid.linestyle': '-',
    'axes.axisbelow': True, 'legend.frameon': False,
    'pdf.fonttype': 42, 'ps.fonttype': 42, 'savefig.bbox': 'tight', 'savefig.pad_inches': 0.02,
    'xtick.major.size': 2.5, 'ytick.major.size': 2.5, 'xtick.major.width': 0.6, 'ytick.major.width': 0.6,
    'mathtext.fontset': 'custom', 'mathtext.rm': FONT, 'mathtext.it': FONT + ':italic', 'mathtext.bf': FONT + ':bold',
})
SINGLE = 3.45   # inches, one column
DOUBLE = 7.1    # inches, two columns


def save(fig, name):
    fig.savefig(OUT / f'{name}.pdf')
    fig.savefig(OUT / f'{name}.png', dpi=300)
    plt.close(fig)
    print('wrote', name)


def read(name):
    with (DATA / name).open(newline='') as f:
        return list(csv.DictReader(f))


def fnum(x):
    return f'{x:,.0f}'


ALG_LABEL = {'ecdsa': 'ECDSA', 'mldsa44': 'ML-DSA-44', 'mldsa65': 'ML-DSA-65', 'mldsa87': 'ML-DSA-87'}
COND_LABEL = {(False, 0): 'none', (False, 2400): 'CE', (True, 0): 'CI', (True, 2400): 'CI+CE'}
COND_ORDER = [(False, 0), (True, 0), (False, 2400), (True, 2400)]


def jitter(n, width=0.22, seed=7):
    rng = np.random.default_rng(seed)
    return rng.uniform(-width, width, n)


# ----------------------------------------------------------------------------- data
W = read('new_wave_accounting.csv')
for r in W:
    r['cached'] = r['cached'] == 'True'
    r['enlargement_bytes'] = int(r['enlargement_bytes'])
    r['latency_ms'] = float(r['latency_ms'])
    r['first_wave_bytes'] = int(r['first_wave_bytes'])
    r['flight_bytes'] = int(r['flight_bytes'])
    r['auth_flight_bytes'] = int(r['auth_flight_bytes']) if r['auth_flight_bytes'] else None
    r['pre_crypto_pads'] = int(r['pre_crypto_pads']) if r['pre_crypto_pads'] else None
    r['rounds'] = int(r['rounds']) if r['rounds'] else None
    r['allowance_bytes'] = int(r['allowance_bytes'])


def cell(block, alg, cached, ce, profile=None):
    return [r for r in W if r['block'] == block and r['algorithm'] == alg and r['cached'] == cached
            and r['enlargement_bytes'] == ce and (profile is None or r['profile'] == profile)]


# ============================================================================= Figure 1
# (a) sequence schematic of the first wave under the two limits; (b) regime map with Block A cells.
def figure1():
    fig = plt.figure(figsize=(DOUBLE, 3.9))
    gs = fig.add_gridspec(1, 2, width_ratios=[1.5, 1.0], wspace=0.2, left=0.005, right=0.99, top=0.97, bottom=0.2)
    ax = fig.add_subplot(gs[0]); ax.set_axis_off(); ax.grid(False)
    ax.set_xlim(0, 10); ax.set_ylim(0, 10)
    xc, xs = 1.55, 5.0                       # client and server lifelines
    xn = 5.45                                # left edge of the notes column
    NOTE = 6.3                                # font size of notes

    def arrow(x0, x1, y, color=INK, lw=0.9):
        ax.add_patch(FancyArrowPatch((x0, y), (x1, y), arrowstyle='-|>', mutation_scale=6.5, lw=lw,
                                     color=color, shrinkA=0, shrinkB=0, zorder=3))

    def gap_label(y, text, color=INK, weight='normal', size=6.8):
        ax.text((xc + xs) / 2, y, text, ha='center', va='bottom', fontsize=size, color=color, weight=weight, zorder=6)

    def note(y, lines, color=INK2, weight='normal', size=NOTE):
        ax.text(xn, y, '\n'.join(lines), ha='left', va='center', fontsize=size, color=color, weight=weight, linespacing=1.2, zorder=6)

    # header boxes and lifelines
    for x, lab in [(xc, 'Client'), (xs, 'Server')]:
        ax.add_patch(Rectangle((x - 0.6, 9.4), 1.2, 0.5, facecolor='white', edgecolor=INK, lw=0.8, zorder=4))
        ax.text(x, 9.65, lab, ha='center', va='center', fontsize=8, weight='bold', color=INK, zorder=5)
        ax.plot([x, x], [2.35, 9.4], color=LIGHT, lw=1.0, zorder=1)
    # time axis (client-side events)
    ax.annotate('', (0.35, 2.45), (0.35, 9.3), arrowprops=dict(arrowstyle='-|>', color=INK2, lw=0.6, mutation_scale=6))
    ax.text(0.35, 9.4, 'time', ha='center', va='bottom', fontsize=6.2, color=INK2, style='italic')
    y_ch, y_ack, y_done = 8.85, 4.85, 2.95
    for y, lab in [(y_ch, '0'), (y_ack, '1 RTT'), (y_done, '2 RTT')]:
        ax.plot([0.25, 0.45], [y, y], color=INK2, lw=0.6)
        ax.text(0.5, y + 0.05, lab, ha='left', va='bottom', fontsize=6.0, color=INK2)
        ax.plot([0.45, 9.9], [y, y], color=GRID, lw=0.5, ls=(0, (1, 2)), zorder=0)

    # 1. ClientHello in two Initial datagrams
    arrow(xc, xs, y_ch); arrow(xc, xs, y_ch - 0.17)
    gap_label(y_ch + 0.06, 'ClientHello (2 × 1,200 B)')
    note(y_ch - 0.08, [r'credit $C_0$ = 2,400 B gives the', r'amplification allowance $3C_0$ = 7,200 B'])

    # 2. first wave under the two limits
    y_fw = 7.8; n_wave = 6; step = 0.14
    for k in range(n_wave):
        arrow(xs, xc, y_fw - step * k, color=ACC, lw=0.85)
    gap_label(y_fw + 0.06, 'first wave', color=ACC, weight='bold')
    gap_label(y_fw - step * (n_wave - 1) - 0.42, 'ServerHello … Finished', color=ACC, size=6.3)
    yb0, yb1 = y_fw + 0.08, y_fw - step * (n_wave - 1) - 0.08
    ax.plot([xs + 0.2, xs + 0.3, xs + 0.3, xs + 0.2], [yb0, yb0, yb1, yb1], color=INK, lw=0.7, zorder=3)
    note((yb0 + yb1) / 2, ['before feedback the server', 'may send at most',
                           r'$3C_0$ = 7,200 B (amplification) and', r'$W_0$ = 12,000 B (initial window)'], color=INK)
    # held remainder: small stack just left of the server lifeline
    y_held = 6.05
    for i in range(3):
        ax.add_patch(Rectangle((xs - 0.3 - 0.19 * i, y_held - 0.12), 0.15, 0.24, facecolor=ACC_L, edgecolor=ACC, lw=0.5, zorder=3))
    ax.text(xs - 0.95, y_held, 'rest of the chain held', ha='right', va='center', fontsize=6.3, color=ACC)
    note(y_held, [r'if $B_{\mathrm{flight}}$ exceeds either limit,', r'the wave stops at $\min(3C_0, W_0)$', 'and the rest of the chain waits'],
         color=ACC, weight='bold')

    # 3. client feedback
    arrow(xc, xs, y_ack)
    gap_label(y_ack + 0.06, 'ACK (+ Handshake packet)')
    note(y_ack - 0.1, ['adds credit, grows the window;', 'a Handshake packet validates', 'the client address'])

    # 4. remainder and completion
    y_rem = 3.85
    arrow(xs, xc, y_rem, color=ACC); arrow(xs, xc, y_rem - 0.17, color=ACC)
    gap_label(y_rem + 0.06, 'remainder of the flight', color=ACC, weight='bold')
    note(y_rem - 0.08, ['the held bytes cost one more', 'round trip'], color=ACC)
    ax.scatter([xc], [y_done], s=16, color=INK, zorder=6)
    ax.text(xc + 0.2, y_done, 'chain verified: complete', ha='left', va='center', fontsize=6.8, color=INK)
    # +1 RTT bracket on the right
    ax.plot([9.5, 9.65, 9.65, 9.5], [y_ack, y_ack, y_done, y_done], color=INK2, lw=0.7)
    ax.text(9.87, (y_ack + y_done) / 2, '+1 RTT', rotation=90, ha='center', va='center', fontsize=6.6, color=INK2)

    # take-away line
    ax.text(5.0, 1.45, r'CI shrinks $B_{\mathrm{flight}}$.    CE raises only $3C_0$.    $W_0$ is unchanged by either.',
            ha='center', va='center', fontsize=7.0, color=INK, weight='bold')
    ax.text(0.05, 9.9, '(a)', fontsize=9, weight='bold', va='center')

    # (b) regime map
    bx = fig.add_subplot(gs[1])
    bx.text(-0.3, 1.0, '(b)', transform=bx.transAxes, fontsize=9, weight='bold', va='bottom')
    W0 = 12000
    bx.set_xlim(0, 20000); bx.set_ylim(0, 25000)
    bx.axhline(W0, color=INK, lw=0.8, ls='--')
    bx.plot([0, 20000], [0, 20000], color=INK, lw=0.8, ls=':')
    bx.text(300, W0 + 450, r'$W_0$ = 12,000 B', ha='left', va='bottom', fontsize=7.2)
    bx.text(16300, 17500, r'flight = $3C_0$', ha='left', va='bottom', fontsize=7.2, rotation=48)
    bx.fill_between([0, W0], 0, [0, W0], color=ACC_L, alpha=0.35, lw=0)
    bx.text(11200, 1800, 'one round\n(both limits met)', ha='right', va='bottom', fontsize=7.2, color=ACC, weight='bold')
    pts = {}
    for alg in ['mldsa44', 'mldsa65', 'mldsa87']:
        for (ci, ce) in COND_ORDER:
            c = cell('A', alg, ci, ce)
            fl = statistics.mode([r['flight_bytes'] for r in c])
            pts[(alg, ci, ce)] = (c[0]['allowance_bytes'], fl, sum(1 for r in c if r['rounds'] == 1))
    mk = {'mldsa44': 'o', 'mldsa65': 's', 'mldsa87': '^'}
    for (alg, ci, ce), (x, y, k) in pts.items():
        filled = k == 30
        bx.scatter([x], [y], marker=mk[alg], s=28, facecolor=ACC if filled else 'white', edgecolor=ACC if filled else INK,
                   lw=0.9, zorder=5)
    x0, y0, _ = pts[('mldsa44', False, 0)]
    x1, y1, _ = pts[('mldsa44', True, 0)]
    x2, y2, _ = pts[('mldsa44', False, 2400)]
    bx.annotate('', (x1, y1 + 450), (x0, y0 - 450), arrowprops=dict(arrowstyle='-|>', color=INK2, lw=0.8, mutation_scale=7))
    bx.annotate('', (x2 - 450, y2), (x0 + 450, y0), arrowprops=dict(arrowstyle='-|>', color=INK2, lw=0.8, mutation_scale=7))
    bx.text(6700, 11100, 'CI', ha='right', va='center', fontsize=7.2, color=INK2, weight='bold')
    bx.text(10800, 13597 + 500, 'CE', ha='center', va='bottom', fontsize=7.2, color=INK2, weight='bold')
    bx.text(14900, 9376, 'CI+CE', ha='left', va='center', fontsize=7.2, color=ACC, weight='bold')
    bx.set_xlabel(r'amplification allowance $3C_0$ (bytes)')
    bx.set_ylabel('first-wave bytes needed (bytes)')
    bx.set_xticks([0, 7200, 14400, 20000]); bx.set_xticklabels(['0', '7,200', '14,400', '20,000'])
    bx.set_yticks([0, 6000, 12000, 18000, 24000]); bx.set_yticklabels(['0', '6,000', '12,000', '18,000', '24,000'])
    handles = [Line2D([], [], marker=mk[a], ls='', mfc='white', mec=INK, ms=5, label=ALG_LABEL[a]) for a in mk]
    handles += [Line2D([], [], marker='o', ls='', mfc=ACC, mec=ACC, ms=5, label='30/30 one round'),
                Line2D([], [], marker='o', ls='', mfc='white', mec=INK, ms=5, label='0/30 one round')]
    bx.legend(handles=handles, loc='upper center', bbox_to_anchor=(0.42, -0.2), ncol=3, handletextpad=0.3,
              columnspacing=1.0, labelspacing=0.3)
    fig.savefig(OUT / 'fig1_two_limits.pdf'); fig.savefig(OUT / 'fig1_two_limits.png', dpi=300); plt.close(fig)
    print('wrote fig1_two_limits')


# ============================================================================= Figure 2
# Authentication flight sizes in TLS and UDP bytes against the two limits
def figure2():
    rows = read('archived_full_chain_sizes.csv')
    labels = ['ECDSA\nX25519', 'ECDSA\nhybrid', 'ML-DSA\n44', 'ML-DSA\n65', 'ML-DSA\n87']   # ML-DSA rows use the hybrid group (caption)
    tls = [int(r['server_tls_bytes']) for r in rows]
    udp = [int(r['server_udp_bytes']) for r in rows]
    fig, ax = plt.subplots(figsize=(SINGLE, 2.5))
    x = np.arange(len(rows)); w = 0.36
    ax.bar(x - w / 2 - 0.02, tls, w, color=LIGHT, label='TLS handshake messages')
    ax.bar(x + w / 2 + 0.02, udp, w, color=ACC, label='observed UDP payload')
    ax.axhline(7200, color=INK, lw=0.8, ls=':')
    ax.axhline(12000, color=INK, lw=0.8, ls='--')
    ax.text(-0.42, 7200 + 300, r'$3C_0$ = 7,200 B', ha='left', va='bottom', fontsize=7)
    ax.text(-0.42, 12000 + 300, r'$W_0$ = 12,000 B', ha='left', va='bottom', fontsize=7)
    i = 2   # ML-DSA-44: TLS bytes below the window, UDP bytes above it
    ax.text(x[i] - w / 2 - 0.02, tls[i] + 300, fnum(tls[i]), ha='center', va='bottom', fontsize=6.5, color=INK)
    ax.text(x[i] + w / 2 + 0.02, udp[i] + 300, fnum(udp[i]), ha='center', va='bottom', fontsize=6.5, color=ACC)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=7)
    ax.set_ylabel('server authentication flight (bytes)')
    ax.set_ylim(0, 24000); ax.set_yticks([0, 6000, 12000, 18000, 24000])
    ax.set_yticklabels(['0', '6,000', '12,000', '18,000', '24,000'])
    ax.legend(loc='upper left', bbox_to_anchor=(0.0, 1.02))
    save(fig, 'fig2_flight_sizes')


# ============================================================================= Figure 3
# Baseline completion vs configured RTT (archived medians) with round bands
def figure3():
    rows = read('archived_baseline_rtt.csv')
    fig, ax = plt.subplots(figsize=(SINGLE, 2.55))
    rt = np.array([20, 60, 120])
    for k in (1, 2, 3):
        ax.plot([0, 122], [0, 122 * k], color=GRID, lw=0.7, ls='-')
        ax.text(124.5, 122 * k, f'{k} RTT', ha='left', va='center', fontsize=7, color=INK2)
    spec = {'ecdsa_h': ('ECDSA / hybrid', 'o', INK2), 'mldsa44': ('ML-DSA-44', 's', ACC),
            'mldsa65': ('ML-DSA-65', 'D', ACC), 'mldsa87': ('ML-DSA-87', '^', INK)}
    for key, (lab, m, col) in spec.items():
        y = [float(r['median_ms']) for r in rows if r['configuration'] == key]
        ax.plot(rt, y, marker=m, ms=4, color=col, lw=1.0, mfc='white' if key == 'mldsa65' else col, mew=1.0, label=lab)
    ax.set_xlim(0, 138); ax.set_ylim(0, 390)
    ax.set_xticks([20, 60, 120]); ax.set_xlabel('configured round-trip time (ms)')
    ax.set_ylabel('median client completion (ms)')
    ax.legend(loc='upper left', handlelength=2.2)
    save(fig, 'fig3_baseline_rounds')


# ============================================================================= Figure 4
# Block A: per-trial first-wave bytes vs limits (top) and completion time (bottom)
def figure4():
    fig, axes = plt.subplots(2, 1, figsize=(DOUBLE, 4.6), sharex=True, gridspec_kw=dict(hspace=0.12, height_ratios=[1.1, 1]))
    algs = ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']
    xs, labels, bounds = [], [], []
    pos = 0
    for a in algs:
        start = pos
        for (ci, ce) in COND_ORDER:
            xs.append((a, ci, ce, pos)); labels.append(COND_LABEL[(ci, ce)]); pos += 1
        bounds.append((start, pos - 1)); pos += 0.8
    top, bot = axes
    for a, ci, ce, x in xs:
        c = cell('A', a, ci, ce)
        acc = (ci and ce == 2400)
        col = ACC if acc else INK
        j = jitter(len(c))
        # flight needed (hollow) and observed first wave (filled)
        top.scatter(x + j, [r['flight_bytes'] for r in c], s=9, facecolor='white', edgecolor=col, lw=0.6, zorder=4)
        top.scatter(x + j, [r['first_wave_bytes'] for r in c], s=9, color=col, lw=0, zorder=5)
        bot.scatter(x + j, [r['latency_ms'] for r in c], s=9, color=col, lw=0, zorder=5)
        k = sum(1 for r in c if r['rounds'] == 1)
        bot.text(x, 41, f'{k}/30', ha='center', va='bottom', fontsize=6.5, color=col)
    for s, e in bounds[1:]:
        top.axvspan(s - 0.5, e + 0.5, color='#f3f3f3', zorder=0, lw=0)
        bot.axvspan(s - 0.5, e + 0.5, color='#f3f3f3', zorder=0, lw=0)
    # limit lines
    top.axhline(7200, color=INK, lw=0.7, ls=':'); top.axhline(12000, color=INK, lw=0.7, ls='--')
    top.axhline(14400, color=INK, lw=0.7, ls=':')
    top.text(-0.45, 7200 + 250, r'$3C_0$ without CE (7,200 B)', ha='left', va='bottom', fontsize=6.8, color=INK2)
    top.text(-0.45, 12000 - 250, r'initial window $W_0$ (12,000 B)', ha='left', va='top', fontsize=6.8, color=INK2)
    top.text(-0.45, 14400 + 250, r'$3C_0$ with CE (14,400 B)', ha='left', va='bottom', fontsize=6.8, color=INK2)
    top.set_ylim(0, 25000); top.set_yticks([0, 6000, 12000, 18000, 24000])
    top.set_yticklabels(['0', '6,000', '12,000', '18,000', '24,000'])
    top.set_ylabel('server bytes in the first wave')
    hl = [Line2D([], [], marker='o', ls='', mfc=INK, mec=INK, ms=4, label='observed first wave'),
          Line2D([], [], marker='o', ls='', mfc='white', mec=INK, ms=4, label='flight needed (authentication + padded ACK)')]
    top.legend(handles=hl, loc='upper left', ncol=2, bbox_to_anchor=(0.0, 1.0), columnspacing=1.2)
    bot.axhline(90, color=INK, lw=0.7, ls='--')
    bot.text(pos - 0.9, 92, 'one-round threshold 1.5 RTT = 90 ms', ha='right', va='bottom', fontsize=6.8, color=INK2)
    bot.set_ylim(36, 205); bot.set_yticks([60, 90, 120, 150, 180])
    bot.set_ylabel('client completion (ms)')
    bot.set_xticks([x for _, _, _, x in xs]); bot.set_xticklabels(labels, fontsize=7)
    import matplotlib.transforms as mtransforms
    tr = mtransforms.blended_transform_factory(bot.transData, bot.transAxes)
    for (s, e), a in zip(bounds, algs):
        bot.text((s + e) / 2, -0.19, ALG_LABEL[a], ha='center', va='top', fontsize=8, weight='bold', color=INK, transform=tr)
    bot.set_xlim(-0.6, pos - 1.2)
    top.text(0.0, 1.03, '(a)', transform=top.transAxes, fontsize=9, weight='bold', va='bottom')
    bot.text(0.0, 1.03, '(b)', transform=bot.transAxes, fontsize=9, weight='bold', va='bottom')
    save(fig, 'fig4_blockA')


# ============================================================================= Figure 5
# Block C: the combined condition under the laboratory and WebPKI-like profiles
def figure5():
    import matplotlib.transforms as mtransforms
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE, 2.9), gridspec_kw=dict(wspace=0.3))
    fig.subplots_adjust(bottom=0.3)
    groups = [('mldsa44', 'laboratory', 'A'), ('mldsa44', 'webpki-like', 'C'), ('mldsa65', 'laboratory', 'A'), ('mldsa65', 'webpki-like', 'C')]
    xpos = [0, 1, 2.4, 3.4]
    ax = axes[0]
    tr = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    for (a, prof, blk), x in zip(groups, xpos):
        c = cell(blk, a, True, 2400, prof)
        col = ACC if prof == 'webpki-like' else INK
        j = jitter(len(c))
        ax.scatter(x + j, [r['flight_bytes'] for r in c], s=10, color=col, lw=0, zorder=5)
    ax.axhline(12000, color=INK, lw=0.7, ls='--')
    ax.text(-0.55, 12000 + 80, r'$W_0$ = 12,000 B', ha='left', va='bottom', fontsize=7, color=INK2)
    ax.annotate('11,878 B\n(122 B under)', (2.4, 11878), (1.75, 10700), fontsize=6.8, color=INK, ha='center', va='top',
                arrowprops=dict(arrowstyle='-', color=INK2, lw=0.6))
    ax.annotate('12,401 B with one padded\nACK-only Initial (401 B over)', (3.4, 12401), (1.9, 13750), fontsize=6.8, color=ACC,
                ha='center', va='center', arrowprops=dict(arrowstyle='-', color=ACC, lw=0.6))
    ax.annotate('11,201 B, no padded\nACK (1 trial)', (3.4, 11201), (3.05, 9600), fontsize=6.8, color=ACC, ha='center', va='top',
                arrowprops=dict(arrowstyle='-', color=ACC, lw=0.6))
    ax.set_ylim(7500, 14500); ax.set_yticks([8000, 10000, 12000, 14000]); ax.set_yticklabels(['8,000', '10,000', '12,000', '14,000'])
    ax.set_ylabel('first-wave bytes needed (CI+CE)')
    ax.set_xticks(xpos); ax.set_xticklabels(['lab.', 'WebPKI-\nlike', 'lab.', 'WebPKI-\nlike'], fontsize=7)
    ax.text(0.5, -0.27, 'ML-DSA-44', ha='center', va='top', fontsize=8, weight='bold', transform=tr)
    ax.text(2.9, -0.27, 'ML-DSA-65', ha='center', va='top', fontsize=8, weight='bold', transform=tr)
    ax.set_xlim(-0.6, 4.0)
    ax.text(0.0, 1.03, '(a)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom')
    ax = axes[1]
    tr = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    for (a, prof, blk), x in zip(groups, xpos):
        c = cell(blk, a, True, 2400, prof)
        col = ACC if prof == 'webpki-like' else INK
        j = jitter(len(c))
        ax.scatter(x + j, [r['latency_ms'] for r in c], s=10, color=col, lw=0, zorder=5)
        k = sum(1 for r in c if r['rounds'] == 1)
        ax.text(x, 143, f'{k}/30', ha='center', va='top', fontsize=7, color=col)
    ax.axhline(90, color=INK, lw=0.7, ls='--')
    ax.text(3.75, 91, '1.5 RTT', ha='right', va='bottom', fontsize=7, color=INK2)
    ax.set_ylim(50, 148); ax.set_yticks([60, 90, 120])
    ax.set_ylabel('client completion (ms)')
    ax.set_xticks(xpos); ax.set_xticklabels(['lab.', 'WebPKI-\nlike', 'lab.', 'WebPKI-\nlike'], fontsize=7)
    ax.text(0.5, -0.27, 'ML-DSA-44', ha='center', va='top', fontsize=8, weight='bold', transform=tr)
    ax.text(2.9, -0.27, 'ML-DSA-65', ha='center', va='top', fontsize=8, weight='bold', transform=tr)
    ax.set_xlim(-0.6, 4.0)
    ax.text(0.0, 1.03, '(b)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom')
    hl = [Line2D([], [], marker='o', ls='', mfc=INK, mec=INK, ms=4, label='laboratory profile (Block A)'),
          Line2D([], [], marker='o', ls='', mfc=ACC, mec=ACC, ms=4, label='WebPKI-like profile, +481 TLS B (Block C)')]
    fig.legend(handles=hl, loc='lower center', ncol=2, bbox_to_anchor=(0.5, 0.0), columnspacing=1.5)
    save(fig, 'fig6_profile_boundary')


# ============================================================================= Figure 6
# (a) classifier disagreements, (b) Retry overhead, (c) slow-uplink medians
def figure6():
    import matplotlib.transforms as mtransforms
    cl = read('archived_classifier_comparison.csv')
    rb = read('archived_robustness_core.csv')
    fig, axes = plt.subplots(1, 3, figsize=(DOUBLE, 2.6), gridspec_kw=dict(wspace=0.75, width_ratios=[1.0, 1.0, 1.25]))
    fig.subplots_adjust(bottom=0.26, top=0.88, left=0.17, right=0.99)
    # (a) classifier disagreements, horizontal bars
    ax = axes[0]
    labels = ['amplification rule,\nTLS-message bytes', 'amplification rule,\nUDP flight bytes', 'both limits,\nUDP flight bytes']
    vals = [int(r['disagreements']) for r in cl]
    cols = [LIGHT, LIGHT, ACC]
    y = [2, 1, 0]
    ax.barh(y, vals, 0.6, color=cols)
    for yi, v in zip(y, vals):
        ax.text(v + 6, yi, f'{v} ({100*v/1740:.1f}%)' if v else '0 (0.0%)', ha='left', va='center', fontsize=7)
    ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=6.8)
    ax.set_xlabel('misclassified traces (of 1,740)'); ax.set_xlim(0, 330)
    ax.set_xticks([0, 100, 200, 300])
    ax.text(-0.95, 1.05, '(a)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom')
    # (b) Retry overhead, horizontal bars
    ax = axes[1]
    rows = [r for r in rb if r['scenario'] == 'Retry']
    labels = ['ECDSA / X25519', 'ECDSA / hybrid', 'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']
    d = [float(r['delta_ms']) for r in rows]
    y = [4, 3, 2, 1, 0]
    ax.barh(y, d, 0.6, color=[LIGHT, ACC, ACC, ACC, LIGHT])
    for yi, v in zip(y, d):
        ax.text(v + 3, yi, f'+{v:.0f} ms', ha='left', va='center', fontsize=7)
    ax.axvline(60, color=INK, lw=0.6, ls=':'); ax.axvline(120, color=INK, lw=0.6, ls=':')
    ax.text(60, 4.55, '1 RTT', ha='center', va='bottom', fontsize=6.5, color=INK2)
    ax.text(120, 4.55, '2 RTT', ha='center', va='bottom', fontsize=6.5, color=INK2)
    ax.set_yticks(y); ax.set_yticklabels(labels, fontsize=6.8)
    ax.set_xlabel('Retry overhead (ms), 60 ms RTT'); ax.set_xlim(0, 175); ax.set_ylim(-0.6, 4.5)
    ax.set_xticks([0, 60, 120])
    ax.text(-0.75, 1.05, '(b)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom')
    # (c) slow uplink
    ax = axes[2]
    tr = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    conf = [('ML-DSA-44 full', 'full'), ('ML-DSA-44 CI', 'CI'), ('ML-DSA-44 CE', 'CE'),
            ('ML-DSA-87 full', 'full'), ('ML-DSA-87 CI', 'CI'), ('ML-DSA-87 CE', 'CE')]
    x = [0, 1, 2, 3.4, 4.4, 5.4]
    v1 = [float(next(r['condition_ms'] for r in rb if r['scenario'] == '1 Mbit/s uplink' and r['configuration'] == c)) for c, _ in conf]
    v10 = [float(next(r['condition_ms'] for r in rb if r['scenario'] == '10 Mbit/s uplink' and r['configuration'] == c)) for c, _ in conf]
    ax.bar([i - 0.2 for i in x], v10, 0.38, color=LIGHT, label='10 Mbit/s uplink')
    ax.bar([i + 0.2 for i in x], v1, 0.38, color=ACC, label='1 Mbit/s uplink')
    for i, v in zip(x, v1):
        ax.text(i + 0.2, v + 2, f'{v:.0f}', ha='center', va='bottom', fontsize=6.3, color=ACC)
    ax.set_xticks(x); ax.set_xticklabels([s for _, s in conf], fontsize=7)
    ax.text(1, -0.22, 'ML-DSA-44', ha='center', va='top', fontsize=7.5, weight='bold', transform=tr)
    ax.text(4.4, -0.22, 'ML-DSA-87', ha='center', va='top', fontsize=7.5, weight='bold', transform=tr)
    ax.set_ylim(0, 215); ax.set_ylabel('median completion (ms)')
    ax.set_yticks([0, 50, 100, 150, 200])
    ax.legend(loc='lower left', bbox_to_anchor=(0.0, 1.0), ncol=2, columnspacing=1.0, borderaxespad=0.0)
    ax.text(-0.34, 1.05, '(c)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom')
    save(fig, 'fig7_classifier_retry_uplink')


# ============================================================================= Figure 7 (main text)
# Block G: the Block A design on a second host with OpenSSL 3.5.5 (control) and 3.5.9
def figure_blockG():
    import matplotlib.transforms as mtransforms
    fig = plt.figure(figsize=(DOUBLE, 3.05))
    gs = fig.add_gridspec(1, 2, width_ratios=[3.6, 1.0], wspace=0.32, left=0.07, right=0.99, top=0.9, bottom=0.27)
    ax = fig.add_subplot(gs[0]); bx = fig.add_subplot(gs[1])
    algs = ['ecdsa', 'mldsa44', 'mldsa65', 'mldsa87']
    runs = [('A', -0.3, dict(facecolor=INK, edgecolor=INK, lw=0), 'Block A: OpenSSL 3.5.5, host 1'),
            ('Gc', 0.0, dict(facecolor='white', edgecolor=INK, lw=0.6), 'Block G control: OpenSSL 3.5.5, host 2'),
            ('G', 0.3, dict(facecolor=ACC, edgecolor=ACC, lw=0), 'Block G: OpenSSL 3.5.9, host 2')]
    xs, labels, bounds = [], [], []
    pos = 0
    for a in algs:
        start = pos
        for (ci, ce) in COND_ORDER:
            xs.append((a, ci, ce, pos)); labels.append(COND_LABEL[(ci, ce)]); pos += 1
        bounds.append((start, pos - 1)); pos += 0.7
    for s_, e_ in bounds[1:]:
        ax.axvspan(s_ - 0.5, e_ + 0.5, color='#f3f3f3', zorder=0, lw=0)
    for a, ci, ce, x in xs:
        for blk, dx, style, _ in runs:
            c = cell(blk, a, ci, ce)
            j = jitter(len(c), 0.07, seed=11)
            ax.scatter(x + dx + j, [r['latency_ms'] for r in c], s=9, zorder=5, **style)
    ax.axhline(90, color=INK, lw=0.7, ls='--'); ax.axhline(150, color=INK, lw=0.7, ls=':')
    ax.text(pos - 0.95, 92, '1.5 RTT: one-round limit', ha='right', va='bottom', fontsize=6.8, color=INK2)
    ax.text(pos - 0.95, 152, '2.5 RTT: two-round limit', ha='right', va='bottom', fontsize=6.8, color=INK2)
    ax.set_ylim(36, 205); ax.set_yticks([60, 90, 120, 150, 180])
    ax.set_ylabel('client completion (ms)')
    ax.set_xticks([x for _, _, _, x in xs]); ax.set_xticklabels(labels, fontsize=7)
    tr = mtransforms.blended_transform_factory(ax.transData, ax.transAxes)
    for (s_, e_), a in zip(bounds, algs):
        ax.text((s_ + e_) / 2, -0.17, ALG_LABEL[a], ha='center', va='top', fontsize=8, weight='bold', color=INK, transform=tr)
    ax.set_xlim(-0.65, pos - 1.05)
    handles = [Line2D([], [], marker='o', ls='', ms=4.2, mfc=st['facecolor'], mec=st['edgecolor'], mew=0.7, label=lab) for _, _, st, lab in runs]
    ax.legend(handles=handles, loc='upper left', bbox_to_anchor=(0.0, 1.12), ncol=3, columnspacing=1.4, handletextpad=0.3, frameon=False)
    ax.text(-0.01, 1.12, '(a)', transform=ax.transAxes, fontsize=9, weight='bold', va='bottom', ha='right')
    # (b) padded ACK-only Initials per run
    counts = []
    for blk, _, style, lab in runs:
        rows = [r for r in W if r['block'] == blk and r['pre_crypto_pads'] is not None]
        counts.append((sum(1 for r in rows if r['pre_crypto_pads'] >= 1), len(rows), style))
    ys = [2, 1, 0]
    for y, (k, n, style) in zip(ys, counts):
        bx.barh(y, 100 * k / n, height=0.62, color=style['facecolor'], edgecolor=style['edgecolor'], lw=0.8, zorder=3)
        bx.text(100 * k / n + 2.5, y, f'{k}/{n}', va='center', ha='left', fontsize=7, color=INK)
    bx.set_yticks(ys); bx.set_yticklabels(['A\n3.5.5, host 1', 'G control\n3.5.5, host 2', 'G\n3.5.9, host 2'], fontsize=6.8)
    bx.set_xlim(0, 118); bx.set_xticks([0, 50, 100]); bx.set_xticklabels(['0', '50', '100 %'])
    bx.set_xlabel('share of trials with a padded ACK-only\nInitial before the first CRYPTO datagram', fontsize=7)
    bx.grid(axis='y', visible=False)
    bx.text(-0.02, 1.12, '(b)', transform=bx.transAxes, fontsize=9, weight='bold', va='bottom', ha='right')
    save(fig, 'fig5_version_host_replication')


# ============================================================================= Detailed plot S2
# ML-DSA-87 full chain: second-wave size and round count
def figure7():
    c = cell('A', 'mldsa87', False, 0)
    fig, ax = plt.subplots(figsize=(SINGLE, 2.4))
    for r in c:
        waves = [int(v) for v in r['wave_bytes'].split(';')]
        r['_w2'] = waves[1] if len(waves) > 1 else 0
    for rounds, x, col in [(2, 0, ACC), (3, 1, INK)]:
        sub = [r for r in c if r['rounds'] == rounds]
        j = jitter(len(sub), 0.18, seed=3)
        ax.scatter(x + j, [r['_w2'] for r in sub], s=12, color=col, lw=0, zorder=5)
        ax.text(x, 17600, f'{len(sub)} trials', ha='center', va='bottom', fontsize=7, color=col)
    ax.axhline(12000, color=INK, lw=0.7, ls='--')
    ax.text(1.42, 12000 + 150, r'$W_0$', ha='right', va='bottom', fontsize=7, color=INK2)
    for y, lab in [(13200, '+1 datagram'), (14400, '+2'), (15600, '+3')]:
        ax.axhline(y, color=GRID, lw=0.6)
    ax.axhline(15921, color=ACC, lw=0.6, ls=':')
    ax.text(0.5, 15921 + 120, 'remainder with one padded ACK\n= 15,921 B', fontsize=6.5, color=ACC, va='bottom', ha='center')
    ax.axhline(14721, color=ACC, lw=0.6, ls=':')
    ax.text(0.5, 14721 - 120, 'remainder without\n= 14,721 B', fontsize=6.5, color=ACC, va='top', ha='center')
    ax.set_xticks([0, 1]); ax.set_xticklabels(['two rounds', 'three rounds'])
    ax.set_xlim(-0.5, 1.5); ax.set_ylim(11000, 18500)
    ax.set_yticks([12000, 13200, 14400, 15600, 16800]); ax.set_yticklabels(['12,000', '13,200', '14,400', '15,600', '16,800'])
    ax.set_ylabel('second server wave (bytes)')
    save(fig, 'figS2_mldsa87_second_wave')


# ============================================================================= Detailed plot S1
# Block F zero-RTT residual
def figure8():
    F = read('block_F_summary.csv')
    order = [('ecdsa', 'x25519', 'ECDSA\nX25519'), ('ecdsa', 'X25519MLKEM768', 'ECDSA\nhybrid'),
             ('mldsa44', 'X25519MLKEM768', 'ML-DSA-44'), ('mldsa65', 'X25519MLKEM768', 'ML-DSA-65'), ('mldsa87', 'X25519MLKEM768', 'ML-DSA-87')]
    fig, ax = plt.subplots(figsize=(SINGLE, 2.3))
    for i, (a, g, lab) in enumerate(order):
        r = next(r for r in F if r['algorithm'] == a and r['group'] == g)
        m, lo, hi = float(r['median_ms']), float(r['ci_low_ms']), float(r['ci_high_ms'])
        col = ACC if a.startswith('mldsa') else LIGHT
        ax.bar(i, m, 0.6, color=col)
        ax.errorbar(i, m, yerr=[[m - lo], [hi - m]], color=INK, lw=0.8, capsize=2.5)
        ax.text(i, hi + 0.15, f'{m:.2f}', ha='center', va='bottom', fontsize=7)
    ax.set_xticks(range(5)); ax.set_xticklabels([o[2] for o in order], fontsize=7)
    ax.set_ylabel('median completion at RTT 0 (ms)'); ax.set_ylim(0, 10)
    save(fig, 'figS1_zero_rtt')


# ============================================================================= Overview plot
def overview_figure():
    # Fixed 13 x 5 cm canvas at 300 dpi, without cropping.
    fig = plt.figure(figsize=(13 / 2.54, 5 / 2.54))
    fig.text(0.5, 0.93, 'Post-quantum certificate authentication in QUIC: one round trip needs both byte limits satisfied',
             ha='center', va='center', fontsize=6.8, weight='bold', color=INK)
    # panel 1: regime map (ML-DSA-44)
    ax = fig.add_axes([0.075, 0.2, 0.2, 0.56])
    ax.tick_params(labelsize=4.8, pad=1.5); ax.grid(False)
    ax.set_xlim(0, 16500); ax.set_ylim(0, 16500)
    ax.fill_between([0, 12000], 0, [0, 12000], color=ACC_L, alpha=0.45, lw=0)
    ax.axhline(12000, color=INK, lw=0.6, ls='--'); ax.plot([0, 16500], [0, 16500], color=INK, lw=0.6, ls=':')
    ax.text(300, 12300, 'window 12,000 B', ha='left', va='bottom', fontsize=4.4)
    ax.text(2300, 3100, 'allowance', ha='left', va='bottom', fontsize=4.4, rotation=45, color=INK2)
    ax.text(10500, 1200, 'one\nround', ha='right', va='bottom', fontsize=4.8, color=ACC, weight='bold')
    pts = [(7200, 13597, False, 'full'), (7200, 9376, False, 'CI'), (14400, 13597, False, 'CE'), (14400, 9376, True, 'CI+CE')]
    for x, y, ok, lab in pts:
        ax.scatter([x], [y], s=11, facecolor=ACC if ok else 'white', edgecolor=ACC if ok else INK, lw=0.7, zorder=5)
    ax.text(7200, 13597 + 700, 'full chain', ha='center', va='bottom', fontsize=4.4)
    ax.text(6500, 9376, 'CI', ha='right', va='center', fontsize=4.4)
    ax.text(13700, 13597, 'CE', ha='right', va='center', fontsize=4.4)
    ax.text(14400, 9376 - 900, 'CI+CE', ha='center', va='top', fontsize=4.6, color=ACC, weight='bold')
    ax.set_xticks([0, 7200, 14400]); ax.set_xticklabels(['0', '7,200', '14,400'])
    ax.set_yticks([0, 6000, 12000]); ax.set_yticklabels(['0', '6,000', '12,000'])
    ax.set_xlabel('3 x client credit (B)', fontsize=5.0, labelpad=1.5); ax.set_ylabel('server first wave (B)', fontsize=5.0, labelpad=1.5)
    ax.set_title('ML-DSA-44 cells, 12,000-B window', fontsize=5.2, pad=2)
    # panel 2: outcome table
    ax = fig.add_axes([0.345, 0.12, 0.28, 0.68]); ax.set_axis_off(); ax.grid(False)
    T = ax.transAxes
    ax.text(0.0, 1.0, 'Interleaved 2 x 2 test, OpenSSL QUIC, 60 ms RTT', fontsize=5.2, weight='bold', va='top', transform=T)
    ax.text(0.0, 0.89, 'one-round completions; ML-DSA-44 and -65 alike', fontsize=4.6, va='top', color=INK2, transform=T)
    ax.text(0.66, 0.74, 'no CE', fontsize=5.0, ha='center', va='center', weight='bold', transform=T)
    ax.text(0.9, 0.74, '+CE', fontsize=5.0, ha='center', va='center', weight='bold', transform=T)
    ax.plot([0.0, 1.0], [0.66, 0.66], color=INK, lw=0.5, transform=T)
    ax.text(0.0, 0.56, 'full chain', fontsize=5.0, va='center', transform=T)
    ax.text(0.66, 0.56, '0/30', fontsize=5.8, ha='center', va='center', transform=T)
    ax.text(0.9, 0.56, '0/30', fontsize=5.8, ha='center', va='center', transform=T)
    ax.text(0.0, 0.42, 'cached interm. (CI)', fontsize=5.0, va='center', transform=T)
    ax.text(0.66, 0.42, '0/30', fontsize=5.8, ha='center', va='center', transform=T)
    ax.text(0.9, 0.42, '30/30', fontsize=6.0, ha='center', va='center', weight='bold', color=ACC, transform=T)
    ax.plot([0.0, 1.0], [0.33, 0.33], color=INK, lw=0.5, transform=T)
    ax.text(0.0, 0.24, 'each single remedy leaves one limit binding:\nthe server first wave stops at exactly\n7,199 B or 11,999 B',
            fontsize=4.6, va='top', color=INK, transform=T, linespacing=1.25)
    # panel 3: key messages (one short line each)
    ax = fig.add_axes([0.685, 0.12, 0.3, 0.68]); ax.set_axis_off(); ax.grid(False)
    T = ax.transAxes
    ax.text(0.0, 1.0, 'What decides the latency band', fontsize=5.2, weight='bold', va='top', transform=T)
    msgs = ['QUIC framing: 11,890 TLS bytes become\n12,397 UDP bytes and cross the window',
            'Chain reduction and client credit are\ncomplementary: only together do they save the round',
            '+481 B of WebPKI-like profile flips ML-DSA-65\nCI+CE from 30/30 to 1/30 one-round completions',
            'ML-DSA-87 stays window-bound; the pattern\nreplicates on a second host and OpenSSL 3.5.9']
    y = 0.86
    for m in msgs:
        ax.text(0.0, y, u'• ' + m, fontsize=4.6, va='top', ha='left', transform=T, linespacing=1.25)
        y -= 0.235
    with plt.rc_context({'savefig.bbox': None, 'savefig.pad_inches': 0}):
        fig.savefig(OUT / 'overview.pdf')
        fig.savefig(OUT / 'overview.png', dpi=300)
    plt.close(fig)
    print('wrote overview')


if __name__ == '__main__':
    figure1(); figure2(); figure3(); figure4(); figure5(); figure6(); figure_blockG(); figure7(); figure8(); overview_figure()
