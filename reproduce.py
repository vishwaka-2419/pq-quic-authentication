#!/usr/bin/env python3
"""Install verified inputs and reproduce the retained QUIC measurements."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent
EXPERIMENT = ROOT / '03_reproducibility' / 'experiment'
DATA = ROOT / '03_reproducibility' / 'data'
RESULTS = ROOT / 'results'
DATA_MANIFEST = 'DATASET_SHA256SUMS.txt'
CODE_MANIFEST = 'CODE_SHA256SUMS.txt'


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def safe_path(name: str) -> Path:
    p = PurePosixPath(name.removeprefix('./'))
    if p.is_absolute() or '..' in p.parts or not p.parts or '\\' in name or ':' in name:
        raise ValueError(f'Unsafe dataset path: {name!r}')
    destination = ROOT.joinpath(*p.parts)
    if not destination.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError(f'Dataset path leaves the repository: {name!r}')
    return destination


def parse_manifest(text: str) -> dict[str, str]:
    entries = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, name = line.split('  ', 1)
        if not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Invalid SHA-256 manifest entry')
        name = safe_path(name).relative_to(ROOT).as_posix()
        if name in entries:
            raise ValueError(f'Duplicate manifest path: {name}')
        entries[name] = digest
    return entries


def verify_manifest(name: str) -> int:
    path = ROOT / name
    if not path.is_file():
        raise FileNotFoundError(f'{name} is missing. Install the dataset first using the unpack command.')
    entries = parse_manifest(path.read_text(encoding='utf-8'))
    bad = [rel for rel, expected in entries.items()
           if not safe_path(rel).is_file() or sha256(safe_path(rel)) != expected]
    if bad:
        raise ValueError(f'{len(bad)} missing or changed files in {name}: ' + ', '.join(bad[:5]))
    print(f'Verified {len(entries)} files against {name}', flush=True)
    return len(entries)


def configuration() -> dict:
    return json.loads((ROOT / 'dataset.json').read_text(encoding='utf-8'))


def unpack(archive: Path) -> None:
    cfg = configuration()
    if sha256(archive) != cfg['archive_sha256']:
        raise ValueError('Dataset archive SHA-256 does not match dataset.json. No files were installed.')
    with zipfile.ZipFile(archive) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        names = [i.filename for i in infos]
        if len(names) != len(set(names)):
            raise ValueError('Dataset archive contains duplicate members')
        entries = parse_manifest(z.read(DATA_MANIFEST).decode('utf-8'))
        if set(names) != set(entries) | {DATA_MANIFEST}:
            raise ValueError('Dataset archive members do not match its integrity manifest')
        for info in infos:
            target = safe_path(info.filename)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError('Symbolic links are not accepted in dataset archives')
            if info.filename not in {DATA_MANIFEST, 'DATASET_README.md'} and not info.filename.startswith((
                    '03_reproducibility/', '05_upstream_archive/', '06_experiment_protocols/')):
                raise ValueError(f'Unexpected dataset destination: {info.filename}')
            if target.is_file() and info.filename in entries and sha256(target) != entries[info.filename]:
                raise ValueError(f'Existing input differs: {info.filename}. Use a fresh code directory.')
        for info in infos:
            target = safe_path(info.filename)
            if target.is_file() and info.filename in entries:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, target.open('wb') as dst:
                shutil.copyfileobj(src, dst)
    verify_manifest(DATA_MANIFEST)


def fetch() -> None:
    cfg = configuration()
    doi = cfg.get('dataset_doi') or ''
    match = re.fullmatch(r'(?:https://doi\.org/)?10\.5281/zenodo\.(\d+)', doi.strip())
    if not match:
        raise ValueError('Set dataset_doi in dataset.json to the published Zenodo DOI, or use unpack with the local ZIP.')
    request = urllib.request.Request('https://zenodo.org/api/records/' + match.group(1),
                                     headers={'User-Agent': 'pq-quic-authentication/2.0.0'})
    with urllib.request.urlopen(request, timeout=60) as response:
        record = json.load(response)
    entries = [f for f in record['files'] if (f.get('key') or f.get('filename')) == cfg['archive_filename']]
    if len(entries) != 1:
        raise ValueError('The published record does not contain the expected dataset archive filename')
    links = entries[0]['links']
    url = links.get('self') or links.get('download')
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in {'zenodo.org', 'www.zenodo.org'}:
        raise ValueError('Unexpected dataset download host')
    downloads = ROOT / 'downloads'
    downloads.mkdir(exist_ok=True)
    target = downloads / cfg['archive_filename']
    partial = target.with_suffix(target.suffix + '.part')
    with urllib.request.urlopen(url, timeout=60) as src, partial.open('wb') as dst:
        shutil.copyfileobj(src, dst)
    if sha256(partial) != cfg['archive_sha256']:
        partial.unlink(missing_ok=True)
        raise ValueError('Downloaded dataset checksum differs from dataset.json')
    partial.replace(target)
    unpack(target)


def run_script(relative: str, log) -> None:
    print(f'Running {relative}', flush=True)
    log.write('\n### ' + relative + '\n')
    log.flush()
    env = dict(__import__('os').environ)
    env['MPLBACKEND'] = 'Agg'
    result = subprocess.run([sys.executable, str(ROOT / relative)], cwd=ROOT,
                            stdout=log, stderr=subprocess.STDOUT, env=env)
    if result.returncode:
        raise RuntimeError(f'{relative} failed; inspect results/reproduce.log')


def analyze(log) -> None:
    (EXPERIMENT / 'analysis').mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)
    for block in ('a', 'c', 'f', 'g'):
        run_script(f'03_reproducibility/experiment/scripts/analyze_block_{block}.py', log)
    for item in (EXPERIMENT / 'analysis').glob('block_*'):
        if item.is_file() and item.suffix in {'.csv', '.json'}:
            shutil.copy2(item, DATA / item.name)
    for item in (EXPERIMENT / 'analysis').glob('preregistration_*.json'):
        shutil.copy2(item, DATA / item.name)
    for name in ('extract_qlog_features.py', 'extract_wave_accounting.py', 'derive_archived_tables.py'):
        run_script('03_reproducibility/scripts/' + name, log)
    run_script('03_reproducibility/tests/check_headlines.py', log)
    print('Analysis and 104 numerical/integrity checks completed.', flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('unpack', help='verify and install a locally downloaded dataset ZIP')
    p.add_argument('archive', type=Path)
    sub.add_parser('fetch', help='download and verify the dataset DOI specified in dataset.json')
    sub.add_parser('verify', help='verify code and installed dataset bytes')
    sub.add_parser('analyze', help='re-derive numerical results and run the 104 checks')
    sub.add_parser('figures', help='generate figures locally after analyze')
    sub.add_parser('tables', help='generate table fragments locally after analyze')
    sub.add_parser('all', help='analyze, validate and generate local figures and table fragments')
    args = parser.parse_args()
    verify_manifest(CODE_MANIFEST)
    if args.command == 'unpack':
        unpack(args.archive.expanduser().resolve())
        return
    if args.command == 'fetch':
        fetch()
        return
    verify_manifest(DATA_MANIFEST)
    if args.command == 'verify':
        return
    if sys.version_info < (3, 12):
        raise RuntimeError('Python 3.12 or newer is required for the analysis and output generators.')
    RESULTS.mkdir(exist_ok=True)
    with (RESULTS / 'reproduce.log').open('a', encoding='utf-8') as log:
        if args.command in {'analyze', 'all'}:
            analyze(log)
        if args.command in {'figures', 'all'}:
            run_script('03_reproducibility/scripts/make_figures.py', log)
        if args.command in {'tables', 'all'}:
            run_script('03_reproducibility/scripts/make_tables.py', log)
    print('Finished. Numerical outputs: 03_reproducibility/data/. Optional outputs: results/.', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile) as error:
        print(f'Error: {error}', file=sys.stderr)
        sys.exit(1)
