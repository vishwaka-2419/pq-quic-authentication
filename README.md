# Post-quantum QUIC authentication

Reproducibility code for certificate-authentication experiments in native OpenSSL QUIC, using
ECDSA P-256 and ML-DSA-44, ML-DSA-65 and ML-DSA-87. The analysis measures UDP and TLS bytes,
the amplification allowance, the initial congestion window, handshake latency and first-round
completion under different certificate and client-credit configurations.

Version: **2.0.0**. Repository: https://github.com/vishwaka-2419/pq-quic-authentication.

## What is included

- A C measurement probe and Python experiment runners.
- Certificate-generation, analysis, byte-accounting and result-validation scripts.
- Optional generators for local plots and numerical table fragments.
- A Python entry point, dependency list, build instructions and code checksums.

The input dataset is distributed separately through Zenodo. Its version, filename and exact ZIP
checksum are recorded in `dataset.json`. The DOI field is empty until the deposit is published.
No dataset or precomputed result files are stored in this repository.

## Dataset

The dataset contains raw observations for **1,830 new connections** (Blocks A, C, F, G and Gc),
the **3,630-attempt archived input ledger**, certificate fixtures, experiment designs and original
environment records. Original packet traces for the archived campaign are not included; that
campaign is reproduced from its normalized ledger. Server qlogs support the qlog-based analysis;
client qlogs can be empty or truncated. All certificate identities and keys are local test fixtures.

## Reproduce from a downloaded dataset

Use **Python 3.12**, the tested runtime. The reanalysis requires NumPy, pandas, SciPy and Matplotlib,
with the tested versions pinned in `requirements.txt`.
It does not require an OpenSSL installation or a compiler. From the code directory:

```text
python -m pip install -r requirements.txt
python reproduce.py unpack /path/to/pq-quic-authentication-v2.0.0-data.zip
python reproduce.py analyze
```

The unpack step verifies the ZIP checksum and the per-file dataset manifest before analysis.
The analysis re-derives the trial records, statistical summaries, qlog features, wave accounting
and archived comparisons, then runs **104 numerical, raw-file and protocol-integrity checks**.
The measured input bytes are never rewritten. Derived CSV and JSON files are written under
`03_reproducibility/experiment/analysis/` and `03_reproducibility/data/`. Logs go to
`results/reproduce.log`. These locations are ignored by Git.

To regenerate plots and table fragments locally after analysis:

```text
python reproduce.py figures
python reproduce.py tables
```

These optional outputs go to `results/figures/` and `results/tables/`. No LaTeX installation is
needed to generate them. `python reproduce.py all` runs the numerical analysis, validation and
both optional output generators. `python reproduce.py verify` checks the retained code and inputs.

Once the dataset DOI is present in `dataset.json`, `python reproduce.py fetch` downloads,
checks and installs the matching ZIP. Manual download and `unpack` work without a DOI.

## Code layout

| Path | Purpose |
|---|---|
| `reproduce.py` | Verified input installation and analysis entry point. |
| `dataset.json` | Dataset DOI, archive name and SHA-256. |
| `03_reproducibility/experiment/src/quic_probe.c` | Native OpenSSL QUIC client/server probe. |
| `03_reproducibility/experiment/scripts/` | Experiment runners, certificate generation and block analyzers. |
| `03_reproducibility/scripts/` | Archived-data derivation, qlog/wave accounting and optional output generators. |
| `03_reproducibility/tests/check_headlines.py` | The 104 numerical and integrity checks. |
| `CODE_SHA256SUMS.txt` | Checksums of executable source, requirements and Makefile. |

The existing relative directory names are retained for compatibility with the recorded experiments.
Downloaded dataset directories are created only when the input archive is installed.

## Run new measurements

New measurements require Linux, a C compiler, pkg-config, an OpenSSL 3.5.x build with native QUIC,
ML-DSA and X25519MLKEM768, and qlog support (`enable-unstable-qlog`). The recorded experiments
used OpenSSL 3.5.5 and 3.5.9. CPU-affinity choices and OpenSSL build details are recorded with the dataset.

After installing the dataset fixtures, build the probe against the system OpenSSL:

```text
make build-probe
python 03_reproducibility/experiment/scripts/run_block_a.py --output rerun/block_a
```

For a separate OpenSSL installation:

```text
make build-probe-prefix PREFIX=/opt/openssl-3.5.9 SUFFIX=3.5.9
python 03_reproducibility/experiment/scripts/run_block_g.py --output rerun/block_g --probe 03_reproducibility/experiment/bin/quic_probe_3.5.9 --cpus 0,1,-
```

The runners bind loopback endpoints. Run fresh measurements into a separate output directory.
The packaged analyzers target the archived dataset; point a separate analysis copy at new outputs
when analyzing a new campaign. New timing values will vary with platform and scheduling.

## Reproducibility and versioning

The original probe and experiment runners are retained byte for byte. The analysis formulas and
statistical procedures are preserved. Validation checks concern numerical results, raw-directory
completeness and original protocol hashes. The G control addendum in the dataset explains the
later control-run extension to its runner. The v1.0.0 tag remains the archived code snapshot.

Qlog feature extraction selects the server log matching the recorded connection ID, using the same
selector as wave accounting. Three trial directories contain an additional server log; selecting the
correct connection removes a filesystem-order dependency in their diagnostic first-CRYPTO
timestamps. The padded-ACK counts, byte counts and reported analysis outcomes are unchanged.

Code hashes exclude editable release metadata, so inserting the real dataset DOI into
`dataset.json` or updating this README does not invalidate source verification. The dataset ZIP
hash must remain unchanged when its DOI is added.

## License and citation

Code: MIT License, see `LICENSE`. Dataset: CC BY 4.0, described in the dataset README.
Use `CITATION.cff` for software attribution and cite the version-specific dataset DOI separately.
