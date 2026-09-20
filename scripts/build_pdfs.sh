#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [[ -f "$HERE/manuscript.tex" ]]; then cd "$HERE"; else cd "$HERE/../paper"; fi
# bibtex.original is available in some containers where a wrapper is absent.
BIBTEX="${BIBTEX:-bibtex}"
if ! command -v "$BIBTEX" >/dev/null 2>&1; then BIBTEX=bibtex.original; fi
for name in manuscript supplement; do
  pdflatex -interaction=nonstopmode -halt-on-error "$name.tex"
  "$BIBTEX" "$name"
  pdflatex -interaction=nonstopmode -halt-on-error "$name.tex"
  pdflatex -interaction=nonstopmode -halt-on-error "$name.tex"
done
