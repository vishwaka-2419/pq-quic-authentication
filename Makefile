SHELL := /bin/bash
PY ?= python3
CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra
EXP := 03_reproducibility/experiment
OPENSSL_FLAGS := $(shell pkg-config --cflags --libs openssl 2>/dev/null)

.PHONY: all analyze figures tables verify build-probe build-probe-prefix
all:
	$(PY) reproduce.py all
analyze:
	$(PY) reproduce.py analyze
figures:
	$(PY) reproduce.py figures
tables:
	$(PY) reproduce.py tables
verify:
	$(PY) reproduce.py verify
build-probe:
	mkdir -p $(EXP)/bin
	$(CC) $(CFLAGS) $(EXP)/src/quic_probe.c -o $(EXP)/bin/quic_probe $(OPENSSL_FLAGS)
build-probe-prefix:
	mkdir -p $(EXP)/bin
	$(CC) $(CFLAGS) $(EXP)/src/quic_probe.c -o $(EXP)/bin/quic_probe_$(SUFFIX) -I$(PREFIX)/include -L$(PREFIX)/lib -Wl,-rpath,$(PREFIX)/lib -lssl -lcrypto
