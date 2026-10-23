PY ?= python3

.PHONY: test collect proof site cle audit

test:  ## run the unit tests
	$(PY) -m unittest discover -q -s tests

collect:  ## fetch all sources, write today's snapshot and change log to data/
	$(PY) -m supportdates collect --data data

proof:  ## extend and verify the hash chain (local only)
	$(PY) -m supportdates.proof --data data --verify

site:  ## render the static site and API to site/
	$(PY) -m supportdates site --data data --out site

cle:  ## write ECMA-428 CLE documents
	$(PY) -m supportdates.cle --data data --out site/cle

audit:  ## self-audit 30 random records against the live sources
	$(PY) -m supportdates.audit --data data --n 30
