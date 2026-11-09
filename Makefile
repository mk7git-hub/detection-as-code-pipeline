.PHONY: test convert coverage all
test: ; pytest -q
convert: ; python scripts/convert.py
coverage: ; python scripts/coverage.py
all: test convert coverage
