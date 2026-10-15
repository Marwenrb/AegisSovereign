PYTHON ?= python3

.PHONY: test verify doctor benchmark

test:
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

verify:
	$(PYTHON) verify_imports.py
	$(PYTHON) verify_config.py
	$(PYTHON) verify_unified.py

doctor:
	$(PYTHON) -m aegis_sovereign doctor

benchmark:
	$(PYTHON) -m aegis_sovereign benchmark -n 5000 --concurrency 16
