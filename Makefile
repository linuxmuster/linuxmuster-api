API_DIR = usr/lib/python3/dist-packages/linuxmusterApi
CREDENTIALS = $(API_DIR)/pytests/credentials.py

# The API ships its own interpreter; the system python3 has neither fastapi nor
# linuxmusterTools. Override on a machine where it lives somewhere else.
PYTHON ?= /opt/linuxmuster/bin/python3

all: build

deb:
	dpkg-buildpackage -rfakeroot -tc -sa -us -uc -I".gitignore" -I".git" -I".github" -I".idea" -I"docs"

# conftest.py imports pytests/credentials.py unconditionally, and that file is
# gitignored, so without this a fresh clone collects nothing at all: pytest aborts
# on the conftest import before it reaches even the tests that mock everything.
$(CREDENTIALS):
	cp $(API_DIR)/pytests/credentials.sample.py $@
	@echo "Created $@ from the sample. Fill in real users to run the integration tests."

test: $(CREDENTIALS)
	cd $(API_DIR) && $(PYTHON) -m pytest $(PYTEST_ARGS)

.PHONY: all deb test
