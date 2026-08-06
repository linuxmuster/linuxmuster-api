API_DIR = usr/lib/python3/dist-packages/linuxmusterApi

# The API ships its own interpreter; the system python3 has neither fastapi nor
# linuxmusterTools. Override on a machine where it lives somewhere else.
PYTHON ?= /opt/linuxmuster/bin/python3

all: build

deb:
	dpkg-buildpackage -rfakeroot -tc -sa -us -uc -I".gitignore" -I".git" -I".github" -I".idea" -I"docs"

test:
	cd $(API_DIR) && $(PYTHON) -m pytest $(PYTEST_ARGS)

.PHONY: all deb test
