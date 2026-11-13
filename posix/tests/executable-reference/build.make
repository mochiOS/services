# Compatibility entry point. Run `mmake native-test-services` first.
ROOT ?= $(CURDIR)
SDK_METADATA ?= $(ROOT)/out/newlib-port/sdk/share/app-build.json
FIXTURE_TARGET ?= $(ROOT)/out/native-fixtures/target
.PHONY: all
all:
	python3 $(ROOT)/services/posix/tests/executable-reference/build.py --sdk-metadata "$(SDK_METADATA)" --target-directory "$(FIXTURE_TARGET)"
