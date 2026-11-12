# Run from the mochiOS workspace root. RUST_SDK must contain the new runtime.
ROOT ?= $(CURDIR)
OUT ?= $(ROOT)/out
JOBS ?= 2
include $(ROOT)/build/mmake/toolchain.mk
.PHONY: all
all:
	@$(MOCHIOS_CARGO) --manifest-path $(ROOT)/services/Cargo.toml --package capability --package user-service --bins
	@$(MOCHIOS_CARGO) --manifest-path $(ROOT)/services/Cargo.toml --package service-manager --bin service-manager --features native-executable-reference-probe
	@$(MOCHIOS_CARGO) --manifest-path $(ROOT)/services/posix/tests/executable-reference/Cargo.toml --bins
