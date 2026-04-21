# claw-code build + deploy discipline
#
# The `claw` binary is symlinked from ~/.local/bin/claw → target/release/claw.
# A stale debug build used to masquerade as a crash (diary 2026-04-19) — always
# rebuild via `make install` after touching runtime code, never hand-link.

CARGO := cargo
RUST_DIR := rust
BIN := $(RUST_DIR)/target/release/claw
SYMLINK := $(HOME)/.local/bin/claw
MODELFILE := ollama/Modelfile.claw-code

.PHONY: all build test release install model doctor clean push smoke

all: release

build:
	cd $(RUST_DIR) && $(CARGO) build --workspace

test:
	cd $(RUST_DIR) && $(CARGO) test --workspace

release:
	cd $(RUST_DIR) && $(CARGO) build --release

install: release
	@mkdir -p $(dir $(SYMLINK))
	@ln -sfn $(abspath $(BIN)) $(SYMLINK)
	@echo "linked $(SYMLINK) → $(abspath $(BIN))"
	@$(BIN) --version

model:
	ollama create claw-code:latest -f $(MODELFILE)
	@ollama show claw-code:latest | grep -E 'num_ctx|context length'

smoke: install model
	@echo "-- smoke: 1-turn sanity check --"
	@curl -fsS http://localhost:11434/api/generate \
	    -d '{"model":"claw-code:latest","prompt":"respond with the single token OK","stream":false}' \
	    | grep -q '"done":true' && echo "OK"

doctor:
	@./scripts/doctor.sh 2>/dev/null || echo "doctor script not yet installed"

push:
	git push origin main

clean:
	cd $(RUST_DIR) && $(CARGO) clean
