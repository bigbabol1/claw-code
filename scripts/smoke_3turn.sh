#!/usr/bin/env bash
# 3-turn smoke test — exercises multi-turn stability, tool call, recovery path.
# Expects `claw` on PATH (via `make install`) and Ollama running claw-code:latest.
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
pass() { printf "${GREEN}[ok]${NC}    %s\n" "$1"; }
fail() { printf "${RED}[fail]${NC}  %s\n" "$1"; exit 1; }

command -v claw >/dev/null || fail "claw not on PATH — run 'make install'"
curl -fsS -m 3 http://localhost:11434/api/tags >/dev/null 2>&1 \
    || fail "Ollama unreachable"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

run_turn() {
    local label="$1" prompt="$2"
    local out
    if ! out=$(printf '%s\n' "$prompt" | timeout 120 claw -p 2>&1); then
        printf '%s\n' "$out" | tail -20
        fail "turn '$label' non-zero exit"
    fi
    if [[ -z "$out" ]]; then
        fail "turn '$label' produced empty output"
    fi
    pass "turn '$label' ok ($(wc -c <<<"$out") bytes)"
}

run_turn "hello"        "Respond with exactly the single word OK."
run_turn "tool-write"   "Create a file smoke.txt with content 'hi'. Then confirm."
run_turn "tool-read"    "Read smoke.txt and tell me its contents."

# Check crash dumps didn't accumulate
crash_dir="$HOME/.local/share/claw/crashes"
if [[ -d "$crash_dir" ]]; then
    recent=$(find "$crash_dir" -type f -newermt "1 minute ago" 2>/dev/null | wc -l)
    if (( recent > 0 )); then
        fail "$recent crash dump(s) produced during smoke run"
    fi
fi
pass "no crash dumps emitted"

printf "${GREEN}smoke 3-turn OK${NC}\n"
