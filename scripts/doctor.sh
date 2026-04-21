#!/usr/bin/env bash
# claw doctor — diagnostic smoke test. Run before filing a crash report.
#
# Checks:
#   1. release binary is newer than HEAD commit
#   2. ~/.local/bin/claw points to release binary
#   3. Ollama is reachable
#   4. claw-code:latest exists and is tagged with num_ctx / no thinking=false
#   5. VRAM headroom for a cold load
#   6. Tool-learning store is writable
set -u

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { printf "${GREEN}[ok]${NC}    %s\n" "$1"; }
warn() { printf "${YELLOW}[warn]${NC}  %s\n" "$1"; }
fail() { printf "${RED}[fail]${NC}  %s\n" "$1"; fails=$((fails+1)); }
fails=0

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
release_bin="$repo_root/rust/target/release/claw"
symlink="$HOME/.local/bin/claw"

# 1. Binary vs HEAD
if [[ ! -x "$release_bin" ]]; then
    fail "release binary missing — run 'make release'"
else
    bin_mtime=$(stat -c %Y "$release_bin")
    head_time=$(cd "$repo_root" && git log -1 --format=%ct rust/ 2>/dev/null || echo 0)
    if (( bin_mtime < head_time )); then
        fail "release binary older than last rust/ commit — run 'make install'"
    else
        pass "release binary is fresh"
    fi
fi

# 2. Symlink
if [[ -L "$symlink" ]]; then
    target=$(readlink -f "$symlink")
    if [[ "$target" == "$(readlink -f "$release_bin")" ]]; then
        pass "symlink $symlink → release binary"
    else
        warn "symlink points to $target (expected $release_bin)"
    fi
else
    fail "symlink $symlink missing — run 'make install'"
fi

# 3. Ollama reachable
if curl -fsS -m 3 http://localhost:11434/api/tags >/dev/null 2>&1; then
    pass "Ollama reachable on localhost:11434"
else
    fail "Ollama unreachable — systemctl status ollama"
fi

# 4. Model config
if ollama show claw-code:latest >/tmp/.claw_doctor_model 2>/dev/null; then
    num_ctx=$(grep -Eo 'num_ctx\s+[0-9]+' /tmp/.claw_doctor_model | awk '{print $2}')
    if [[ -n "$num_ctx" && "$num_ctx" -ge 32768 ]]; then
        pass "claw-code:latest num_ctx=$num_ctx"
    else
        warn "claw-code:latest num_ctx=${num_ctx:-unset} (want ≥32768)"
    fi
    if grep -q 'thinking false' /tmp/.claw_doctor_model; then
        fail "modelfile has thinking=false — causes runner restarts on Qwen3.5"
    else
        pass "no thinking=false override"
    fi
    rm -f /tmp/.claw_doctor_model
else
    fail "claw-code:latest not found — run 'make model'"
fi

# 5. VRAM headroom
if command -v nvidia-smi >/dev/null; then
    free_mib=$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits | head -1)
    if (( free_mib >= 18000 )); then
        pass "GPU free: ${free_mib} MiB"
    else
        warn "GPU free: ${free_mib} MiB (claw-code wants ~18 GB free to cold-load)"
    fi
fi

# 6. Tool-learning store
tls="$HOME/.local/share/claw/tool_outcomes.jsonl"
mkdir -p "$(dirname "$tls")" 2>/dev/null
if touch "$tls" 2>/dev/null; then
    lines=$(wc -l <"$tls" 2>/dev/null || echo 0)
    pass "tool_outcomes.jsonl writable ($lines lines)"
else
    fail "cannot write $tls"
fi

echo
if (( fails > 0 )); then
    printf "${RED}%d check(s) failed${NC}\n" "$fails"
    exit 1
fi
printf "${GREEN}all checks passed${NC}\n"
