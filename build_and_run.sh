#!/usr/bin/env bash
# build_and_run.sh – Build the kernel module + FrostDumper, load kmod, and run.
# Usage: sudo ./build_and_run.sh [PID]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KMOD_DIR="$SCRIPT_DIR/kernel_module/src"
KMOD_NAME="memreader"
BINARY="$SCRIPT_DIR/FrostDumper"
TARGET_PID="${1:-}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { echo -e "\e[32m[+]\e[0m $*"; }
warn()  { echo -e "\e[33m[!]\e[0m $*"; }
error() { echo -e "\e[31m[-]\e[0m $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || error "This script must be run as root (sudo $0 $*)."
}

# ---------------------------------------------------------------------------
# 1. Build + load kernel module (skipped entirely if already attached)
# ---------------------------------------------------------------------------
ensure_kmod() {
    # /sys/module/<name> is the canonical kernel-maintained indicator
    local sysmod="/sys/module/${KMOD_NAME}"
    local mod_loaded=false dev_exists=false
    [[ -d "$sysmod" ]]             && mod_loaded=true
    [[ -e "/dev/$KMOD_NAME" ]]     && dev_exists=true

    if $mod_loaded && $dev_exists; then
        info "Kernel module '$KMOD_NAME' already loaded – skipping build & insmod."
        return
    fi

    if ! $mod_loaded; then
        info "Building kernel module in $KMOD_DIR ..."
        make -C "$KMOD_DIR" all
        info "Kernel module built: $KMOD_DIR/$KMOD_NAME.ko"

        info "Loading kernel module ..."
        insmod "$KMOD_DIR/$KMOD_NAME.ko"
    else
        warn "/sys/module/$KMOD_NAME exists but /dev/$KMOD_NAME missing – skipping insmod."
    fi

    if [[ ! -e "/dev/$KMOD_NAME" ]]; then
        error "/dev/$KMOD_NAME does not exist after insmod. Check dmesg."
    fi
    info "Module ready – /dev/$KMOD_NAME OK."
}

# ---------------------------------------------------------------------------
# 3. Build FrostDumper binary (and optional probe tools)
# ---------------------------------------------------------------------------
build_dumper() {
    info "Building FrostDumper ..."
    g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 \
        -I"$SCRIPT_DIR" \
        -o "$BINARY" \
        "$SCRIPT_DIR/main.cpp" \
        -lm
    info "Binary built: $BINARY"

    # Also build probe tools (best-effort, not fatal)
    if [[ -f "$SCRIPT_DIR/probe_subprop.cpp" ]]; then
        g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 \
            -I"$SCRIPT_DIR" \
            -o "$SCRIPT_DIR/probe_subprop" \
            "$SCRIPT_DIR/probe_subprop.cpp" -lm 2>/dev/null \
            && info "Probe tool built: probe_subprop" || warn "probe_subprop build skipped"
    fi
    if [[ -f "$SCRIPT_DIR/probe_next.cpp" ]]; then
        g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 \
            -I"$SCRIPT_DIR" \
            -o "$SCRIPT_DIR/probe_next" \
            "$SCRIPT_DIR/probe_next.cpp" -lm 2>/dev/null \
            && info "Probe tool built: probe_next" || warn "probe_next build skipped"
    fi
}

# ---------------------------------------------------------------------------
# 4. Resolve target PID if not supplied
# ---------------------------------------------------------------------------
resolve_pid() {
    if [[ -n "$TARGET_PID" ]]; then
        info "Using supplied PID: $TARGET_PID"
        return
    fi

    # Try to find the ARC Raiders Wine process automatically.
    # Unreal Engine names its main thread "GameThread" via prctl, so search by
    # comm first (avoids matching wrapper shell scripts with the game exe in argv).
    local found
    found=$(pgrep "GameThread" 2>/dev/null | head -1 || true)
    if [[ -z "$found" ]]; then
        # Fallback for other naming conventions (older builds, custom runners)
        found=$(pgrep -f "PioneerGame.*Binaries|ARC-Win64-Ship|ARC-WinGDK-Ship|ARC-WinGDK" 2>/dev/null | head -1 || true)
    fi
    if [[ -n "$found" ]]; then
        TARGET_PID="$found"
        info "Auto-detected game PID: $TARGET_PID"
    else
        warn "Could not auto-detect game PID."
        warn "Run as: sudo $0 <PID> to specify manually."
        error "Could not find ARC Raiders process. Is the game running?"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
require_root "$@"

ensure_kmod
build_dumper
resolve_pid

echo ""
echo "======================================"
echo "  FrostDumper – ARC Raiders SDK Dump"
echo "  March 2026 patch"
echo "  Target PID : $TARGET_PID"
echo "======================================"
echo ""

exec "$BINARY" "$TARGET_PID"
