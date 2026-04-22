#!/usr/bin/env bash
# build_and_run.sh – Build the kernel module + FrostDumper, load kmod, and run.
# Usage: sudo ./build_and_run.sh [PID]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KMOD_DIR="$SCRIPT_DIR/kernel_module/src"
KMOD_NAME="memreader"
BINARY="$SCRIPT_DIR/FrostDumper"

# Split argv into a numeric PID (if any) + pass-through flags forwarded to the binary.
TARGET_PID=""
PASSTHROUGH_ARGS=()
for arg in "$@"; do
    if [[ "$arg" =~ ^[0-9]+$ ]] && [[ -z "$TARGET_PID" ]]; then
        TARGET_PID="$arg"
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done

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

    # The Linux kernel build system (Kbuild) does not handle spaces in module
    # source paths. Detect that and skip the kmod — the dumper falls back to
    # process_vm_readv which works for all non-VMProtect pages.
    if [[ "$KMOD_DIR" == *" "* ]]; then
        warn "KMOD_DIR contains spaces ('$KMOD_DIR'); Kbuild rejects such paths."
        warn "Skipping kernel module — falling back to process_vm_readv-only reads."
        warn "(Encrypted/VMProtect pages may be unreadable without the module.)"
        return
    fi

    if ! $mod_loaded; then
        info "Building kernel module in $KMOD_DIR ..."
        if ! make -C "$KMOD_DIR" all; then
            warn "Kernel module build failed — continuing without it."
            warn "The dumper will use process_vm_readv only."
            return
        fi
        info "Kernel module built: $KMOD_DIR/$KMOD_NAME.ko"

        info "Loading kernel module ..."
        if ! insmod "$KMOD_DIR/$KMOD_NAME.ko"; then
            warn "insmod failed — continuing without kernel module."
            return
        fi
    else
        warn "/sys/module/$KMOD_NAME exists but /dev/$KMOD_NAME missing – skipping insmod."
    fi

    if [[ ! -e "/dev/$KMOD_NAME" ]]; then
        warn "/dev/$KMOD_NAME does not exist after insmod — continuing without it."
        return
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
        -lcapstone -lunicorn -lm
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
    if [[ -f "$SCRIPT_DIR/probe_live_rvas.cpp" ]]; then
        g++ -std=c++17 -O2 -march=native \
            -I"$SCRIPT_DIR" \
            -o "$SCRIPT_DIR/probe_live_rvas" \
            "$SCRIPT_DIR/probe_live_rvas.cpp" -lm 2>/dev/null \
            && info "Probe tool built: probe_live_rvas" || warn "probe_live_rvas build skipped"
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

    # Try to find the ARC Raiders Wine process automatically. The binary does
    # its own /proc scan, but we resolve here too so the banner below shows a
    # concrete PID. Unreal Engine names its main thread "GameThread" via prctl.
    local found
    # GameThread-named PIDs can include CrashReportClient.exe (UE's crash
    # uploader — same thread name, wrong binary). Filter those out by
    # rejecting any PID whose /proc/pid/cmdline contains CrashReportClient.
    found=""
    for pid in $(pgrep "GameThread" 2>/dev/null); do
        if ! grep -q CrashReportClient "/proc/$pid/cmdline" 2>/dev/null; then
            found="$pid"
            break
        fi
    done
    if [[ -z "$found" ]]; then
        found=$(pgrep -f "PioneerGame.*Binaries|ARC-Win64-Ship|ARC-WinGDK-Ship|ARC-WinGDK" 2>/dev/null | head -1 || true)
    fi
    if [[ -n "$found" ]]; then
        TARGET_PID="$found"
        info "Auto-detected game PID: $TARGET_PID"
    else
        warn "Could not auto-detect game PID. Binary will self-detect or exit."
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
echo "  Target PID : ${TARGET_PID:-<auto>}"
echo "  Flags      : ${PASSTHROUGH_ARGS[*]:-<none>}"
echo "======================================"
echo ""

if [[ -n "$TARGET_PID" ]]; then
    exec "$BINARY" "$TARGET_PID" "${PASSTHROUGH_ARGS[@]}"
else
    exec "$BINARY" "${PASSTHROUGH_ARGS[@]}"
fi
