#!/usr/bin/env bash
set -uo pipefail

ScriptDir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
Binary="$ScriptDir/FrostDumper"
SdkArchiveDir="$ScriptDir/sdk_archive"
LogDir="$ScriptDir/logs"
JoinScript="$ScriptDir/auto_join_match.py"
SteamAppId="1729320"
LaunchTimeout=120
MenuWait=90
MatchWait=180
DumpTimeout=300

Red='\e[31m'
Green='\e[32m'
Yellow='\e[33m'
Cyan='\e[36m'
Bold='\e[1m'
Reset='\e[0m'

mkdir -p "$SdkArchiveDir" "$LogDir"

StatusLine() {
    local State="$1"
    local Detail="${2:-}"
    local Ts
    Ts=$(date '+%H:%M:%S')
    printf "\r\e[K${Bold}[%s]${Reset} ${Cyan}%-20s${Reset} %s" "$Ts" "$State" "$Detail"
}

Log() {
    local Ts
    Ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${Green}[+]${Reset} [$Ts] $*"
}

Warn() {
    local Ts
    Ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${Yellow}[!]${Reset} [$Ts] $*"
}

Err() {
    local Ts
    Ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${Red}[-]${Reset} [$Ts] $*"
}

FindGamePid() {
    local Pid=""
    for P in $(pgrep "GameThread" 2>/dev/null); do
        if ! grep -q CrashReportClient "/proc/$P/cmdline" 2>/dev/null; then
            Pid="$P"
            break
        fi
    done
    if [[ -z "$Pid" ]]; then
        Pid=$(pgrep -f "PioneerGame.*Binaries|ARC-Win64-Ship|ARC-WinGDK-Ship" 2>/dev/null | head -1 || true)
    fi
    echo "$Pid"
}

LaunchGame() {
    Log "Launching ARC Raiders via Steam (AppID $SteamAppId)..."
    sudo -u "${SUDO_USER:-$USER}" steam "steam://rungameid/$SteamAppId" &>/dev/null &
    disown

    local Elapsed=0
    while [[ $Elapsed -lt $LaunchTimeout ]]; do
        StatusLine "LAUNCHING" "${Elapsed}s / ${LaunchTimeout}s"
        sleep 5
        Elapsed=$((Elapsed + 5))
        local Pid
        Pid=$(FindGamePid)
        if [[ -n "$Pid" ]]; then
            echo ""
            Log "Game process detected: PID $Pid"
            return 0
        fi
    done
    echo ""
    Err "Game did not start within ${LaunchTimeout}s"
    return 1
}

WaitForMenu() {
    Log "Waiting ${MenuWait}s for game to reach main menu..."
    local Elapsed=0
    while [[ $Elapsed -lt $MenuWait ]]; do
        StatusLine "WAIT_MENU" "${Elapsed}s / ${MenuWait}s"
        sleep 5
        Elapsed=$((Elapsed + 5))
        local Pid
        Pid=$(FindGamePid)
        if [[ -z "$Pid" ]]; then
            echo ""
            Err "Game crashed during menu load"
            return 1
        fi
    done
    echo ""
    Log "Menu wait complete"
    return 0
}

JoinMatch() {
    Log "Attempting to join practice range via auto_join_match.py..."
    if [[ ! -f "$JoinScript" ]]; then
        Warn "auto_join_match.py not found — skipping match join"
        Warn "Dumping in current state (main menu = ~37% naming)"
        return 0
    fi

    local JoinUser="${SUDO_USER:-$USER}"
    if sudo -u "$JoinUser" python3 "$JoinScript" --timeout "$MatchWait" 2>&1 | while IFS= read -r Line; do
        StatusLine "JOIN_MATCH" "$Line"
    done; then
        echo ""
        Log "Match join sequence completed"
        return 0
    else
        echo ""
        Warn "Match join failed — dumping in current state"
        return 0
    fi
}

WaitForMatch() {
    local GamePid="$1"
    Log "Checking if game is in-match (UWorld probe)..."

    local QuickDump
    QuickDump=$(timeout 30 "$Binary" "$GamePid" --probe-world 2>&1 || true)
    if echo "$QuickDump" | grep -q "UWorld.*valid\|in-match\|PersistentLevel"; then
        Log "Game is in-match (UWorld valid)"
        return 0
    else
        Warn "UWorld not available — game likely in main menu"
        Warn "Proceeding with dump anyway (37% naming rate expected)"
        return 0
    fi
}

BuildDumper() {
    StatusLine "BUILDING" "Compiling FrostDumper..."
    echo ""
    mkdir -p "$ScriptDir/build"
    local ZydisObj="$ScriptDir/build/Zydis.o"
    if [[ ! -f "$ZydisObj" ]] || [[ "$ScriptDir/zydis/Zydis.c" -nt "$ZydisObj" ]]; then
        gcc -O2 -fPIC -I"$ScriptDir/zydis" -c "$ScriptDir/zydis/Zydis.c" -o "$ZydisObj" || {
            Err "Zydis build failed"
            return 1
        }
    fi
    g++ -std=c++17 -O2 -march=native -mavx2 -msse4.1 \
        -I"$ScriptDir" -I"$ScriptDir/../KernelDriver/include" \
        -o "$Binary" "$ScriptDir/main.cpp" "$ZydisObj" \
        -lcapstone -lm || {
        Err "FrostDumper build failed"
        return 1
    }
    Log "FrostDumper built OK"
    return 0
}

RunDump() {
    local GamePid="$1"
    local Ts
    Ts=$(date '+%Y%m%d_%H%M%S')
    local LogFile="$LogDir/dump_${Ts}.log"

    Log "Running FrostDumper on PID $GamePid → $LogFile"

    if timeout "$DumpTimeout" "$Binary" "$GamePid" 2>&1 | tee "$LogFile" | while IFS= read -r Line; do
        CleanLine=$(echo "$Line" | tr -d '\r' | strings -a 2>/dev/null | head -1)
        if [[ -n "$CleanLine" ]]; then
            case "$CleanLine" in
                *"[autodisc]"*|*"[sig]"*|*"[fname]"*)
                    StatusLine "DISCOVERY" "${CleanLine:0:60}" ;;
                *"[scan]"*|*"valid="*)
                    StatusLine "SCANNING" "${CleanLine:0:60}" ;;
                *"[sdk]"*|*"Written"*)
                    StatusLine "SDK_GEN" "${CleanLine:0:60}" ;;
                *"[+]"*Classes*|*"[+]"*Properties*|*"[+]"*Enums*|*"[+]"*Functions*)
                    echo ""
                    Log "$CleanLine" ;;
                *"[type-hist]"*|*"[resolve]"*|*"[stats]"*)
                    echo ""
                    Log "$CleanLine" ;;
            esac
        fi
    done; then
        echo ""
        Log "Dump completed successfully"

        local ArchiveTs
        ArchiveTs=$(date '+%Y%m%d_%H%M%S')
        local ArchivePath="$SdkArchiveDir/sdk_$ArchiveTs"
        if [[ -d "$ScriptDir/sdk" ]]; then
            cp -r "$ScriptDir/sdk" "$ArchivePath"
            Log "SDK archived → $ArchivePath"
        fi
        if [[ -f "$ScriptDir/sdk/SDK_Output.txt" ]]; then
            cp "$ScriptDir/sdk/SDK_Output.txt" "$SdkArchiveDir/SDK_Output_${ArchiveTs}.txt"
        fi
        return 0
    else
        local Ex=$?
        echo ""
        if [[ $Ex -eq 124 ]]; then
            Err "Dump timed out after ${DumpTimeout}s"
        else
            Err "Dump failed with exit code $Ex"
        fi
        return 1
    fi
}

EnsureKmod() {
    if [[ -d "/sys/module/memreader" ]] && [[ -e "/dev/memreader" ]]; then
        return 0
    fi

    local KmodDir="$ScriptDir/../KernelDriver/src"
    if [[ "$KmodDir" == *" "* ]]; then
        Warn "Kmod dir has spaces — skipping kernel module (process_vm_readv fallback)"
        return 0
    fi
    if [[ ! -d "$KmodDir" ]]; then
        Warn "Kernel driver source not found — continuing without it"
        return 0
    fi
    make -C "$KmodDir" all 2>/dev/null && insmod "$KmodDir/memreader.ko" 2>/dev/null
    if [[ -e "/dev/memreader" ]]; then
        Log "Kernel module loaded"
    else
        Warn "Kernel module load failed — using process_vm_readv"
    fi
}

if [[ $EUID -ne 0 ]]; then
    Err "Must run as root: sudo $0"
    exit 1
fi

echo -e "${Bold}${Cyan}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   FrostSDKDumper — Auto Dump Loop        ║"
echo "  ║   Monitors game, auto-restarts on crash  ║"
echo "  ║   Ctrl+C to stop                         ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${Reset}"

LoopCount=0
while true; do
    LoopCount=$((LoopCount + 1))
    echo ""
    Log "═══ Loop iteration #$LoopCount ═══"

    EnsureKmod

    GamePid=$(FindGamePid)

    if [[ -z "$GamePid" ]]; then
        Warn "Game not running"
        if ! LaunchGame; then
            Err "Failed to launch game — retrying in 30s"
            sleep 30
            continue
        fi
        GamePid=$(FindGamePid)
        if [[ -z "$GamePid" ]]; then
            Err "Still no game PID after launch — retrying in 30s"
            sleep 30
            continue
        fi
        if ! WaitForMenu; then
            continue
        fi
        JoinMatch
        sleep 10
    fi

    GamePid=$(FindGamePid)
    if [[ -z "$GamePid" ]]; then
        Warn "Game disappeared — restarting loop"
        continue
    fi

    Log "Game PID: $GamePid"

    if ! BuildDumper; then
        Err "Build failed — fix errors and restart"
        sleep 60
        continue
    fi

    if ! RunDump "$GamePid"; then
        GamePid=$(FindGamePid)
        if [[ -z "$GamePid" ]]; then
            Warn "Game crashed during dump — restarting in 15s"
            sleep 15
            continue
        else
            Warn "Dump failed but game still running — retrying in 30s"
            sleep 30
            continue
        fi
    fi

    Log "Dump #$LoopCount complete — waiting 60s before next check"
    sleep 60

    GamePid=$(FindGamePid)
    if [[ -z "$GamePid" ]]; then
        Warn "Game exited after successful dump — will restart on next iteration"
    fi
done
