"""Locate UObject::ProcessEvent by observing a live BP callsite.

WARNING (2026-09-12): tested against ARC Raiders v20260908 running under
Proton/Wine — HWBP EXEC on `.text` pages does NOT fire. Wine maps the
game's executable from `/memfd:wine-mapping` as `MAP_SHARED r-xs` and
the per-CPU DR registers are silently inert on that mapping (same class
of failure as uprobes, documented in the project CLAUDE.md). See
`docs/v908_ida_reference.md ## UObject::ProcessEvent (v908) # Dynamic
resolve attempt` for the confirming test. This script only works on a
build where the game runs natively OR on a kernel where MAP_SHARED HWBP
delivery works. Kept in-tree as a reference implementation.


Dynamic resolve for v20260908/CL-1372005 — Theia stripped every static anchor
string (see docs/v908_ida_reference.md ## UObject::ProcessEvent). The path
that survives is: whenever a UFunction with FUNC_Native (0x400) fires, the
call comes from ProcessEvent's dispatch tail via
    call qword ptr [rax + <NativeFunc off>]
so the return address on the top of the stack at the moment of the call
sits inside ProcessEvent, a few bytes after the CALL instruction. Walking
the return address backwards to the containing function prologue yields
the RVA.

Usage:
    sudo python3 tools/find_processevent.py <pid> <native_func_va>

Both arguments are decimal or 0x-prefixed hex. `native_func_va` is an
absolute VA (image_base + RVA) of any UFunction's NativeFunc pointer that
you know gets called at runtime — e.g. a Blueprint-callable UFunction on
an object that Ticks or is invoked from a UI button.

The tool sets a HWBP EXEC on that address, waits up to WAIT_SECONDS for the
BP to fire, then reads [rsp] to get the ProcessEvent return address, and
scans backwards for a plausible function prologue.

Requires /dev/memreader.
"""

import ctypes
import fcntl
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, MemreaderReadRequest, _IOC, _IOC_READ, _IOC_WRITE  # noqa

_MAGIC = 'M'


class HwbpRequest(ctypes.Structure):
    _fields_ = [
        ("pid",     ctypes.c_int),
        ("bp_num",  ctypes.c_int),
        ("address", ctypes.c_ulong),
        ("type",    ctypes.c_int),
        ("len",     ctypes.c_int),
    ]


class BpHitInfo(ctypes.Structure):
    _fields_ = [
        ("pid",         ctypes.c_int),
        ("hit",         ctypes.c_int),
        ("bp_num",      ctypes.c_int),
        ("rip",         ctypes.c_ulong),
        ("rsp",         ctypes.c_ulong),
        ("fault_addr",  ctypes.c_ulong),
        ("dr6",         ctypes.c_ulong),
        ("timestamp",   ctypes.c_ulong),
    ]


_SET_HWBP     = _IOC(_IOC_WRITE,          _MAGIC, 10, ctypes.sizeof(HwbpRequest))
_CLEAR_HWBP   = _IOC(_IOC_WRITE,          _MAGIC, 11, ctypes.sizeof(HwbpRequest))
_GET_BP_HIT   = _IOC(_IOC_READ | _IOC_WRITE, _MAGIC, 12, ctypes.sizeof(BpHitInfo))
_CLEAR_BP_HIT = _IOC(_IOC_WRITE,          _MAGIC, 13, ctypes.sizeof(BpHitInfo))

HWBP_TYPE_EXEC = 0
HWBP_LEN_1     = 0

IMAGE_BASE   = 0x140000000
IMAGE_SIZE   = 0x14091000
WAIT_SECONDS = 60
SCAN_BACK    = 0x4000    # ProcessEvent bodies are large; scan up to 16 KiB back


def set_hwbp(fd, pid, address, bp_num=0):
    req = HwbpRequest(pid=pid, bp_num=bp_num, address=address,
                      type=HWBP_TYPE_EXEC, len=HWBP_LEN_1)
    fcntl.ioctl(fd, _SET_HWBP, req)


def clear_hwbp(fd, pid, bp_num=0):
    req = HwbpRequest(pid=pid, bp_num=bp_num, address=0,
                      type=HWBP_TYPE_EXEC, len=HWBP_LEN_1)
    fcntl.ioctl(fd, _CLEAR_HWBP, req)


def get_bp_hit(fd, pid):
    info = BpHitInfo(pid=pid)
    fcntl.ioctl(fd, _GET_BP_HIT, info)
    return info


def clear_bp_hit(fd, pid):
    info = BpHitInfo(pid=pid)
    fcntl.ioctl(fd, _CLEAR_BP_HIT, info)


def find_prologue(mr: MemReader, ret_addr: int, back: int = SCAN_BACK) -> int:
    """Scan backwards from `ret_addr` for a plausible function prologue.

    UE ProcessEvent has a huge stack frame (>= 0x400 bytes) preceded by a
    push-rbp/push r15..r12/push rbx sequence and INT3-padded from the
    previous function. Look for exactly that.
    """
    start = ret_addr - back
    try:
        blob = mr.read(start, back)
    except OSError:
        return 0

    # Prologue signature: (0x48 0x83 0xEC imm8) OR (0x48 0x81 0xEC imm32)
    # with imm >= 0x400, preceded (within 32 bytes above) by at least two
    # `push r64` opcodes (0x50-0x57, or 0x41 0x54-0x57 for R12-R15) and by
    # INT3 padding just above the first push.
    candidates = []
    for i in range(64, back - 8):
        # 48 83 EC imm8
        if blob[i] == 0x48 and blob[i + 1] == 0x83 and blob[i + 2] == 0xEC:
            imm = blob[i + 3]
            if imm < 0x40:
                continue
            insn_va = start + i
            candidates.append((insn_va, imm, 4))
        # 48 81 EC imm32
        elif blob[i] == 0x48 and blob[i + 1] == 0x81 and blob[i + 2] == 0xEC:
            imm = struct.unpack("<I", blob[i + 3:i + 7])[0]
            if imm < 0x400:
                continue
            insn_va = start + i
            candidates.append((insn_va, imm, 7))

    # Prefer the closest sub-rsp to ret_addr whose imm is largest (PE frame is huge).
    if not candidates:
        return 0
    candidates.sort(key=lambda t: (-t[1], t[0]))
    sub_rsp_va = candidates[0][0]

    # Walk backwards from sub_rsp_va over push instructions to the true entry.
    off = sub_rsp_va - start
    entry_va = sub_rsp_va
    while off > 0:
        # single-byte push r64
        if 0x50 <= blob[off - 1] <= 0x57:
            entry_va -= 1
            off -= 1
            continue
        # REX + push r64 (push r12..r15)
        if off >= 2 and blob[off - 2] == 0x41 and 0x54 <= blob[off - 1] <= 0x57:
            entry_va -= 2
            off -= 2
            continue
        break
    return entry_va


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    pid = int(sys.argv[1], 0)
    native_va = int(sys.argv[2], 0)

    with MemReader(pid) as mr, os.fdopen(os.open("/dev/memreader", os.O_RDWR), "rb", buffering=0, closefd=True) as ctrl:
        fd = ctrl.fileno()

        print(f"[+] pid={pid} native_func_va=0x{native_va:X}")
        clear_bp_hit(fd, pid)
        set_hwbp(fd, pid, native_va, bp_num=0)
        print(f"[+] HWBP EXEC set on 0x{native_va:X}, waiting {WAIT_SECONDS}s for hit ...")

        t0 = time.time()
        info = None
        while time.time() - t0 < WAIT_SECONDS:
            info = get_bp_hit(fd, pid)
            if info.hit:
                break
            time.sleep(0.05)

        clear_hwbp(fd, pid, bp_num=0)

        if not info or not info.hit:
            print("[-] no hit within timeout", file=sys.stderr)
            sys.exit(1)

        print(f"[+] BP hit at rip=0x{info.rip:X} rsp=0x{info.rsp:X}")
        ret_addr = int.from_bytes(mr.read(info.rsp, 8), "little")
        print(f"[+] return address on stack: 0x{ret_addr:X}")
        if not (IMAGE_BASE <= ret_addr < IMAGE_BASE + IMAGE_SIZE):
            print(f"[-] return address outside module range — probably not ProcessEvent (may be a thunk/Wine glue)",
                  file=sys.stderr)
            sys.exit(1)
        print(f"[+] return RVA: 0x{ret_addr - IMAGE_BASE:X}")

        entry_va = find_prologue(mr, ret_addr)
        if not entry_va:
            print("[-] could not locate a plausible function prologue", file=sys.stderr)
            sys.exit(1)
        entry_rva = entry_va - IMAGE_BASE
        print(f"[+] candidate UObject::ProcessEvent  VA 0x{entry_va:X}  RVA 0x{entry_rva:X}")
        print(f"[+] update arc_decrypt.h:v20260908::RVA_UOBJECT_PROCESSEVENT = 0x{entry_rva:X}ULL;")


if __name__ == "__main__":
    main()
