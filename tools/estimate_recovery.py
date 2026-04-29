"""Estimate how many of the 5303 /Script/Class.X bucket entries will
be recovered to a real package by the new GetPackagePtr logic.

Mirrors the C++ implementation in fname_decrypt.h::GetPackagePtr.
"""
import os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid
from fname_pipeline import MASK32, slot_decrypt, LiveResolver, MODULE_BASE

UPACKAGE_VT = MODULE_BASE + 0xAD8AE70
MOD_LO = MODULE_BASE
MOD_HI = MODULE_BASE + 0x10000000

def try_decode_slot(mr, base, slot):
    addr = base + 0x20 + slot * 0x20
    try:
        enc = mr.read(addr, 16)
    except OSError:
        return 0
    dec = slot_decrypt(enc)
    if dec == 0: return 0
    lo, hi = dec & MASK32, (dec >> 32) & MASK32
    if hi < 0x10000: return 0
    p = (lo << 32) | hi
    if p < 0x100000 or p >= 0x800000000000:
        return 0
    return p

def read_vt(mr, p):
    try:
        return int.from_bytes(mr.read(p, 8), "little")
    except OSError:
        return 0

def get_package_ptr(mr, obj):
    visited = set()
    cur = obj
    last = 0
    for d in range(24):
        if cur in visited: break
        visited.add(cur)
        # Pass1: any slot pointing to UPackage
        for s in range(4):
            p = try_decode_slot(mr, cur, s)
            if p and read_vt(mr, p) == UPACKAGE_VT:
                return p
        # Pass2: first slot whose target has module vtable
        nxt = 0
        for s in range(4):
            p = try_decode_slot(mr, cur, s)
            if not p or p == cur or p in visited:
                continue
            vt = read_vt(mr, p)
            if MOD_LO <= vt < MOD_HI:
                nxt = p; break
        if not nxt:
            return last or cur
        last = nxt
        cur = nxt
    return last or cur

def main():
    sdk = open("/media/frost/Coding Stuf/Linux/FrostSDKDumper/SDK_Output.txt").read()
    bad = re.findall(r'^// Class /Script/Class\.(\S+)\n// Address: (0x[0-9a-fA-F]+)', sdk, re.M)
    print(f"Total bad entries: {len(bad)}")

    pid = find_pid()
    print(f"PID = {pid}")
    fully_recovered = 0  # ended at real UPackage
    same_pkg_path = 0    # ended at non-package (no improvement)
    pkg_counter = {}
    started = time.time()
    with MemReader(pid) as mr:
        rv = LiveResolver(mr)
        for i, (name, addr_s) in enumerate(bad):
            addr = int(addr_s, 16)
            try:
                p = get_package_ptr(mr, addr)
            except Exception as e:
                continue
            if not p:
                continue
            vt = read_vt(mr, p)
            if vt == UPACKAGE_VT:
                fully_recovered += 1
                # try resolve name
                if i % 200 == 0:
                    pkg_name = ""
                    for s in range(4):
                        a = p + 0x20 + s*0x20
                        try:
                            enc = mr.read(a, 16)
                        except OSError:
                            continue
                        dec = slot_decrypt(enc)
                        for v in (dec & MASK32, (dec >> 32) & MASK32):
                            if 0 < v < 0x2000000:
                                pp = rv.resolve_name_ptr(v)
                                if pp:
                                    nn = rv.decrypt_name_string(pp)
                                    if nn and nn.startswith('/'):
                                        pkg_name = nn; break
                        if pkg_name: break
                    pkg_counter[pkg_name] = pkg_counter.get(pkg_name, 0) + 1
                    print(f"  [{i:5}/{len(bad)}] {name} -> 0x{p:X} pkg={pkg_name!r}")
            else:
                same_pkg_path += 1
            if i % 500 == 499:
                elapsed = time.time() - started
                print(f"  ... {i+1} done in {elapsed:.1f}s; recovered={fully_recovered} no_pkg={same_pkg_path}")
    print(f"\n=== ESTIMATE ===")
    print(f"  Fully recovered (chain ended at UPackage): {fully_recovered} / {len(bad)}")
    print(f"  Stalled (ended at non-package UObject):    {same_pkg_path}")

if __name__ == "__main__":
    sys.exit(main() or 0)
