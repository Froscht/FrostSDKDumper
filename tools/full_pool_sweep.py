"""Full sweep of the heap chunk-pool region.
Identifies UClass / UScriptStruct / UEnum / UFunction / UPackage / UBPGenClass
objects via vtable match. For each, decodes name and walks Outer to package.

Compares to the dump_objects.txt set (object addresses already discovered
by GUObjectArray scan) to compute the gap.
"""
import argparse
import os
import sys
import struct
import re
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid
from fname_pipeline import (
    LiveResolver, MODULE_BASE, slot_decrypt, slot_picker, MASK32,
)

MOD_LO = 0x140000000
MOD_HI = 0x160000000

VT_KIND = {
    0x140000000 + 0xAD6D440: "Class",
    0x140000000 + 0xAD6CB80: "ScriptStruct",
    0x140000000 + 0xAD6FF30: "Enum",
    0x140000000 + 0xAD6D980: "Function",
    0x140000000 + 0xAD8AE70: "Package",
    0x140000000 + 0xB527FC0: "BlueprintGeneratedClass",
}
KIND_VTS = {k: v for v, k in VT_KIND.items()}


def decode_pointer_slots(data, base):
    """Extract pointer-slot decrypts from a 0x100-byte buffer (UObject header)."""
    out = []
    for slot in range(4):
        off = 0x20 + slot * 0x20
        if off + 16 > len(data):
            break
        enc = bytes(data[off:off + 16])
        if not any(enc):
            continue
        dec = slot_decrypt(enc)
        lo = dec & MASK32
        hi = (dec >> 32) & MASK32
        if hi < 0x10000:
            continue
        ptr = (lo << 32) | hi
        if ptr < 0x100000 or ptr >= 0x800000000000:
            continue
        out.append((slot, ptr))
    return out


def decode_fname_slots(data):
    out = []
    for slot in range(4):
        off = 0x20 + slot * 0x20
        if off + 16 > len(data):
            break
        enc = bytes(data[off:off + 16])
        if not any(enc):
            continue
        dec = slot_decrypt(enc)
        lo = dec & MASK32
        hi = (dec >> 32) & MASK32
        if hi >= 0x10000:
            continue
        if 0 < lo < 0x2000000:
            out.append((slot, lo))
    return out


def get_object_name_via_buffer(rv, hdr_buf):
    """hdr_buf is bytes from obj_addr+0..0xA0 covering the 4 slots."""
    cands = decode_fname_slots(hdr_buf)
    for slot, ci in cands:
        ptr = rv.resolve_name_ptr(ci)
        if not ptr:
            continue
        name = rv.decrypt_name_string(ptr)
        if name and all(0x20 <= ord(c) <= 0x7E for c in name):
            return name
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start",   default="0x70000000")
    ap.add_argument("--end",     default="0xA0000000")
    ap.add_argument("--stride",  default="0x10")
    ap.add_argument("--name-cap", type=int, default=4000,
                    help="Resolve names for up to N objects (caps total runtime).")
    args = ap.parse_args()

    pid = find_pid("GameThread")
    print(f"[+] pid={pid}")

    start = int(args.start, 0)
    end   = int(args.end, 0)
    stride = int(args.stride, 0)

    # Collect addresses already in dump_objects.txt
    obj_addrs_in_dump = set()
    pat = re.compile(r"^\[\d+\] 0x([0-9A-F]+)")
    dump_path = os.path.join(os.path.dirname(__file__), "..", "dump_objects.txt")
    with open(dump_path) as f:
        for line in f:
            m = pat.match(line)
            if m:
                obj_addrs_in_dump.add(int(m.group(1), 16))
    print(f"[+] dump_objects.txt has {len(obj_addrs_in_dump)} unique addrs")

    # Sweep the region
    found = defaultdict(list)  # kind -> [obj_addr]
    BULK = 0x100000
    addr = start

    with MemReader(pid) as mr:
        rv = LiveResolver(mr)

        ok_pages = 0
        skip_pages = 0
        while addr < end:
            try:
                data = mr.read(addr, min(BULK, end - addr))
                ok_pages += 1
            except Exception:
                addr += BULK
                skip_pages += 1
                continue
            for off in range(0, len(data) - 8, stride):
                v = struct.unpack_from("<Q", data, off)[0]
                kind = VT_KIND.get(v)
                if kind:
                    found[kind].append(addr + off)
            addr += BULK

        print(f"[+] sweep done ({ok_pages} pages OK, {skip_pages} skipped)")
        for kind, lst in sorted(found.items()):
            in_dump = sum(1 for a in lst if a in obj_addrs_in_dump)
            print(f"    {kind:30s} total={len(lst):6d}  in_dump={in_dump:5d}  missing={len(lst)-in_dump:5d}")

        # Sub-pool boundary detection: cluster Class objects by 0x100000 page.
        cls = sorted(set(found.get("Class", [])))
        if cls:
            buckets = Counter()
            for a in cls:
                buckets[a >> 20] += 1  # 1MB buckets
            print(f"\n=== Class object distribution by 1MB bucket (first 40) ===")
            sorted_buckets = sorted(buckets.items())
            for k, c in sorted_buckets[:40]:
                print(f"  0x{k<<20:010X}-0x{(k+1)<<20:010X}: {c:5d}")
            print(f"  ... total buckets: {len(sorted_buckets)}")

        # Now resolve names + packages for a sample of all UClass-vtable objects.
        all_cls = sorted(set(found.get("Class", [])) - obj_addrs_in_dump)[:args.name_cap]
        print(f"\n=== Resolving names for {len(all_cls)} missing UClasses ===")
        per_pkg = Counter()
        unresolved = 0
        unprintable = 0
        # Read 0x100 bytes per object
        for i, ua in enumerate(all_cls):
            if i % 500 == 0:
                print(f"  ...{i}/{len(all_cls)}  (so far {sum(per_pkg.values())} resolved)")
            try:
                hdr = mr.read(ua, 0xA0)
            except Exception:
                unresolved += 1
                continue
            name = get_object_name_via_buffer(rv, hdr)
            if not name:
                unresolved += 1
                continue
            # Walk pointer slots; pick first Package, otherwise traverse one Class hop.
            ptrs = decode_pointer_slots(hdr, ua)
            pkg_addr = 0
            for slot, p in ptrs:
                try:
                    pvt = mr.read_u64(p)
                except Exception:
                    continue
                if pvt == KIND_VTS["Package"]:
                    pkg_addr = p
                    break
            # If no direct package, try one hop
            if not pkg_addr:
                for slot, p in ptrs:
                    try:
                        sub = mr.read(p, 0xA0)
                    except Exception:
                        continue
                    sub_ptrs = decode_pointer_slots(sub, p)
                    for s2, p2 in sub_ptrs:
                        try:
                            pvt = mr.read_u64(p2)
                        except Exception:
                            continue
                        if pvt == KIND_VTS["Package"]:
                            pkg_addr = p2
                            break
                    if pkg_addr:
                        break
            pkg_name = ""
            if pkg_addr:
                try:
                    phdr = mr.read(pkg_addr, 0xA0)
                except Exception:
                    phdr = None
                if phdr:
                    pkg_name = get_object_name_via_buffer(rv, phdr)
            per_pkg[pkg_name or "<unknown>"] += 1
            if pkg_name and not pkg_name.startswith("/"):
                # malformed; pkg-walk picked an intermediate
                pass

        print(f"\n=== Missing-UClass package distribution ===")
        for p, c in per_pkg.most_common():
            print(f"  {c:6d}  {p}")
        print(f"  unresolved (no name): {unresolved}")


if __name__ == "__main__":
    main()
