"""Comprehensive metaclass-vtable discovery.

Walk dump_classes.txt, group entries by class-kind tag. Read first u64 (vtable)
for each. Report distinct vtables by class-kind.
"""
import os
import sys
import re
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

MOD_LO = 0x140000000
MOD_HI = 0x160000000


def main():
    pid = find_pid("GameThread")
    print(f"[+] pid={pid}")
    classes_path = os.path.join(os.path.dirname(__file__), "..", "dump_classes.txt")
    pat = re.compile(r"^\[(\d+)\] 0x([0-9A-F]+) \| (\S+)\s+(\S+)")
    samples = defaultdict(list)
    with open(classes_path) as f:
        for line in f:
            m = pat.match(line)
            if not m:
                continue
            obj_addr = int(m.group(2), 16)
            kind     = m.group(3)
            samples[kind].append(obj_addr)

    with MemReader(pid) as mr:
        kind_to_vt = defaultdict(Counter)
        for kind, addrs in sorted(samples.items()):
            for a in addrs:
                try:
                    v = mr.read_u64(a)
                except Exception:
                    continue
                if MOD_LO <= v < MOD_HI:
                    kind_to_vt[kind][v] += 1

        # show kind -> top-3 vtables
        print(f"\n=== Per-kind dominant vtables ===")
        for kind, vts in sorted(kind_to_vt.items()):
            if not vts:
                continue
            print(f"\n  {kind}  (samples={sum(vts.values())})")
            for v, c in vts.most_common(3):
                print(f"    vtable=0x{v:016X}  rva=0x{v-MOD_LO:08X}  count={c}")

        # Reverse map: which kinds use which vtable
        print(f"\n=== Vtable -> kinds ===")
        vt_to_kinds = defaultdict(Counter)
        for kind, vts in kind_to_vt.items():
            for v, c in vts.items():
                vt_to_kinds[v][kind] += c
        sorted_vt = sorted(vt_to_kinds.items(), key=lambda kv: -sum(kv[1].values()))
        for v, kc in sorted_vt[:30]:
            kinds = ", ".join(f"{k}={c}" for k, c in kc.most_common(5))
            print(f"  vtable=0x{v:016X}  rva=0x{v-MOD_LO:08X}  total={sum(kc.values())}  kinds=[{kinds}]")


if __name__ == "__main__":
    main()
