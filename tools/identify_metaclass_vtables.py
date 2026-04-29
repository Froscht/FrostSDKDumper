"""From dump_objects.txt entries, identify which vtables correspond to which
metaclass kinds (UClass, UScriptStruct, UEnum, UFunction, UPackage, ...).

For each entry, read the first u64 (vtable). Tally vtable -> set of names.
"""
import os
import sys
import re
import struct
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

MOD_LO = 0x140000000
MOD_HI = 0x160000000


def main():
    pid = find_pid("GameThread")
    print(f"[+] pid={pid}")

    # We don't actually have the kind classification per object name in
    # dump_classes.txt, but we DO have e.g. "Function /Script/...", "Class /Script/..."
    # Parse class-prefix tokens.
    classes_path = os.path.join(os.path.dirname(__file__), "..", "dump_classes.txt")
    pat = re.compile(r"^\[(\d+)\] 0x([0-9A-F]+) \| (\S+)\s+(\S+)")

    # Sample N objects per kind
    KINDS_OF_INTEREST = {
        "Class", "ScriptStruct", "Enum", "Function", "Package",
        "BlueprintGeneratedClass", "DelegateFunction",
    }
    samples = defaultdict(list)
    with open(classes_path) as f:
        for line in f:
            m = pat.match(line)
            if not m:
                continue
            obj_addr = int(m.group(2), 16)
            kind     = m.group(3)
            if kind in KINDS_OF_INTEREST and len(samples[kind]) < 200:
                samples[kind].append(obj_addr)

    with MemReader(pid) as mr:
        for kind, addrs in samples.items():
            vt_counts = Counter()
            for a in addrs:
                try:
                    v = mr.read_u64(a)
                except Exception:
                    continue
                if MOD_LO <= v < MOD_HI:
                    vt_counts[v] += 1
            print(f"\n=== kind={kind:30s} samples={len(addrs)}  unique vtables={len(vt_counts)} ===")
            for v, c in vt_counts.most_common(5):
                rva = v - MOD_LO
                print(f"   vtable=0x{v:016X}  rva=0x{rva:08X}  count={c}")


if __name__ == "__main__":
    main()
