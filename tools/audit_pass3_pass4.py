"""Audit Pass 3 / Pass 4 false positives in sdk_generator.h UFunction discovery.

Strategy:
  - Read dump_objects.txt to get all (idx, addr, name) triples
  - For each object, read vtable, FunctionFlags @ +0x120, NativeFunc @ +0x148,
    NextPtr @ +0x90, NumParms @ +0xB0
  - Classify by vtable
  - For objects that pass the Pass 3/4 gate but have suspicious traits, flag them
  - Real UFunctions: vtable == 0x14AD6D980, NativeFunc points to module text,
    FunctionFlags <= 0x10000000, NumParms small

Usage: python3 audit_pass3_pass4.py
"""

import os
import sys
import struct
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

DUMP_PATH = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_objects.txt"
MODULE_BASE = 0x140000000
MODULE_END = 0x150000000  # ~256MB module
HEAP_LO = 0x10000
HEAP_HI = 0x800000000000

# UFunction layout offsets (patch 20260428)
OFF_VTABLE = 0x000
OFF_NEXTPTR = 0x098
OFF_NUMPARMS = 0x0B0  # u8
OFF_CHILDPROPS = 0x0D0
OFF_FUNCFLAGS = 0x120
OFF_NATIVEFUNC = 0x148  # NOTE: arc_decrypt.h says 0x150 but live probe says 0x148

# Known UFunction vtables from live probe.
#   0x14AD6D980 — base UFunction vtable (Tick, ExecuteUbergraph_*)
#   0x14AD6CB80 — sibling UFunction vtable, same vtable bytes (UDelegateFunction?)
# Both share destructor sub_3411E0 (UFunction_Destructor) and same VFT contents.
KNOWN_UFUNC_VTABLES = {0x14AD6D980, 0x14AD6CB80}
# UObject::ProcessInternal VM thunk — every BP UFunction's NativeFunc points here.
PROCESSINTERNAL_THUNK = 0x14049AE10


def parse_dump_objects(path):
    """Parse dump_objects.txt -> list of (idx, addr, name)."""
    objs = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("="):
                continue
            # [12345] 0xCAFEBABE | Name
            if not line.startswith("["):
                continue
            try:
                rb = line.index("]")
                idx = int(line[1:rb])
                rest = line[rb+1:].strip()
                pipe = rest.index("|")
                addr = int(rest[:pipe].strip(), 16)
                name = rest[pipe+1:].strip()
                objs.append((idx, addr, name))
            except (ValueError, IndexError):
                continue
    return objs


def classify(mr, addr):
    """Return dict of fields for an object."""
    try:
        buf = mr.read(addr, 0x180)
    except OSError:
        return None
    out = {
        "vtable": struct.unpack_from("<Q", buf, OFF_VTABLE)[0],
        "nextptr": struct.unpack_from("<Q", buf, OFF_NEXTPTR)[0],
        "numparms": buf[OFF_NUMPARMS],
        "childprops": struct.unpack_from("<Q", buf, OFF_CHILDPROPS)[0],
        "funcflags": struct.unpack_from("<I", buf, OFF_FUNCFLAGS)[0],
        "nativefunc": struct.unpack_from("<Q", buf, OFF_NATIVEFUNC)[0],
    }
    return out


def is_module_text(p):
    return MODULE_BASE <= p < MODULE_END


def is_heap(p):
    return HEAP_LO <= p < HEAP_HI


def main():
    pid = find_pid()
    if not pid:
        print("ERR: GameThread PID not found", file=sys.stderr)
        sys.exit(1)
    print(f"[*] PID = {pid}")

    objs = parse_dump_objects(DUMP_PATH)
    print(f"[*] Parsed {len(objs)} objects from dump_objects.txt")

    # For Pass-3-style auditing we don't have the C++ allTypeAddrs set.
    # Instead, classify by vtable distribution and field patterns.
    # The key signal: TRUE UFunctions all have vtable 0x14AD6D980
    # (and possibly delegate variants — track them).

    vtable_count = Counter()
    vtable_examples = defaultdict(list)
    funcflags_dist = Counter()
    pass3_passers = []
    pass3_real = 0
    pass3_suspicious = 0
    sampled = 0

    # Also track: objects that pass FunctionFlags filter (nonzero, <=0x10000000)
    # and have a non-UFunction vtable -- these are the candidate FPs
    # if Pass 3's "outer_ok" path admits them.
    candidates_outer_only = []

    with MemReader(pid) as mr:
        for idx, addr, name in objs:
            sampled += 1
            if sampled % 5000 == 0:
                print(f"  ... sampled {sampled}/{len(objs)}", file=sys.stderr)

            info = classify(mr, addr)
            if info is None:
                continue

            vt = info["vtable"]
            ff = info["funcflags"]
            nf = info["nativefunc"]
            np = info["numparms"]

            vtable_count[vt] += 1
            if len(vtable_examples[vt]) < 3:
                vtable_examples[vt].append((addr, name))

            # Pass 3 filter: skip name empty / starts with /
            if not name or name[0] == '/':
                continue
            if name.startswith("Default__"):
                continue
            # Pass 3: flags!=0 && flags<=0x10000000
            if ff == 0 or ff > 0x10000000:
                continue

            # We can't check allTypeAddrs in Python directly, but we CAN check
            # if this looks like a real UFunction vs not.
            is_real_uf = (vt in KNOWN_UFUNC_VTABLES) and is_module_text(nf)

            funcflags_dist[ff] += 1

            entry = (idx, addr, name, info)
            pass3_passers.append(entry)

            if is_real_uf:
                pass3_real += 1
            else:
                pass3_suspicious += 1
                if len(candidates_outer_only) < 100:
                    candidates_outer_only.append(entry)

    print(f"\n[*] Total sampled: {sampled}")
    print(f"[*] Pass-3 filter survivors (named, non-/-prefixed, ff in (0,0x10000000]):")
    print(f"      real UFunctions (vt=0x14AD6D980 + nativefunc in text): {pass3_real}")
    print(f"      suspicious (different vtable or bogus nativefunc):     {pass3_suspicious}")
    print(f"[*] Total survivors: {len(pass3_passers)}")

    print(f"\n[*] Top 20 vtables among survivors:")
    survivor_vts = Counter()
    for _, _, _, info in pass3_passers:
        survivor_vts[info["vtable"]] += 1
    for vt, cnt in survivor_vts.most_common(20):
        examples = vtable_examples[vt][:2]
        ex_str = ", ".join(f"{n}@{a:#x}" for a,n in examples)
        marker = "  <-- KNOWN UFUNC" if vt in KNOWN_UFUNC_VTABLES else ""
        print(f"  vt={vt:#018x}  count={cnt:6d}  {ex_str}{marker}")

    print(f"\n[*] Sample of suspicious survivors (likely FPs if Pass 3 admits them):")
    for idx, addr, name, info in candidates_outer_only[:30]:
        nf_text = "TEXT" if is_module_text(info["nativefunc"]) else (
            "ZERO" if info["nativefunc"] == 0 else (
                "HEAP" if is_heap(info["nativefunc"]) else "OTHER"))
        print(f"  [{idx:6d}] {addr:#018x} | {name[:40]:<40} "
              f"vt={info['vtable']:#018x} ff={info['funcflags']:#x} "
              f"nf={info['nativefunc']:#x} ({nf_text}) np={info['numparms']}")

    # Distinguishing trait test: among survivors with vtable != KNOWN, how many
    # have NativeFunc pointing to module text?
    print(f"\n[*] Among 'suspicious' (vt not in KNOWN_UFUNC_VTABLES) survivors:")
    nf_text_cnt = sum(1 for _,_,_,i in pass3_passers
                     if i["vtable"] not in KNOWN_UFUNC_VTABLES
                     and is_module_text(i["nativefunc"]))
    nf_zero_cnt = sum(1 for _,_,_,i in pass3_passers
                     if i["vtable"] not in KNOWN_UFUNC_VTABLES
                     and i["nativefunc"] == 0)
    nf_other_cnt = sum(1 for _,_,_,i in pass3_passers
                      if i["vtable"] not in KNOWN_UFUNC_VTABLES
                      and i["nativefunc"] != 0
                      and not is_module_text(i["nativefunc"]))
    print(f"  NativeFunc in module text: {nf_text_cnt}")
    print(f"  NativeFunc = 0:            {nf_zero_cnt}")
    print(f"  NativeFunc other (heap?):  {nf_other_cnt}")

    # NativeFunc == ProcessInternal thunk is the strongest BP-UFunction signal.
    pi_cnt = sum(1 for _,_,_,i in pass3_passers
                 if i["nativefunc"] == PROCESSINTERNAL_THUNK)
    print(f"\n[*] Survivors with NativeFunc == ProcessInternal_VMThunk ({PROCESSINTERNAL_THUNK:#x}):")
    print(f"      {pi_cnt}")
    pi_byvt = Counter()
    for _,_,_,i in pass3_passers:
        if i["nativefunc"] == PROCESSINTERNAL_THUNK:
            pi_byvt[i["vtable"]] += 1
    for vt, c in pi_byvt.most_common(10):
        marker = "  <-- KNOWN UFUNC" if vt in KNOWN_UFUNC_VTABLES else ""
        print(f"      vt={vt:#018x} count={c}{marker}")


if __name__ == "__main__":
    main()
