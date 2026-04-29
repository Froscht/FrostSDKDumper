"""For specific objects, decode their ClassPrivate to confirm meta-class."""

import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

# Read the second slot pair after vtable (rough heuristic): the obfuscated
# ClassPrivate appears at slot index 1 or 2 in encrypted form. We don't have
# the decryptor here, so just dump raw layout for each candidate.

CANDIDATES = [
    # (name, addr, hypothesis)
    ("Anchors",                  0x8AB13230, "vt-known ff-valid NF=0 — UDelegateFunction?"),
    ("FocusEvent",               0x8AB145C0, "vt-known ff-valid NF=0"),
    ("OverlaySlot@0x13619ad80",  0x13619AD80, "vt-unknown ff-valid NF=0 — Pass3 FP candidate"),
    ("StaticMeshSocket",         0x16EB56500, "vt-unknown ff-valid NF=0"),
    ("SM_Barrier_01_A",          0x187C02700, "vt-unknown ff-valid NF=junk"),
    ("ShowCelebration",          0x8C0C40D0,  "vt=0x14B8ADCD0 — what class?"),
    ("Construct (BP widget)",    0x8C0C34D0,  "vt=0x14B8AE100"),
    ("DropZoneAcceptedCarryableInfo", 0x8B8188F0, "vt=0x14B8B2420"),
    ("CancelLatentActions",      0x8AB12A50,  "vt-known ff-valid native UF — sanity"),
]

def main():
    pid = find_pid()
    print(f"PID={pid}\n")
    with MemReader(pid) as mr:
        for label, addr, hypo in CANDIDATES:
            try:
                buf = mr.read(addr, 0x180)
            except OSError as e:
                print(f"{label}: read failed: {e}")
                continue
            vt = struct.unpack_from('<Q', buf, 0)[0]
            ff = struct.unpack_from('<I', buf, 0x120)[0]
            nf = struct.unpack_from('<Q', buf, 0x148)[0]
            np_byte = buf[0xB0]
            super_q = struct.unpack_from('<Q', buf, 0xB0)[0]
            children = struct.unpack_from('<Q', buf, 0xD0)[0]
            print(f"-- {label}  ({hypo})")
            print(f"   addr={addr:#x}  vt={vt:#018x}  ff={ff:#010x}  nf={nf:#018x}")
            print(f"   numparms[u8]={np_byte}  super[u64@0xB0]={super_q:#x}")
            print(f"   children@0xD0={children:#x}")
            # Walk slot pairs at +0x20, +0x40, +0x60, +0x80 — encrypted slots
            for s in (0x20, 0x40, 0x60, 0x80):
                lo = struct.unpack_from('<Q', buf, s)[0]
                hi = struct.unpack_from('<Q', buf, s+8)[0]
                ok = "PAIR" if lo == hi and lo != 0 else "    "
                print(f"   slot@+{s:#04x}: {lo:#018x} {hi:#018x} {ok}")
            print()

if __name__ == '__main__':
    main()
