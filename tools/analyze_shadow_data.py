#!/usr/bin/env python3
import struct, sys

PID = 12035
MODULE_BASE = 0x140000000

SHADOWS = [
    0x1918B6640, 0x1918B6DC0, 0x1BC668B00, 0x1918B6F00, 0x18FCAB000,
    0x1B4B7AEC0, 0x1B4B7A380, 0x1B4B75600, 0x1B4B75880, 0x1B4B745C0
]

def read_mem(addr, sz):
    try:
        with open(f"/proc/{PID}/mem", "rb") as f:
            f.seek(addr)
            d = f.read(sz)
            if len(d) < sz:
                return None
            return d
    except:
        return None

def read_u64(addr):
    d = read_mem(addr, 8)
    if not d:
        return 0
    return struct.unpack('<Q', d)[0]

def read_u32(addr):
    d = read_mem(addr, 4)
    if not d:
        return 0
    return struct.unpack('<I', d)[0]

def is_module_ptr(v):
    return MODULE_BASE <= v < MODULE_BASE + 0x10000000

def is_heap_ptr(v):
    return 0x10000 < v < 0x800000000000 and not is_module_ptr(v)

print("=" * 80)
print("SHADOW OBJECT ANALYSIS")
print("=" * 80)

DataPtrSet = set()

for Sh in SHADOWS:
    Vt = read_u64(Sh)
    VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
    DataPtr = read_u64(Sh + 0xC0)
    TaggedOwner = read_u64(Sh + 0xA8)
    Owner = TaggedOwner & ~1
    OwnerTag = TaggedOwner & 1
    Super = read_u64(Sh + 0xB0)
    PSize = read_u32(Sh + 0xE0)
    ChildP = read_u64(Sh + 0x118)

    StructAt130 = read_u64(Sh + 0x130)
    At138 = read_u64(Sh + 0x138)

    print(f"\nShadow 0x{Sh:X}:")
    print(f"  vtable     = 0x{Vt:X} (RVA 0x{VtRva:X})")
    print(f"  +0xA8 owner= 0x{TaggedOwner:X} (cleared=0x{Owner:X}, tag={OwnerTag})")
    print(f"  +0xB0 super= 0x{Super:X}")
    print(f"  +0xC0 .data= 0x{DataPtr:X}")
    print(f"  +0xE0 psize= {PSize}")
    print(f"  +0x118 chld= 0x{ChildP:X}")
    print(f"  +0x130      = 0x{StructAt130:X}")
    print(f"  +0x138      = 0x{At138:X}")

    if is_module_ptr(DataPtr):
        DataPtrSet.add(DataPtr)

    if Owner and is_heap_ptr(Owner):
        OwnerVt = read_u64(Owner)
        OwnerVtRva = (OwnerVt - MODULE_BASE) if OwnerVt > MODULE_BASE else 0
        OwnerIsShadow = 0xB400000 <= OwnerVtRva < 0xB500000
        print(f"  Owner object @ 0x{Owner:X}: vt_rva=0x{OwnerVtRva:X} shadow={OwnerIsShadow}")
        OwnerDataPtr = read_u64(Owner + 0xC0)
        OwnerName_CI_raw = read_u64(Owner + 0x90)
        print(f"    owner +0xC0 = 0x{OwnerDataPtr:X}")
        print(f"    owner +0x90 = 0x{OwnerName_CI_raw:X}")

print("\n" + "=" * 80)
print(f".DATA POINTER ANALYSIS ({len(DataPtrSet)} unique)")
print("=" * 80)

for Dp in sorted(DataPtrSet):
    print(f"\n.data entry @ 0x{Dp:X} (RVA 0x{Dp - MODULE_BASE:X}):")
    D = read_mem(Dp, 64)
    if not D:
        print("  UNREADABLE")
        continue

    Vals = struct.unpack('<8Q', D)
    for I, V in enumerate(Vals):
        Off = I * 8
        Extra = ""
        if is_module_ptr(V):
            Extra = f" → MODULE (RVA 0x{V - MODULE_BASE:X})"
        elif is_heap_ptr(V):
            Extra = f" → HEAP"
        print(f"  +0x{Off:02X}: 0x{V:016X}{Extra}")

    FuncPtr = Vals[6]  # +0x30
    NextPtr = Vals[1]  # +0x08

    if is_module_ptr(FuncPtr):
        print(f"  >>> Function at +0x30: RVA 0x{FuncPtr - MODULE_BASE:X}")

    print(f"\n  Linked list walk (+0x08 chain):")
    Cur = Dp
    Depth = 0
    SeenFuncs = []
    while Depth < 6:
        Entry = read_mem(Cur, 64)
        if not Entry:
            break
        Ev = struct.unpack('<8Q', Entry)
        Fn = Ev[6]  # +0x30
        Nxt = Ev[1]  # +0x08
        if is_module_ptr(Fn):
            SeenFuncs.append((Depth, Fn, Fn - MODULE_BASE))
            print(f"    [{Depth}] 0x{Cur:X}: fn=0x{Fn:X} (RVA 0x{Fn - MODULE_BASE:X})  next=0x{Nxt:X}")
        else:
            print(f"    [{Depth}] 0x{Cur:X}: fn=0x{Fn:016X} (not module)  next=0x{Nxt:X}")
        if not Nxt or not is_module_ptr(Nxt):
            break
        Cur = Nxt
        Depth += 1

    if SeenFuncs:
        print(f"  Unique function RVAs in chain: {[f'0x{rva:X}' for _, _, rva in SeenFuncs]}")

print("\n" + "=" * 80)
print("SHADOW VTABLE COMPARISON")
print("=" * 80)

VtMap = {}
for Sh in SHADOWS:
    Vt = read_u64(Sh)
    VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
    if VtRva not in VtMap:
        VtMap[VtRva] = []
    VtMap[VtRva].append(Sh)

print(f"\nUnique vtables: {len(VtMap)}")
for VtRva, Addrs in sorted(VtMap.items()):
    print(f"  0x{VtRva:X}: {len(Addrs)} shadows → {[f'0x{a:X}' for a in Addrs]}")

print("\n" + "=" * 80)
print("SHADOW +0xB8 PATTERN (potential encrypted data / SIMD constants)")
print("=" * 80)

for Sh in SHADOWS:
    B8 = read_mem(Sh + 0xB8, 8)
    D8 = read_mem(Sh + 0xD8, 8)
    if B8 and D8:
        print(f"  0x{Sh:X}: +0xB8={B8.hex()}  +0xD8={D8.hex()}")

print("\n" + "=" * 80)
print("CHECK NON-ZERO REGIONS IN SHADOW OBJECTS")
print("=" * 80)

for Sh in SHADOWS[:3]:
    D = read_mem(Sh, 0x140)
    if not D:
        continue
    print(f"\n  0x{Sh:X} non-zero qwords:")
    for Off in range(0, 0x140, 8):
        V = struct.unpack_from('<Q', D, Off)[0]
        if V != 0:
            Extra = ""
            if is_module_ptr(V):
                Extra = f" MODULE RVA=0x{V - MODULE_BASE:X}"
            elif is_heap_ptr(V):
                Extra = f" HEAP"
            print(f"    +0x{Off:03X}: 0x{V:016X}{Extra}")

print("\n" + "=" * 80)
print("OWNER CHAIN ANALYSIS (follow tagged owner at +0xA8)")
print("=" * 80)

for Sh in SHADOWS[:5]:
    print(f"\n  Shadow 0x{Sh:X} owner chain:")
    Cur = Sh
    Depth = 0
    while Depth < 5:
        Tagged = read_u64(Cur + 0xA8)
        Addr = Tagged & ~1
        Tag = Tagged & 1
        if not Addr or not is_heap_ptr(Addr):
            print(f"    [{Depth}] ends: tagged=0x{Tagged:X}")
            break
        Vt = read_u64(Addr)
        VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
        IsShadow = 0xB400000 <= VtRva < 0xB500000
        DataP = read_u64(Addr + 0xC0)
        print(f"    [{Depth}] → 0x{Addr:X} vt_rva=0x{VtRva:X} shadow={IsShadow} .data=0x{DataP:X} tag={Tag}")
        Cur = Addr
        Depth += 1

print("\nDone.")
