#!/usr/bin/env python3
import struct

PID = 12035
MODULE_BASE = 0x140000000

def read_u64(pid, addr):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            d = f.read(8)
            if len(d) < 8: return 0
            return struct.unpack('<Q', d)[0]
    except:
        return 0

Actor = 0x39789700
ChildHead = read_u64(PID, Actor + 0x118)

FCLASS_STRUCT = 0x14E630CD0

Cur = ChildHead
Idx = 0
StructFields = []
while Cur and Cur > 0x10000 and Cur < 0x800000000000 and Idx < 200:
    Cp = read_u64(PID, Cur + 0xC0)
    if Cp == FCLASS_STRUCT:
        StructFields.append((Idx, Cur))
    Cur = read_u64(PID, Cur + 0xB0)
    Idx += 1

print(f"FStructProperty fields in Actor (ClassPrivate=0x{FCLASS_STRUCT:X}): {len(StructFields)}")

for Idx, Ff in StructFields:
    P130 = read_u64(PID, Ff + 0x130)
    P138 = read_u64(PID, Ff + 0x138)
    ElemSize = read_u64(PID, Ff + 0x118) & 0xFFFFFFFF
    Next = read_u64(PID, Ff + 0xB0)

    P130Vt = read_u64(PID, P130) if P130 else 0
    P130Rva = (P130Vt - MODULE_BASE) if P130Vt > MODULE_BASE else 0
    P138Vt = read_u64(PID, P138) if P138 and P138 > 0x10000 and P138 < 0x800000000000 else 0
    P138Rva = (P138Vt - MODULE_BASE) if P138Vt > MODULE_BASE else 0

    IsShadow130 = 0xB400000 <= P130Rva < 0xB500000
    IsShadow138 = 0xB400000 <= P138Rva < 0xB500000

    print(f"  [{Idx}] ff=0x{Ff:X} elemSz={ElemSize}")
    print(f"    +0x130=0x{P130:X} vt_rva=0x{P130Rva:X} shadow={IsShadow130} same_as_next={P130==Next}")
    print(f"    +0x138=0x{P138:X} vt_rva=0x{P138Rva:X} shadow={IsShadow138}")

OtherClasses = [
    (0x765BBB00, "ActorComponent"),
    (0x765B7F00, "StaticMeshActor"),
]

for ClsAddr, ClsName in OtherClasses:
    Ch = read_u64(PID, ClsAddr + 0x118)
    Cur = Ch
    Count = 0
    StructCount = 0
    while Cur and Cur > 0x10000 and Cur < 0x800000000000 and Count < 200:
        Cp = read_u64(PID, Cur + 0xC0)
        if Cp == FCLASS_STRUCT:
            StructCount += 1
            if StructCount <= 3:
                P138 = read_u64(PID, Cur + 0x138)
                P138Vt = read_u64(PID, P138) if P138 and P138 > 0x10000 and P138 < 0x800000000000 else 0
                P138Rva = (P138Vt - MODULE_BASE) if P138Vt > MODULE_BASE else 0
                ElemSz = read_u64(PID, Cur + 0x118) & 0xFFFFFFFF
                print(f"\n{ClsName} struct field: +0x138=0x{P138:X} vt_rva=0x{P138Rva:X} elemSz={ElemSz}")

                SuperS = read_u64(PID, P138 + 0xB0) if P138 and P138 > 0x10000 else 0
                PropSz = read_u64(PID, P138 + 0xE0) & 0xFFFFFFFF if P138 and P138 > 0x10000 else 0
                ChildP = read_u64(PID, P138 + 0x118) if P138 and P138 > 0x10000 else 0
                print(f"    target: super=0x{SuperS:X} propSz={PropSz} childProps=0x{ChildP:X}")
        Cur = read_u64(PID, Cur + 0xB0)
        Count += 1
    print(f"\n{ClsName}: {StructCount} FStructProperty fields out of {Count} total")

print("\n\n--- Check if +0x138 targets share vtable with known shadows ---")
Cur = ChildHead
Idx = 0
Targets138 = set()
while Cur and Cur > 0x10000 and Cur < 0x800000000000 and Idx < 200:
    Cp = read_u64(PID, Cur + 0xC0)
    if Cp == FCLASS_STRUCT:
        P138 = read_u64(PID, Cur + 0x138)
        if P138 and P138 > 0x10000 and P138 < 0x800000000000:
            Vt = read_u64(PID, P138)
            VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
            Targets138.add(VtRva)
    Cur = read_u64(PID, Cur + 0xB0)
    Idx += 1

print(f"Unique vtable RVAs for +0x138 targets: {len(Targets138)}")
for Rva in sorted(Targets138):
    print(f"  0x{Rva:X}")
