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

def read_bytes(pid, addr, sz):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            return f.read(sz)
    except:
        return b'\x00' * sz

Actor = 0x39789700
ChildHead = read_u64(PID, Actor + 0x118)

Ff0 = ChildHead
ClassPriv0 = read_u64(PID, Ff0 + 0xC0)
Next0 = read_u64(PID, Ff0 + 0xB0)
print(f"Field[0] @ 0x{Ff0:X}")
print(f"  ClassPrivate = 0x{ClassPriv0:X}")
print(f"  Next = 0x{Next0:X}")

Data0 = read_bytes(PID, Ff0, 0x180)
print(f"\nFull hex dump of field[0] (0x180 bytes):")
for Off in range(0, 0x180, 8):
    V = struct.unpack_from('<Q', Data0, Off)[0]
    Label = ""
    if Off == 0: Label = " ← VTable"
    elif Off == 0x90: Label = " ← NameEncrypted"
    elif Off == 0x98: Label = " ← SaltSentinel"
    elif Off == 0xA8: Label = " ← Owner"
    elif Off == 0xB0: Label = " ← Next"
    elif Off == 0xC0: Label = " ← ClassPrivate"
    elif Off == 0xD0: Label = " ← PropertyFlags"
    elif Off == 0xE4 and (V & 0xFFFFFFFF): Label = " ← Offset_Internal?"
    elif Off == 0x110: Label = " ← ArrayDim?"
    elif Off == 0x118: Label = " ← ElementSize?"

    if 0x10000 < V < 0x800000000000:
        Vt = read_u64(PID, V)
        VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
        IsShadow = 0xB400000 <= VtRva < 0xB500000
        if IsShadow:
            Label += f" → SHADOW(vt=0x{VtRva:X})"
        elif 0 < VtRva < 0x10000000:
            Label += f" → module(vt=0x{VtRva:X})"
        elif V > MODULE_BASE and V < MODULE_BASE + 0x10000000:
            Label += f" → .data/.text"
        else:
            Label += f" → heap(vt=0x{Vt:X})"

    print(f"  +0x{Off:03X}: 0x{V:016X}{Label}")

FclassNames = {}
FclassDescriptors = set()
Cur = ChildHead
Idx = 0
while Cur and Cur > 0x10000 and Cur < 0x800000000000 and Idx < 81:
    Cp = read_u64(PID, Cur + 0xC0)
    FclassDescriptors.add(Cp)
    Cur = read_u64(PID, Cur + 0xB0)
    Idx += 1

print(f"\n\nUnique FFieldClass descriptors in Actor property chain: {len(FclassDescriptors)}")
for Fc in sorted(FclassDescriptors):
    FcName = read_u64(PID, Fc + 0x10)
    FcSize = read_u64(PID, Fc + 0x18)
    FcLinked = read_u64(PID, Fc + 0x08)
    FcFn = read_u64(PID, Fc + 0x30)
    FcFnRva = (FcFn - MODULE_BASE) if FcFn > MODULE_BASE else 0
    Count = sum(1 for d in [read_u64(PID, ChildHead + i * 0) for i in range(1)] if True)

    Cur = ChildHead
    Cnt = 0
    while Cur and Cur > 0x10000 and Cur < 0x800000000000:
        if read_u64(PID, Cur + 0xC0) == Fc:
            Cnt += 1
        Cur = read_u64(PID, Cur + 0xB0)
        if Cnt > 100: break

    print(f"  0x{Fc:X}: count={Cnt} linked=0x{FcLinked:X} fn_rva=0x{FcFnRva:X}")
