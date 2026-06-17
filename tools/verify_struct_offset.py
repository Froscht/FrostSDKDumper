#!/usr/bin/env python3
import struct

PID = 12035
MODULE_BASE = 0x140000000

FFIELD_CLASS_PRIVATE = 0xC0
FFIELD_NEXT = 0xB0
FFIELD_NAME_ENC = 0x90
CHILD_PROPS = 0x118
PSHUFB_MASK = [6,5,2,3,4,1,0,7]
XOR_LO64 = 0x5EA772D07F910744

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
ChildHead = read_u64(PID, Actor + CHILD_PROPS)
print(f"Actor @ 0x{Actor:X}, ChildProperties @ +0x{CHILD_PROPS:X} = 0x{ChildHead:X}")

Cur = ChildHead
FieldIdx = 0
StructProps = []
while Cur and Cur > 0x10000 and Cur < 0x800000000000 and FieldIdx < 200:
    Vt = read_u64(PID, Cur)
    ClassPriv = read_u64(PID, Cur + FFIELD_CLASS_PRIVATE)
    Next = read_u64(PID, Cur + FFIELD_NEXT)

    ClassVt = read_u64(PID, ClassPriv) if ClassPriv else 0
    ClassVtRva = (ClassVt - MODULE_BASE) if ClassVt > MODULE_BASE else 0

    print(f"  [{FieldIdx}] ff=0x{Cur:X} ClassPrivate=0x{ClassPriv:X} (vt_rva=0x{ClassVtRva:X}) next=0x{Next:X}")

    StructProps.append(Cur)

    Cur = Next
    FieldIdx += 1

print(f"\nTotal fields: {FieldIdx}")
print(f"\nProbing sub-property pointers for first 5 FField objects:")

for Ff in StructProps[:5]:
    print(f"\n  FField @ 0x{Ff:X}:")
    for Off in range(0xD0, 0x180, 8):
        P = read_u64(PID, Ff + Off)
        if P < 0x10000 or P >= 0x800000000000:
            continue
        Vt = read_u64(PID, P)
        VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
        IsShadow = 0xB400000 <= VtRva < 0xB500000
        IsModule = 0 < VtRva < 0x10000000
        Label = ""
        if IsShadow:
            Label = " SHADOW"
        elif IsModule:
            Label = f" module(0x{VtRva:X})"
        print(f"    +0x{Off:X}: 0x{P:X} → vt=0x{Vt:X} (rva=0x{VtRva:X}){Label}")
