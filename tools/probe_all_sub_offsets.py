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

FCLASS_STRUCT  = 0x14E630CD0
FCLASS_OBJECT  = 0x14E630450
FCLASS_ENUM    = 0x14E6301D0
FCLASS_ARRAY   = 0x14E6305E0
FCLASS_BOOL    = 0x14E62FA30
FCLASS_MAP     = 0x14E630D60
FCLASS_DELEGATE = 0x14E62FF50
FCLASS_SOFTOBJ = 0x14E62FAB0

AllClasses = [
    (0x39789700, "Actor"),
    (0x765BBB00, "ActorComponent"),
    (0x3978E200, "Object"),
]

for ClsAddr, ClsName in AllClasses:
    Ch = read_u64(PID, ClsAddr + 0x118)
    if not Ch or Ch < 0x10000:
        print(f"{ClsName}: no ChildProperties")
        continue

    Cur = Ch
    Count = 0
    while Cur and Cur > 0x10000 and Cur < 0x800000000000 and Count < 300:
        Cp = read_u64(PID, Cur + 0xC0)
        Next = read_u64(PID, Cur + 0xB0)

        TypeLabel = "?"
        if Cp == FCLASS_STRUCT: TypeLabel = "FStructProperty"
        elif Cp == FCLASS_OBJECT: TypeLabel = "FObjectProperty"
        elif Cp == FCLASS_ENUM: TypeLabel = "FEnumProperty"
        elif Cp == FCLASS_ARRAY: TypeLabel = "FArrayProperty"
        elif Cp == FCLASS_BOOL: TypeLabel = "FBoolProperty(?)"
        elif Cp == FCLASS_MAP: TypeLabel = "FMapProperty"
        elif Cp == FCLASS_DELEGATE: TypeLabel = "FDelegateProperty(?)"
        elif Cp == FCLASS_SOFTOBJ: TypeLabel = "FSoftObjectProperty(?)"

        if TypeLabel in ("FStructProperty", "FObjectProperty", "FEnumProperty", "FArrayProperty", "FMapProperty"):
            print(f"\n{ClsName} [{Count}] {TypeLabel} @ 0x{Cur:X}:")
            for Off in (0x130, 0x138, 0x140, 0x148, 0x150):
                P = read_u64(PID, Cur + Off)
                if P < 0x10000 or P >= 0x800000000000:
                    print(f"  +0x{Off:X} = 0x{P:X} (invalid)")
                    continue
                Vt = read_u64(PID, P)
                VtRva = (Vt - MODULE_BASE) if Vt > MODULE_BASE else 0
                IsShadow = 0xB400000 <= VtRva < 0xB500000
                IsFField = P == Next
                Label = ""
                if IsFField: Label = " =NEXT"
                if IsShadow: Label += " SHADOW"
                elif 0 < VtRva < 0x10000000: Label += f" module(0x{VtRva:X})"
                print(f"  +0x{Off:X} = 0x{P:X} vt_rva=0x{VtRva:X}{Label}")

        Cur = Next
        Count += 1
