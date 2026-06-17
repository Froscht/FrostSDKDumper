#!/usr/bin/env python3
import struct, sys

PID = 12035

def read_u64(pid, addr):
    try:
        with open(f"/proc/{pid}/mem", "rb") as f:
            f.seek(addr)
            data = f.read(8)
            if len(data) < 8: return 0
            return struct.unpack('<Q', data)[0]
    except:
        return 0

ShadowExamples = [0xBBCB4980, 0xBBC8DD80, 0xBBCB4AC0]

for Sh in ShadowExamples:
    print(f"\nShadow @ 0x{Sh:X}:")
    Cur = Sh
    Depth = 0
    while Cur and Depth < 10:
        Vt = read_u64(PID, Cur)
        VtRva = (Vt - 0x140000000) if Vt > 0x140000000 else 0
        Super = read_u64(PID, Cur + 0xB0)
        Ps = struct.unpack('<I', struct.pack('<Q', read_u64(PID, Cur + 0xE0))[:4])[0]
        IsShadow = (VtRva >= 0xB400000 and VtRva < 0xB500000)
        ChProp = read_u64(PID, Cur + 0x118)
        print(f"  [{Depth}] 0x{Cur:X}  vt_rva=0x{VtRva:X}  shadow={IsShadow}  super=0x{Super:X}  propsSize={Ps}  childProps=0x{ChProp:X}")
        if not Super or Super < 0x10000 or Super >= 0x800000000000:
            print(f"  [{Depth}] chain ends (super=0x{Super:X})")
            break
        Cur = Super
        Depth += 1

print("\n\n--- Check if any shadow super chain reaches a non-shadow ---")
TestShadows = []
with open(f"/proc/{PID}/mem", "rb") as f:
    for Base in [0xBBCB4980]:
        for i in range(200):
            Addr = Base + i * 0x140
            try:
                f.seek(Addr)
                Data = f.read(8)
                Vt = struct.unpack('<Q', Data)[0]
                VtRva = (Vt - 0x140000000) if Vt > 0x140000000 else 0
                if VtRva >= 0xB400000 and VtRva < 0xB500000:
                    TestShadows.append(Addr)
            except:
                break

print(f"Found {len(TestShadows)} shadow objects in contiguous region")

ReachesNonShadow = 0
for Sh in TestShadows[:50]:
    Cur = read_u64(PID, Sh + 0xB0)
    Depth = 0
    while Cur and Depth < 10:
        Vt = read_u64(PID, Cur)
        VtRva = (Vt - 0x140000000) if Vt > 0x140000000 else 0
        IsShadow = (VtRva >= 0xB400000 and VtRva < 0xB500000)
        if not IsShadow:
            print(f"  0x{Sh:X} → non-shadow at depth {Depth+1}: 0x{Cur:X} (vt_rva=0x{VtRva:X})")
            ReachesNonShadow += 1
            break
        Cur = read_u64(PID, Cur + 0xB0)
        Depth += 1

print(f"\n{ReachesNonShadow}/{min(len(TestShadows),50)} shadows reach a non-shadow super")
