#!/usr/bin/env python3
import struct

PID = 12035

def read(addr, sz):
    with open(f'/proc/{PID}/mem', 'rb') as f:
        f.seek(addr)
        return f.read(sz)

def u64(addr):
    d = read(addr, 8)
    return struct.unpack('<Q', d)[0] if len(d) == 8 else 0

def u32(addr):
    d = read(addr, 4)
    return struct.unpack('<I', d)[0] if len(d) == 4 else 0

def i32(addr):
    d = read(addr, 4)
    return struct.unpack('<i', d)[0] if len(d) == 4 else 0

def i64(addr):
    d = read(addr, 8)
    return struct.unpack('<q', d)[0] if len(d) == 8 else 0

Enums = [
    (0x1B4EAAE40, "EaseInFunction"),
    (0x1B4EAAD80, "EaseOutFunction"),
    (0x1B3B9EA00, "DA_PingInfo_Camera"),
]

for Addr, Name in Enums:
    print(f"\n{'='*60}")
    print(f"{Name} @ 0x{Addr:X}")
    print(f"{'='*60}")
    Vt = u64(Addr)
    print(f"  +0x00 vtable = 0x{Vt:X} (RVA 0x{Vt-0x140000000:X})")

    for Off in range(0x90, 0x180, 8):
        V = u64(Addr + Off)
        if V == 0:
            continue
        Low32 = V & 0xFFFFFFFF
        Hi32 = (V >> 32) & 0xFFFFFFFF
        IsPtr = 0x10000 < V < 0x800000000000
        Label = ""
        if IsPtr:
            Label = " PTR"
            Next4 = u32(Addr + Off + 8)
            Next4b = u32(Addr + Off + 12)
            if 0 < Next4 < 300 and Next4b >= Next4 and Next4b < 300:
                Label = f" TArray? cnt={Next4} max={Next4b}"
        elif Low32 > 0 and Low32 < 0x1FFFFFFF and Hi32 == 0:
            Label = f" CI={Low32}"
        print(f"  +0x{Off:X} = 0x{V:016X}{Label}")

    print(f"\n  --- Full TArray scan (ptr+cnt+max at every offset) ---")
    for Off in range(0x90, 0x180, 8):
        Ptr = u64(Addr + Off)
        if Ptr < 0x10000 or Ptr >= 0x800000000000:
            continue
        Cnt = u32(Addr + Off + 8)
        Max = u32(Addr + Off + 12)
        if Cnt > 0 and Cnt < 500 and Max >= Cnt and Max < 500:
            print(f"  +0x{Off:X}: ptr=0x{Ptr:X} cnt={Cnt} max={Max}")
            for J in range(min(Cnt, 4)):
                Ep = Ptr + J * 16
                Ci = i32(Ep)
                Num = u32(Ep + 4)
                Val = i64(Ep + 8)
                print(f"    [{J}] ci={Ci} num={Num} val={Val}")
