#!/usr/bin/env python3
import struct, os, json

PID = 9046

def ReadMem(Addr, Size):
    try:
        Fd = os.open(f"/proc/{PID}/mem", os.O_RDONLY)
        os.lseek(Fd, Addr, os.SEEK_SET)
        Data = os.read(Fd, Size)
        os.close(Fd)
        return Data if len(Data) == Size else None
    except:
        return None

def ReadU64(Addr):
    D = ReadMem(Addr, 8)
    return struct.unpack("<Q", D)[0] if D else 0

GnpRva = 0xE577700
ModBase = 0x140000000
GnpAddr = ModBase + GnpRva

SuccessCi = 6
FailCi = 675568

for Ci in [SuccessCi, FailCi, 2, 4, 1316, 7588]:
    CiU = Ci & 0xFFFFFFFF
    ChkOff = (CiU >> 8) & 0xFFFF00
    NameOff = CiU & 0xFFFF
    ChunkAddr = GnpAddr + ChkOff

    ChunkData = ReadMem(ChunkAddr, 64)
    if ChunkData:
        HexStr = " ".join(f"{B:02X}" for B in ChunkData[:32])
    else:
        HexStr = "READ FAIL"

    print(f"CI={Ci:>8} (0x{CiU:08X}) chunk_off=0x{ChkOff:06X} name_off=0x{NameOff:04X} chunkAddr=0x{ChunkAddr:X}")
    print(f"  chunk[0:32] = {HexStr}")

print("\n=== Testing FNamePool structure ===")
print(f"GNamePool base = 0x{GnpAddr:X}")
for Off in [0, 0x8, 0x10, 0x18, 0x20, 0x100, 0x200, 0x1000, 0x10000, 0x20000, 0x100000, 0x200000, 0x400000, 0x600000]:
    Data = ReadMem(GnpAddr + Off, 16)
    if Data:
        Vals = struct.unpack("<QQ", Data)
        HasData = any(B != 0 for B in Data)
        print(f"  GNP+0x{Off:06X}: {Vals[0]:016X} {Vals[1]:016X} {'(has data)' if HasData else '(zeros)'}")

TargetCis = [100, 500, 1000, 5000, 10000, 50000, 100000, 200000, 500000, 675568]
print("\n=== ChunkOff scan for various CIs ===")
for Ci in TargetCis:
    ChkOff = (Ci >> 8) & 0xFFFF00
    ChunkAddr = GnpAddr + ChkOff
    D = ReadMem(ChunkAddr, 8)
    HasData = any(B != 0 for B in D) if D else False
    print(f"  CI={Ci:>8} chunk_off=0x{ChkOff:06X} chunkAddr=0x{ChunkAddr:X} hasData={HasData}")

print("\n=== Searching for first non-zero chunk ===")
FirstNonZero = None
for Off in range(0, 0x700000, 0x100):
    D = ReadMem(GnpAddr + Off, 8)
    if D and any(B != 0 for B in D):
        FirstNonZero = Off
        print(f"  First non-zero data at GNP+0x{Off:X}")
        if Off > 0x1000:
            break
    if Off < 0x100:
        print(f"  GNP+0x{Off:03X}: {'non-zero' if (D and any(B != 0 for B in D)) else 'zeros'}")
