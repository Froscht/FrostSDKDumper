#!/usr/bin/env python3
import struct, os

PID = 1195523
ModBase = 0x140000000
GnpRva = 0xE577700

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

def ReadU32(Addr):
    D = ReadMem(Addr, 4)
    return struct.unpack("<I", D)[0] if D else 0

def ReadU16(Addr):
    D = ReadMem(Addr, 2)
    return struct.unpack("<H", D)[0] if D else 0

GnpAddr = ModBase + GnpRva

LargeCis = [11627615, 11626469, 11706041, 11706008, 11705906, 11705872, 11705805, 10323790, 10323724]

print("=== Checking large CIs in GNamePool ===")
print(f"GNamePool base: 0x{GnpAddr:X}")

NumShards = ReadU32(GnpAddr + 0x08)
print(f"GNamePool num_shards: {NumShards}")

HdrLenLoMask = 0x3FF
HdrIsWideBit = 0x400

for Ci in LargeCis:
    ShardIdx = (Ci >> 16) & 0xFFFF
    SlotIdx = Ci & 0xFFFF

    ShardBase = GnpAddr + 0x20 + ShardIdx * 0x40
    ShardDataPtr = ReadU64(ShardBase + 0x00)
    ShardCap = ReadU32(ShardBase + 0x08)
    ShardLen = ReadU32(ShardBase + 0x0C)

    if not ShardDataPtr or ShardDataPtr < 0x10000:
        print(f"  CI={Ci} (shard={ShardIdx} slot={SlotIdx}): shard data NULL")
        continue

    EntryAddr = ShardDataPtr + SlotIdx * 2

    EntryData = ReadMem(EntryAddr, 16)
    if not EntryData:
        print(f"  CI={Ci} (shard={ShardIdx} slot={SlotIdx}): read failed @ 0x{EntryAddr:X}")
        continue

    Hdr = struct.unpack("<H", EntryData[:2])[0]
    RawLen = Hdr & HdrLenLoMask
    IsWide = bool(Hdr & HdrIsWideBit)

    if RawLen == 0 or RawLen > 1024:
        print(f"  CI={Ci} (shard={ShardIdx} slot={SlotIdx}): bad header 0x{Hdr:04X} len={RawLen}")
        NameBytes = EntryData[2:16]
        print(f"    raw bytes: {' '.join(f'{B:02X}' for B in NameBytes)}")
        continue

    NameBytes = ReadMem(EntryAddr + 2, min(RawLen, 128))
    if not NameBytes:
        print(f"  CI={Ci}: name read failed")
        continue

    try:
        if IsWide:
            Name = NameBytes[:RawLen*2].decode('utf-16le', errors='replace')
        else:
            Name = NameBytes[:RawLen].decode('utf-8', errors='replace')
        print(f"  CI={Ci} (shard={ShardIdx} slot={SlotIdx}): len={RawLen} wide={IsWide} → \"{Name}\"")
    except:
        print(f"  CI={Ci}: decode error")

print("\n=== Testing if FNamePool is keystreamed ===")
Ci1 = 1
ShardIdx = 0
SlotIdx = 1
ShardBase = GnpAddr + 0x20
ShardDataPtr = ReadU64(ShardBase)
print(f"Shard 0 data ptr: 0x{ShardDataPtr:X}")
if ShardDataPtr:
    EntryAddr = ShardDataPtr + SlotIdx * 2
    EntryData = ReadMem(EntryAddr, 32)
    if EntryData:
        print(f"  Entry bytes: {' '.join(f'{B:02X}' for B in EntryData[:16])}")
        Hdr = struct.unpack("<H", EntryData[:2])[0]
        print(f"  Hdr=0x{Hdr:04X} len_lo={Hdr & 0x3FF} wide={bool(Hdr & 0x400)}")
        print(f"  Name raw: {EntryData[2:12]}")

print("\n=== Checking shard structure more carefully ===")
for Si in range(min(10, NumShards if NumShards < 1000 else 10)):
    SBase = GnpAddr + 0x20 + Si * 0x40
    DPtr = ReadU64(SBase)
    Cap = ReadU32(SBase + 0x08)
    Len = ReadU32(SBase + 0x0C)
    print(f"  Shard[{Si}]: data=0x{DPtr:X} cap={Cap} len={Len}")
