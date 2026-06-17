#!/usr/bin/env python3
import struct, os

PID = 1195523
ModBase = 0x140000000
GobjRva = 0xE632260
ModSize = 0x1179C000
TextStart = 0x1000
TextEnd = 0xB3DD000

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

def IsHeap(P):
    return P > 0x10000 and P < 0x800000000000

def IsModule(P):
    return P >= ModBase and P < ModBase + ModSize

def IsText(P):
    return P >= ModBase + TextStart and P < ModBase + TextEnd

GobjAddr = ModBase + GobjRva

print(f"=== GUObjectArray @ 0x{GobjAddr:X} ===")

Buf = ReadMem(GobjAddr, 0x200)
if not Buf:
    print("Read failed!")
    exit(1)

print(f"\nRaw dump (first 0x200 bytes):")
for Off in range(0, 0x200, 16):
    Hex = ' '.join(f'{B:02X}' for B in Buf[Off:Off+16])
    Vals64 = []
    for I in range(0, 16, 8):
        V = struct.unpack("<Q", Buf[Off+I:Off+I+8])[0]
        Vals64.append(V)
    Marker = ""
    for V in Vals64:
        if IsHeap(V) and not IsModule(V):
            Marker += " HEAP"
        elif IsModule(V):
            Marker += " MOD"
        elif 100 < V < 10000000:
            Marker += f" NUM={V}"
    print(f"  +0x{Off:03X}: {Hex}{Marker}")

print(f"\n=== Searching for chunk-array pointer ===")
NumElems = ReadU32(GobjAddr + 0xF4)
print(f"NumElements @ +0xF4 = {NumElems}")
NumChunks = (NumElems + 0xFFFF) // 0x10000
print(f"Expected chunks: {NumChunks}")

for Off in range(0, 0x200, 8):
    Ptr = struct.unpack("<Q", Buf[Off:Off+8])[0]
    if not IsHeap(Ptr) or IsModule(Ptr):
        continue

    ValidCount = 0
    for I in range(min(NumChunks, 4)):
        ChunkPtr = ReadU64(Ptr + I * 8)
        if not ChunkPtr or not IsHeap(ChunkPtr) or IsModule(ChunkPtr):
            break
        Obj = ReadU64(ChunkPtr)
        if not Obj or not IsHeap(Obj):
            break
        Vt = ReadU64(Obj)
        if not IsModule(Vt):
            break
        ValidCount += 1

    if ValidCount >= 2:
        print(f"  +0x{Off:03X}: ptr=0x{Ptr:X} → {ValidCount}/{min(NumChunks,4)} valid chunks (CANDIDATE!)")
    elif ValidCount == 1:
        print(f"  +0x{Off:03X}: ptr=0x{Ptr:X} → 1 valid (weak)")

print(f"\n=== Depth-2: follow each heap pointer and check its fields ===")
for Off in range(0, 0x200, 8):
    Ptr = struct.unpack("<Q", Buf[Off:Off+8])[0]
    if not IsHeap(Ptr) or IsModule(Ptr):
        continue

    SubBuf = ReadMem(Ptr, 0x100)
    if not SubBuf:
        continue

    for SubOff in range(0, 0x100, 8):
        SubPtr = struct.unpack("<Q", SubBuf[SubOff:SubOff+8])[0]
        if not IsHeap(SubPtr) or IsModule(SubPtr):
            continue

        ValidCount = 0
        for I in range(min(NumChunks, 4)):
            ChunkPtr = ReadU64(SubPtr + I * 8)
            if not ChunkPtr or not IsHeap(ChunkPtr) or IsModule(ChunkPtr):
                break
            Obj = ReadU64(ChunkPtr)
            if not Obj or not IsHeap(Obj):
                break
            Vt = ReadU64(Obj)
            if not IsModule(Vt):
                break
            ValidCount += 1

        if ValidCount >= 2:
            print(f"  +0x{Off:03X} → +0x{SubOff:03X}: ptr=0x{SubPtr:X} → {ValidCount} valid chunks!")

print(f"\n=== Try encrypted chunk ptrs (XOR, PSHUFB, ROL) ===")
for Off in range(0, 0x200, 8):
    RawPtr = struct.unpack("<Q", Buf[Off:Off+8])[0]
    if RawPtr == 0:
        continue
    for Xor in [0x4632C279BC9DECB2, 0x5EA772D07F910744, 0xD22BC6399DD7BE75]:
        Dec = RawPtr ^ Xor
        if IsHeap(Dec) and not IsModule(Dec):
            ValidCount = 0
            for I in range(min(NumChunks, 4)):
                ChunkPtr = ReadU64(Dec + I * 8)
                if not ChunkPtr or not IsHeap(ChunkPtr):
                    break
                Obj = ReadU64(ChunkPtr)
                if not Obj or not IsHeap(Obj):
                    break
                Vt = ReadU64(Obj)
                if not IsModule(Vt):
                    break
                ValidCount += 1
            if ValidCount >= 2:
                print(f"  +0x{Off:03X}: raw=0x{RawPtr:X} ^ 0x{Xor:X} = 0x{Dec:X} → {ValidCount} chunks!")
