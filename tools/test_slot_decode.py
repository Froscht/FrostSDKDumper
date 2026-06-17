#!/usr/bin/env python3
import struct, os, ctypes

PID = 1195523
ModBase = 0x140000000

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

MaskRva = 0xB43D4D0
XorRva = 0xB43D4E0

PshufMask = ReadMem(ModBase + MaskRva, 16)
XorKey = ReadMem(ModBase + XorRva, 16)

print(f"PSHUFB mask @ 0x{MaskRva:X}: {' '.join(f'{B:02X}' for B in PshufMask)}")
print(f"XOR key     @ 0x{XorRva:X}: {' '.join(f'{B:02X}' for B in XorKey)}")

XorU64 = struct.unpack("<Q", XorKey[:8])[0]
print(f"XOR key as u64: 0x{XorU64:016X}")
print(f"Our config XOR: 0x5EA772D07F910744")

FnvMul = 0x1000193
FnvSeed = 0x5619A446

def Rotl32(V, N):
    V &= 0xFFFFFFFF
    return ((V << N) | (V >> (32-N))) & 0xFFFFFFFF

def Rotl64(V, N):
    V &= 0xFFFFFFFFFFFFFFFF
    return ((V << N) | (V >> (64-N))) & 0xFFFFFFFFFFFFFFFF

def ComputeSlot(Ptr):
    Lo = Ptr & 0xFFFFFFFF
    Hi = (Ptr >> 32) & 0xFFFFFFFF
    H = (Rotl32(Lo, 0x1A) * FnvMul + FnvSeed) & 0xFFFFFFFF
    H = (Rotl32(H, 0x1B) * FnvMul + Hi + FnvSeed) & 0xFFFFFFFF
    H >>= 6
    H = (H * FnvMul + FnvSeed) & 0xFFFFFFFF
    H >>= 5
    H = (H * FnvMul + FnvSeed) & 0xFFFFFFFF
    return H ^ (H >> 16)

def PshufbSim(Data16, Mask16):
    Out = bytearray(16)
    for I in range(16):
        Idx = Mask16[I]
        if Idx & 0x80:
            Out[I] = 0
        else:
            Out[I] = Data16[Idx & 0x0F]
    return bytes(Out)

def DecryptSlot(Addr):
    Enc = ReadMem(Addr, 16)
    if not Enc:
        return 0
    Shuffled = PshufbSim(Enc, PshufMask)
    XorResult = bytearray(16)
    for I in range(16):
        XorResult[I] = Shuffled[I] ^ XorKey[I]
    Val = struct.unpack("<Q", bytes(XorResult[:8]))[0]
    return Rotl64(Val, 0x20)

def GetObjectId(ObjAddr):
    Sel = ComputeSlot(ObjAddr + 0x10)
    SlotIdx = (Sel & 3) ^ 2
    SlotAddr = ObjAddr + SlotIdx * 32 + 0x20
    return DecryptSlot(SlotAddr) & 0xFFFFFFFF

GnpRva = 0xE577700
GnpAddr = ModBase + GnpRva

GobjRva = 0xE632260
NumElems = ReadU32(ModBase + GobjRva + 0xF4)
print(f"\nNumElements: {NumElems}")

print("\n=== Testing GetObjectId on first 20 objects ===")
ChunkTableAddr = ModBase + GobjRva + 0x10
ValidCount = 0
for ChunkI in range(min(5, (NumElems + 255) // 256)):
    ChunkPtr = ReadU64(ChunkTableAddr + ChunkI * 8)
    if not ChunkPtr:
        continue
    for ElemI in range(256):
        ObjAddr = ReadU64(ChunkPtr + ElemI * 8)
        if not ObjAddr or ObjAddr < 0x10000:
            continue
        Ci = GetObjectId(ObjAddr)
        Mark = ""
        if 1 < Ci < 0x6A00000:
            Mark = "VALID"
            ValidCount += 1
        elif Ci == 0:
            Mark = "ZERO"
        else:
            Mark = "OUT-OF-RANGE"
        if ValidCount <= 20 or Mark != "VALID":
            print(f"  obj=0x{ObjAddr:X} CI={Ci} (0x{Ci:08X}) → {Mark}")
        if ValidCount >= 50:
            break
    if ValidCount >= 50:
        break

print(f"\nValid CIs from first batch: {ValidCount}")

print("\n=== Comparing with our old FNV (SLOT_HASH_ADD=0x8F957A95) ===")
OldFnvSeed = 0x8F957A95
def ComputeSlotOld(Ptr):
    Lo = Ptr & 0xFFFFFFFF
    Hi = (Ptr >> 32) & 0xFFFFFFFF
    H = (Rotl32(Lo, 17) * FnvMul + OldFnvSeed) & 0xFFFFFFFF
    H = (Rotl32(H, 19) * FnvMul + Hi + OldFnvSeed) & 0xFFFFFFFF
    H = (Rotl32(H, 17) * FnvMul + OldFnvSeed) & 0xFFFFFFFF
    H >>= 13
    return H ^ (H >> 16)

TestObj = None
for ChunkI in range(1):
    ChunkPtr = ReadU64(ChunkTableAddr + ChunkI * 8)
    if not ChunkPtr:
        continue
    ObjAddr = ReadU64(ChunkPtr)
    if ObjAddr and ObjAddr > 0x10000:
        TestObj = ObjAddr
        break

if TestObj:
    SelNew = ComputeSlot(TestObj + 0x10)
    SelOld = ComputeSlotOld(TestObj + 0x10)
    print(f"  obj=0x{TestObj:X}")
    print(f"  NEW slot hash: 0x{SelNew:08X} → idx={(SelNew & 3) ^ 2}")
    print(f"  OLD slot hash: 0x{SelOld:08X} → idx={(SelOld & 3) ^ 2}")

    for SlotI in range(4):
        SlotAddr = TestObj + SlotI * 32 + 0x20
        Dec = DecryptSlot(SlotAddr) & 0xFFFFFFFF
        print(f"  slot[{SlotI}] addr=0x{SlotAddr:X} decrypted_ci={Dec} (0x{Dec:08X}) {'VALID' if 1 < Dec < 0x6A00000 else ''}")
