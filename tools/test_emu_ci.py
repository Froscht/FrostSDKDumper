#!/usr/bin/env python3
import struct, os, sys

PID = 9046
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

FFIELD_NAME_OFF = 0x90
FFIELD_NEXT_OFF = 0xB0
CHILDPROPS_OFF = 0x118
ASCLASS_RVA = 0xBC8DE90

SHUF_IMM = 0x1E

def Pshuflw(Val, Imm):
    Words = [(Val >> (I*16)) & 0xFFFF for I in range(4)]
    HiWords = [(Val >> (I*16)) & 0xFFFF for I in range(4, 8)]
    Out = [0]*4
    Out[0] = Words[(Imm >> 0) & 3]
    Out[1] = Words[(Imm >> 2) & 3]
    Out[2] = Words[(Imm >> 4) & 3]
    Out[3] = Words[(Imm >> 6) & 3]
    Result = 0
    for I in range(4):
        Result |= (Out[I] & 0xFFFF) << (I*16)
    return Result

def Rol16PerWord(Val, N):
    Result = 0
    for I in range(4):
        W = (Val >> (I*16)) & 0xFFFF
        W = ((W << N) | (W >> (16 - N))) & 0xFFFF
        Result |= W << (I*16)
    return Result

def Rol64(Val, N):
    Val &= 0xFFFFFFFFFFFFFFFF
    return ((Val << N) | (Val >> (64 - N))) & 0xFFFFFFFFFFFFFFFF

XorKey = 0x365789E8756FBA38
Rol16Amt = 1
Rol64Amt = 32

def TryV20260616(Enc):
    V = Pshuflw(Enc, SHUF_IMM)
    V ^= XorKey
    V &= 0xFFFFFFFFFFFFFFFF
    V = Rol16PerWord(V, Rol16Amt)
    V = Rol64(V, Rol64Amt)
    return V & 0xFFFFFFFF

def TryKeylessRol32(Enc, Rol32=17, Shuf=0x1E, Rol64A=32):
    Lo = Enc & 0xFFFFFFFF
    Hi = (Enc >> 32) & 0xFFFFFFFF
    def R32(V, N):
        V &= 0xFFFFFFFF
        return ((V << N) | (V >> (32-N))) & 0xFFFFFFFF
    Lo = R32(Lo, Rol32)
    Hi = R32(Hi, Rol32)
    V = Lo | (Hi << 32)
    V = Pshuflw(V, Shuf)
    V = Rol64(V, Rol64A)
    return V & 0xFFFFFFFF

CiRange = 0x2000000

ObjAddrs = []
print("Finding UClass objects...")
for ChunkI in range(200):
    ChunkData = ReadMem(ModBase + 0xE632260 + 0x10 + ChunkI * 8, 8)
    if not ChunkData:
        continue
    ChunkPtr = struct.unpack("<Q", ChunkData)[0]
    if not ChunkPtr or ChunkPtr < 0x10000:
        continue

ObjAddrs = []

print("Scanning for ASClass objects by vtable 0xBC8DE90 in heap...")
TestAddrs = []

SdkPath = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/SDK_Output.txt"
import re

FailingFfAddrs = []
with open("/tmp/dumper_pipe2.log") as F:
    for Line in F:
        M = re.search(r'emu_fail: ff=0x([A-Fa-f0-9]+)', Line)
        if M:
            FailingFfAddrs.append(int(M.group(1), 16))

print(f"Found {len(FailingFfAddrs)} failing FField addresses from dump log")

SuccessCount = 0
FailCount = 0
for I, Ff in enumerate(FailingFfAddrs[:5]):
    FullData = ReadMem(Ff, 0x150)
    if not FullData or len(FullData) < 0x150:
        print(f"  ff=0x{Ff:X}: READ FAIL")
        continue

    Enc90 = struct.unpack("<Q", FullData[0x90:0x98])[0]
    Next = struct.unpack("<Q", FullData[0xB0:0xB8])[0]
    Owner = struct.unpack("<Q", FullData[0xA8:0xB0])[0]
    ClassPtr = struct.unpack("<Q", FullData[0xC0:0xC8])[0]

    CiV616 = TryV20260616(Enc90)
    CiKeyless = TryKeylessRol32(Enc90)

    print(f"\n  FField 0x{Ff:X}:")
    print(f"    +0x90 (NamePrivate) = 0x{Enc90:016X}")
    print(f"    +0xA8 (Owner)       = 0x{Owner:016X}")
    print(f"    +0xB0 (Next)        = 0x{Next:016X}")
    print(f"    +0xC0 (ClassPtr)    = 0x{ClassPtr:016X}")
    print(f"    CI from v20260616:    {CiV616} (0x{CiV616:08X}) {'VALID' if 1 < CiV616 < CiRange else 'OUT-OF-RANGE'}")
    print(f"    CI from keyless ROL32: {CiKeyless} (0x{CiKeyless:08X}) {'VALID' if 1 < CiKeyless < CiRange else 'OUT-OF-RANGE'}")

    for NameOff in [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88]:
        TestEnc = struct.unpack("<Q", FullData[NameOff:NameOff+8])[0]
        if TestEnc == 0:
            continue
        CiTest = TryV20260616(TestEnc)
        CiTest2 = TryKeylessRol32(TestEnc)
        Mark = ""
        if 1 < CiTest < CiRange:
            Mark = " <-- v616 VALID"
        if 1 < CiTest2 < CiRange:
            Mark += " <-- keyless VALID"
        if Mark:
            print(f"    +0x{NameOff:02X} = 0x{TestEnc:016X} → ci_v616={CiTest} ci_kl={CiTest2}{Mark}")

print("\n=== Now checking a WORKING FField for comparison ===")
WorkingEncs = []
with open("/tmp/dumper_pipe2.log") as F:
    for Line in F:
        if "auto-calibrated NamePrivate" in Line:
            M = re.search(r"sample name='(\w+)' CI=(\d+)", Line)
            if M:
                print(f"  Calibration sample: name='{M.group(1)}' CI={M.group(2)}")
                break

SuccessAddrs = []
with open("/tmp/dumper_pipe2.log") as F:
    for Line in F:
        M = re.search(r'\[ffield\] auto-calibrated.*FField (0x[A-Fa-f0-9]+)', Line)
        if M:
            SuccessAddrs.append(int(M.group(1), 16))

if not SuccessAddrs:
    print("  No working FField sample found in log. Trying first FField from first class...")
    for Ff in FailingFfAddrs[:1]:
        Owner = ReadU64(Ff + 0xA8)
        OwnerClean = Owner & ~1
        if OwnerClean > 0x10000:
            Cp = ReadU64(OwnerClean + CHILDPROPS_OFF)
            if Cp and Cp > 0x10000 and Cp != Ff:
                print(f"  Owner=0x{OwnerClean:X} ChildProps=0x{Cp:X}")
                WorkFf = Cp
                FullData = ReadMem(WorkFf, 0xA0)
                if FullData:
                    Enc = struct.unpack("<Q", FullData[0x90:0x98])[0]
                    Ci = TryV20260616(Enc)
                    Ci2 = TryKeylessRol32(Enc)
                    print(f"  Working FField 0x{WorkFf:X}: enc=0x{Enc:016X} ci_v616={Ci} ci_kl={Ci2}")
