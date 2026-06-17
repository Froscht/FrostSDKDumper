#!/usr/bin/env python3
import struct, sys, os, json, ctypes

PID = 9046
MODULE_BASE = 0x140000000

def open_mem():
    try:
        Fd = os.open("/dev/memreader", os.O_RDWR)
        Buf = struct.pack("<I", PID)
        os.write(Fd, Buf)
        return Fd
    except:
        return open(f"/proc/{PID}/mem", "rb")

class MemReader:
    def __init__(self):
        self.Fd = open_mem()
        self.IsDevMem = not hasattr(self.Fd, 'read')

    def Read(self, Addr, Size):
        try:
            if self.IsDevMem:
                Req = struct.pack("<QI", Addr, Size)
                os.write(self.Fd, Req)
                Data = b""
                while len(Data) < Size:
                    Chunk = os.read(self.Fd, Size - len(Data))
                    if not Chunk:
                        return None
                    Data += Chunk
                return Data
            else:
                self.Fd.seek(Addr)
                return self.Fd.read(Size)
        except:
            return None

    def ReadU64(self, Addr):
        D = self.Read(Addr, 8)
        return struct.unpack("<Q", D)[0] if D and len(D) == 8 else 0

    def ReadU32(self, Addr):
        D = self.Read(Addr, 4)
        return struct.unpack("<I", D)[0] if D and len(D) == 4 else 0

    def ReadU16(self, Addr):
        D = self.Read(Addr, 2)
        return struct.unpack("<H", D)[0] if D and len(D) == 2 else 0

Mem = MemReader()

FFIELD_NAME_OFF = 0x90
FFIELD_NEXT_OFF = 0xB0
FFIELD_OWNER_OFF = 0xA8
FFIELD_CLASSPTR_OFF = 0xC0
FPROP_OFFSET_OFF = 0xE4
FPROP_ELEMSZ_OFF = 0x118
FPROP_ARRAYDIM_OFF = 0x110

USTRUCT_CHILDPROPS = 0x118
USTRUCT_SUPERSTR = 0xB0

PROP_OFFSET_XOR = 0xEAABEC11

def BswapDecrypt(Stored):
    Swapped = struct.unpack(">I", struct.pack("<I", Stored))[0]
    return Swapped ^ PROP_OFFSET_XOR

ConfigPath = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/decrypt_export.json"
with open(ConfigPath) as F:
    Config = json.load(F)

SHUF_IMM = 0x1E
XOR_KEY = 0x365789E8756FBA38
ROL64 = 32
ROL16 = 1

def DecryptFFieldNameCI(FfAddr):
    Data = Mem.Read(FfAddr + FFIELD_NAME_OFF, 8)
    if not Data or len(Data) < 8:
        return -1
    Enc = struct.unpack("<Q", Data)[0]
    if Enc == 0:
        return 0

    Words = [
        (Enc >>  0) & 0xFFFF,
        (Enc >> 16) & 0xFFFF,
        (Enc >> 32) & 0xFFFF,
        (Enc >> 48) & 0xFFFF,
    ]
    Shuffled = [
        Words[(SHUF_IMM >> 0) & 3],
        Words[(SHUF_IMM >> 2) & 3],
        Words[(SHUF_IMM >> 4) & 3],
        Words[(SHUF_IMM >> 6) & 3],
    ]
    Val = 0
    for I in range(4):
        Val |= (Shuffled[I] & 0xFFFF) << (I * 16)

    Val ^= XOR_KEY

    NewWords = []
    for I in range(4):
        W = (Val >> (I * 16)) & 0xFFFF
        W = ((W << ROL16) | (W >> (16 - ROL16))) & 0xFFFF
        NewWords.append(W)
    Val = 0
    for I in range(4):
        Val |= (NewWords[I] & 0xFFFF) << (I * 16)

    Val = ((Val << ROL64) | (Val >> (64 - ROL64))) & 0xFFFFFFFFFFFFFFFF

    Ci = Val & 0xFFFFFFFF
    return Ci

GnamePoolRva = int(Config.get("gnamepool_rva", "0"), 16) if isinstance(Config.get("gnamepool_rva"), str) else Config.get("gnamepool_rva", 0)
if GnamePoolRva == 0:
    for K, V in Config.items():
        if "gnamepool" in K.lower() or "namepool" in K.lower():
            print(f"  config key: {K} = {V}")

print(f"GNamePool RVA from config: 0x{GnamePoolRva:X}")

GobjectsRva = 0
for K, V in Config.items():
    if "gobjectarray" in K.lower() or "guobjectarray" in K.lower():
        if isinstance(V, str):
            GobjectsRva = int(V, 16)
        else:
            GobjectsRva = V
        print(f"  GObjectArray RVA: 0x{GobjectsRva:X} (key={K})")

print("\n=== Scanning SDK_Output.txt for Prop_CI addresses ===")
SdkPath = "/media/frost/Coding Stuf/Linux/FrostSDKDumper/SDK_Output.txt"

TargetCis = {}
ClassAddrs = []
with open(SdkPath) as F:
    CurrentClass = None
    CurrentClassAddr = 0
    for Line in F:
        Line = Line.rstrip()
        if Line.startswith("// ── "):
            Parts = Line.split("@")
            if len(Parts) >= 2:
                AddrStr = Parts[-1].strip().rstrip(" ──")
                try:
                    CurrentClassAddr = int(AddrStr, 16)
                except:
                    CurrentClassAddr = 0
        if "Prop_CI" in Line and "Off0x" in Line:
            import re
            M = re.search(r'Prop_CI(\d+)_Off0x([A-F0-9]+)', Line)
            if M:
                Ci = int(M.group(1))
                if Ci not in TargetCis:
                    TargetCis[Ci] = 0
                TargetCis[Ci] += 1

print(f"\nTop unresolved CIs ({len(TargetCis)} unique):")
Sorted = sorted(TargetCis.items(), key=lambda X: -X[1])[:20]
for Ci, Count in Sorted:
    print(f"  CI={Ci}: {Count}x")

print("\n=== Probing live FField addresses ===")

SampleClasses = []
with open(SdkPath) as F:
    for Line in F:
        if Line.startswith("// ── ") and "@0x" in Line:
            import re
            M = re.search(r'@(0x[A-Fa-f0-9]+)', Line)
            if M:
                Addr = int(M.group(1), 16)
                SampleClasses.append(Addr)

print(f"Found {len(SampleClasses)} classes in SDK output")

TotalProps = 0
ZeroNameSlot = 0
NonZeroButFail = 0
SuccessCount = 0
CiDistrib = {}

for ClassAddr in SampleClasses[:500]:
    ChildProps = Mem.ReadU64(ClassAddr + USTRUCT_CHILDPROPS)
    if not ChildProps or ChildProps < 0x10000 or ChildProps > 0x800000000000:
        continue

    Ff = ChildProps
    Visited = set()
    while Ff and Ff > 0x10000 and Ff < 0x800000000000 and Ff not in Visited and len(Visited) < 200:
        Visited.add(Ff)
        TotalProps += 1

        NameData = Mem.Read(Ff + FFIELD_NAME_OFF, 8)
        if not NameData or len(NameData) < 8:
            Ff = Mem.ReadU64(Ff + FFIELD_NEXT_OFF)
            continue

        Enc = struct.unpack("<Q", NameData)[0]
        if Enc == 0:
            ZeroNameSlot += 1
        else:
            Ci = DecryptFFieldNameCI(Ff)
            if Ci <= 1 or Ci >= 0x06A00000:
                NonZeroButFail += 1
                if TotalProps <= 20 or NonZeroButFail <= 10:
                    print(f"  FAIL: ff=0x{Ff:X} enc=0x{Enc:016X} ci={Ci}")
            else:
                SuccessCount += 1
                Bucket = Ci // 100000
                CiDistrib[Bucket] = CiDistrib.get(Bucket, 0) + 1

        Ff = Mem.ReadU64(Ff + FFIELD_NEXT_OFF)

print(f"\n=== Results from {len(SampleClasses[:500])} classes ===")
print(f"Total FFields walked: {TotalProps}")
print(f"Zero name slot (+0x90 all zeros): {ZeroNameSlot} ({100*ZeroNameSlot/max(TotalProps,1):.1f}%)")
print(f"Non-zero but CI invalid: {NonZeroButFail} ({100*NonZeroButFail/max(TotalProps,1):.1f}%)")
print(f"CI valid: {SuccessCount} ({100*SuccessCount/max(TotalProps,1):.1f}%)")
print(f"\nCI distribution (bucket*100k):")
for B in sorted(CiDistrib.keys()):
    print(f"  {B*100000}-{(B+1)*100000}: {CiDistrib[B]}")
