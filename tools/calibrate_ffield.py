#!/usr/bin/env python3
import struct, os, re, sys

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

FFIELD_NAMEPRIVATE = 0x90
FFIELD_OWNER = 0xA8
FFIELD_NEXT = 0xB0
CHILDPROPS = 0x118

def IsValidPtr(P):
    return P > 0x10000 and P < 0x800000000000

ClassAddrs = {}
with open("/media/frost/Coding Stuf/Linux/FrostSDKDumper/dump_classes.txt") as F:
    for Line in F:
        Line = Line.strip()
        if Line.startswith("//") or not Line:
            continue
        M = re.match(r'\[(\d+)\]\s+0x([A-Fa-f0-9]+)\s+\|\s+(\S+)', Line)
        if M:
            Addr = int(M.group(2), 16)
            Name = M.group(3)
            ClassAddrs[Addr] = Name

print(f"Loaded {len(ClassAddrs)} class entries")

Samples = []
Tested = 0
for Addr, Name in ClassAddrs.items():
    if len(Samples) >= 50:
        break
    Tested += 1
    Cp = ReadU64(Addr + CHILDPROPS)
    if not IsValidPtr(Cp):
        continue

    VtCheck = ReadU64(Cp)
    if not VtCheck or VtCheck < ModBase or VtCheck > ModBase + 0x20000000:
        continue

    Owner = ReadU64(Cp + FFIELD_OWNER)
    OwnerClean = Owner & ~1

    EncData = ReadMem(Cp + FFIELD_NAMEPRIVATE, 16)
    if not EncData:
        continue
    Enc = struct.unpack("<QQ", EncData)
    if Enc[0] == 0:
        continue

    Samples.append({
        'ClassAddr': Addr,
        'ClassName': Name,
        'FfAddr': Cp,
        'Enc': Enc,
        'Owner': Owner,
        'OwnerClean': OwnerClean,
    })

print(f"Tested {Tested} classes, found {len(Samples)} with valid FField chain + non-zero enc")

if len(Samples) == 0:
    print("No samples found!")
    sys.exit(1)

def Pshuflw(Val, Imm):
    Words = [(Val >> (I*16)) & 0xFFFF for I in range(4)]
    Out = [0]*4
    Out[0] = Words[(Imm >> 0) & 3]
    Out[1] = Words[(Imm >> 2) & 3]
    Out[2] = Words[(Imm >> 4) & 3]
    Out[3] = Words[(Imm >> 6) & 3]
    Result = 0
    for I in range(4):
        Result |= (Out[I] & 0xFFFF) << (I*16)
    return Result & 0xFFFFFFFFFFFFFFFF

def Rol32Each(Val, N):
    Lo = Val & 0xFFFFFFFF
    Hi = (Val >> 32) & 0xFFFFFFFF
    Lo = ((Lo << N) | (Lo >> (32-N))) & 0xFFFFFFFF
    Hi = ((Hi << N) | (Hi >> (32-N))) & 0xFFFFFFFF
    return Lo | (Hi << 32)

def Rol16Each(Val, N):
    Result = 0
    for I in range(4):
        W = (Val >> (I*16)) & 0xFFFF
        W = ((W << N) | (W >> (16-N))) & 0xFFFF
        Result |= W << (I*16)
    return Result

def Rol64(Val, N):
    Val &= 0xFFFFFFFFFFFFFFFF
    return ((Val << N) | (Val >> (64-N))) & 0xFFFFFFFFFFFFFFFF

CiMax = 0x2000000

print("\n=== Sample FField NamePrivate enc values ===")
for I, S in enumerate(Samples[:15]):
    print(f"  [{I}] class={S['ClassName']:<35} ff=0x{S['FfAddr']:X}")
    print(f"       enc=0x{S['Enc'][0]:016X} enc[1]=0x{S['Enc'][1]:016X}")
    print(f"       owner=0x{S['Owner']:016X} (clean=0x{S['OwnerClean']:X})")

print("\n=== Testing known pipelines ===")
AllEncs = [S['Enc'][0] for S in Samples]

Pipelines = [
    ('v20260616: SHUF→XOR→ROL16→ROL64', lambda e: Rol64(Rol16Each(Pshuflw(e, 0x1E) ^ 0x365789E8756FBA38, 1), 32) & 0xFFFFFFFF),
    ('build20260519: XOR1→ROL32→SHUF→XOR2→ROL64', lambda e: Rol64(Rol16Each(Pshuflw(e ^ 0xC88F612129941481, 0x1E), 17) ^ 0x018A6E394CF4AED0, 32) & 0xFFFFFFFF),
    ('keyless ROL32(17)→SHUF→ROL64', lambda e: Rol64(Pshuflw(Rol32Each(e, 17), 0x1E), 32) & 0xFFFFFFFF),
    ('keyless ROL32(23)→SHUF→ROL64', lambda e: Rol64(Pshuflw(Rol32Each(e, 23), 0x1E), 32) & 0xFFFFFFFF),
    ('just SHUF(0x1E)→ROL64(32)', lambda e: Rol64(Pshuflw(e, 0x1E), 32) & 0xFFFFFFFF),
    ('just ROL64(32)', lambda e: Rol64(e, 32) & 0xFFFFFFFF),
    ('identity', lambda e: e & 0xFFFFFFFF),
]

for PName, PFunc in Pipelines:
    ValidCount = 0
    SampleCis = []
    for E in AllEncs:
        Ci = PFunc(E)
        if 1 < Ci < CiMax:
            ValidCount += 1
        SampleCis.append(Ci)
    print(f"  {PName:<50}: valid={ValidCount}/{len(AllEncs)}")
    if ValidCount > 0:
        for I, S in enumerate(Samples[:3]):
            print(f"    sample[{I}] enc=0x{S['Enc'][0]:016X} → CI={SampleCis[I]} (0x{SampleCis[I]:08X})")

print("\n=== Exhaustive SHUF × ROL32 × ROL16 × ROL64 brute-force (no XOR) ===")
BestCount = 0
BestDesc = ""

for Shuf in [0x1E, 0x4E, 0xB1, 0xE1, 0x1B, 0xE4, 0xD8, 0x93, 0x27, 0x39, 0x72, 0x6C, 0x78, 0xC9]:
    for R32 in [0, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31]:
        for R16 in [0, 1, 3, 5, 7, 9, 11, 13, 15]:
            for R64 in [0, 8, 16, 24, 32, 40, 48, 56]:
                Count = 0
                for E in AllEncs:
                    V = E
                    if R32: V = Rol32Each(V, R32)
                    V = Pshuflw(V, Shuf)
                    if R16: V = Rol16Each(V, R16)
                    V = Rol64(V, R64)
                    Ci = V & 0xFFFFFFFF
                    if 1 < Ci < CiMax:
                        Count += 1
                if Count > BestCount:
                    BestCount = Count
                    BestDesc = f"ROL32({R32})→SHUF(0x{Shuf:02X})→ROL16({R16})→ROL64({R64})"
                    if Count == len(AllEncs):
                        print(f"  PERFECT: {BestDesc}  ({Count}/{len(AllEncs)})")

print(f"\nBest keyless: {BestDesc}  ({BestCount}/{len(AllEncs)})")

if BestCount < len(AllEncs):
    print("\n=== Now trying with XOR key derivation ===")
    S0 = Samples[0]
    E0 = S0['Enc'][0]
    print(f"Using sample enc=0x{E0:016X} from class={S0['ClassName']}")

    for R32 in [0, 17, 23]:
        for Shuf in [0x1E, 0x1B]:
            for R16 in [0, 1]:
                for R64 in [32, 0, 16, 48]:
                    V = E0
                    if R32: V = Rol32Each(V, R32)
                    V = Pshuflw(V, Shuf)
                    XorInPoint = V
                    if R16: V = Rol16Each(V, R16)
                    V = Rol64(V, R64)
                    Lo = V & 0xFFFFFFFF
                    for TargetCi in range(2, 5000):
                        Delta = (TargetCi ^ Lo) & 0xFFFFFFFF
                        if Delta < 0x100:
                            pass
