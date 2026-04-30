"""Probe GUObjectArray + chunks_manager decrypt for ARC Raiders CL-1177146.

Reads BOTH candidate GUObjectArray base RVAs from live memory, dumps the head
of each, identifies the correct one (FChunkedFixedUObjectArray vtable + counters
+ encrypted blob @ +0xB0), then attempts the chunks_manager XOR decrypt with
the known 20260428 8-byte XOR const. If the result is a valid heap pointer
(0x10000..0x800000000000), we keep that const RVA; else brute-search nearby
.rdata RVAs for an 8-byte block that produces a valid result.

Output JSON:
    {
        "gobj_array_rva": <hex>,
        "chunks_mgr_xor_rva": <hex>,
        "chunks_mgr_xor_value": <hex>,
        "decrypted_chunks_mgr": <hex>
    }
"""

import argparse
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from memreader import MemReader, find_pid


MODULE_BASE = 0x140000000
MASK64 = 0xFFFFFFFFFFFFFFFF

CANDIDATES = [
    ("config",   0xDBA6CC0),
    ("sigscan",  0xDE6F6E0),
    ("20260428", 0xDE173A0),
]

OLD_XOR_CONST_8B = bytes([0x38, 0xBA, 0x6F, 0x75, 0xE8, 0x89, 0x57, 0x36])
OLD_XOR_CONST_U64 = int.from_bytes(OLD_XOR_CONST_8B, "little")

OLD_XOR_RVA_20260428 = 0xAD0FE50
OLD_XOR_RVA_FFIELD   = 0xB7FF0E0

RDATA_START = 0xAD3A000
RDATA_END   = 0xDAF3000

SCAN_RDATA_LO = 0xAC00000
SCAN_RDATA_HI = 0xDB00000


def Pshuflw(Src8: bytes) -> bytes:
    Words = [int.from_bytes(Src8[i*2:i*2+2], "little") for i in range(4)]
    Out = [Words[2], Words[3], Words[1], Words[0]]
    return b"".join(w.to_bytes(2, "little") for w in Out)


def Rol16Lanes(Src8: bytes, n: int) -> bytes:
    Out = bytearray(8)
    for i in range(4):
        v = int.from_bytes(Src8[i*2:i*2+2], "little")
        n_ = n & 15
        r = ((v << n_) | (v >> (16 - n_))) & 0xFFFF
        Out[i*2:i*2+2] = r.to_bytes(2, "little")
    return bytes(Out)


def CanonicalDecrypt(Blob16: bytes, XorConst8: bytes) -> int:
    Lo8 = Blob16[:8]
    Shuf = Pshuflw(Lo8)
    Xored = bytes(a ^ b for a, b in zip(Shuf, XorConst8))
    Rolled = Rol16Lanes(Xored, 1)
    return int.from_bytes(Rolled, "little")


def IsValidHeap(Addr: int) -> bool:
    return 0x10000 <= Addr < 0x800000000000


def IsValidVtable(VtPtr: int, Base: int) -> bool:
    return Base + 0x1000 <= VtPtr < Base + 0x10000000


def DumpCandidate(Mr: MemReader, Label: str, Rva: int, Base: int):
    Addr = Base + Rva
    try:
        Data = Mr.read(Addr, 0x100)
    except OSError as e:
        print(f"[{Label}] read 0x{Addr:X} failed: {e}")
        return None
    print(f"\n=== Candidate {Label} @ RVA 0x{Rva:X} (abs 0x{Addr:X}) ===")
    for Off in range(0, 0x100, 16):
        HexBytes = " ".join(f"{b:02X}" for b in Data[Off:Off+16])
        print(f"  +0x{Off:03X}: {HexBytes}")
    Vt = int.from_bytes(Data[0x00:0x08], "little")
    N38 = int.from_bytes(Data[0x38:0x40], "little")
    P78 = int.from_bytes(Data[0x78:0x80], "little")
    P80 = int.from_bytes(Data[0x80:0x88], "little")
    Blob = Data[0xB0:0xC0]
    BlobNonZero = any(Blob)
    print(f"  vt(+0x00)={Vt:016X}  +0x38={N38}  +0x78=0x{P78:X}  +0x80=0x{P80:X}")
    print(f"  +0xB0 (16B encrypted blob): {Blob.hex()}  nonzero={BlobNonZero}")
    return {"data": Data, "vt": Vt, "n38": N38, "p78": P78, "p80": P80, "blob": Blob}


def ScoreCandidate(Info, Base: int, Mr=None) -> int:
    if Info is None:
        return -1
    Score = 0
    Data = Info["data"]
    N30 = int.from_bytes(Data[0x30:0x38], "little")
    Lo30 = N30 & 0xFFFFFFFF
    Hi30 = (N30 >> 32) & 0xFFFFFFFF
    LooksPlainNum30 = 1000 <= Lo30 <= 2_000_000 and Hi30 == 0
    if LooksPlainNum30:
        Score += 8
    if 0 < Info["n38"] < 5_000_000 and (Info["n38"] >> 32) == 0:
        Score += 3
    if IsValidHeap(Info["p80"]):
        Score += 4
        if Mr is not None:
            try:
                Vt = int.from_bytes(Mr.read(Info["p80"], 8), "little")
                if IsValidVtable(Vt, Base):
                    Score += 2
            except OSError:
                pass
    Init40 = int.from_bytes(Data[0x40:0x48], "little")
    if Init40 == 1:
        Score += 1
    InitFlagF0 = Data[0xF0] if len(Data) > 0xF0 else 0
    if InitFlagF0 == 1:
        Score += 2
    return Score


def TryAllChunkPipelines(Blob16: bytes, XorConst8: bytes):
    Results = {}
    Lo8 = Blob16[:8]
    Hi8 = Blob16[8:16]
    for SrcLabel, SrcBytes in [("lo8", Lo8), ("hi8", Hi8)]:
        Shuf = Pshuflw(SrcBytes)
        Xored = bytes(a ^ b for a, b in zip(Shuf, XorConst8))
        for Rot in (1, 5, 12, 15):
            Rolled = Rol16Lanes(Xored, Rot)
            Val = int.from_bytes(Rolled, "little")
            Results[f"{SrcLabel}_rol{Rot}"] = Val
    return Results


def BruteSearchXor(Mr: MemReader, Blob16: bytes, Base: int, MaxAttempts: int = 200000):
    print(f"\n[brute] scanning .rdata for 8B XOR const that produces valid heap ptr")
    print(f"        range [0x{SCAN_RDATA_LO:X}..0x{SCAN_RDATA_HI:X}], step=0x10, blob={Blob16.hex()}")

    ChunkSize = 0x10000
    Hits = []
    Attempts = 0
    for ChunkStart in range(SCAN_RDATA_LO, SCAN_RDATA_HI, ChunkSize):
        try:
            Chunk = Mr.read(Base + ChunkStart, ChunkSize)
        except OSError:
            continue
        for Off in range(0, ChunkSize - 8, 0x10):
            XorConst8 = Chunk[Off:Off+8]
            if XorConst8 == b"\x00" * 8:
                continue
            Result = CanonicalDecrypt(Blob16, XorConst8)
            Attempts += 1
            if Attempts > MaxAttempts:
                print(f"  [brute] aborted after {MaxAttempts} attempts (no hit)")
                return Hits
            if IsValidHeap(Result):
                Vt = 0
                try:
                    Vt = int.from_bytes(Mr.read(Result, 8), "little")
                except OSError:
                    continue
                if IsValidVtable(Vt, Base):
                    Rva = ChunkStart + Off
                    Hits.append((Rva, XorConst8, Result, Vt))
                    print(f"  HIT @ RVA 0x{Rva:X}: const={XorConst8.hex()} -> ptr=0x{Result:X} (vt=0x{Vt:X})")
                    if len(Hits) >= 8:
                        return Hits
    return Hits


def Main():
    Ap = argparse.ArgumentParser(description=__doc__)
    Ap.add_argument("--pid", type=int)
    Ap.add_argument("--json-out")
    Args = Ap.parse_args()

    Pid = Args.pid or find_pid()
    if not Pid:
        print("could not find game PID", file=sys.stderr)
        return 1
    print(f"[+] PID = {Pid}")

    Result = {
        "pid": Pid,
        "gobj_array_rva": 0,
        "chunks_mgr_xor_rva": 0,
        "chunks_mgr_xor_value": 0,
        "decrypted_chunks_mgr": 0,
    }

    with MemReader(Pid) as Mr:
        Base = MODULE_BASE
        Infos = {}
        for Label, Rva in CANDIDATES:
            Infos[Label] = (Rva, DumpCandidate(Mr, Label, Rva, Base))

        print("\n=== Scoring ===")
        Best = None
        BestScore = -1
        for Label, (Rva, Info) in Infos.items():
            Sc = ScoreCandidate(Info, Base, Mr)
            print(f"  {Label:10s} RVA=0x{Rva:X}  score={Sc}")
            if Sc > BestScore:
                BestScore = Sc
                Best = (Label, Rva, Info)

        if Best is None or Best[2] is None:
            print("[!] no candidate readable", file=sys.stderr)
            return 2

        Label, Rva, Info = Best
        print(f"\n[+] Best candidate: {Label} @ RVA 0x{Rva:X} (score {BestScore})")
        Result["gobj_array_rva"] = Rva
        Data = Info["data"]
        N30 = int.from_bytes(Data[0x30:0x38], "little")
        Lo30 = N30 & 0xFFFFFFFF
        Hi30 = (N30 >> 32) & 0xFFFFFFFF
        if 1000 <= Lo30 <= 2_000_000 and Hi30 == 0:
            print(f"[+] CL-1177146 layout: NumElements is plain at +0x30 = {Lo30}")
            print(f"    encrypted-blob pipeline is bypassed on this patch")
            Result["chunks_mgr_xor_rva"] = OLD_XOR_RVA_FFIELD
            Result["chunks_mgr_xor_value"] = OLD_XOR_CONST_U64
            Result["decrypted_chunks_mgr"] = 0
            Result["num_elements_plain"] = Lo30
            Result["num_elements_offset"] = 0x30
            Result["layout"] = "CL-1177146 (plain NumElements @ +0x30)"
            print("\n=== Final JSON ===")
            Js = {
                "pid": Result["pid"],
                "gobj_array_rva":      f"0x{Result['gobj_array_rva']:X}",
                "chunks_mgr_xor_rva":  f"0x{Result['chunks_mgr_xor_rva']:X}",
                "chunks_mgr_xor_value": f"0x{Result['chunks_mgr_xor_value']:016X}",
                "decrypted_chunks_mgr": f"0x{Result['decrypted_chunks_mgr']:X}",
                "num_elements_plain":   Result["num_elements_plain"],
                "num_elements_offset":  f"0x{Result['num_elements_offset']:X}",
                "layout":               Result["layout"],
            }
            print(json.dumps(Js, indent=2))
            if Args.json_out:
                with open(Args.json_out, "w") as F:
                    json.dump(Js, F, indent=2)
            return 0

        Blob = Info["blob"]
        if not any(Blob):
            print("[!] selected candidate has zero-blob @ +0xB0; aborting decrypt", file=sys.stderr)
            return 3

        print("\n=== Trying canonical pipeline with KNOWN 20260428 XOR const ===")
        print(f"  XOR const bytes: {OLD_XOR_CONST_8B.hex()} (= 0x{OLD_XOR_CONST_U64:016X})")

        for Label2, RvaCand in [("AD0FE50 (20260428)", OLD_XOR_RVA_20260428),
                                ("B7FF0E0 (FField)",   OLD_XOR_RVA_FFIELD)]:
            try:
                Live = Mr.read(Base + RvaCand, 8)
                print(f"  live @ RVA 0x{RvaCand:X}: {Live.hex()}")
            except OSError as e:
                print(f"  live @ RVA 0x{RvaCand:X}: FAIL ({e})")

        Decrypted = CanonicalDecrypt(Blob, OLD_XOR_CONST_8B)
        print(f"  decrypted (lo→shuf→xor→rol16(1)) = 0x{Decrypted:X}  valid_heap={IsValidHeap(Decrypted)}")

        if IsValidHeap(Decrypted):
            try:
                Vt = int.from_bytes(Mr.read(Decrypted, 8), "little")
                print(f"  *(decrypted) = 0x{Vt:X}  valid_vt={IsValidVtable(Vt, Base)}")
            except OSError:
                Vt = 0
        else:
            Vt = 0

        if IsValidHeap(Decrypted) and IsValidVtable(Vt, Base):
            print("[+] CONST UNCHANGED — pipeline produces valid heap+vtable pointer")
            Result["chunks_mgr_xor_rva"] = OLD_XOR_RVA_20260428
            Result["chunks_mgr_xor_value"] = OLD_XOR_CONST_U64
            Result["decrypted_chunks_mgr"] = Decrypted
        else:
            print("[!] canonical pipeline failed with known const; trying alt pipelines + brute search")

            print("\n=== Alt pipelines (sanity check) ===")
            AltResults = TryAllChunkPipelines(Blob, OLD_XOR_CONST_8B)
            for K, V in AltResults.items():
                Mark = " HEAP" if IsValidHeap(V) else ""
                print(f"  {K:12s} = 0x{V:016X}{Mark}")

            Hits = BruteSearchXor(Mr, Blob, Base)
            if Hits:
                Best2 = Hits[0]
                Result["chunks_mgr_xor_rva"] = Best2[0]
                Result["chunks_mgr_xor_value"] = int.from_bytes(Best2[1], "little")
                Result["decrypted_chunks_mgr"] = Best2[2]
                print(f"\n[+] Brute hit: RVA=0x{Best2[0]:X} const=0x{Result['chunks_mgr_xor_value']:016X} ptr=0x{Best2[2]:X}")
            else:
                print("[!] no brute hit", file=sys.stderr)
                return 4

    print("\n=== Final JSON ===")
    Js = {
        "pid": Result["pid"],
        "gobj_array_rva":      f"0x{Result['gobj_array_rva']:X}",
        "chunks_mgr_xor_rva":  f"0x{Result['chunks_mgr_xor_rva']:X}",
        "chunks_mgr_xor_value": f"0x{Result['chunks_mgr_xor_value']:016X}",
        "decrypted_chunks_mgr": f"0x{Result['decrypted_chunks_mgr']:X}",
    }
    print(json.dumps(Js, indent=2))

    if Args.json_out:
        with open(Args.json_out, "w") as F:
            json.dump(Js, F, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(Main())
