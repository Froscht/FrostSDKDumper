#pragma once

#include <cstdint>
#include <cstring>
#include <immintrin.h>

#ifdef _MSC_VER
#include <stdlib.h>
#define __builtin_bswap64(x) _byteswap_uint64((unsigned __int64)(x))
#define __builtin_bswap32(x) _byteswap_ulong((unsigned long)(x))
#endif

// =============================================================================
// ARC Raiders – central decrypt constants & inline helpers (patch 20260414)
// Discovered by IDA analysis on Arc_Raiders_Binary_Steam_2026_04_14.exe
// =============================================================================

namespace ArcDecrypt {

// =============================================================================
// Utility helpers
// =============================================================================
inline uint32_t ROL32(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
inline uint64_t ROL64(uint64_t v, int n) { return (v << n) | (v >> (64 - n)); }
inline uint32_t ROR32(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

inline uint64_t bswap64(uint64_t x) { return __builtin_bswap64(x); }
inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }

// =============================================================================
// 1. UObject Slot Hash Constants (patch 20260409)
// Confirmed from sub_1404E8610 (UObjectHash.cpp)
// Pipeline: ROL64(45) → PSHUFLW(0x1E) → XOR(sentinel)
// =============================================================================
namespace ActorFName {
    constexpr uint32_t FNV_PRIME   = 0x01000193u;
    constexpr int32_t  HASH_ADD    = static_cast<int32_t>(0x8E195662);
}

inline uint32_t ComputeHashAndIndex(uintptr_t ObjBase, uint32_t& OutIdx) {
    constexpr uint32_t P = ActorFName::FNV_PRIME;
    constexpr int32_t  K = ActorFName::HASH_ADD;
    uint64_t Ptr = ObjBase + 0x10;
    uint32_t Lo = static_cast<uint32_t>(Ptr);
    uint32_t Hi = static_cast<uint32_t>(Ptr >> 32);
    uint32_t H = ROL32(Lo, 24);
    H = static_cast<uint32_t>(P * H + K);
    H = ROL32(H, 25);
    H = static_cast<uint32_t>(P * H + Hi + K);
    H = ROL32(H, 24);
    H = static_cast<uint32_t>(P * H + K);
    H >>= 7;
    uint32_t V8 = static_cast<uint32_t>(P * H + K);
    OutIdx = ((((uint8_t)V8) ^ ((uint8_t)(V8 >> 16))) & 3u) ^ 2u;
    return V8;
}

inline uint32_t GetFNameSlotIndex(uintptr_t obj_base) {
    uint32_t idx = 0;
    ComputeHashAndIndex(obj_base, idx);
    return idx;  // FName slot from ComputeHashAndIndex
}

inline uint32_t GetClassSlotIndex(uintptr_t obj_base) {
    uint32_t idx = 0;
    ComputeHashAndIndex(obj_base, idx);
    return idx ^ 2u;  // Class slot = idx ^ 2 (other person's g_classSlotXor=2)
}

inline uint32_t GetOuterSlotIndex(uintptr_t obj_base) {
    uint32_t idx = 0;
    ComputeHashAndIndex(obj_base, idx);
    return idx ^ 3u;  // Outer slot = idx ^ 3 (other person's g_outerSlotXor=3)
}

// =============================================================================
// 2a. FProperty Offset_Internal (patch 20260402, FField new system)
//    Confirmed live: stored as PLAIN uint32 at FProperty+0xD8.
//    NOTE: +0xE0 is NOT Offset_Internal — it holds a FFieldClass-like pointer.
// =============================================================================
inline int32_t DecryptPropertyOffset(uint32_t raw) {
    // No decryption needed: raw is already the plain byte offset.
    return static_cast<int32_t>(raw);
}

// =============================================================================
// 2b. UProperty Offset_Internal (patch 20260402, old UField/UProperty system)
//    Confirmed from sub_140441080 constructor and live FVector X/Y/Z properties:
//    stored = bswap32(rawOffset ^ 0xC43565C9)
//    decode = bswap32(stored) ^ 0xC43565C9
//    Verified: X=0, Y=8, Z=16 (FVector uses double = 8 bytes per component).
// =============================================================================
inline int32_t DecryptUPropertyOffset(uint32_t stored) {
    return static_cast<int32_t>(__builtin_bswap32(stored) ^ 0xC43565C9u);
}

// =============================================================================
// 3. Key Structure Offsets (patch 20260409)
// =============================================================================
// =============================================================================
// Offsets — RUNTIME-MUTABLE GLOBALS.
//
// Every member here is `inline` (not `constexpr`) so AutoOffsets::DiscoverAll()
// can overwrite the compile-time defaults at startup with values probed from
// live data. The defaults are the last-verified CL-1177146 values; on a new
// patch the probe phase walks each candidate offset, scores it against type-
// shape oracles (heap-ptr / module-ptr / TArray-shape / parent-backref / etc.),
// and writes the consensus winner here. All ~108 read sites consume these
// directly so no consumer-side change is needed when the layout shifts.
// =============================================================================
namespace Offsets {
    // Set when a patch's layout has been recovered from the constructors that
    // WRITE these fields, rather than inferred from live pointer shapes. The
    // live probes in auto_offsets.h then report disagreements instead of
    // applying them — see AutoOffsets::VetoOverride.
    inline bool        g_Authoritative = false;
    inline const char* g_AuthoritySrc  = "";

    namespace UObject {
        inline uint64_t VTable       = 0x00;
        inline uint64_t InternalIndex= 0x0C;
        inline uint64_t FieldsSlots  = 0x20;
    }
    namespace FField {
        inline uint64_t VTable        = 0x00;
        inline uint64_t ClassPrivate  = 0xC0;     // CL-1315578 (IDA sub_1403C5FE0 result[12]; was 0x70 on CL-1299607)
        inline uint64_t Next          = 0x78;     // CL-1315578 (IDA sub_1403C5FE0 result[7].hi64; was 0x60 on CL-1299607)
        inline uint64_t Owner         = 0x80;     // CL-1315578 (IDA sub_1403C5FE0 result[8].lo64; was 0x58 on CL-1299607)
        inline uint64_t NameEncrypted = 0xA0;     // CL-1315578 (IDA sub_1403C5FE0 result[10]; was 0x40 on CL-1299607)
        inline uint64_t NamePrivate   = 0xA0;     // CL-1315578 (IDA sub_1403C5FE0 result[10]; was 0x40 on CL-1299607)
        inline uint64_t SaltSentinel  = 0xB0;     // CL-1315578 (IDA sub_1403C5FE0 result[11].lo64; was 0x68 on CL-1299607)
    }
    namespace FFieldClass {
        inline uint64_t ElementSize  = 0x70;
    }
    namespace FProperty {
        inline uint64_t ArrayDim        = 0x110;  // CL-1315578 (IDA sub_140438E50 a1+272=1; was 0xC0 on CL-1299607)
        inline uint64_t ElementSize     = 0xD0;   // CL-1315578 (IDA sub_14042DF20 a1[52]; was 0x7C on CL-1299607)
        inline uint64_t Offset_Internal = 0xE4;   // CL-1315578 (auto-discovered; was 0x94 on CL-1299607)
        inline uint32_t Offset_XOR      = 0xA271DBC5u;  // CL-1315578 (auto-discovered; was 0x057F15E5 on CL-1299607)
        inline uint64_t PropertyFlags   = 0xE8;   // CL-1315578 (estimate — between OffsetInternal+0xE4 and ArrayDim+0x110; was 0x80 on CL-1299607)
    }
    namespace FBoolProperty {
        inline uint64_t FieldSize  = 0x138;  // CL-1315578 (shifted +0x50; was 0xE8 on CL-1299607)
        inline uint64_t ByteOffset = 0x139;  // CL-1315578 (shifted +0x50; was 0xE9 on CL-1299607)
        inline uint64_t ByteMask   = 0x13A;  // CL-1315578 (shifted +0x50; was 0xEA on CL-1299607)
        inline uint64_t FieldMask  = 0x13B;  // CL-1315578 (shifted +0x50; was 0xEB on CL-1299607)
    }
    namespace FStructProperty  { inline uint64_t Struct        = 0x138; }  // CL-1315578 (IDA sub_140450230 a1+312; was 0xE8 on CL-1299607)
    namespace FObjectProperty  { inline uint64_t PropertyClass = 0x138; }  // CL-1315578 (shifted +0x50; was 0xE8)
    namespace FEnumProperty    {
        inline uint64_t UnderlyingProp = 0x138;                             // CL-1315578 (shifted +0x50; was 0xE8)
        inline uint64_t Enum           = 0x140;                             // CL-1315578 (shifted +0x50; was 0xF0)
    }
    namespace FArrayProperty   { inline uint64_t Inner         = 0x138; }  // CL-1315578 (shifted +0x50; was 0xE8)
    namespace FSetProperty     { inline uint64_t ElementProp   = 0x138; }  // CL-1315578 (shifted +0x50; was 0xE8)
    namespace FSoftObjectProperty { inline uint64_t PropertyClass = 0x138; } // CL-1315578 (shifted +0x50; was 0xE8)
    namespace FMapProperty {
        inline uint64_t KeyProp   = 0x138;                                 // CL-1315578 (shifted +0x50; was 0xE8)
        inline uint64_t ValueProp = 0x140;                                 // CL-1315578 (shifted +0x50; was 0xF0)
    }
    namespace UField {
        inline uint64_t Next            = 0x90;
    }
    namespace UProperty {
        inline uint64_t Next            = 0x90;
        inline uint64_t Offset_Internal = 0x64;
        inline uint64_t ElementSize     = 0x68;
        inline uint64_t ArrayDim        = 0x6C;
        inline uint64_t PropertyFlags   = 0x70;
    }
    namespace UStruct {
        // CL-1177678: shifted from CL-1177146. Verified live against
        // Pawn(0x75B71600).Super=Actor(0x2A5A9700) and Actor.Super=UObject_UClass
        // (0x2A5A1300). PropertiesSize verified: Actor=0x3A0, Pawn=0x430,
        // ARFilter=0x150 — all read from +0x110.
        // CL-1195482: UStruct layout shifted significantly. Live histogram
        // probe across 32 UClass samples shows heap-pointer hits at:
        //   off=+0x168 hits=32/32  ← ChildProperties (FField chain head)
        //   off=+0x148 hits= 2/32
        //   off=+0x178 hits= 1/32
        // auto-offsets probe identifies PropertiesSize at +0x100 (auto-fixed
        // from 0x190 by live oracle, 100/200 hits).
        inline uint64_t SuperStruct     = 0xB0;    // CL-1299607 (live-verified: EmbarkPlayerController→PlayerController→Controller→Actor)
        inline uint64_t Children        = 0xC8;    // alias for ChildProperties (FField walk)
        inline uint64_t ChildProperties = 0xC8;    // CL-1299607 (IDA sub_143A848D0 a2+200; was 0x118)
        inline uint64_t PropertiesSize  = 0xD0;    // CL-1315578 (auto-discovered; was 0x90 on CL-1299607)
        inline uint64_t MinAlignment    = 0x94;    // CL-1299607 (follows PropertiesSize; was 0xE4)
    }
    namespace UEnum {
        inline uint64_t Names = 0x60;            // CL-1299607 (-0x50 shift; was 0xB0)
    }
    namespace UFunction {
        inline uint64_t VTable        = 0x000;
        inline uint64_t NextPtr       = 0x048;   // CL-1299607 (-0x50 shift; was 0x098)
        inline uint64_t FunctionFlags = 0x128;   // CL-1299607 (live-verified: 0x54020401 = FUNC_Native|... at this offset)
        inline uint64_t NativeFunc    = 0x150;   // CL-1299607 (live-verified: 0x145F0E3A0 module .text ptr)
        inline uint64_t NumParms      = 0x12C;   // CL-1299607 (right after FunctionFlags at +0x128)
    }
    namespace UClass {
        inline uint64_t FuncMap_PairsData      = 0x218;  // CL-1299607 (live-verified: Actor Num=140, UFunction ptrs confirmed)
        inline uint64_t FuncMap_Num            = 0x220;  // CL-1299607 (live-verified)
        inline uint64_t FuncMap_Max            = 0x224;  // CL-1299607 (live-verified)
        inline uint64_t FuncMap_AllocFlags     = 0x238;  // CL-1299607 (TBitArray secondary ptr, live-verified)
        inline uint64_t FuncMap_AllocFlagsNum  = 0x240;  // CL-1299607 (NumBits)
        inline uint64_t FuncMap_FirstFreeIdx   = 0x248;  // CL-1299607 (live-verified: -1 when no free)
        inline uint64_t FuncMap_NumFreeIndices = 0x24C;  // CL-1299607 (live-verified: 0 when no free)
        inline uint64_t FuncMap_PairStride = 24;
        inline uint64_t FuncMapPair_FName    = 0x00;
        inline uint64_t FuncMapPair_UFunction = 0x08;
    }
    namespace UWorld {
        inline uint64_t PersistentLevel = 0x0A0;  // CL-1299607 (-0x50 shift; was 0x0F0)
        inline uint64_t Levels          = 0x360;  // CL-1299607 (-0x50 shift; was 0x3B0)
    }
    namespace USceneComponent {
        inline uint64_t ComponentToWorld = 0x2E0;  // CL-1299607 (-0x50 shift; was 0x330)
    }
}

// =============================================================================
// 4. Global Address Constants (patch 20260409)
// =============================================================================
constexpr uint64_t MODULE_BASE = 0x140000000;

// Runtime-overridable anchors (sig-scan may rewrite these at Init; hardcoded
// values are the fallback and the "known good for current patch" default).
// Values are the latest verified patch's defaults; older patches kept as
// comments so a stale sig-scan or a partial revert can fall back gracefully.
inline uint64_t RVA_GWORLD              = 0xE83FC58;   // CL-1233465 (was 0xE706C58 on CL-1201801)
inline uint64_t RVA_GNAMES_BASE         = 0xE0ED7D0;   // CL-1201801 live (was 0xE23DA00; CL-1177146: 0xDBB3F80, 20260428: 0xDB5BE80)
inline uint64_t RVA_FNAME_KEY_TABLE     = 0xDE5B6E0;   // CL-1201801 (= SIMD consts block 0xDE5B6D8 + 8); 20260519: 0xE17C7FC; CL-1177146: 0xDAF88EC
inline uint64_t RVA_GOBJECT_ARRAY_BASE  = 0xE4F8F60;   // CL-1195482 (Steam 19.05 evening; was 0xE4F8ED0 in pre-CL-1195482 morning build)
constexpr uint64_t GOBJ_ENCRYPTED_OFF   = 0x30;        // legacy pipeline offset (unused on 20260428: NumElements is plain at +0x38)

// SIMD runtime tables (GUObjectArray decrypt — patch 20260414)
// Pipeline: ROL32(20) → XOR(key) → ROL16(12) [no PSHUFB step]
inline uint64_t RVA_SIMD_OBJARRAY_XOR   = 0xAD2FC50;
// Element count: AND/ANDNOT blend → XOR → ROL16(12) → PSHUFB(constant)
inline uint64_t RVA_ELEM_MASK_A         = 0xAD8EE10;
inline uint64_t RVA_ELEM_MASK_B         = 0xAD8EE20;
inline uint64_t RVA_ELEM_XOR_KEY        = 0xAD8EE30;

// SIMD runtime tables (CIdx → FName address resolve — patch 20260414)
// Level 1 CIdx decode CHANGED: CI → ROL16(14) → PSHUFLW(0x93) → PXOR(cidxXor1)  [no PSHUFB]
inline uint64_t    RVA_CIDX_XOR1         = 0xAD30540;  // CIdx pxor key (was 0xAC64940)
// Level 2 CIdx decode
constexpr uint64_t RVA_CIDX_XOR3         = 0xAD30590;  // second-level XOR (was 0xAC64CE0)
// Block header decrypt tables (patch 20260414)
constexpr uint64_t RVA_BLOCK_HDR_AND     = 0xAD305C0;  // AND mask (was 0xAC64AE0)
constexpr uint64_t RVA_BLOCK_HDR_ANDNOT  = 0xAD305B0;  // ANDNOT source (was 0xAC64AD0)
constexpr uint64_t RVA_BLOCK_HDR_SHUF    = 0xAD2FCC0;  // pshufb mask (was 0xAC64AF0) — moved to CIdx HDR area
constexpr uint64_t RVA_BLOCK_HDR_XOR     = 0xAD305D0;  // pxor key (was 0xAC64B00)
// Slot data PSHUFB masks (FName block decrypt — patch 20260414)
constexpr uint64_t RVA_BLOCK_SLOT_SHUF   = 0xAD305A0;  // slot pshufb (was 0xAC64950)
constexpr uint64_t RVA_BLOCK_SLOT_SHUF2  = 0xAD30550;  // slot decrypt pshufb (new)

// UObject field slot decrypt (confirmed from sub_1404E8610 / UObjectHash.cpp, patch 20260409)
// Pipeline: ROL64(45) → PSHUFLW(0x1E) → extract lo64 → XOR(sentinel)
// FName:    same pipeline, then ROL64(32) → lo32=CI, hi32=Number
// Pointer:  same pipeline → result is pointer directly
// Null:     after ROL+PSHUFLW, lo64 == sentinel → null
constexpr uint64_t UOBJ_SLOT_SENTINEL    = 0x0B982F16865A5F21ULL;  // was 0x07C3784BD4ECB382
constexpr int      UOBJ_SLOT_ROL64       = 45;           // ROL64 applied FIRST (was PSHUFLW first)
constexpr int      UOBJ_SLOT_PSHUFLW_IMM = 0x1E;         // applied AFTER ROL64 (was 0x93)
// After XOR(sentinel): pointer fields give ptr directly; FName fields need ROL64(32) for CI
constexpr int      UOBJ_SLOT_FNAME_ROL   = 32;           // final ROL64 for FName (swap hi/lo)

// GObjectArray decrypt pipeline constants (patch 20260414)
// ROL32(20) → XOR(key) → ROL16(12)  [pipeline restructured]
constexpr int      OBJARRAY_ROL32        = 20;            // was 9
constexpr int      OBJARRAY_ROL16        = 12;            // replaces PSHUFLW
// Element count: XOR(key) → ROL16(12) → PSHUFB(shuf) — TODO: verify PSLLQ/pextrd with IDA
constexpr int      OBJCNT_PSLLQ          = 15;            // TODO: verify with IDA

// CIdx pipeline constants (patch 20260414)
// Level 1 CHANGED: ROL16(14) → PSHUFLW(0x93) → PXOR  [no PSHUFB, no ROL64]
constexpr int      CIDX_ROL16            = 14;            // was ROL64(13), now ROL16
constexpr int      CIDX_PSHUFLW_IMM      = 0x93;
// Block header: AND/ANDNOT → PSHUFB → PXOR → XOR(HDR_XOR) → ROL32(HDR_ROL)
constexpr uint32_t CIDX_HDR_XOR          = 0x0A48BA45u;   // bswap of {45,BA,48,0A} (was 0x8440FBE5)
constexpr int      CIDX_HDR_ROL          = 30;            // unchanged

// FName slot index FNV-32 step constants (patch 20260409)
// hash_addr = pool_base + pool_off + 0x90
// s1 = P * (hash_addr_lo >> 5) + K
// s2 = P * ROL32(s1, 19) + hi + K
// s3 = P * ROL32(s2, 27) + K
// v7 = P * (s3 >> 13) + K
// slot_idx = ((uint8_t)v7 ^ BYTE2(v7)) & 7
constexpr uint32_t FNV32_SLOT_PRIME      = 0x1000193u;    // unchanged
constexpr uint32_t FNV32_SLOT_K          = 0x866DFAD3u;   // was 0x8FD97DFC (patch 20260414)
constexpr uint64_t FNV32_HASH_OFF        = 0x90;          // was 0x7080
constexpr uint64_t FNV32_SLOT_OFF        = 0xA0;          // was 0x7090

// FName block decrypt FNV-64 chain constants (patch 20260409)
constexpr uint64_t FNAME_FNV_PRIME       = 0x100000001B3ULL;          // unchanged
// FName block resolve constants (patch 20260414, confirmed working)
// Block decrypt: PSHUFLW(0x2D=45) → ROL16(15) — no XOR
constexpr int      FNAME_BLOCK_PSHUFLW   = 0x2D;          // PSHUFLW immediate for block decrypt
constexpr int      FNAME_BLOCK_ROL16     = 15;            // ROL16 amount for block decrypt
// FNV fold: ROL64(57) → P*x + OFFSET → ROL64(42) → P*x + OFFSET
constexpr uint64_t FNAME_FNV_OFFSET      = 0x2AE2DE663CDF7F3AULL;
constexpr int      FNAME_FNV_ROL1        = 57;            // was 27/31
constexpr int      FNAME_FNV_ROL2        = 42;            // was 45/44
// Pointer fixup: bswap64(R ^ XOR1) ^ XOR2 → bswap64(^ XOR3)
constexpr uint64_t FNAME_PTR_XOR1        = 0x2ECA4D72ULL;
constexpr uint64_t FNAME_PTR_XOR2        = 0x0020CE00000000ULL;
constexpr uint64_t FNAME_PTR_XOR3        = 0x724DEAE000000000ULL;
// Block hash: ROL32(20,22,20), >>10, K=0x9583237A
constexpr uint32_t FNAME_BHASH_ADD       = 0x9583237Au;
// Per-chunk pointer at chunk_header + 0xD8 = SHARED module cache base (same for all chunks).
// Real per-chunk heap pool is at chunk_header + 0xD0 (used by hashtable lookup, not direct
// resolve). The resolver in fname_decrypt.h reads this shared cache once and adds
// `(CI >> 8) & 0x1FFF00` as a sub-block offset before walking blocks at +32 + 32*idx.
constexpr int      FNAME_CHUNK_BLOCK_PTR_OFF = 0xD8;

// FName string decrypt key constants (patch 20260414, confirmed working)
// Header: isWide = bit15 (header < 0 as int16), charCount = header & 0x3FF
// ANSI: key = (uint16)(charCount - 25184); buf[i] ^= keyTable[(key+i) & 0x3F] >> 3
// Wide: key = charCount + 40352; word[i] ^= keyTable[(key+i) & 0x3F]
// Key table: 64 uint16 entries at RVA_FNAME_KEY_TABLE (sequential, no +offset)
constexpr int      FNAME_ANSI_KEY_BASE    = -25184;       // (uint16)(cc + this) = starting key
constexpr int      FNAME_WIDE_KEY_BASE    = 40352;        // cc + this = starting key

// UProperty (old UField-subclass) FName storage — patch 20260409
// Same pipeline: PSHUFB(inv_mask) → ROR32(6) → XOR(key) → ROL64(32) → lo32=CI
constexpr uint64_t UPROP_FNAME_OFFSET    = 0x50;
constexpr uint64_t UPROP_FNAME_XOR_KEY   = 0x19AE9873B7A3AC48ULL;     // same key as FNAME_BLOCK2_XOR (patch 20260414)

// =============================================================================
// 5. Patch 20260421 / 20260428 active constants
//
// 20260428 (2026-04-28) breakdown — RE'd from IDA instance jjn1
// (binary `ARC_RAIDERS_UNKNOWN_20260428_111248_D3D694C7_77PagesDecrypted.exe`):
//
// - FNamePool resolver: shape mostly preserved, but ~every constant changed.
//   See FNamePool20260421 below — values updated in-place; old values kept
//   in trailing comments. Verified from `sub_22F3E0` (FNamePool_ResolveCI)
//   decompile.
// - GUObjectArray encrypted blob moved to +0xB0 (was +0x00 in 20260421).
//   Decrypt shape now uses PSHUFLW(0x1E) → ROL16(1) (similar to old FField
//   name decrypt). `vtable[5]` (offset 40) replaces `vtable[7]` for the
//   chunks_manager indirection. Full chain still needs live RE.
// - FNameEntry decrypt is no longer a simple per-byte XOR. It's now a
//   stateful LCG that emits two keystream lookups per pair, with a
//   multiplicative state advance — see feedback_20260428_breakdown.md
//   for the exact formula. New keytable RVA = 0xDAA07F4.
// =============================================================================
namespace Patch20260421 {
    // FName_ToString @ RVA 0x24C8130 recovers the entry pointer from the
    // public FName handle via:
    //     entry_ptr = bswap64(handle_qword ^ ENTRY_HANDLE_XOR)
    //
    // Runtime-overridable: extracted from the live game's FName function
    // body during DiscoverFNameConsts (see find_fname_func.h::ExtractEntryHandleXor).
    // If extraction fails, the patch-20260421 default is used.
    // 20260428: 0x9CB9AD0A00000000  (auto-extracted at runtime by
    //           find_fname_func.h::ExtractEntryHandleXor; verified in IDA jjn1
    //           decompile of FName_ToString_20260428 @ 0x23AD40)
    // 20260421: 0x59B07C3D00000000
    inline uint64_t ENTRY_HANDLE_XOR = 0x91BB95D79830CB3DULL;
    inline void SetEntryHandleXor(uint64_t v) { ENTRY_HANDLE_XOR = v; }

    // Secondary XOR seen on (entry + 192) field in FName_ToString:
    //     field_dec = bswap32(*(u32*)(entry+0xC0) ^ ENTRY_FIELD_XOR)
    constexpr uint32_t ENTRY_FIELD_XOR       = 0x01C4B859u;

    // FNamePool base — moved each patch.
    //   20260414: 0xDB48E80
    //   20260421: 0xDB0FE00
    //   20260428: 0xDB5BE80   (verified via init guard `byte_DB5BE78` before
    //                           the static initializer in FNamePool_ResolveCI)
    constexpr uint64_t RVA_GNAMES_BASE_NEW   = 0xDB5BE80;

    // FNameEntry keystream table (shifted +0x4C000 in 20260428).
    // Old (≤20260421): 0xDA547F4 — still has structured non-keystream bytes,
    //                  causes `[sig] FNameKeyTbl 0xDA547F4 (matches constant)`
    //                  false positive in current sig scan.
    // New (20260428): 0xDAA07F4 (uniform-random byte pattern; verified via
    //                  FNameEntry_AppendNameToString_20260428 decompile).
    constexpr uint64_t RVA_FNAME_KEYSTREAM   = 0xDAA07F4;

    // FField NamePrivate decrypt SIMD constants moved:
    //   PSHUFB mask (`07 02 03 06 05 00 01 04`) — was 0xAD85670
    //   XOR const  (`31 7E 97 77 56 27 31 31`) — was 0xAD85690
    // 20260428 live-verified locations (IDA instance e3k3, doubled in .rdata):
    //   0xB59FDF0 / 0xB59FE00 are stale (zero-filled in 20260428).
    //   Real PSHUFB mask now at 0xB5E3020 (and 0xB5E3028); real XOR const at 0xB5E3030 (and 0xB5E3038).
    // Patch CL-1177146 (2026-04-30): both moved by +0x18E1E0 to:
    //   PSHUFB mask 0xB771200; XOR const 0xB771210.
    constexpr uint64_t RVA_FFIELD_PSHUFB_MASK = 0xB771200;
    constexpr uint64_t RVA_FFIELD_XOR_CONST   = 0xB771210;

    // GUObjectArray moved from 0xDE04650 → 0xDDCB420.
    // The 16-byte xmmword at this address IS the encrypted chunks-manager
    // pointer (NOT at +0x30 as in the older patch).
    //
    // Pipeline (verified on live PID, patch 20260421):
    //     a = ROL32(xmmword_DDCB420, 23)
    //     b = PSHUFB(a, xmmword_ACBFCA0_lo64)        (loadl_epi64 → low 8 bytes)
    //     c = ROL32(b, 13)
    //     chunks_manager_ptr = lo64(c)
    //
    // NumElements/MaxElements — at chunks_manager + 0x70 (encrypted xmmword):
    //     a2 = PSHUFLW(enc, 0xA3)                   (lane permute 3,0,2,2)
    //     b2 = PXOR(a2, xmmword_AD12960_lo64)
    //     num = lo32(ROL64(b2, 15))
    //
    // FUObjectItem stride = **20 bytes** (not 24). ObjectsPerChunk = 65536.
    //   chunk_idx = iter >> 16;  in_chunk = iter & 0xFFFF
    //   slot = chunks_array[chunk_idx] + 20 * in_chunk
    // 20260428: GUObjectArray moved to 0xDE173A0 AND the encrypted blob
    // moved from +0x00 to +0x B0. The `RVA_GUOBJECT_ARRAY_NEW` is now
    // mutable so `sig_scan` can update it; `RVA_GOBJECT_ARRAY_BASE`
    // (in the parent namespace) is also auto-fixed but the 20260421 path
    // was reading this stale constexpr instead.
    inline    uint64_t RVA_GUOBJECT_ARRAY_NEW   = 0xDE173A0;   // 20260421: 0xDDCB420
    constexpr uint64_t RVA_GOBJ_PSHUFB_MASK     = 0xACBFCA0;   // 20260428: pipeline shape changed; this RVA is stale
    constexpr uint64_t RVA_GOBJ_MAX_XOR_KEY     = 0xAD12960;   // 20260428: pipeline shape changed; this RVA is stale
    constexpr int      GOBJ_PIPELINE_ROL32_A    = 23;
    constexpr int      GOBJ_PIPELINE_ROL32_B    = 13;
    constexpr int      GOBJ_MAX_PSHUFLW_IMM     = 0xA3;
    constexpr int      GOBJ_MAX_ROL64           = 15;
    constexpr uint64_t GOBJ_MANAGER_MAX_OFFSET  = 0x70;
    constexpr int      FUOBJECTITEM_STRIDE      = 20;
    constexpr int      OBJECTS_PER_CHUNK        = 0x10000;

    // FName CityHash64 entry point (moved from 0xC0C80).
    // 20260421: 0xC1960
    // 20260428: 0xF1540  — verified via cross-binary signature `48 B8 4F 40 90 2F 3B 6A E1 9A 41 83 FD 10 0F 87` (see SIGNATURES.md §11.5)
    constexpr uint64_t RVA_FNAME_CITYHASH64   = 0xF1540;

    // FName_ToString entry.
    // 20260421: 0x24C8130
    // 20260428: 0x24BE2F0 — verified via §11.1 signature still hitting on new binary
    constexpr uint64_t RVA_FNAME_TOSTRING     = 0x24BE2F0;

    // Decrypt the public FName handle (the 64-bit value stored in any
    // FName-typed field) to recover a pointer to the FNameEntry.
    inline uint64_t DecryptEntryHandle(uint64_t handle) {
        return __builtin_bswap64(handle ^ ENTRY_HANDLE_XOR);
    }

    // Decrypt the GUObjectArray encrypted chunks-manager pointer.
    // Reads 16 bytes from the global and returns the lo64 of the pipeline.
    // Verified on live PID: gave 0x183E1110 from xmmword `0000110101E00182`.
    inline uint64_t DecryptGObjChunksManager(const uint8_t* enc16,
                                             const uint8_t* pshufb_mask_lo8)
    {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc16));
        // ROL32(23) = PSLLD(23) | PSRLD(9)
        __m128i a = _mm_or_si128(_mm_slli_epi32(v, 23),
                                 _mm_srli_epi32(v, 9));
        // PSHUFB with the 8-byte mask loaded via loadl_epi64 (high 8 bytes zero)
        alignas(16) uint8_t mask_full[16] = {};
        std::memcpy(mask_full, pshufb_mask_lo8, 8);
        __m128i m = _mm_load_si128(reinterpret_cast<const __m128i*>(mask_full));
        __m128i b = _mm_shuffle_epi8(a, m);
        // ROL32(13)
        __m128i c = _mm_or_si128(_mm_slli_epi32(b, 13),
                                 _mm_srli_epi32(b, 19));
        uint64_t lo;
        _mm_storel_epi64(reinterpret_cast<__m128i*>(&lo), c);
        return lo;
    }

    // =========================================================================
    // FField NamePrivate decrypt (patch 20260421) — from FField_GetFName @ 0x3DBE00.
    // The 16-byte encrypted slot lives at FField+0x60. Pipeline:
    //   1. PSHUFLW(slot, 0x1E)
    //   2. XOR with xmmword_AD15750  (low 8 bytes: 38 BA 6F 75 E8 89 57 36; high = 0)
    //   3. ROL16(lo_qword, 1) per word-lane
    //   4. Take lo64
    //   5. ROL64(lo64, 32) → final = (Number << 32) | CI  (CI in LO32)
    // =========================================================================
    namespace FFieldName20260421 {
        // 20260428: XOR const relocated from AD15750 → AD0FE50 (lo8 + zero8).
        // CL-1177146 (2026-04-30): relocated again to B7FF0E0; layout now lo8 + permuted-lo8
        // (38 BA 6F 75 E8 89 57 36 | 57 36 E8 89 38 BA 6F 75) instead of lo8 + zero8.
        // Reading 16 bytes still yields the canonical XOR const in the lo qword.
        constexpr uint64_t RVA_XOR_CONST = 0xB7FF0E0;  // 20260428: 0xAD0FE50
        constexpr int      PSHUFLW_IMM   = 0x1E;
        constexpr int      ROL16_AMT     = 1;
        constexpr int      ROL64_AMT     = 32;
    }

    // =========================================================================
    // FProperty::Offset_Internal decrypt (patch 20260421)
    //   stored = bswap32(real) ^ 0x01C4B859    (equivalent: bswap32(real ^ 0x59B8C401))
    //   real   = bswap32(stored) ^ 0x59B8C401  (equivalent: bswap32(stored ^ 0x01C4B859))
    // stored=0x01C4B859 (sentinel) decrypts to 0.
    // =========================================================================
    // Runtime-overridable XOR key for FProperty::Offset_Internal decrypt.
    // Set by AutoDiscovery::DiscoverFPropertyOffsetXor at init time. Falls
    // back to the CL-1177146 verified value when discovery hasn't run.
    inline uint32_t g_PropertyOffsetXor = 0xA271DBC5u;   // CL-1315578 (auto-discovered; was 0x057F15E5 on CL-1299607)

    inline uint32_t DecryptPropertyOffsetNew(uint32_t stored) {
        // CL-1195482: the IDA *encode* sites do `xor eax, 0xD632B3E9; bswap eax;
        // mov [rbx+0x64], eax`. That stores `bswap(real ^ XOR)`. The inverse is
        // `bswap(stored) ^ XOR` — bswap first, then xor. Our previous form
        // (`bswap(stored ^ XOR)`) collapses to `real ^ (XOR ^ bswap(XOR))` which
        // produces garbage for every offset except where the constant happens
        // to be its own bswap.
        return __builtin_bswap32(stored) ^ g_PropertyOffsetXor;
    }

    // =========================================================================
    // UObject NamePrivate/ClassPrivate/OuterPrivate slot decrypt (patch 20260421)
    // — from sub_24DEB60 @ 0x24DEB60. Slot layout unchanged from prior patches:
    //   4 slots at obj+0x20, +0x40, +0x60, +0x80 (stride 0x20).
    // Decrypt (on the 16-byte slot): PSHUFLW(0xB1) → ROL32(15) per lane
    //   → PSHUFB(mask_AD128C0) → XOR(const_AD128D0) → take lo64.
    // Result: if the slot holds an FName, lo64 = (CI << 32) | Number.
    //         if it holds a pointer (Class/Outer), lo64 = heap pointer.
    // =========================================================================
    namespace UObjSlot20260421 {
        // Patch CL-1177146 (2026-04-30): pipeline simplified to PSHUFB(mask) → XOR(const_lo64).
        // No ROL32 between PSHUFB and XOR; ROL64(32) applied only to NAME slot (post-XOR).
        // PSHUFB mask @ RVA 0xAD93EF0 = 06 05 02 03 04 01 00 07 (verified IDA + live).
        // XOR const  @ RVA 0xAD93F00 = 0x5EA772D07F910744 (lo64) (verified IDA + live).
        constexpr uint64_t RVA_SHUF_MASK   = 0xAD93EF0;
        constexpr uint64_t RVA_XOR_CONST   = 0xAD93F00;
        constexpr uint64_t SLOT_XOR_CONST  = 0x5EA772D07F910744ULL;  // CL-1177146 live-verified
        constexpr int      PSHUFLW_IMM     = 0xB1;
        constexpr int      ROL32_AMT       = 0;       // CL-1177146: pipeline has NO rol32 step
        constexpr int      ROL64_AMT       = 32;
        // Slot base offset and stride (same as older patches).
        constexpr int      SLOT_BASE_OFF   = 0x20;
        constexpr int      SLOT_STRIDE     = 0x20;
    }

    // =========================================================================
    // 20260428 UObject 4-slot decrypt — pipeline ENTIRELY DIFFERENT from 20260421
    // From REFERENCE_FName_20260428.h ("Actor FName decrypt"):
    //   shuffle_epi8(enc, ACTOR_SHUF_MASK) → ROL32(17) → XOR(scalar) → ROL64(32)
    // Slot picker hash uses ROL32(25/27) and ADD=0x114E4953.
    // Slot offset = idx*32 + 0x20 (stride 0x20; same as older patches).
    // The decrypted lo32 IS the comp_index directly (no high-half "Number").
    // =========================================================================
    namespace UObjSlot20260428 {
        // CL-1177146: 8-byte PSHUFB mask (bytes: 06 05 02 03 04 01 00 07; lo64).
        // Was 01 06 00 04 07 03 02 05 on 20260428.
        constexpr uint8_t SHUF_MASK_BYTES[8] = { 0x06, 0x05, 0x02, 0x03,
                                                 0x04, 0x01, 0x00, 0x07 };
        constexpr uint64_t XOR_SCALAR    = 0x5EA772D07F910744ULL;  // CL-1177146 live-verified (lo64 of xmm @ 0xAD93F00)
        constexpr int      ROL32_AMT     = 0;        // CL-1177146: NO rol32 between PSHUFB and XOR
        constexpr int      ROL64_AMT     = 32;
        constexpr int      SLOT_BASE_OFF = 0x20;
        constexpr int      SLOT_STRIDE   = 0x20;

        // Slot index hash constants — verified IDA lf50 (sub_2CB4E0/sub_2D6900):
        //   s1 = P * ROL32(lo, 24) + ADD
        //   s2 = P * ROL32(s1, 25) + ADD
        //   t  = hi + s2
        //   s3 = P * ROL32(t, 24) + ADD
        //   v3 = P * (s3 >> 7) + ADD
        //   raw_idx   = ((u8(v3) ^ BYTE2(v3)) & 3)
        //   name_slot = (raw_idx ^ 2) & 3
        //   class_slot = raw_idx (no XOR fold)
        //   outer_slot = (raw_idx + 1) & 3
        constexpr uint32_t HASH_PRIME = 0x01000193u;     // FNV32 prime (unchanged)
        constexpr uint32_t HASH_ADD   = 0x8E195662u;     // CL-1177146 verified
        constexpr int      HASH_ROL1  = 24;              // CL-1177146 verified
        constexpr int      HASH_ROL2  = 25;              // CL-1177146 verified
        constexpr int      HASH_ROL3  = 24;              // CL-1177146: third ROL on (t)
        constexpr int      HASH_SHR1  = 7;
        constexpr int      HASH_SHR2  = 0;               // CL-1177146: only one SHR (was 5 on older patches)
    }

    // =========================================================================
    // 20260428 FNamePool full resolver — verified via REFERENCE_FName_20260428.h
    // Takes a comp_index (i32) and returns FNameEntry*. Three-stage SIMD CI
    // transform → block-selector hash → 2 block decrypts → FNV fold → 3-XOR
    // pointer fixup.
    // =========================================================================
    namespace FNamePool20260428 {
        constexpr uint64_t CHUNK_FNV_SEED_OFF  = 0x7090;   // 28816
        constexpr uint64_t CHUNK_BLOCK_BASE_OFF = 0x70A0;  // 28832

        // CI 3-stage transform constants (verified live + reference):
        //   Stage 1 SHUF1 @ 0xAD49100 — bytes (lo8): 00 02 00 01 03 00 00 00 (replicated to hi8)
        //   Stage 1 XOR1  @ 0xAD49110 — bytes (lo8): BC BD 4B 43 C8 09 FF 4B (replicated to hi8)
        //   Stage 2 XOR   @ 0xAD49390 — bytes (lo8): 00 BD 00 43 C8 09 00 00 (replicated to hi8)
        //   Stage 3 SHUF  @ 0xAD49140 — bytes:       05 03 01 04 00*12       (CI extract mask)
        //   Stage 3 XOR   @ 0xAD49150 — bytes:       09 43 BD C8 00*12       (CI extract const)
        constexpr uint64_t RVA_GIDX_SHUF1   = 0xAD49100;
        constexpr uint64_t RVA_GIDX_XOR1    = 0xAD49110;
        constexpr uint64_t RVA_STAGE2_XOR   = 0xAD49390;
        constexpr uint64_t RVA_EXTRACT_SHUF = 0xAD49140;
        constexpr uint64_t RVA_EXTRACT_XOR  = 0xAD49150;
        constexpr int      STAGE_PSHUFLW_IMM = 0xB1;
        constexpr int      STAGE_ROL32_A     = 17;  // stages 1/2 final ROL
        constexpr int      STAGE_ROL32_B     = 15;  // stages 2/3 entry ROL

        // Block-selector hash:
        //   h = ((seed_lo >> 6) | 0x40000000) → P*h + BHASH_ADD
        //   h = ROL32(h, 28) → P*h + seed_hi + BHASH_ADD
        //   h >>= 6; h = P*h + BHASH_ADD; h >>= 4
        //   nxt = P*h + BHASH_ADD
        //   bidx = ((-109*h - 126) ^ (nxt >> 16)) & 0xFF
        constexpr uint32_t BHASH_PRIME = 0x01000193u;
        constexpr uint32_t BHASH_ADD   = 0xCA104182u;  // (= -904904318)
        constexpr int      BHASH_ROL   = 28;

        // Block decrypt (8-byte PSHUFB mask + 16-bit ROL + scalar XOR):
        //   shuffle_epi8(slot, BLOCK_SHUF) → ROL16(5) → XOR(BLOCK_POST_XOR)
        // BLOCK_SHUF @ 0xAD49130 (lo8): 05 00 06 04 03 07 02 01
        constexpr uint64_t RVA_BLOCK_SHUF      = 0xAD49130;
        constexpr int      BLOCK_ROL16_AMT     = 5;
        constexpr uint64_t BLOCK_POST_XOR      = 0x9F737271C0F041C4ULL;

        // FNV fold on first decoded block:
        //   fnv = P64 * ROL64(v14, 50) + OFF
        //   fnv = P64 * ROL64(fnv, 56) + OFF
        constexpr uint64_t FNV64_PRIME = 0x100000001B3ULL;
        constexpr uint64_t FNV64_OFF   = 0x7631B6D6E2D67842ULL;
        constexpr int      FNV64_ROL1  = 50;
        constexpr int      FNV64_ROL2  = 56;

        // Result composition:
        //   R = v14 + (fnv ^ v15_dec) + 2 * (uint16)v5
        //   a = bswap64(R ^ PTR_XOR_1)
        //   b = a ^ PTR_XOR_2
        //   name_ptr = bswap64(b ^ PTR_XOR_3)
        constexpr uint64_t PTR_XOR_1 = 0x00000000BD8F879CULL;
        constexpr uint64_t PTR_XOR_2 = 0x003E22B700000000ULL;
        constexpr uint64_t PTR_XOR_3 = 0x9CB9AD0A00000000ULL;  // = ENTRY_HANDLE_XOR
    }

    // =========================================================================
    // 20260428 FNameEntry string decrypt — char-based LCG (8-bit signed key)
    // Header:
    //   v3 = hdr & 0x7F
    //   v4 = (hdr >> 5) & 0x380
    //   length = v3 + v4
    //   isWide = bit15
    // Keystream (key is 8-bit signed, advances per-pair):
    //   key0 = (char)(length - 68)
    //   For each pair (i, i+1):
    //     idx_a = key & 0x3F
    //     idx_b = (68 * key + 96) & 0x3C
    //     ANSI:  byte ^= keytable[idx_a + 8] >> 3
    //            byte ^= keytable[idx_b + 8] >> 3
    //     Wide:  word ^= keytable[idx_a + 8]
    //            word ^= keytable[idx_b + 8]
    //     key = (char)(16 * key - 32)
    //   Trailing odd byte/word: ^= keytable[idx_a + 8] (>>3 for ANSI)
    // Key table is at RVA_FNAME_KEY_TABLE = 0xDAA07F4 (uint16 array; +8 entries
    // = +16 bytes pre-offset is the actual data; the +8 in the indexing
    // formulas is encoded in the keystream offsets themselves).
    // =========================================================================
    namespace FNameEntryString20260428 {
        constexpr int      KEY_TABLE_UINT16_OFFSET = 8;
        constexpr int8_t   KEY_START_BIAS = -68;
        constexpr int8_t   KEY_LCG_MUL    = 16;
        constexpr int8_t   KEY_LCG_ADD    = -32;
        constexpr uint8_t  IDX_A_MASK     = 0x3F;
        constexpr uint8_t  IDX_B_MASK     = 0x3C;
        constexpr uint8_t  IDX_B_MUL      = 68;
        constexpr uint8_t  IDX_B_ADD      = 96;
    }

    // =========================================================================
    // FNamePool resolve pipeline (patch 20260421) — from sub_242FC0 @ 0x242FC0
    //
    // Input: si128 = a 16-byte CI-encoded FName slot (output of the UObject
    // slot decrypt chain, or equivalent — see FName_ToString).
    // Output: FNameEntry* pointer on the heap.
    // =========================================================================
    namespace FNamePool20260421 {
        // Chunk header access: per-chunk data begins at RVA_GNAMES_BASE+chunk_off.
        // 20260421:  +0x6570 / +0x6580
        // 20260428:  +0x7090 / +0x70A0  (verified — sub_22F3E0 reads
        //            `v8 + 28816` and `v8[..*32 + 28832]`)
        constexpr uint64_t CHUNK_FNV_SEED_OFF = 28816;   // 0x7090 (was 0x6570 = 25968)
        constexpr uint64_t CHUNK_SLOT_BASE    = 28832;   // 0x70A0 (was 0x6580 = 25984)

        // CI decode pipeline shape changed in 20260428:
        //   20260421:  PSHUFLW(0x39) → PSRLD(6)        → PSHUFB(mask) → cvtsi128_si32
        //   20260428:  PSHUFLW(0xB1) → ROL32(15)       → PSHUFB(mask) → PXOR(const) → cvtsi128_si32
        // PSRLD is gone; ROL32(15) inserted; an extra PXOR step appears after PSHUFB.
        // The dumper's static decode in fname_decrypt.h::DecryptCI must be
        // rewritten to match — this namespace only carries the constants.
        constexpr uint64_t RVA_CI_PSHUFB_MASK = 0xAD49140;  // 20260421: 0xACF8D20
        constexpr uint64_t RVA_CI_XOR_CONST   = 0xAD49150;  // NEW (no analogue in 20260421)
        constexpr int      CI_PSHUFLW_IMM     = 0xB1;       // 20260421: 0x39
        constexpr int      CI_ROL32_AMT       = 15;         // NEW (20260421 used PSRLD 6, no ROL)

        // FNV32 hash constants (pick slot_idx)
        constexpr uint32_t FNV32_PRIME = 0x01000193u;
        constexpr uint32_t FNV32_K     = 0xCA104182u;        // 20260421: 0xCA3F9BE2 (signed -904904318)

        // Slot decrypt:
        //   20260421:  PSHUFLW(0x93) → ROL32(25) → lo64 → XOR(SLOT_XOR)
        //   20260428:  loadl(slot_mask) → PSHUFB → ROL16(5)  → lo64 → XOR(SLOT_XOR)
        // Per-uint16 lane rotation (was per-uint32). PSHUFB step uses an 8-byte
        // mask loaded via `loadl_epi64` from RVA_SLOT_PSHUFB_MASK.
        // Existing fname_decrypt.h::ResolveNamePtrFull lambda uses the 20260421
        // values; rewrite when wiring 20260428.
        constexpr uint64_t SLOT_XOR    = 0x9F737271C0F041C4ULL;  // 20260421: 0x662CF9C2408E7B59
        constexpr int      SLOT_ROL32  = 25;             // 20260421 (also: 20260428 SLOT_ROL_AMT=5 per uint16 lane)
        constexpr int      SLOT_PSHUFLW_IMM = 0x93;      // 20260421 (gone in 20260428; PSHUFB replaces it)
        // 20260428-specific (unused by current code):
        constexpr uint64_t RVA_SLOT_PSHUFB_MASK_20260428 = 0xAD49130;
        constexpr int      SLOT_ROL_AMT_20260428         = 5;
        constexpr int      SLOT_ROL_LANE_20260428        = 16;

        // FNV64 fold on v11 (first slot decrypted):
        //   fnv = P64 * ROL64(P64 * ROL64(v11, ROL1) + OFF, ROL2) + OFF
        constexpr uint64_t FNV64_PRIME  = 0x100000001B3ULL;
        constexpr uint64_t FNV64_OFF    = 0x7631B6D6E2D67842ULL;  // 20260421: 0xA369D63928ACD6A2
        constexpr int      FNV64_ROL1   = 50;   // 20260421: 51
        constexpr int      FNV64_ROL2   = 56;   // 20260421: 38

        // Final: result = (fnv ^ v15_decoded ^ SLOT_XOR) + v14 + 2*name_offset_word
        // 20260428: sub_22F3E0 writes  *(qword*)(a2+8) = bswap64(result ^ 0xBD8F879C)
        //           and returns un-bswapped/un-XORed `result`.
        // 20260421: chain collapsed to entry_ptr = result (RESULT_TO_ENTRY_XOR = 0).
        // For 20260428 the result-to-entry chain is a single bswap64+XOR step.
        constexpr uint64_t RESULT_TO_ENTRY_XOR = 0xBD8F879CULL;  // 20260421: 0
    }

    // =========================================================================
    // FNameEntry string decrypt
    //
    // 20260421 (FNameEntry_AppendNameToString @ 0x22EC20):
    //   header:  length = (hdr & 3) | ((hdr >> 5) & 0x3FC); isWide = bit15
    //   key_idx: 52 + ((key_start + i) & 0x3F)
    //   key_start = (uint16)(length - 17564)
    //   ANSI: byte ^= keytable[idx] >> 3
    //   Wide: word ^= keytable[idx]
    //
    // 20260428 (FNameEntry_AppendNameToString_20260428 @ 0x23B950):
    //   header:  length = (hdr & 0x7F) | ((hdr >> 5) & 0x380); isWide = bit15
    //   STATEFUL LCG keystream — 2 keytable lookups per pair, advance state
    //   each iteration. NOT a simple per-byte/per-word XOR anymore.
    //
    //   Common: keytable base = RVA_FNAME_KEYSTREAM (= 0xDAA07F4 in 20260428)
    //           idx_a = (state & 0x3F) + 8           (uint16 units)
    //           idx_b = ((68 * state + 96) & 0x3C) + 8
    //
    //   ANSI:   state0 = ((hdr & 0x7F) | ((hdr >> 5) & 0x80)) - 68
    //           per pair (i, i+1):
    //             byte[i]   ^= keytable[idx_a] >> 3
    //             byte[i+1] ^= keytable[idx_b] >> 3
    //             state = 16 * state - 32
    //           (tail byte if length is odd: byte ^= keytable[idx_a] >> 3)
    //
    //   Wide:   state0 = length + 61116
    //           per pair (i, i+1):
    //             word[i]   ^= keytable[idx_a]
    //             word[i+1] ^= keytable[idx_b]
    //             state = -559801840 * state - 537812000     (LCG)
    //           (tail word if length is odd: word ^= keytable[idx_a])
    //
    // Implementation lives in fname_decrypt.h — must be rewritten for
    // 20260428 (per-pair LCG, not per-byte stateless XOR). Constants below
    // are the patch-20260421 values; the 20260428 namespace `FNameEntry20260428`
    // carries the new ones.
    // =========================================================================
    namespace FNameEntry20260421 {
        // 20260421 values (kept for reference / fallback)
        constexpr int      KEY_TABLE_UINT16_OFFSET = 52;
        constexpr int32_t  KEY_START_BIAS          = -17564;
    }

    namespace FNameEntry20260428 {
        // Header bit-extract masks
        constexpr uint16_t LENGTH_LO_MASK    = 0x007F;   // bits 0..6 of hdr → bits 0..6 of length
        constexpr uint16_t LENGTH_HI_MASK    = 0x0380;   // ((hdr >> 5) & 0x380) → bits 7..9 of length
        constexpr uint16_t LENGTH_HI_LO8     = 0x0080;   // ((hdr >> 5) & 0x80) → bit 7 of length (ANSI state)
        constexpr uint16_t IS_WIDE_BIT       = 0x8000;   // bit15 = wide flag

        // Key-table indexing (uint16 units)
        constexpr int      KEY_TABLE_UINT16_OFFSET = 8;
        constexpr int      IDX_B_MUL = 68;
        constexpr int      IDX_B_ADD = 96;
        constexpr int      IDX_B_MASK = 0x3C;

        // ANSI LCG: state = ANSI_LCG_MUL * state + ANSI_LCG_ADD
        constexpr int32_t  ANSI_KEY_START_BIAS_HI  = -68;     // hdr_lo8 - 68
        constexpr int32_t  ANSI_LCG_MUL            = 16;      // state = 16*state - 32
        constexpr int32_t  ANSI_LCG_ADD            = -32;

        // Wide LCG: state = WIDE_LCG_MUL * state + WIDE_LCG_ADD
        constexpr int32_t  WIDE_KEY_START_BIAS     = 61116;   // length + 61116
        constexpr int32_t  WIDE_LCG_MUL            = -559801840;
        constexpr int32_t  WIDE_LCG_ADD            = -537812000;
    }

    // Decrypt the NumElements/MaxElements stored at chunks_manager + 0x70.
    // Reads 16 bytes from chunks_manager+0x70 and returns the i32 in lo32
    // of ROL64(15)(PSHUFLW(0xA3)(enc) XOR xor_key_lo64).
    // Verified on live PID: 0x443E1 (279521) from sample chunks_manager.
    inline int32_t DecryptGObjMaxElements(const uint8_t* enc16,
                                          uint64_t xor_key_lo64)
    {
        __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(enc16));
        // PSHUFLW imm=0xA3 = {3,0,2,2}
        __m128i a = _mm_shufflelo_epi16(v, 0xA3);
        // XOR with key (only low 64 bits matter; high 8 bytes of key are zero)
        __m128i key = _mm_set_epi64x(0, (long long)xor_key_lo64);
        __m128i b = _mm_xor_si128(a, key);
        // ROL64(15) = PSLLQ(15) | PSRLQ(49)
        __m128i c = _mm_or_si128(_mm_slli_epi64(b, 15),
                                 _mm_srli_epi64(b, 49));
        return _mm_cvtsi128_si32(c);
    }
}


// =============================================================================
// Build 2026-05-19 (Steam 19.05) — FName pipeline constants
//
// All-new resolver shape vs CL-1177146:
//   - Stage A1+A2+A3 chained SIMD transform on CI to produce (chunk_off, name_off)
//   - Block-pair hash uses ROL32(13) × 4 with HASH_ADD 0x22243756
//   - Chunk hash seed at +0x70D0, block base at +0x70E0 (was +0x7000 / +0x7010)
//   - FNV fold: P * ROL64(v, 57) + 0x61E912C25C5F0996 ; then again with ROL64(56)
//     (ADDITIVE — CL-1177146 used SUBTRACTIVE - 0x679E1C621411ACFA which is the
//      same offset, but the sign matters for chain correctness)
//   - Single XOR + bswap final (0xA05F743A) — vs three-XOR chain on CL-1177146
//
// UObject slot decrypt:
//   shufflelo(57) → XOR(@0xB34B180) → ROL32(9) → XOR(0x890EF320D7E2DC4C) → ROL64(32)
//
// String decrypt:
//   header: length = (h & 0x7F) | ((h >> 5) & 0x380), isWide = h & 0x8000
//   narrow: u8 LCG seed = length - 107, update: seed = -71*seed - 124
//   wide:   u32 LCG seed = length + 45717, update: seed = 2090044089*seed - 382688636
//   per-pair key1 = (107 * (u8)seed - 77) & 0x3F
//   narrow XORs (key >> 3); wide XORs full u16
//   keytable indexed as (key_idx & 0x3F) -- our local 64-entry table starts at the
//   +0x08 offset in the SIMD constants block, so the "+4 word" bias is baked in.
// =============================================================================
namespace v20260519 {
    // ── RVAs (build 2026-05-19, CL-1201801) ─────────────────────────────
    constexpr uint64_t RVA_GNAMEPOOL              = 0xE0FAA80ULL;  // CL-1201801 (was 0xE0ED7D0 on CL-1195482)
    constexpr uint64_t RVA_GNAMEPOOL_INIT_GUARD   = 0xE0FAA78ULL;  // CL-1201801
    constexpr uint64_t RVA_FNAME_SIMD_CONSTS      = 0xE0397F4ULL;  // CL-1201801 (was 0xDE5B6D8 on CL-1195482)
    constexpr uint64_t RVA_FNAME_KEYTABLE         = RVA_FNAME_SIMD_CONSTS + 168ULL;  // 0xE03989C (was +0x08)

    constexpr uint64_t RVA_UOBJ_SLOT_XOR          = 0xB1F0B90ULL;   // CL-1201801 (was 0xB34B0E0 on CL-1195482)

    constexpr uint64_t RVA_GUOBJECTARRAY          = 0xE4F8F60ULL;   // CL-1195482
    constexpr uint64_t RVA_GWORLD                 = 0xE706C58ULL;

    // ── Scalar constants (FName pipeline) ─────────────────────────────────
    constexpr int      SLOT_BASE_OFF        = 0x20;
    constexpr int      SLOT_STRIDE          = 0x20;

    constexpr uint32_t HASH_PRIME           = 0x01000193u;      // FNV32 prime (shared)
    constexpr uint32_t SLOT_HASH_ADD        = 0x8F957A95u;      // CL-1201801
    constexpr uint32_t SLOT_INNER_BIAS      = 0x0001DFE0u;      // 122832

    // ── Shard hash-table constants (CL-1201801) ──────────────────────────
    // FNamePool is now a sharded hash-table. CI → (NameOff, ChunkOff) via
    // identity PSHUFB chain. Each shard has a block-pair at +0xA0 selected
    // by FNV32 hash of the shard address + 0x90.
    constexpr uint32_t SHARD_HASH_ADD       = 0x4A3617A2u;      // FNV32 offset for shard hash (disasm-verified, decompiler showed wrong 0x4A3FAF42)
    constexpr uint64_t SHARD_HASH_SEED_OFF  = 0x90ULL;          // hash input addr offset within shard (was 0x70D0)
    constexpr uint64_t SHARD_BLOCK_BASE_OFF = 0xA0ULL;          // block-pair base within shard (was 0x70E0)
    constexpr int      SHARD_HASH_ROL_A     = 19;               // first & third ROL32 in hash chain
    constexpr int      SHARD_HASH_ROL_B     = 26;               // second ROL32 in hash chain

    // Block decrypt: shufflelo(SHUF_A) → ROL64(BLOCK_ROL) → shufflelo(SHUF_B) → lo64
    constexpr int      BLOCK_SHUF_A         = 0x8D;
    constexpr int      BLOCK_ROL            = 46;
    constexpr int      BLOCK_SHUF_B         = 0x4B;

    constexpr uint64_t FNV_PRIME            = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD              = 0xBF571668EC20FA62ULL; // CL-1201801 (was 0x61E912C25C5F0996 on CL-1195482)
    constexpr int      FNV_ROL1             = 29;                // CL-1201801 (was 57)
    constexpr int      FNV_ROL2             = 30;                // CL-1201801 (was 56)

    constexpr uint64_t UOBJ_SLOT_XOR_64     = 0xD22BC6399DD7BE75ULL;  // CL-1201801 (was 0xEA99FC6989F63908)
    constexpr int      UOBJ_SLOT_ROL32      = 0;                // CL-1201801: no ROL32 step (was 9 on CL-1195482)
    constexpr int      UOBJ_SLOT_FINAL_ROL  = 37;              // CL-1201801 NAME slot (CI in lo32)
    constexpr int      UOBJ_SLOT_PTR_ROL    = 5;               // CL-1201801 CLASS/OUTER slots (direct pointer)

    // FField::NamePrivate decode (CL-1201801, verified sub_1403B8A70 @ 0x1403B8A70):
    // lo64(FField+0x40) → XOR(KEY1) → ROL32(17)/lane → PSHUFLW(0x1E) → XOR(KEY2) → ROL64(32)
    // Result: (Number<<32)|CI ; CI in lo32. Constants at .rdata RVA 0xB23EF10/0xB23EF20.
    constexpr uint64_t FFIELD_NAME_KEY1     = 0xC88F612129941481ULL;
    constexpr uint64_t FFIELD_NAME_KEY2     = 0x018A6E394CF4AED0ULL;
    constexpr int      FFIELD_NAME_ROL32    = 17;
    constexpr uint8_t  FFIELD_NAME_SHUF     = 0x1E;
    constexpr int      FFIELD_NAME_ROL64    = 32;

    // FFieldClass::NamePrivate decode (CL-1201801, verified sub_14034F690):
    // 16B(FFieldClass+0x40) → PSHUFB(mask@0xB2220E0) → PXOR(key@0xB2220F0) → lo64 → ROL64(27)
    // Result: (Number<<32)|CI ; CI in lo32. NamePrivate is at FFieldClass+0x40.
    constexpr uint64_t FFIELD_CLASS_NAME_KEY = 0x7938404F49C579D2ULL;  // CL-1233465 (auto-discovered 9 sites; was 0x08EA69F63989FC99 on CL-1201801)
    constexpr int      FFIELD_CLASS_NAME_ROL64 = 23;                   // CL-1233465 (was 27 on CL-1201801)
    constexpr uint32_t FFIELD_CLASS_NAME_OFF   = 0x10;                 // CL-1233465 (was 0x40 on CL-1201801)

    constexpr int      KEY_TABLE_SIZE       = 64;
    constexpr uint8_t  KEY_INDEX_MASK       = 0x3F;

    // CL-1201801: sequential keytable walk (no LCG).
    // key[i] = keytable[(init + i) & 0x3F]; narrow XOR >>3, wide XOR full u16.
    constexpr int8_t   KEY_INIT_BIAS_NARROW = -93;           // CL-1201801 (was -107 on CL-1195482)
    constexpr int16_t  KEY_INIT_BIAS_WIDE   = -93;           // CL-1201801 (was 45717 on CL-1195482)

    // Header bit-layout (CL-1201801)
    constexpr uint16_t HDR_LENGTH_LO_MASK   = 0x003F;       // bits 0..5 (was 0x007F: bits 0..6)
    constexpr uint16_t HDR_LENGTH_HI_MASK   = 0x03C0;       // ((hdr >> 1) & 0x3C0) → bits 6..9 (was 0x0380)
    constexpr int      HDR_LENGTH_HI_SHIFT  = 1;             // (was 5)
    constexpr uint16_t HDR_IS_WIDE_BIT      = 0x0040;        // bit 6 (was 0x8000 = bit 15)
} // namespace v20260519

namespace v20260616 {
    constexpr uint64_t RVA_GNAMEPOOL               = 0xE376A80ULL;
    constexpr uint64_t RVA_GNAMEPOOL_INIT_GUARD    = 0xE376A78ULL;
    constexpr uint64_t RVA_GWORLD                  = 0xE83FC58ULL;
    constexpr uint64_t RVA_KEYSTREAM               = 0xE2B57F4ULL;
    constexpr int      KEYSTREAM_DECRYPT_BASE      = 96;

    constexpr int      SLOT_BASE_OFF        = 0x20;
    constexpr int      SLOT_STRIDE          = 0x20;
    constexpr int      SLOT_HASH_INPUT_OFF  = 0x10;

    constexpr uint32_t HASH_PRIME           = 0x01000193u;
    constexpr uint32_t SLOT_HASH_ADD        = 0x5619A446u;

    constexpr uint8_t  UOBJ_SLOT_PSHUFB[8]  = { 0x06, 0x05, 0x02, 0x03, 0x04, 0x01, 0x00, 0x07 };
    constexpr uint64_t UOBJ_SLOT_XOR_64     = 0x5EA772D07F910744ULL;
    constexpr int      UOBJ_SLOT_FINAL_ROL  = 32;

    constexpr int      BLOCK_SHUF_A         = 0x93;
    constexpr int      BLOCK_ROL32          = 23;
    constexpr uint64_t BLOCK_XOR_PRE        = 0x890EF320D7E2DC4CULL;
    constexpr uint64_t BLOCK_XOR_POST       = 0x6E6B7A701FF6D296ULL;

    constexpr uint64_t FNV_PRIME            = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD              = 0x124CB31365185276ULL;
    constexpr int      FNV_ROL1             = 54;
    constexpr int      FNV_ROL2             = 32;

    constexpr uint32_t SHARD_HASH_ADD       = 0xD4CEBC36u;
    constexpr uint64_t SHARD_HASH_SEED_OFF  = 3152ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF = 3168ULL;

    constexpr uint64_t ENTRY_XOR            = 0xE5C864C1A6B54C7FULL;
    constexpr int      ENTRY_ROL64          = 39;
    constexpr uint8_t  ENTRY_PSHUFB_MASK[16] = {
        0x02, 0x06, 0x03, 0x01, 0x00, 0x04, 0x07, 0x05,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    constexpr uint8_t  ENTRY_XOR_MASK[16] = {
        0xFC, 0x10, 0xD3, 0xFB, 0xCE, 0x56, 0x88, 0x68,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    constexpr uint8_t  ENTRY_BLEND_XOR[16] = {
        0xCE, 0xFB, 0xFC, 0xD3, 0x56, 0x68, 0x10, 0x88,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr uint8_t  FFIELD_NAME_SHUF_IMM = 0x1E;
    constexpr uint64_t FFIELD_NAME_XOR_KEY  = 0x365789E8756FBA38ULL;
    constexpr int      FFIELD_NAME_ROL16    = 1;
    constexpr int      FFIELD_NAME_ROL64    = 32;

    constexpr uint32_t PROPERTY_OFFSET_XOR  = 0xEAABEC11u;

    constexpr uint64_t FCLASS_NAME_XOR1     = 0x890EF320D7E2DC4CULL;
    constexpr uint64_t FCLASS_NAME_XOR2     = 0x6E6B7A701FF6D296ULL;
    constexpr uint8_t  FCLASS_NAME_SHUF_DEC = 0x39;
    constexpr int      FCLASS_NAME_ROR32    = 9;

    constexpr uint16_t HDR_IS_WIDE_BIT      = 0x0020;
    constexpr int8_t   KEY_INIT_BIAS_NARROW = -76;
    constexpr int      KEY_PAIR_STEP        = -36;
    constexpr int      KEY_PAIR_OFFSET      = 46;
    constexpr int16_t  KEY_INIT_BIAS_WIDE   = 21172;
    constexpr int      KEY_PAIR_STEP_WIDE   = 2012;
    constexpr uint8_t  KEY_INDEX_MASK       = 0x3F;
} // namespace v20260616

namespace v20260707 {
    constexpr uint64_t RDATA_BASE_REF       = 0xB4BD000ULL;
    constexpr int      SLOT_BASE_OFF        = 0x20;
    constexpr int      SLOT_STRIDE          = 0x20;
    constexpr int      SLOT_HASH_INPUT_OFF  = 0x10;

    constexpr uint32_t HASH_PRIME           = 0x01000193u;
    constexpr uint32_t SLOT_HASH_ADD        = 0x5A5A703Fu;
    constexpr int      HASH_ROL1            = 25;
    constexpr int      HASH_ROL2            = 15;
    constexpr int      HASH_ROL3            = 25;
    constexpr int      HASH_ROL4            = 15;

    constexpr uint64_t UOBJ_SLOT_XOR_64     = 0x9A492C85DDF6F193ULL;
    constexpr int      UOBJ_SLOT_ROL32      = 13;
    constexpr int      UOBJ_SLOT_FINAL_ROL  = 39;

    constexpr uint8_t  FFIELD_NAME_PSHUFB[8] = { 0x01, 0x03, 0x00, 0x02, 0x05, 0x04, 0x06, 0x07 };
    constexpr uint64_t FFIELD_NAME_XOR_KEY   = 0x2BC795817F5A4D23ULL;
    constexpr int      FFIELD_NAME_ROL64     = 32;

    constexpr uint32_t PROPERTY_OFFSET_XOR   = 0x057F15E5u;

    constexpr uint64_t RVA_GNAMEPOOL          = 0xE4F2A00ULL;
    constexpr uint64_t RVA_KEYTABLE           = 0xE4318E4ULL;

    constexpr uint64_t RVA_SEED_XOR1          = 0xB4FD4B0ULL;
    constexpr uint64_t RVA_SEED_BLEND         = 0xB4FD690ULL;
    constexpr uint64_t RVA_SEED_BLEND_NOT     = 0xB4FD680ULL;
    constexpr uint64_t RVA_SEED_XOR2          = 0xB4FD6A0ULL;
    constexpr uint64_t RVA_SEED_XOR3          = 0xB4FD620ULL;
    constexpr uint64_t RVA_SEED_XOR4          = 0xB4FD4C0ULL;
    constexpr uint64_t RVA_CHUNK_XOR          = 0xB4FD840ULL;
    constexpr uint64_t SEED_MID_XOR           = 0xAB76454000000000ULL;
    constexpr uint32_t CHUNK_ID_XOR           = 0x1DC01268u;

    constexpr uint32_t SHARD_HASH_ADD         = 0x282106A6u;
    constexpr uint64_t SHARD_HASH_SEED_OFF    = 0x6FD0ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF   = 0x6FE0ULL;
    constexpr int      SHARD_HASH_ROL_A       = 24;
    constexpr int      SHARD_HASH_ROL_B       = 19;
    constexpr int      SHARD_HASH_ROL_C       = 24;
    constexpr int      SHARD_HASH_SHIFT       = 13;
    constexpr int      SHARD_SLOT_SELECT_ADD  = 166;

    constexpr int      BLOCK_PSHUFLW          = 0x1B;
    constexpr int      BLOCK_ROL64            = 10;
    constexpr uint64_t BLOCK_FNV_XOR          = 0x1BC3B58FFB88504CULL;

    constexpr uint64_t FNV_PRIME              = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD                = 0xEB1E82D44384D6E6ULL;
    constexpr int      FNV_ROL1               = 51;
    constexpr int      FNV_ROL2               = 39;

    constexpr uint16_t HDR_LENGTH_FORMULA     = 1;
    constexpr uint16_t HDR_IS_WIDE_BIT        = 0x8000u;
    constexpr int      KEY_TABLE_SIZE         = 64;
    constexpr uint8_t  KEY_INDEX_MASK         = 0x3F;
    constexpr uint32_t KEY_BIAS_NARROW        = 0xFFFF9D4Eu;
    constexpr uint32_t KEY_BIAS_ADD           = 0xEu;
    constexpr uint32_t KEY_PAIR_STEP          = 0x29Cu;
} // namespace v20260707

namespace v20260709 {
    constexpr int      UOBJ_SLOT_ROL64_FIRST = 29;
    constexpr int      UOBJ_SLOT_PSHUFLW     = 0x39;
    constexpr int      UOBJ_SLOT_ROL32_PER   = 5;
    constexpr int      UOBJ_SLOT_FINAL_ROL   = 32;

    constexpr uint32_t SLOT_HASH_ADD         = 0xF3D8DA36u;
    constexpr int      SLOT_HASH_ROL1        = 21;
    constexpr int      SLOT_HASH_ROL2        = 13;
    constexpr int      SLOT_HASH_ROL3        = 21;
    constexpr int      SLOT_HASH_ROL4        = 13;

    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0xD5AF8E52u;
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x2F90ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x2FA0ULL;
    constexpr int      SHARD_HASH_ROL_A      = 17;
    constexpr int      SHARD_HASH_ROL_B      = 13;
    constexpr int      SHARD_SLOT_SELECT_ADD = 82;

    constexpr int      BLOCK_ROL64           = 13;
    constexpr int      BLOCK_PSHUFLW         = 0x93;
    inline    uint64_t BLOCK_FNV_XOR         = 0x19EA7DF486E7194EULL;
    constexpr uint64_t BLOCK_FNV_XOR_RVA     = 0xB523C50ULL;

    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0x10F3A73711CE0312ULL;
    constexpr int      FNV_ROL1              = 37;
    constexpr int      FNV_ROL2              = 40;

    constexpr uint64_t FNAME_PTR_XOR1        = 0x14329DBFULL;
    constexpr uint64_t FNAME_PTR_XOR2        = 0x2E3400000000ULL;
    constexpr uint64_t FNAME_PTR_XOR3        = 0xBF9D1C2000000000ULL;

    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x20u;
    constexpr int      HDR_LENGTH_SHIFT      = 6;
    constexpr uint32_t KEY_INIT_ADD          = 0xA7B4u;
    constexpr uint32_t KEY_MUL_INNER         = 0xFFFF584Cu;
    constexpr uint32_t KEY_ADD_INNER         = 0xF629u;
    constexpr uint8_t  KEY_MASK_INNER        = 0x3Du;
    constexpr uint32_t KEY_MUL_ADVANCE       = 0x6DDC5690u;
    constexpr uint32_t KEY_ADD_ADVANCE       = 0x5EBF2255u;
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      KEYTABLE_BYTE_OFFSET  = 0xE8;

    constexpr uint64_t FFIELD_NAME_XOR_KEY   = 0x8FFAB191C340B792ULL;
    constexpr uint8_t  FFIELD_NAME_PSHUFB[8] = { 0x07, 0x06, 0x04, 0x05, 0x02, 0x03, 0x00, 0x01 };
    constexpr int      FFIELD_NAME_ROL16     = 12;
    constexpr int      FFIELD_NAME_ROL64     = 32;
} // namespace v20260709

// ─────────────────────────────────────────────────────────────────────────────
// Patch 2026-08 (image size 0x11853000).
//
// Every value below was read out of the game image by disassembly and then
// re-verified; nothing here is a guess. Provenance is noted per block so the
// next patch-day port can re-derive them the same way.
//
// Three things changed *structurally*, not just numerically — swapping the
// v20260709 constants into the old code paths is NOT sufficient:
//   1. The shard hash mixes with plain right SHIFTS, not rotates, and the slot
//      selector is back to the simple `H ^ (H>>16)` fold (the `-109*T+K`
//      multiply form from CL-1315578 is gone).
//   2. Block decode reordered to PSHUFLW -> XOR -> ROL64 (was ROL64 ->
//      PSHUFLW -> XOR), and the XOR key is now an inline `movabs` immediate
//      rather than an .rdata load, so RVA-based discovery cannot find it.
//   3. The string key schedule lost its multipliers — it is now a plain
//      `key += 0x716` per character pair.
// ─────────────────────────────────────────────────────────────────────────────
namespace v20260805 {
    // ── FName resolver, from RVA 0x2319F0 (core) / 0x23B120 / 0x23AAE0 ──
    // GNamePool: `lea r8,[rip+0xe1ffeb5]` @ 0x231AC4. Init flag lives at
    // POOL-8; the pool is lazily built by 0x23C720 on first name lookup.
    constexpr uint64_t RVA_GNAMEPOOL         = 0xE431980ULL;
    constexpr uint64_t RVA_GNAMEPOOL_INITFLAG= 0xE431978ULL;

    // CompIndex needs NO decode. The three SIMD layers at 0x23AB01 / 0x23B1C4 /
    // 0x231AA4 (pxor/rol32/pshufb, bit-select, pshufb/rol32/xor) cancel exactly
    // — verified by simulating all three layers over the real .rdata masks for
    // CI = 0,1,2,0x1234,0x10000,0x410045,0x871210,0xDEADBEEF,0xFFFFFFFF.
    constexpr bool     CI_DECODE_IS_IDENTITY = true;

    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0x46BD406Eu;   // @0x231AEF, x4 sites
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x4C90ULL;     // `add rdx,0x4c90` @0x231AD2
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x4CA0ULL;     // pshuflw disp @0x231B3E
    constexpr uint64_t SHARD_BLOCK_STRIDE    = 32ULL;         // `shl edx,5` @0x231B3B

    // Shard FNV32. Note the seed is the chunk ADDRESS, never a memory read, so
    // it depends on the live module base — do not hardcode 0x140000000.
    //   r8d = lo32(SeedAddr) >> 4      (`shld r8d,edx,0x1c` with r8d=0x10; the
    //                                   0x10 shifts out of 32 bits, so it is a
    //                                   plain >>4 — confirmed by simulation)
    constexpr int      SHARD_SEED_SHR        = 4;             // @0x231ADF
    constexpr int      SHARD_SHR_A           = 3;             // @0x231AF6
    constexpr int      SHARD_SHR_B           = 4;             // @0x231B0A
    constexpr int      SHARD_SHR_C           = 3;             // @0x231B19
    // Slot select @0x231B28..0x231B48. The `mov edx,r9d` at 0x231B32 is easy to
    // miss and is what makes BOTH indices derive from T (not H).
    //   T = H ^ (H>>16);  Bidx1 = T & 7;  Bidx2 = (T+1) & 7
    constexpr int      SHARD_SELECT_SHR      = 16;

    // Block decode @0x231B3E..0x231B7C. pshuflw imm 0x93 permutes words
    // [w0,w1,w2,w3] -> [w3,w0,w1,w2], which on the low qword is exactly
    // ROL64(x,16); it is applied to the RAW memory operand, before the XOR.
    constexpr int      BLOCK_PSHUFLW         = 0x93;
    constexpr uint64_t BLOCK_FNV_XOR         = 0x07C3784BD4ECB382ULL;  // movabs @0x231B51
    constexpr int      BLOCK_ROL64           = 15;            // `rol r8,0xf` @0x231B61

    // FNV64 fold @0x231B80..0x231BAA. ROL1 is 55 relative to the *pre*-ROL64(15)
    // block value, i.e. 40 relative to V13.
    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0xBB3A9A3B042493AEULL; // movabs @0x231B95
    constexpr int      FNV_ROL1_PREROT       = 55;            // `rol rdx,0x37`
    constexpr int      FNV_ROL2              = 57;            // `rol rdx,0x39`

    // Pointer XOR chain: 0x231BB7 (^X1, bswap), 0x23B241 (^X2), 0x23AB4C
    // (^X3, bswap). Net effect is IDENTITY this patch:
    //   X2^X3 = 0xD87E9E3E00000000, and bswap64(that) == X1, so
    //   bswap(bswap(P^X1) ^ X2 ^ X3) == P.
    constexpr uint64_t FNAME_PTR_XOR1        = 0x3E9E7ED8ULL;
    constexpr uint64_t FNAME_PTR_XOR2        = 0x0000801B00000000ULL;
    constexpr uint64_t FNAME_PTR_XOR3        = 0xD87E1E2500000000ULL;
    constexpr bool     PTR_CHAIN_IS_IDENTITY = true;

    // FNameEntry header @0x23AB69: `shr eax,5; and eax,0x3ff`, wide = sign bit.
    constexpr int      HDR_LENGTH_SHIFT      = 5;
    constexpr uint32_t HDR_LENGTH_MASK       = 0x3FFu;
    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x8000u;

    // String decrypt @0x230020. Keystream is uint16[64]; the base LEA targets
    // 0xE3707F4 and every load adds +0x58, so the table proper starts there.
    constexpr uint64_t RVA_FNAME_KEYTABLE    = 0xE37084CULL;
    constexpr uint32_t KEY_INIT_ADD          = 0x6C22u;       // @0x230059
    constexpr uint32_t KEY_STEP              = 0x716u;        // @0x2300EC
    constexpr uint32_t KEY_PAIR_DELTA        = 0x0Bu;         // @0x2300D5
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      KEY_NARROW_SHR        = 3;             // narrow only; wide uses the raw u16

    // ── FField::NamePrivate decode ──
    // Two independent sites agree: 0x454A9F (pand/pandn bit-select form) and
    // 0x3975B7 (literal pxor form). Their constants differ by exactly one
    // PSHUFLW(0x39) because the shuffle sits on the other side of the XOR —
    // i.e. PSHUFLW(K2,0x39) == 0xD2966E6B7A701FF6, the key seen at 0x3975B7.
    // Cross-checked end-to-end: the static NAME_None template at .rdata
    // 0xB4E9AC0 (0xE9125C1BEE9842D2) decodes to CI=0, Number=0.
    //   t   = enc ^ K2
    //   t   = PSHUFLW(t, 0x39)
    //   t   = ROL32_per_dword(t, 9)
    //   raw = t ^ K1
    //   CI  = hi32(raw), Number = lo32(raw)   [ROL64(raw,32) puts CI in lo32]
    constexpr uint64_t FFIELD_NAME_XOR_K2    = 0x6E6B7A701FF6D296ULL;
    constexpr int      FFIELD_NAME_PSHUFLW   = 0x39;
    constexpr int      FFIELD_NAME_ROL32     = 9;
    constexpr uint64_t FFIELD_NAME_XOR_K1    = 0x890EF320D7E2DC4CULL;
    constexpr int      FFIELD_NAME_ROL64     = 32;

    // ── FField / FProperty / UStruct layout ──
    // From the FField ctor @0x3872B0, FProperty ctor @0x431630, the named
    // FProperty variant @0x448430 and UStruct::AddCppProperty @0x350460.
    namespace Off {
        constexpr uint64_t FField_NamePrivate   = 0x60;   // movdqa [rax+0x60] @0x3873D5
        constexpr uint64_t FField_FlagsPrivate  = 0x70;
        constexpr uint64_t FField_Owner         = 0x78;   // bit0 tags "is UObject"
        constexpr uint64_t FField_Next          = 0x80;   // @0x350467
        constexpr uint64_t FField_Salt          = 0x88;
        constexpr uint64_t FField_ClassPrivate  = 0x90;   // @0x3C0E5D
        constexpr uint64_t FProperty_ElementSize= 0x9C;   // @0x4316CA / 0x43D480
        constexpr uint64_t FProperty_Flags      = 0xA0;
        constexpr uint64_t FProperty_Offset     = 0xB4;   // @0x4316F0 / 0x44884E
        constexpr uint64_t FProperty_ArrayDim   = 0xE0;   // @0x431708
        constexpr uint64_t FProperty_SubPtr0    = 0x108;  // first subclass field
        constexpr uint64_t UStruct_ChildProps   = 0x108;  // @0x350460
    }
    constexpr uint64_t FFIELD_SALT_SENTINEL   = 0x4F463D342B221910ULL;

    // Offset_Internal encode @0x44884E is `xor eax,0x76C317A2; bswap eax`, so
    // decode is bswap-THEN-xor. The constant-folded zero case stored at
    // 0x4316F0 is 0xA217C376 == bswap32(0 ^ key), which confirms the order.
    constexpr uint32_t PROPERTY_OFFSET_XOR    = 0x76C317A2u;

    // ── GUObjectArray ──
    // NOT yet confirmed against a live process: the .data slot holds a Theia
    // placeholder that is fixed up at startup, and the image has no reloc
    // directory, so only a running game can validate these.
    constexpr uint64_t RVA_GOBJ_FCA_ENC       = 0xE6ED2A0ULL;  // encrypted FCA ptr (xmmword)
    constexpr uint64_t RVA_GOBJ_PTR_XOR       = 0xB48A020ULL;  // = 0xA738DD8241D227C2
    constexpr int      GOBJ_PTR_ROL64         = 38;
    constexpr int      GOBJ_PTR_PSHUFLW       = 0x39;
    constexpr uint64_t GOBJ_NUMELEMENTS_OFF   = 0x70;
    constexpr int      GOBJ_NUMEL_ROL64       = 13;
    constexpr int      GOBJ_NUMEL_PSHUFLW     = 0xE3;
    constexpr uint64_t RVA_GOBJ_NUMEL_XOR     = 0xB4DD440ULL;  // low dword 0x86E7194E
    constexpr uint64_t GOBJ_CHUNKACCESSOR_OFF = 0xA0;          // this + vtable, call vtable[3]
    constexpr uint64_t GOBJ_CHUNKBLOB_OFF     = 0xD0;
    constexpr uint32_t GOBJ_VTABLE_SLOT       = 0x18;          // [vt+0x18]
    constexpr uint32_t GOBJ_ITEM_STRIDE       = 20;            // `lea rax,[r12+r12*4]; shl eax,2`
    constexpr uint32_t GOBJ_SLOTS_PER_CHUNK   = 65536;         // idx>>16 / idx&0xFFFF

    // Install the disassembly-verified layout into the live Offsets tables.
    // Called once the FName pipeline has confirmed we are on this patch.
    //
    // These are stated with much higher confidence than a live probe can reach:
    // they come from the constructors that WRITE the fields, so there is no
    // predicate that could mistake a neighbouring pointer for the real one.
    // The live probes in auto_offsets.h are the thing that got these wrong last
    // run (it picked FProperty's own PropertyLinkNext chain at +0xE8..+0x100 as
    // the subclass pointers, and an always-None FName field as NamePrivate).
    inline void ApplyOffsets() {
        namespace O = ArcDecrypt::Offsets;

        O::FField::NamePrivate   = Off::FField_NamePrivate;    // 0x60
        O::FField::NameEncrypted = Off::FField_NamePrivate;
        O::FField::Owner         = Off::FField_Owner;          // 0x78
        O::FField::Next          = Off::FField_Next;           // 0x80
        O::FField::SaltSentinel  = Off::FField_Salt;           // 0x88
        O::FField::ClassPrivate  = Off::FField_ClassPrivate;   // 0x90

        O::FProperty::ElementSize     = Off::FProperty_ElementSize;  // 0x9C
        O::FProperty::PropertyFlags   = Off::FProperty_Flags;        // 0xA0
        O::FProperty::Offset_Internal = Off::FProperty_Offset;       // 0xB4
        O::FProperty::ArrayDim        = Off::FProperty_ArrayDim;     // 0xE0
        O::FProperty::Offset_XOR      = PROPERTY_OFFSET_XOR;

        // All FProperty subclasses start their own fields at +0x108; the base
        // class ends there. UE declares Map/Enum as two pointers in order.
        constexpr uint64_t S0 = Off::FProperty_SubPtr0;        // 0x108
        O::FStructProperty::Struct         = S0;
        O::FObjectProperty::PropertyClass  = S0;
        O::FArrayProperty::Inner           = S0;
        O::FSetProperty::ElementProp       = S0;
        O::FSoftObjectProperty::PropertyClass = S0;
        O::FEnumProperty::UnderlyingProp   = S0;
        O::FEnumProperty::Enum             = S0 + 8;
        O::FMapProperty::KeyProp           = S0;
        O::FMapProperty::ValueProp         = S0 + 8;
        O::FBoolProperty::FieldSize        = S0;
        O::FBoolProperty::ByteOffset       = S0 + 1;
        O::FBoolProperty::ByteMask         = S0 + 2;
        O::FBoolProperty::FieldMask        = S0 + 3;

        O::UStruct::ChildProperties = Off::UStruct_ChildProps;  // 0x108
        O::UStruct::Children        = Off::UStruct_ChildProps;
    }
} // namespace v20260805

} // namespace ArcDecrypt
