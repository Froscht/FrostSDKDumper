#pragma once

#include <vector>

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
// Build 24653108: chunks_manager is a standalone encrypted 16-byte global, so
// this legacy slot now carries the same value as v20260811::RVA_CHUNKMGR_GLOBAL
// (it cannot reference it — that namespace is declared further down). The v811
// hot path reads g_Sheet.ChunkMgrRva; this keeps the legacy fallbacks and the
// exported config from carrying a CL-1195482 address.
inline uint64_t RVA_GOBJECT_ARRAY_BASE  = 0xE64B260;   // == v20260811::RVA_CHUNKMGR_GLOBAL
//inline uint64_t RVA_GOBJECT_ARRAY_BASE  = 0xE4F8F60; // CL-1195482 (Steam 19.05 evening; was 0xE4F8ED0 pre-CL-1195482)
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
    constexpr uint64_t FFIELD_NAME_XOR_K2    = 0x6E6B7A701FF6D296ULL;
    constexpr int      FFIELD_NAME_PSHUFLW   = 0x39;
    constexpr int      FFIELD_NAME_ROL32     = 9;
    constexpr uint64_t FFIELD_NAME_XOR_K1    = 0x890EF320D7E2DC4CULL;
    constexpr int      FFIELD_NAME_ROL64     = 32;

    // ── FField / FProperty / UStruct layout ──
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

    constexpr uint32_t PROPERTY_OFFSET_XOR    = 0x76C317A2u;

    // ── GUObjectArray ──
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
}

// CL-1325322 (image size 0x11853000). Live-verified 2026-08-08 against PID
// 16430 — sequential pool walk decoded 60/60 engine names cleanly.
//
// Reversed from three chained functions (IDA base 0x140000000):
//   sub_1402319F0  core pool resolve  (shard hash, block decode, FNV, PTR_XOR1)
//   sub_14023B120  middle stage       (PTR_XOR2)
//   sub_14023AAE0  outer stage        (PTR_XOR3, header length extract)
//   sub_140230020  string decrypt     (keystream XOR, narrow/wide widen pass)
//
// Divergences from v20260709 that matter:
//   • Shard hash uses SHR (4,3,4,3), NOT ROL. IDA's pseudocode renders the
//     slot select as `-109*T + 110`; the disassembly at 0x140231B28 shows the
//     real form is `H ^ (H >> 16)`. Trust the disasm (see CLAUDE.md note on
//     the decompiler shard-hash bug).
//   • Block decode order is PSHUFLW → XOR → ROL64(15); v709 was ROL64 first.
//   • Wide-string flag moved to bit 15 (0x8000); length is (hdr >> 5) & 0x3FF.
//   • Key schedule is linear (+22 per pair, second index +11) — the v709
//     multiply/add LCG is gone.
//   • Keystream entries are indexed from +44, not +96/+0xE8.
// The CI → (chunk, name offset) SIMD chain spans all three functions and
// cancels to identity (verified by simulating the PSHUFB/ROL/blend masks at
// 0x14B4C3380 / 0x3390 / 0x3840 / 0x3850 / 0x3860 / 0x3870 / 0x34F0).
// ─────────────────────────────────────────────────────────────────────────────
namespace v20260808 {
    constexpr uint64_t RVA_GNAMEPOOL         = 0xE431980ULL;
    constexpr uint64_t RVA_KEYSTREAM         = 0xE3707F4ULL;
    constexpr int      KEYSTREAM_BASE_INDEX  = 44;
    constexpr int      KEYSTREAM_ENTRIES     = 160;

    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0x46BD406Eu;
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x4C90ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x4CA0ULL;
    constexpr uint64_t SHARD_BLOCK_STRIDE    = 32ULL;
    constexpr int      SHARD_SHIFT_A         = 4;
    constexpr int      SHARD_SHIFT_B         = 3;

    constexpr int      BLOCK_PSHUFLW         = 0x93;
    constexpr int      BLOCK_ROL64           = 15;
    constexpr uint64_t BLOCK_FNV_XOR         = 0x07C3784BD4ECB382ULL;

    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0xBB3A9A3B042493AEULL;
    constexpr int      FNV_ROL1              = 40;
    constexpr int      FNV_ROL2              = 57;

    constexpr uint64_t FNAME_PTR_XOR1        = 0x3E9E7ED8ULL;
    constexpr uint64_t FNAME_PTR_XOR2        = 0x0000801B00000000ULL;
    constexpr uint64_t FNAME_PTR_XOR3        = 0xD87E1E2500000000ULL;

    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x8000u;
    constexpr int      HDR_LENGTH_SHIFT      = 5;
    constexpr uint16_t HDR_LENGTH_MASK       = 0x3FFu;
    constexpr uint32_t KEY_INIT_ADD          = 34u;
    constexpr uint32_t KEY_PAIR_ADVANCE      = 22u;
    constexpr uint32_t KEY_SECOND_DELTA      = 11u;
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      NARROW_KEY_SHIFT      = 3;

    // ── GUObjectArray (from sub_1404B0BF0, the object-registration path) ──
    constexpr uint64_t RVA_GUOBJECTARRAY     = 0xE6ED190ULL;
    constexpr uint64_t GOBJ_CHUNKMGR_OFF     = 0x110ULL;
    constexpr uint64_t GOBJ_NUMELEMENTS_OFF  = 0x50ULL;
    constexpr uint64_t CHUNKMGR_XOR_RVA      = 0xB48A020ULL;
    constexpr int      CHUNKMGR_ROL64        = 38;
    constexpr int      CHUNKMGR_PSHUFLW      = 0x39;
    constexpr uint64_t MGR_VTABLE_OFF        = 0xA0ULL;
    constexpr uint64_t MGR_BLOB_OFF          = 0xD0ULL;
    constexpr uint64_t MGR_VTABLE_SLOT       = 3ULL;

    constexpr uint32_t FUOBJECTITEM_STRIDE   = 20;
    constexpr uint32_t ITEMS_PER_CHUNK       = 65536;
    constexpr uint64_t UOBJECT_INTERNAL_IDX  = 0x0CULL;

    constexpr int      THUNK_PSHUFLW         = 0x8D;
    constexpr int      THUNK_ROL64           = 46;
    constexpr uint64_t THUNK_XOR_RVA         = 0xB517910ULL;
    constexpr uint64_t THUNK_SALT_IMM64      = 0xB2DA4299DB155ED3ULL;
    constexpr uint32_t THUNK_PEB_ADD         = 0x4D56C2E0u;

    constexpr uint64_t UOBJ_NAME_SEED_OFF    = 0x10ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_BASE   = 0x20ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_STRIDE = 0x20ULL;
    constexpr uint32_t UOBJ_SLOT_HASH_PRIME  = 0x1000193u;
    constexpr uint32_t UOBJ_SLOT_HASH_ADD    = 0x31F5C55Fu;
    constexpr int      UOBJ_SLOT_HASH_ROL    = 22;
    constexpr int      UOBJ_SLOT_SHIFT_A     = 4;
    constexpr int      UOBJ_SLOT_SHIFT_B     = 4;
    constexpr int      UOBJ_SLOT_SHIFT_C     = 0xA;
    constexpr uint32_t UOBJ_SLOT_MASK_A      = 0x565AFC0u;
    constexpr uint32_t UOBJ_SLOT_MASK_B      = 0x565AFC1u;
    constexpr uint32_t UOBJ_SLOT_MASK_C      = 0x565AFC3u;
    constexpr int      UOBJ_NAME_PSHUFLW     = 0x39;
    constexpr uint64_t UOBJ_NAME_XOR1        = 0xBF6D1474CC9622A5ULL;
    constexpr int      UOBJ_NAME_ROL1        = 62;
    constexpr uint64_t UOBJ_NAME_XOR2        = 0xAB7645401DC01268ULL;
    constexpr int      UOBJ_NAME_ROL2        = 32;

    constexpr uint64_t FFIELD_NAME_OFF       = 0x60ULL;
    constexpr uint64_t FFIELD_NEXT_OFF       = 0x80ULL;
    constexpr uint64_t USTRUCT_CHILDPROPS    = 0xD0ULL;
    constexpr uint64_t FFIELD_OWNER_OFF      = 0x78ULL;
    constexpr uint64_t FFIELD_CLASSPRIV_OFF  = 0x90ULL;
    constexpr uint64_t FPROP_ELEMSIZE_OFF    = 0x9CULL;
    constexpr uint64_t FFIELD_NAME_BLEND     = 0xDB4ADB4ADB4ADB4AULL;
    constexpr int      FFIELD_NAME_PSHUFLW   = 0x39;
    constexpr uint64_t FFIELD_NAME_XOR1      = 0x09DCB521A13AC4BCULL;
    constexpr int      FFIELD_NAME_ROL32     = 9;
    constexpr uint64_t FFIELD_NAME_XOR2      = 0x890EF320D7E2DC4CULL;
    constexpr int      FFIELD_NAME_ROL64     = 32;
    constexpr uint64_t FPROP_ARRAYDIM_OFF    = 0xE0ULL;
    constexpr uint64_t FPROP_PROPFLAGS_OFF   = 0xA0ULL;
    constexpr uint64_t FPROP_OFFSETINT_OFF   = 0xB4ULL;
    constexpr uint32_t FPROP_OFFSET_XOR      = 0x76C317A2u;
    constexpr uint64_t USTRUCT_PROPSIZE_OFF  = 0xD8ULL;
    constexpr uint64_t USTRUCT_SUPER_OFF     = 0xA8ULL;
    constexpr uint64_t UENUM_NAMES_OFF       = 0xA8ULL;
    constexpr uint64_t FBOOLPROP_FIELDSIZE   = 0x108ULL;
    constexpr uint64_t FBOOLPROP_BYTEOFFSET  = 0x109ULL;
    constexpr uint64_t FBOOLPROP_BYTEMASK    = 0x10AULL;
    constexpr uint64_t FBOOLPROP_FIELDMASK   = 0x10BULL;
} // namespace v20260808

// Steam build 24653108, image size 0x117E9000.
// Every value below is live-verified against PID 53906 (100% naming rate,
// 9048 sampled objects, 0 "None"). See CLAUDE.md for the derivation.
namespace v20260811 {
    constexpr uint64_t IMAGE_SIZE            = 0x117E9000ULL;

    constexpr uint64_t RVA_GNAMEPOOL         = 0xE38FA00ULL;
    constexpr uint64_t RVA_POOL_INIT_FLAG    = 0xE38F9F8ULL;
    constexpr uint64_t RVA_FNAME_RESOLVER    = 0x23EC40ULL;
    // The at-rest bytes in the module dump are NOT the runtime table; it is
    // decrypted in place at load. This RVA must be read from live memory.
    constexpr uint64_t RVA_KEYSTREAM         = 0xE2CE7F4ULL;
    constexpr int      KEYSTREAM_BASE_INDEX  = 80;
    constexpr int      KEYSTREAM_ENTRIES     = 144;

    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0x6E149835u;
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x6550ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x6560ULL;
    constexpr uint64_t SHARD_BLOCK_STRIDE    = 32ULL;
    constexpr uint32_t SHARD_SEED_OR         = 0x40000000u;
    constexpr int      SHARD_SEED_SHR        = 6;
    constexpr int      SHARD_ROL_A           = 0x15;
    constexpr int      SHARD_ROL_B           = 0x1A;
    constexpr int      SHARD_SHR_C           = 0x0B;

    constexpr uint8_t  BLOCK_PSHUFB[8]       = { 1, 4, 6, 0, 3, 7, 2, 5 };
    constexpr int      BLOCK_ROL16           = 2;
    constexpr uint64_t BLOCK_FNV_XOR         = 0x01554577E835E9F4ULL;

    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0x323C186F5D5C1B15ULL;
    constexpr int      FNV_ROL1              = 0x28;
    constexpr int      FNV_ROL2              = 0x29;

    // bswap64(0x43231D85) == 0x851D234300000000, so the four-step pointer
    // chain is an algebraic identity. EntryPtr == RawPtr; nothing to apply.
    constexpr bool     FNAME_PTR_CHAIN_IS_NOP = true;

    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x0800u;
    constexpr uint16_t HDR_LENGTH_LO_MASK    = 0x003Fu;
    constexpr int      HDR_LENGTH_HI_SHIFT   = 6;
    constexpr uint32_t HDR_LENGTH_HI_MASK    = 0xFFFFFFC0u;
    // One cyclic sequence, +1 per element. No LCG, no paired schedule.
    constexpr uint32_t KEY_INIT_ADD          = 0x7216u;
    constexpr uint32_t KEY_ADVANCE           = 1u;
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      NARROW_KEY_SHIFT      = 3;
    constexpr int      WIDE_KEY_SHIFT        = 0;

    // No GUObjectArray struct on this patch: the chunks_manager is a
    // standalone encrypted 16-byte global, rip-absolute at all 838 read
    // sites, with zero writes and zero leas. Anchor on the absolute RVA.
    constexpr uint64_t RVA_CHUNKMGR_GLOBAL   = 0xE64B260ULL;
    constexpr uint64_t CHUNKMGR_XOR_RVA      = 0xB3F4030ULL;
    constexpr uint64_t CHUNKMGR_PSHUFB_RVA   = 0xB3F4040ULL;
    constexpr uint64_t CHUNKMGR_XOR_KEY      = 0x8387081898D8D8DDULL;
    constexpr int      CHUNKMGR_PSHUFLW      = 0x4B;
    constexpr int      CHUNKMGR_ROL32        = 5;

    constexpr uint64_t MGR_NUMELEMENTS_OFF   = 0x30ULL;
    constexpr uint64_t MGR_VTABLE_OFF        = 0x60ULL;
    constexpr uint64_t MGR_BLOB_OFF          = 0x90ULL;
    constexpr uint64_t MGR_VTABLE_SLOT       = 6ULL;
    constexpr uint64_t NUMELEM_PSHUFB_RVA    = 0xB447380ULL;
    constexpr int      NUMELEM_ROL16         = 2;
    constexpr uint32_t NUMELEM_XOR           = 0xE835E9F4u;

    constexpr uint32_t FUOBJECTITEM_STRIDE   = 20;
    constexpr uint32_t ITEMS_PER_CHUNK       = 65536;
    constexpr uint64_t UOBJECT_INTERNAL_IDX  = 0x0CULL;

    // 37 consecutive 0x40-byte vtables; runtime picks one via hash % 37.
    // 74 thunks, 73 structurally unique - interpretation is mandatory.
    constexpr uint64_t THUNK_VTABLE_POOL_LO  = 0xB47FB80ULL;
    constexpr uint64_t THUNK_VTABLE_POOL_HI  = 0xB4804C0ULL;
    constexpr uint32_t THUNK_VTABLE_COUNT    = 37;

    constexpr uint64_t UOBJ_NAME_SEED_OFF    = 0x10ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_BASE   = 0x20ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_STRIDE = 0x20ULL;
    constexpr uint64_t RVA_UOBJECT_GETFNAME  = 0x5027E0ULL;
    constexpr uint32_t UOBJ_SLOT_HASH_PRIME  = 0x01000193u;
    constexpr uint32_t UOBJ_SLOT_HASH_ADD    = 0x21B21773u;
    constexpr int      UOBJ_SLOT_HASH_ROL    = 0x18;
    constexpr int      UOBJ_SLOT_SHIFT_A     = 3;
    constexpr int      UOBJ_SLOT_SHIFT_B     = 8;
    constexpr int      UOBJ_SLOT_SHIFT_C     = 3;
    constexpr uint32_t UOBJ_SLOT_NAME_XOR    = 2u;
    constexpr uint32_t UOBJ_SLOT_CLASS_ADJ   = 0u;
    constexpr uint32_t UOBJ_SLOT_OUTER_ADJ   = 1u;
    constexpr uint8_t  UOBJ_NAME_PSHUFB[8]   = { 1, 4, 6, 0, 3, 7, 2, 5 };
    constexpr uint64_t UOBJ_NAME_PSHUFB_RVA  = 0xB42D360ULL;
    constexpr int      UOBJ_NAME_ROL16       = 2;
    constexpr uint64_t UOBJ_NAME_XOR         = 0x01554577E835E9F4ULL;
    constexpr int      UOBJ_NAME_ROL64       = 32;

    // Generic Theia pointer decrypt on this patch, same constants as the
    // chunks_manager global.
    constexpr uint64_t PTR_XOR_KEY           = 0x8387081898D8D8DDULL;
    constexpr int      PTR_PSHUFLW           = 0x4B;
    constexpr int      PTR_ROL32             = 5;
    constexpr uint8_t  PTR_PSHUFB[8]         = { 6, 2, 0, 7, 5, 1, 3, 4 };

    constexpr uint64_t USTRUCT_SUPER_OFF     = 0xA8ULL;
    constexpr uint64_t USTRUCT_CHILDREN      = 0xF8ULL;
    constexpr uint64_t USTRUCT_CHILDPROPS    = 0x100ULL;
    constexpr uint64_t USTRUCT_PROPSIZE_OFF  = 0x110ULL;
    constexpr uint64_t USTRUCT_MINALIGN_OFF  = 0xD8ULL;
    constexpr uint64_t USTRUCT_BASECHAIN_OFF = 0x98ULL;
    constexpr uint64_t UFIELD_NEXT_OFF       = 0x90ULL;
    constexpr uint64_t UCLASS_CASTFLAGS_OFF  = 0x1E8ULL;
    constexpr uint64_t UCLASS_CLASSFLAGS_OFF = 0x158ULL;
    constexpr uint64_t UCLASS_WITHIN_OFF     = 0x150ULL;
    constexpr uint64_t UCLASS_CONFIGNAME_OFF = 0x1F0ULL;

    // Intact on this patch - Theia stripped it on CL-1233465.
    constexpr uint64_t UENUM_NAMES_OFF       = 0xA8ULL;
    constexpr uint64_t UENUM_NUM_OFF         = 0xB0ULL;
    constexpr uint64_t UENUM_PAIR_STRIDE     = 0x10ULL;

    // NamePrivate is key-free on this patch: no XOR constant at all.
    constexpr uint64_t FFIELD_NAME_OFF       = 0x70ULL;
    constexpr int      FFIELD_NAME_PSHUFLW_A = 0x8D;
    constexpr int      FFIELD_NAME_ROL64_A   = 46;
    constexpr int      FFIELD_NAME_PSHUFLW_B = 0x4B;
    constexpr int      FFIELD_NAME_ROL64_B   = 32;

    constexpr uint64_t FFIELD_NEXT_OFF       = 0x80ULL;
    constexpr uint64_t FFIELD_SENTINEL_OFF   = 0x88ULL;
    constexpr uint64_t FFIELD_FLAGS_OFF      = 0x98ULL;
    constexpr uint64_t FFIELD_OWNER_OFF      = 0xA0ULL;

    constexpr uint64_t FPROP_SENTINEL_OFF    = 0xA8ULL;
    constexpr uint64_t FPROP_REPINDEX_OFF    = 0xB0ULL;
    constexpr uint64_t FPROP_PROPFLAGS_OFF   = 0xB8ULL;
    constexpr uint64_t FPROP_OFFSETINT_OFF   = 0xC4ULL;
    constexpr uint32_t FPROP_OFFSET_XOR      = 0xEE0CA1CBu;
    constexpr uint64_t FPROP_REPNOTIFY_OFF   = 0xE0ULL;
    constexpr uint64_t FPROP_ARRAYDIM_OFF    = 0xF0ULL;
    constexpr uint64_t FPROP_ELEMSIZE_OFF    = 0xF8ULL;
    constexpr uint64_t FPROP_SIZEOF          = 0x120ULL;

    constexpr uint64_t FBOOLPROP_FIELDSIZE   = 0x120ULL;
    constexpr uint64_t FBOOLPROP_BYTEOFFSET  = 0x121ULL;
    constexpr uint64_t FBOOLPROP_BYTEMASK    = 0x122ULL;
    constexpr uint64_t FBOOLPROP_FIELDMASK   = 0x123ULL;
} // namespace v20260811

// ─────────────────────────────────────────────────────────────────────────────
// Steam build CL-1341255 (1.42.x, 2026-08-18). Image size 0x116E7000.
//
// Theia changed shape here, it did not merely move: the UObject slot decode is
// now PCLMULQDQ over GF(2) instead of a shuffle/rotate chain, the chunks_manager
// lost its vtable-and-thunk indirection entirely, and UObject::InternalIndex
// moved from +0x0C to +0x90. Every RVA moved with the section layout as well
// (.text shrank 0x6F000, .data 0x35000).
// ─────────────────────────────────────────────────────────────────────────────
namespace v20260818 {
    constexpr uint64_t IMAGE_SIZE            = 0x116E7000ULL;

    constexpr uint64_t RVA_GNAMEPOOL         = 0xE35AB00ULL;
    constexpr uint64_t RVA_FNAME_RESOLVER    = 0x236220ULL;
    // Decrypted in place at load, so the module image holds the at-rest form.
    // This must be read from live memory.
    constexpr uint64_t RVA_KEYSTREAM         = 0xE2997F4ULL;
    constexpr int      KEYSTREAM_BASE_INDEX  = 80;
    constexpr int      KEYSTREAM_ENTRIES     = 144;

    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0x30091BB7u;
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x6FD0ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x6FE0ULL;
    constexpr uint64_t SHARD_BLOCK_STRIDE    = 32ULL;
    // ROL-based again, unlike the SHR-based first step on build 24653108.
    constexpr int      SHARD_ROL_A           = 0x17;
    constexpr int      SHARD_ROL_B           = 0x15;
    constexpr int      SHARD_ROL_C           = 0x17;
    constexpr int      SHARD_SHR_D           = 0x0B;

    // No PSHUFB in the block decode on this patch: ROL64 then XOR then ROL32.
    constexpr int      BLOCK_ROL64           = 4;
    constexpr int      BLOCK_ROL32           = 2;
    constexpr uint64_t BLOCK_FNV_XOR         = 0xF31D220392B6800BULL;
    constexpr uint64_t BLOCK_XOR_RVA         = 0xB3BEC30ULL;

    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0x6463CD794F959557ULL;
    constexpr int      FNV_ROL1              = 0x30;
    constexpr int      FNV_ROL2              = 0x2E;

    // The whole pointer-xor chain is gone; the FNV result IS the entry.
    constexpr bool     FNAME_PTR_CHAIN_IS_NOP = true;

    // Header moved: the length is a plain 10-bit field and the wide flag is
    // the sign bit, where build 24653108 split the length across two ranges
    // and used 0x800 for wide.
    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x8000u;
    constexpr uint16_t HDR_LENGTH_MASK       = 0x03FFu;
    constexpr uint32_t KEY_INIT_ADD          = 0xD917u;
    constexpr uint32_t KEY_ADVANCE           = 1u;
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      NARROW_KEY_SHIFT      = 3;
    constexpr int      WIDE_KEY_SHIFT        = 0;

    // Standalone encrypted 16-byte global, as on build 24653108, but the
    // vtable/thunk indirection is gone: NumElements and the chunk array are
    // xor+bswap fields on the decoded manager itself.
    constexpr uint64_t RVA_CHUNKMGR_GLOBAL   = 0xE616340ULL;
    constexpr uint64_t CHUNKMGR_PSHUFB_RVA   = 0xB3850F0ULL;
    constexpr uint8_t  CHUNKMGR_PSHUFB[8]    = { 5, 0, 4, 6, 7, 2, 3, 1 };
    constexpr int      CHUNKMGR_ROL64        = 50;
    constexpr int      CHUNKMGR_ROL32        = 22;

    constexpr uint64_t MGR_NUMELEMENTS_OFF   = 0x0CULL;
    constexpr uint32_t MGR_NUMELEMENTS_XOR   = 0xC460461Fu;
    constexpr uint64_t MGR_CHUNKARRAY_OFF    = 0x20ULL;
    constexpr uint64_t MGR_CHUNKARRAY_XOR    = 0xED46031B00000000ULL;

    constexpr uint32_t FUOBJECTITEM_STRIDE   = 20;
    constexpr uint32_t ITEMS_PER_CHUNK       = 65536;
    constexpr uint64_t FUOBJECTITEM_FLAGS    = 0x08ULL;
    constexpr uint64_t UOBJECT_INTERNAL_IDX  = 0x90ULL;

    constexpr uint64_t RVA_UOBJECT_GETFNAME  = 0x364780ULL;
    constexpr uint64_t RVA_SLOT_DECODER      = 0x3550C0ULL;
    constexpr uint64_t UOBJ_NAME_SEED_OFF    = 0x10ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_BASE   = 0x20ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_STRIDE = 0x20ULL;
    constexpr uint32_t UOBJ_SLOT_HASH_PRIME  = 0x01000193u;
    constexpr uint32_t UOBJ_SLOT_HASH_ADD    = 0xD4C2DB3Au;
    constexpr int      UOBJ_SLOT_ROL_A       = 0x19;
    constexpr int      UOBJ_SLOT_ROL_B       = 0x0E;
    constexpr int      UOBJ_SLOT_ROL_C       = 0x19;
    constexpr int      UOBJ_SLOT_ROL_D       = 0x0E;
    constexpr uint32_t UOBJ_SLOT_NAME_XOR    = 2u;
    constexpr uint32_t UOBJ_SLOT_CLASS_ADJ   = 0u;
    constexpr uint32_t UOBJ_SLOT_OUTER_ADJ   = 1u;
    constexpr int      UOBJ_NAME_ROL64       = 32;

    // The slot decoder is a shared leaf function; each call site passes its
    // own pair of 64-bit polynomials. The pandn blend around the first product
    // cancels — both halves xor the same rip constant — so what remains is
    // two carry-less multiplies.
    //   A = slot[0..8), B = slot[8..16)
    //   T = B ^ clmul_lo(K1, A)
    //   V = clmul_lo(K2, T) ^ A
    constexpr uint64_t SLOT_CLMUL_K1         = 0x0B6641A64F1B214DULL;
    constexpr uint64_t SLOT_CLMUL_K2         = 0x8FA21A13D9179A47ULL;

    constexpr uint64_t USTRUCT_SUPER_OFF     = 0xB0ULL;
    constexpr uint64_t USTRUCT_CHILDREN      = 0xE0ULL;
    constexpr uint64_t USTRUCT_CHILDPROPS    = 0xF8ULL;
    constexpr uint64_t USTRUCT_PROPSIZE_OFF  = 0x108ULL;
    constexpr uint64_t UCLASS_CASTFLAGS_OFF  = 0x130ULL;
    constexpr uint64_t UCLASS_WITHIN_OFF     = 0x128ULL;
    constexpr uint64_t UENUM_NAMES_OFF       = 0xB0ULL;
    constexpr uint64_t UENUM_NUM_OFF         = 0xB8ULL;

    // NamePrivate carries a key again, and the second stage is a per-dword ADD
    // rather than an XOR.
    //   V = ROL32_perdword(enc ^ K1, 29) ; V = PADDD(V, K2) ; ROL64(V.lo, 32)
    constexpr uint64_t FFIELD_NAME_OFF       = 0x50ULL;
    constexpr uint64_t FFIELD_NAME_K1        = 0xFDF20AE0DF1B2EFBULL;
    constexpr uint64_t FFIELD_NAME_K2        = 0x020DF52020E4D105ULL;
    constexpr uint64_t FFIELD_NAME_K1_RVA    = 0xB3DB830ULL;
    constexpr uint64_t FFIELD_NAME_K2_RVA    = 0xB3DB840ULL;
    constexpr int      FFIELD_NAME_ROL32     = 29;
    constexpr int      FFIELD_NAME_ROL64     = 32;

    constexpr uint64_t FFIELD_NEXT_OFF       = 0x60ULL;
    constexpr uint64_t FFIELD_CLASS_OFF      = 0x70ULL;
    constexpr uint64_t FFIELD_FLAGS_OFF      = 0x78ULL;
    constexpr uint64_t FFIELD_OWNER_OFF      = 0x80ULL;

    constexpr uint64_t FPROP_PROPFLAGS_OFF   = 0xC0ULL;
    constexpr uint64_t FPROP_OFFSETINT_OFF   = 0xA4ULL;
    constexpr uint32_t FPROP_OFFSET_XOR      = 0x7BDAAA72u;
    constexpr uint64_t FPROP_ARRAYDIM_OFF    = 0xD0ULL;
    constexpr uint64_t FPROP_ELEMSIZE_OFF    = 0xD8ULL;
    constexpr uint64_t FPROP_SIZEOF          = 0x100ULL;

    constexpr uint64_t FBOOLPROP_FIELDSIZE   = 0x100ULL;
    constexpr uint64_t FBOOLPROP_BYTEOFFSET  = 0x101ULL;
    constexpr uint64_t FBOOLPROP_BYTEMASK    = 0x102ULL;
    constexpr uint64_t FBOOLPROP_FIELDMASK   = 0x103ULL;
} // namespace v20260818


// ─────────────────────────────────────────────────────────────────────────────
// Steam build CL-1372005 (1.45.x, UE 5.7, 2026-09-08). Image size 0x14091000.
//
// UE 5.7 change: FUObjectItem grew to 24 bytes and the UObject pointer moved
// from +0 to +8 (first 8 bytes are flags now). ITEMS_PER_CHUNK stays 65536.
//
// Theia changes on this patch:
//   - Slot decoder is again a shared leaf, but the pair of 64-bit polynomials
//     changed (both K1 and K2 point at 0x14D4DF8D0 / 0x14D4DF910 in .rdata).
//   - FName resolver is split across three functions instead of two — a new
//     "middle" layer wraps the inner resolver. All three pointer XORs collapse
//     to identity like on v20260818, so EntryPtr = FNV_out + 2*NameOff.
//   - FField NamePrivate now decodes via PSHUFB + XOR + per-word ROL16(13) +
//     final ROL64(32), NOT the ROL32/PADDD chain used on CL-1341255.
//   - Block decode uses (pand/pandn)+pxor blend, per-dword ROL32(3), and a
//     per-dword PADDD constant — none of ROL64+XOR+ROL32 from v818.
//   - Shard hash goes back to a rotate-heavy FNV-32 (rols 19,13,19,13) with
//     a slot selector `(-109*T + 102) ^ ((P*T + ADD) >> 16) & 7`, like the
//     CL-1315578 shape rather than v818's `S = H^(H>>16); B = S & 7`.
//   - chunks_manager is still a standalone encrypted 16-byte global. Its
//     concrete decode shape is not extracted yet — set below to zero and gated
//     off until Auto-Resolve provides it.
// ─────────────────────────────────────────────────────────────────────────────
namespace v20260908 {
    constexpr uint64_t IMAGE_SIZE            = 0x14091000ULL;

    // Pool address is 0x150AB5DC0 in IDA (RVA 0x10AB5DC0). Verified against
    // the .rdata bytes at rest — 0x150AB5DC0 shows the expected FNamePool
    // block header while heap-probe candidates like 0x150A36B08 are runs of
    // 0xFF bytes and are NOT pools.
    constexpr uint64_t RVA_GNAMEPOOL         = 0x10AB5DC0ULL;
    constexpr uint64_t RVA_POOL_INIT_FLAG    = 0x10AB5D98ULL;
    constexpr uint64_t RVA_GNAMEPOOL_INIT    = 0x10AB5D98ULL; // legacy alias

    // Keystream window: uint16 table at RVA_KEYSTREAM. Decryptable entries
    // start at index KEYSTREAM_BASE_INDEX (byte-offset +0xF0 -> u16 idx 120).
    // Decrypted in place at load, so it MUST be read from live memory.
    constexpr uint64_t RVA_KEYSTREAM         = 0x1095926CULL;
    constexpr int      KEYSTREAM_BASE_INDEX  = 0x78;
    constexpr int      KEYSTREAM_ENTRIES     = 0x80;
    // Legacy alias.
    constexpr int      KEYSTREAM_BASE_OFF    = 0xF0;

    // FName entry function anchors.
    constexpr uint64_t RVA_FNAME_TOSTRING    = 0x2BF200ULL;
    constexpr uint64_t RVA_FNAME_STEP2       = 0x2DA4A0ULL;
    constexpr uint64_t RVA_FNAME_INNER       = 0x2DA260ULL;
    constexpr uint64_t RVA_POOL_INIT         = 0x2C7D20ULL;
    constexpr uint64_t RVA_FNAME_RESOLVER    = 0x2D5F40ULL; // sub_1402D5F40 (legacy alias)

    // Shard hash: 3 IMULs + final ROL32(13), then the CL-1315578-style slot
    // selector `(-109*v9 + 102) ^ ((P*v9+ADD) >> 16) & 7`. NOT `H ^ (H>>16)`.
    constexpr uint32_t HASH_PRIME            = 0x01000193u;
    constexpr uint32_t SHARD_HASH_PRIME      = 0x01000193u;
    constexpr uint32_t SHARD_HASH_ADD        = 0x902D0766u;
    constexpr int      SHARD_HASH_ROL_A      = 19;
    constexpr int      SHARD_HASH_ROL_B      = 13;
    constexpr uint64_t SHARD_HASH_SEED_OFF   = 0x2490ULL;
    constexpr uint64_t SHARD_BLOCK_BASE_OFF  = 0x24A0ULL;
    constexpr uint64_t SHARD_BLOCK_STRIDE    = 0x20ULL;
    // Legacy aliases so old references still compile.
    constexpr int      SHARD_ROL_A           = 19;
    constexpr int      SHARD_ROL_B           = 13;
    constexpr int      SHARD_ROL_C           = 19;
    constexpr int      SHARD_ROL_D           = 13;
    constexpr uint32_t SHARD_SLOT_M          = 0xFFFFFF93u;
    constexpr uint32_t SHARD_SLOT_ADD        = 102u;
    constexpr int      SHARD_SLOT_ROL        = 13;

    // Block decrypt. Blend `(x & K1) | (~x & K2)` collapses to `x ^ K2`
    // because K2 == ~K1, and `K2_C80 ^ K3_CA0 == K_BB0`, so both blocks
    // reduce to the SAME effective XOR key = BLOCK2_XOR.
    constexpr uint64_t BLOCK1_BLEND_K1_RVA   = 0xD4D3C80ULL;
    constexpr uint64_t BLOCK1_BLEND_K2_RVA   = 0xD4D3C90ULL;
    constexpr uint64_t BLOCK1_XOR_RVA        = 0xD4D3CA0ULL;
    constexpr uint64_t BLOCK_ADD_RVA         = 0xD4D3BC0ULL;
    constexpr uint64_t BLOCK2_XOR_RVA        = 0xD4D3BB0ULL;
    constexpr uint64_t BLOCK1_BLEND_K2       = 0x2B4667862B466786ULL;
    constexpr uint64_t BLOCK1_XOR            = 0x9B9D24BF5D56B7D8ULL;
    constexpr uint64_t BLOCK_ADD             = 0xB0DB433A7610D05FULL;
    constexpr uint64_t BLOCK2_XOR            = 0x4F24BCC689EF2FA1ULL;
    constexpr int      BLOCK_ROL32           = 3;
    // Legacy aliases.
    constexpr uint64_t BLOCK1_BLEND_K_A      = 0x2B4667862B466786ULL;
    constexpr uint64_t BLOCK1_BLEND_K_B      = 0xD4B99879D4B99879ULL;

    // FNV64 chain.
    constexpr uint64_t FNV_PRIME             = 0x100000001B3ULL;
    constexpr uint64_t FNV_ADD               = 0x6292C37EFA7F5FA6ULL;
    constexpr int      FNV_ROL1              = 37;
    constexpr int      FNV_ROL2              = 48;

    // Pointer chain (3 steps across sub_1402DA260 / DA4A0 / BF200).
    // Applied explicitly for correctness (algebraically it collapses to
    // identity because K1_i == K2_(7-i) ^ K3_(7-i)), but keeping the three
    // steps means any future change to the chain flows through automatically.
    constexpr uint64_t PTR_XOR1              = 0x5D4B82B8ULL;
    constexpr uint64_t PTR_XOR2              = 0x0000516500000000ULL;
    constexpr uint64_t PTR_XOR3              = 0xB8821A3800000000ULL;
    // Legacy aliases.
    constexpr uint64_t FNAME_PTR_XOR_INNER   = 0x000000005D4B82B8ULL;
    constexpr uint64_t FNAME_PTR_XOR_MIDDLE  = 0x0000516500000000ULL;
    constexpr uint64_t FNAME_PTR_XOR_OUTER   = 0xB8821A3800000000ULL;
    constexpr bool     FNAME_PTR_CHAIN_IS_NOP = true;

    // CI transform at head of sub_1402BF200 (used by the pool wrapper, not
    // by external CI passers — ResolveEntry consumes CI as-is).
    constexpr uint64_t RVA_CI_TRANSFORM_KEY  = 0xD4D38A0ULL;
    constexpr uint64_t CI_TRANSFORM_KEY_LO64 = 0x878588013124D57FULL;
    constexpr int      CI_TRANSFORM_ROL32    = 0x19;

    // FNameEntry header: 10-bit RAW-BYTE-COUNT length. Wide-flag sign bit.
    constexpr uint16_t HDR_IS_WIDE_BIT       = 0x8000u;
    constexpr uint16_t HDR_LENGTH_MASK       = 0x03FFu;
    // Legacy split-mask aliases.
    constexpr uint16_t HDR_LEN_LOW_MASK      = 0x0007u;
    constexpr uint16_t HDR_LEN_HIGH_MASK     = 0x03F8u;
    constexpr int      HDR_LEN_HIGH_SHIFT    = 5;

    // String decrypt (paired key schedule): idx1 = key & 0x3F, idx2 =
    // (key-1) & 0x3F. narrow shifts u16 by 3 to get byte key; wide XORs
    // full u16. After each pair, key += KEY_STEP_PAIR. Odd tail advances
    // by KEY_STEP_SINGLE.
    constexpr uint32_t KEY_INIT_ADD          = 0x2E0u;
    constexpr uint32_t KEY_STEP_PAIR         = 0x67Eu;
    constexpr uint32_t KEY_STEP_SINGLE       = 0x33Fu;
    constexpr uint8_t  KEY_INDEX_MASK        = 0x3Fu;
    constexpr int      NARROW_KEY_SHIFT      = 3;
    constexpr int      WIDE_KEY_SHIFT        = 0;
    // Legacy aliases.
    constexpr uint32_t KEY_ADVANCE_NARROW    = 0x33Fu;
    constexpr uint32_t KEY_ADVANCE_WIDE      = 0x3F0u;

    // chunks_manager (encrypted 16-byte global in .data). Decrypt:
    //   step1 = blob ^ MGR_KEY
    //   step2 = ROL16(step1, 13)
    //   mgr_ptr = PSHUFLW(step2, 27).lo64
    // Then on the decoded manager:
    //   NumElements = bswap32(*(u32*)(mgr + 4)  ^ MGR_NUMELEMENTS_XOR)
    //   ChunkArray  = bswap64(*(u64*)(mgr + 48) ^ MGR_CHUNKARRAY_XOR)
    // The RVA leading byte is 0x10 (chunkmgr sits in .data at 0x10D853F0),
    // NOT 0xD853F0 — losing that nibble was the first-port bug.
    constexpr uint64_t RVA_CHUNKMGR_GLOBAL   = 0x10D853F0ULL;
    constexpr uint64_t RVA_CHUNKMGR_KEY      = 0xD4B22B0ULL;
    constexpr int      CHUNKMGR_ROL16        = 13;
    constexpr int      CHUNKMGR_PSHUFLW_IMM  = 27;
    constexpr uint64_t MGR_NUMELEMENTS_OFF   = 0x04ULL;
    constexpr uint32_t MGR_NUMELEMENTS_XOR   = 0xBD497AA1u;
    constexpr uint64_t MGR_CHUNKARRAY_OFF    = 0x30ULL;
    constexpr uint64_t MGR_CHUNKARRAY_XOR    = 0x6BC7FB8600000000ULL;
    // Legacy aliases.
    constexpr uint64_t CHUNKMGR_XOR_KEY_RVA  = 0xD4B22B0ULL;
    constexpr uint64_t CHUNKMGR_XOR_KEY_LO64 = 0xD4A8B60E86179E4EULL;

    // FUObjectItem (UE 5.7): stride 24, UObject* at +8 (flags at +0..+7).
    // Still 65536 items per chunk despite the class-comment note about 8192 —
    // live probes confirm 65536.
    constexpr uint32_t FUOBJECTITEM_STRIDE   = 24;
    constexpr uint32_t ITEMS_PER_CHUNK       = 65536;
    constexpr int      CHUNK_INDEX_SHIFT     = 16;
    constexpr uint64_t CHUNK_INDEX_MASK      = 0xFFFFULL;
    constexpr uint64_t FUOBJECTITEM_OBJ_OFF  = 0x08ULL;
    constexpr uint64_t FUOBJECTITEM_FLAGS    = 0x00ULL;
    constexpr uint64_t UOBJECT_INTERNAL_IDX  = 0x90ULL;

    // UObject::GetFName. Anchored via AngelScript "FName GetName() const"
    // string. Slot decode:
    //   V = PSHUFLW(*Slot, 30) ^ SLOT_XOR_KEY_LO64
    //   V = ROL64(V, 17)
    //   V = PSHUFB(V, SLOT_PSHUF_MASK)
    //   FName = ROL64(V.lo64, 32)
    // Slot hash: uses SUBTRACT ADD not add, and a distinct IDX-ADD constant.
    constexpr uint64_t RVA_UOBJECT_GETFNAME  = 0x51A1928ULL;
    constexpr uint64_t RVA_GETFNAME          = 0x51A1928ULL;
    constexpr uint64_t RVA_SLOT_DECODER      = 0x5E7490ULL;
    constexpr uint64_t UOBJ_NAME_SEED_OFF    = 0x10ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_BASE   = 0x20ULL;
    constexpr uint64_t UOBJ_NAME_SLOT_STRIDE = 0x20ULL;
    constexpr uint32_t UOBJ_SLOT_HASH_PRIME  = 0x01000193u;
    constexpr uint32_t UOBJ_SLOT_HASH_ADD    = 0x993B3384u; // ADDitive (not sub)
    constexpr uint32_t UOBJ_SLOT_IDX_ADD     = 209796u;      // 0x33384
    constexpr int      UOBJ_SLOT_ROL_A       = 13;
    constexpr int      UOBJ_SLOT_ROL_B       = 22;
    constexpr int      UOBJ_SLOT_ROL_C       = 13;
    constexpr int      UOBJ_SLOT_SHR         = 10;
    constexpr int      UOBJ_SLOT_SHR_D       = 10; // legacy
    // Slot role adjustments: Name = Idx ^ 2, Class = (Idx + 1) & 3, Outer = Idx.
    constexpr uint32_t UOBJ_SLOT_NAME_XOR    = 2u;
    constexpr uint32_t UOBJ_SLOT_CLASS_ADJ   = 1u;
    constexpr uint32_t UOBJ_SLOT_OUTER_ADJ   = 0u;
    constexpr int      UOBJ_SLOT_PSHUFLW_IMM = 30;
    constexpr int      UOBJ_SLOT_ROL64       = 17;
    constexpr int      UOBJ_NAME_ROL64       = 32;
    constexpr uint64_t RVA_SLOT_XOR_KEY      = 0xD4DF910ULL;
    constexpr uint64_t RVA_SLOT_XOR_KEY_ALT  = 0xD4DF8D0ULL;
    constexpr uint64_t RVA_SLOT_SHUF_MASK    = 0xD4DF8E0ULL;
    constexpr uint64_t SLOT_XOR_KEY_LO64     = 0x06CC58E720047BF7ULL;
    constexpr uint8_t  SLOT_PSHUF_MASK[8]    = { 0x02, 0x05, 0x04, 0x06, 0x00, 0x07, 0x01, 0x03 };
    // Legacy aliases.
    constexpr uint64_t SLOT_KEY_A            = 0x06CC58E720047BF7ULL;
    constexpr uint64_t SLOT_KEY_B            = 0x06CC58E720047BF7ULL;
    constexpr uint8_t  SLOT_PSHUFB[8]        = { 2, 5, 4, 6, 0, 7, 1, 3 };

    // FField NamePrivate: PSHUFB(mask) -> XOR(key) -> ROL16(13) -> ROL64(32).
    constexpr uint64_t FFIELD_NAME_OFF       = 0x90ULL;
    constexpr uint64_t RVA_FFIELD_NAME_MASK  = 0xD4DF950ULL;
    constexpr uint64_t RVA_FFIELD_NAME_KEY   = 0xD4DF960ULL;
    constexpr uint64_t FFIELD_NAME_KEY_LO64  = 0x0D58B9970DD2BBAFULL;
    constexpr uint8_t  FFIELD_NAME_PSHUF_MASK[8] = { 0x05, 0x06, 0x01, 0x04, 0x03, 0x07, 0x02, 0x00 };
    constexpr int      FFIELD_NAME_ROL16     = 13;
    constexpr int      FFIELD_NAME_ROL64     = 32;
    // Legacy aliases.
    constexpr uint8_t  FFIELD_NAME_PSHUFB[8] = { 5, 6, 1, 4, 3, 7, 2, 0 };
    constexpr uint64_t FFIELD_NAME_XOR_KEY   = 0x0D58B9970DD2BBAFULL;

    // FField layout (verified 2026-09-08 via live probing).
    constexpr uint64_t FFIELD_OWNER_OFF      = 0x68ULL;
    constexpr uint64_t FFIELD_CLASS_OFF      = 0x70ULL;
    constexpr uint64_t FFIELD_FLAGS_OFF      = 0x78ULL;
    constexpr uint64_t FFIELD_NEXT_OFF       = 0x108ULL;

    // FProperty layout.
    // PropertyFlags at +0xA0 verified live (produces 4 distinct u64 values
    // across 5 sampled properties whereas +0xC0 gives the same repeating
    // 0x0E0E020206060202 byte pattern for every field).
    constexpr uint64_t FPROP_PROPFLAGS_OFF   = 0xA0ULL;
    constexpr uint64_t FPROP_OFFSETINT_OFF   = 0xB0ULL;
    constexpr uint32_t FPROP_OFFSET_XOR      = 0xC2CEEE92u;
    constexpr uint64_t FPROP_ELEMSIZE_OFF    = 0xB8ULL;
    constexpr uint64_t FPROP_ARRAYDIM_OFF    = 0xBCULL;
    constexpr uint64_t FPROP_SIZEOF          = 0x100ULL;

    // FBoolProperty extended slot (base is 0x118, not sizeof).
    constexpr uint64_t FBOOLPROP_FIELDSIZE   = 0x118ULL;
    constexpr uint64_t FBOOLPROP_BYTEOFFSET  = 0x119ULL;
    constexpr uint64_t FBOOLPROP_BYTEMASK    = 0x11AULL;
    constexpr uint64_t FBOOLPROP_FIELDMASK   = 0x11BULL;

    // UStruct layout.
    constexpr uint64_t USTRUCT_SUPER_OFF     = 0xA8ULL; // provisional
    constexpr uint64_t USTRUCT_CHILDPROPS    = 0x108ULL;
    constexpr uint64_t USTRUCT_PROPSIZE_OFF  = 0xD0ULL;
    constexpr uint64_t USTRUCT_BASECHAIN     = 0xA0ULL;
    constexpr uint64_t USTRUCT_BASECHAIN_DEPTH = 0xA8ULL;
    constexpr uint64_t USTRUCT_MINALIGN      = 0xD8ULL; // provisional

    // UClass / UFunction / UEnum (provisional).
    constexpr uint64_t UCLASS_CASTFLAGS_OFF  = 0x1E8ULL;
    constexpr uint64_t UCLASS_FLAGS_OFF      = 0x158ULL;
    constexpr uint64_t UCLASS_WITHIN_OFF     = 0x150ULL;
    constexpr uint64_t UFUNCTION_NATIVEFUNC  = 0x150ULL;
    constexpr uint64_t UENUM_NAMES_OFF       = 0xB0ULL;
    constexpr uint64_t UENUM_NUM_OFF         = 0xB8ULL;
} // namespace v20260908


// Applied twice: once when the pipeline is adopted, and again after
// auto_offsets runs, because the generic probes need a working FField name
// decode to score candidates — the very thing they are trying to discover —
// and they overwrite these values on the way out.
// ─────────────────────────────────────────────────────────────────────────────
// The live sheet.
//
// Everything auto_resolve.h can extract and validate lives here rather than in
// a constexpr namespace, so a patch that only moves these values no longer
// requires a source edit. Defaults are the v20260811 numbers; Phase 6.5
// overwrites them only after extraction succeeds, and the FName "None"
// self-test plus the structural slot scorer decide whether it was right.
// ─────────────────────────────────────────────────────────────────────────────
// The shard hash is recorded as a program, not a fixed op list. Its shape
// already changed once — CL-1325322 seeded it with `Lo >> 4`, build 24653108
// with a `mov r8d,0x10 ; shld r8d,edx,0x1A` pair yielding
// (0x40000000 | (Lo >> 6)) — so assume the alphabet, never the sequence.
struct HashOp {
    enum Kind { SeedShr, SeedRol, SeedShld, Rol, Shr, Imul, Add, AddHi } K = Imul;
    uint32_t A = 0;
    uint32_t B = 0;
};

inline uint32_t RunHashProgram(const std::vector<HashOp>& Ops, uint32_t Lo, uint32_t Hi) {
    uint32_t H = Lo;
    for (const auto& O : Ops) {
        switch (O.K) {
            case HashOp::SeedShr:  H = Lo >> (O.A & 31); break;
            case HashOp::SeedRol:  { uint32_t N = O.A & 31; H = N ? ((Lo << N) | (Lo >> (32 - N))) : Lo; break; }
            case HashOp::SeedShld: { uint32_t N = O.A & 31; H = (uint32_t)(O.B << N) | (N ? (Lo >> (32 - N)) : 0); break; }
            case HashOp::Rol:      { uint32_t N = O.A & 31; if (N) H = (H << N) | (H >> (32 - N)); break; }
            case HashOp::Shr:   H >>= (O.A & 31); break;
            case HashOp::Imul:  H *= O.A; break;
            case HashOp::Add:   H += O.A; break;
            case HashOp::AddHi: H += Hi; break;
        }
    }
    return H;
}

struct LiveSheet {
    bool     Resolved = false;

    uint32_t SlotHashPrime = v20260811::UOBJ_SLOT_HASH_PRIME;
    uint32_t SlotHashAdd   = v20260811::UOBJ_SLOT_HASH_ADD;
    int      SlotHashRol   = v20260811::UOBJ_SLOT_HASH_ROL;
    int      SlotShiftA    = v20260811::UOBJ_SLOT_SHIFT_A;
    int      SlotShiftB    = v20260811::UOBJ_SLOT_SHIFT_B;
    int      SlotShiftC    = v20260811::UOBJ_SLOT_SHIFT_C;

    uint32_t SlotNameXor   = v20260811::UOBJ_SLOT_NAME_XOR;
    uint32_t SlotClassAdj  = v20260811::UOBJ_SLOT_CLASS_ADJ;
    uint32_t SlotOuterAdj  = v20260811::UOBJ_SLOT_OUTER_ADJ;
    uint64_t SlotBase      = v20260811::UOBJ_NAME_SLOT_BASE;
    uint64_t SlotStride    = v20260811::UOBJ_NAME_SLOT_STRIDE;

    uint8_t  SlotPshufb[8] = { 1, 4, 6, 0, 3, 7, 2, 5 };
    int      SlotRol16     = v20260811::UOBJ_NAME_ROL16;
    uint64_t SlotXor64     = v20260811::UOBJ_NAME_XOR;
    int      SlotFinalRol  = v20260811::UOBJ_NAME_ROL64;

    uint64_t ChunkMgrRva   = v20260811::RVA_CHUNKMGR_GLOBAL;

    // FName pipeline. An empty ShardHashProgram means "use the compiled
    // shard hash"; auto-resolve fills it once CI=0 has decoded to "None".
    uint64_t PoolRva      = v20260811::RVA_GNAMEPOOL;
    uint64_t SeedOff      = v20260811::SHARD_HASH_SEED_OFF;
    uint64_t BlockBase    = v20260811::SHARD_BLOCK_BASE_OFF;
    uint64_t BlockStride  = v20260811::SHARD_BLOCK_STRIDE;
    std::vector<HashOp> ShardHashProgram;

    uint8_t  BlockPshufb[8] = { 1, 4, 6, 0, 3, 7, 2, 5 };
    int      BlockRol16     = v20260811::BLOCK_ROL16;
    uint64_t BlockXor       = v20260811::BLOCK_FNV_XOR;

    uint64_t FnvPrime = v20260811::FNV_PRIME;
    uint64_t FnvAdd   = v20260811::FNV_ADD;
    int      FnvRol1  = v20260811::FNV_ROL1;
    int      FnvRol2  = v20260811::FNV_ROL2;

    // Only its value mod 64 matters, and the keystream sweep already absorbs
    // that, so this is read out of the string-decrypt sites rather than
    // derived from any decode.
    uint32_t KeyInitAdd = v20260811::KEY_INIT_ADD;

    // Base of FieldSize/ByteOffset/ByteMask/FieldMask, from SetBoolSize.
    uint64_t BoolFieldBase = v20260811::FBOOLPROP_FIELDSIZE;

    // Recovered from FProperty::SetupOffset.
    uint64_t PropOffsetInternal = v20260811::FPROP_OFFSETINT_OFF;
    uint32_t PropOffsetXor      = v20260811::FPROP_OFFSET_XOR;
    uint64_t ClassCastFlagsOff  = v20260811::UCLASS_CASTFLAGS_OFF;
    uint64_t StructPropSizeOff  = v20260811::USTRUCT_PROPSIZE_OFF;

    // Table address plus base index, so indexing is simply idx*2 from here.
    uint64_t KeystreamWindowRva =
        v20260811::RVA_KEYSTREAM + (uint64_t)v20260811::KEYSTREAM_BASE_INDEX * 2;

    // The v20260818 anchors. Kept separate from the v811 fields above rather
    // than overloading them: the two pipelines differ in shape, not just in
    // value, so a half-adopted mix of the two would decode plausible garbage
    // instead of failing.
    // Anything auto_resolve818 can extract lives here, so a patch that only
    // moves these needs no source edit. Both hash chains are stored as
    // programs rather than fixed op slots: the shard hash has already gone
    // SHR-form (build 24653108) and back to ROL-form (CL-1341255), and a
    // fixed-slot representation cannot express that without a code change.
    uint64_t Pool818Rva      = v20260818::RVA_GNAMEPOOL;
    uint64_t Keystream818Rva =
        v20260818::RVA_KEYSTREAM + (uint64_t)v20260818::KEYSTREAM_BASE_INDEX * 2;
    uint64_t ChunkMgr818Rva  = v20260818::RVA_CHUNKMGR_GLOBAL;
    uint64_t BlockXor818     = v20260818::BLOCK_FNV_XOR;
    uint64_t FFieldNameK1_818 = v20260818::FFIELD_NAME_K1;
    uint64_t FFieldNameK2_818 = v20260818::FFIELD_NAME_K2;
    uint64_t SlotClmulK1_818 = v20260818::SLOT_CLMUL_K1;
    uint64_t SlotClmulK2_818 = v20260818::SLOT_CLMUL_K2;
    uint32_t KeyInitAdd818   = v20260818::KEY_INIT_ADD;

    std::vector<HashOp> Shard818Program;   // empty => the compiled ROL form
    uint64_t Seed818Off      = v20260818::SHARD_HASH_SEED_OFF;
    uint64_t Block818Base    = v20260818::SHARD_BLOCK_BASE_OFF;
    uint64_t Block818Stride  = v20260818::SHARD_BLOCK_STRIDE;
    int      Block818Rol64   = v20260818::BLOCK_ROL64;
    int      Block818Rol32   = v20260818::BLOCK_ROL32;
    uint64_t Fnv818Prime     = v20260818::FNV_PRIME;
    uint64_t Fnv818Add       = v20260818::FNV_ADD;
    int      Fnv818Rol1      = v20260818::FNV_ROL1;
    int      Fnv818Rol2      = v20260818::FNV_ROL2;
    uint16_t Hdr818LenMask   = v20260818::HDR_LENGTH_MASK;
    uint16_t Hdr818WideBit   = v20260818::HDR_IS_WIDE_BIT;

    std::vector<HashOp> Slot818Program;    // empty => the compiled ROL form
    uint64_t Slot818SeedOff  = v20260818::UOBJ_NAME_SEED_OFF;
    uint64_t Slot818Base     = v20260818::UOBJ_NAME_SLOT_BASE;
    uint64_t Slot818Stride   = v20260818::UOBJ_NAME_SLOT_STRIDE;
    uint32_t Slot818NameXor  = v20260818::UOBJ_SLOT_NAME_XOR;
    uint32_t Slot818ClassAdj = v20260818::UOBJ_SLOT_CLASS_ADJ;
    uint32_t Slot818OuterAdj = v20260818::UOBJ_SLOT_OUTER_ADJ;
    int      Slot818FinalRol = v20260818::UOBJ_NAME_ROL64;

    uint8_t  ChunkMgr818Pshufb[8] = { 5, 0, 4, 6, 7, 2, 3, 1 };
    int      ChunkMgr818Rol64 = v20260818::CHUNKMGR_ROL64;
    int      ChunkMgr818Rol32 = v20260818::CHUNKMGR_ROL32;
    uint64_t Mgr818NumOff     = v20260818::MGR_NUMELEMENTS_OFF;
    uint32_t Mgr818NumXor     = v20260818::MGR_NUMELEMENTS_XOR;
    uint64_t Mgr818ArrOff     = v20260818::MGR_CHUNKARRAY_OFF;
    uint64_t Mgr818ArrXor     = v20260818::MGR_CHUNKARRAY_XOR;

    // Set once every 818 area has been extracted and the pipeline self-test
    // passed, so a run can report whether it is standing on resolved values
    // or on the compiled defaults.
    bool     Resolved818      = false;

    // Set once an area has been extracted and validated, so ApplyOffsets818 —
    // which runs several times per session — re-asserts a compiled default only
    // where nothing better is known. Without this the second call quietly undoes
    // every adoption the first one enabled.
    bool     PropOff818Resolved    = false;
    bool     FFieldName818Resolved = false;
    bool     Layout818Resolved     = false;

    uint64_t FFieldName818Off     = v20260818::FFIELD_NAME_OFF;
    int      FFieldName818Rol32   = v20260818::FFIELD_NAME_ROL32;
    int      FFieldName818Rol64   = v20260818::FFIELD_NAME_ROL64;
    uint64_t FProp818Sizeof       = v20260818::FPROP_SIZEOF;
    uint64_t FField818Next        = v20260818::FFIELD_NEXT_OFF;
    uint64_t FField818Owner       = v20260818::FFIELD_OWNER_OFF;
    uint64_t UStruct818ChildProps = v20260818::USTRUCT_CHILDPROPS;
    uint64_t UStruct818Super      = v20260818::USTRUCT_SUPER_OFF;
    uint64_t UStruct818Children   = v20260818::USTRUCT_CHILDREN;

    // The v20260908 anchors. Same rule as the 818 fields above: separate from
    // 811/818 rather than overloaded, so a half-adopted mix cannot silently
    // decode garbage. Shape differences on v908:
    //   - Block decode uses per-dword ROL32(3) + PADDD, with a
    //     pand/pandn/por blend on block 1 keyed by two different constants
    //   - FField name decode is PSHUFB + XOR + ROL16(13) + ROL64(32)
    //   - Slot decoder is a shared leaf again but with new K1/K2 polynomials
    //   - Chunks-manager decrypt shape is not extracted yet; the array init
    //     path falls back to the 818 shape (and will fail) until Auto-Resolve
    //     supplies the v908 decode.
    uint64_t Pool908Rva          = v20260908::RVA_GNAMEPOOL;
    // Keystream window: KEYSTREAM_RVA + KEYSTREAM_BASE_INDEX*2 bytes.
    uint64_t Keystream908Rva     =
        v20260908::RVA_KEYSTREAM + (uint64_t)v20260908::KEYSTREAM_BASE_INDEX * 2;
    uint64_t ChunkMgr908Rva      = v20260908::RVA_CHUNKMGR_GLOBAL;
    uint64_t ChunkMgr908KeyRva   = v20260908::RVA_CHUNKMGR_KEY;
    uint32_t Mgr908NumOff        = (uint32_t)v20260908::MGR_NUMELEMENTS_OFF;
    uint32_t Mgr908NumXor        = v20260908::MGR_NUMELEMENTS_XOR;
    uint64_t Mgr908ArrOff        = v20260908::MGR_CHUNKARRAY_OFF;
    uint64_t Mgr908ArrXor        = v20260908::MGR_CHUNKARRAY_XOR;

    std::vector<HashOp> Shard908Program;   // empty => the compiled ROL form
    uint64_t Seed908Off        = v20260908::SHARD_HASH_SEED_OFF;
    uint64_t Block908Base      = v20260908::SHARD_BLOCK_BASE_OFF;
    uint64_t Block908Stride    = v20260908::SHARD_BLOCK_STRIDE;
    uint64_t Block1BlendKa908  = v20260908::BLOCK1_BLEND_K_A;
    uint64_t Block1BlendKb908  = v20260908::BLOCK1_BLEND_K_B;
    uint64_t Block1Xor908      = v20260908::BLOCK1_XOR;
    uint64_t Block2Xor908      = v20260908::BLOCK2_XOR;
    uint64_t BlockAdd908       = v20260908::BLOCK_ADD;
    int      BlockRol32_908    = v20260908::BLOCK_ROL32;
    uint64_t Fnv908Prime       = v20260908::FNV_PRIME;
    uint64_t Fnv908Add         = v20260908::FNV_ADD;
    int      Fnv908Rol1        = v20260908::FNV_ROL1;
    int      Fnv908Rol2        = v20260908::FNV_ROL2;
    uint16_t Hdr908WideBit     = v20260908::HDR_IS_WIDE_BIT;
    uint16_t Hdr908LenLoMask   = v20260908::HDR_LEN_LOW_MASK;
    uint16_t Hdr908LenHiMask   = v20260908::HDR_LEN_HIGH_MASK;
    int      Hdr908LenHiShift  = v20260908::HDR_LEN_HIGH_SHIFT;
    uint32_t KeyInitAdd908     = v20260908::KEY_INIT_ADD;
    uint32_t KeyAdvanceNarrow908 = v20260908::KEY_ADVANCE_NARROW;
    uint32_t KeyAdvanceWide908 = v20260908::KEY_ADVANCE_WIDE;

    std::vector<HashOp> Slot908Program;    // empty => compiled ROL/SHR form
    uint64_t Slot908SeedOff    = v20260908::UOBJ_NAME_SEED_OFF;
    uint64_t Slot908Base       = v20260908::UOBJ_NAME_SLOT_BASE;
    uint64_t Slot908Stride     = v20260908::UOBJ_NAME_SLOT_STRIDE;
    uint32_t Slot908NameXor    = v20260908::UOBJ_SLOT_NAME_XOR;
    uint32_t Slot908ClassAdj   = v20260908::UOBJ_SLOT_CLASS_ADJ;
    uint32_t Slot908OuterAdj   = v20260908::UOBJ_SLOT_OUTER_ADJ;
    int      Slot908FinalRol   = v20260908::UOBJ_NAME_ROL64;
    uint64_t SlotKeyA_908      = v20260908::SLOT_KEY_A;
    uint64_t SlotKeyB_908      = v20260908::SLOT_KEY_B;
    uint8_t  SlotPshufb908[8]  = { 2, 5, 4, 6, 0, 7, 1, 3 };

    bool     Resolved908           = false;
    bool     PropOff908Resolved    = false;
    bool     FFieldName908Resolved = false;
    bool     Layout908Resolved     = false;
    bool     ChunkMgr908Resolved   = false;

    uint64_t FFieldName908Off        = v20260908::FFIELD_NAME_OFF;
    uint64_t FFieldNameKey908        = v20260908::FFIELD_NAME_XOR_KEY;
    uint8_t  FFieldNamePshufb908[8]  = { 5, 6, 1, 4, 3, 7, 2, 0 };
    int      FFieldName908Rol16      = v20260908::FFIELD_NAME_ROL16;
    int      FFieldName908Rol64      = v20260908::FFIELD_NAME_ROL64;
    uint64_t FProp908Sizeof          = v20260908::FPROP_SIZEOF;
    uint64_t FField908Next           = v20260908::FFIELD_NEXT_OFF;
    uint64_t FField908Owner          = v20260908::FFIELD_OWNER_OFF;
    uint64_t FField908Class          = v20260908::FFIELD_CLASS_OFF;
    uint64_t FField908Flags          = v20260908::FFIELD_FLAGS_OFF;
    uint64_t UStruct908ChildProps    = v20260908::USTRUCT_CHILDPROPS;
    uint64_t UStruct908Super         = v20260908::USTRUCT_SUPER_OFF;
    uint64_t UStruct908BaseChain     = v20260908::USTRUCT_BASECHAIN;
    uint32_t FUObjectItemStride908   = v20260908::FUOBJECTITEM_STRIDE;
    uint64_t FUObjectItemObjOff908   = v20260908::FUOBJECTITEM_OBJ_OFF;
    uint64_t UObjectInternalIdx908   = v20260908::UOBJECT_INTERNAL_IDX;
};

inline LiveSheet g_Sheet;

inline void ApplyOffsets811() {
    namespace V = v20260811;
    namespace Off = Offsets;
    Off::FField::NamePrivate        = V::FFIELD_NAME_OFF;
    Off::FField::NameEncrypted      = V::FFIELD_NAME_OFF;
    Off::FField::Next               = V::FFIELD_NEXT_OFF;
    Off::FField::Owner              = V::FFIELD_OWNER_OFF;
    Off::UStruct::ChildProperties   = V::USTRUCT_CHILDPROPS;
    Off::UStruct::PropertiesSize    = g_Sheet.StructPropSizeOff;
    Off::UStruct::SuperStruct       = V::USTRUCT_SUPER_OFF;
    Off::UEnum::Names               = V::UENUM_NAMES_OFF;
    Off::FProperty::ArrayDim        = V::FPROP_ARRAYDIM_OFF;
    Off::FProperty::ElementSize     = V::FPROP_ELEMSIZE_OFF;
    Off::FProperty::PropertyFlags   = V::FPROP_PROPFLAGS_OFF;
    // These four come from the sheet: auto-resolve recovers them from
    // FProperty::SetupOffset, and this function runs after that.
    Off::FProperty::Offset_Internal = g_Sheet.PropOffsetInternal;
    Off::FProperty::Offset_XOR      = g_Sheet.PropOffsetXor;
    Off::FBoolProperty::FieldSize   = g_Sheet.BoolFieldBase;
    Off::FBoolProperty::ByteOffset  = g_Sheet.BoolFieldBase + 1;
    Off::FBoolProperty::ByteMask    = g_Sheet.BoolFieldBase + 2;
    Off::FBoolProperty::FieldMask   = g_Sheet.BoolFieldBase + 3;
    Patch20260421::g_PropertyOffsetXor = g_Sheet.PropOffsetXor;

    // Subclass data starts right after the FProperty base, which is 0x120 on
    // this patch. The inherited 0x138 came from CL-1315578 and reads past the
    // allocation: every array's "Inner" then resolves to the NEXT field in the
    // chain, so the pseudo __Item entry collides with that field in the
    // ff_addr map and evicts it. That is what removed AActor::RootComponent,
    // ParentComponent and BlueprintCreatedComponents from the dump, and what
    // gave Tags the type of the delegate that follows it.
    // Probed live: +0x110 and +0x118 are the link fields and both hold Next,
    // +0x120 is the first subclass slot, and the array's element property sits
    // at +0x128 — element sizes there come out as 8 for TArray<FName> and 32
    // for TArray<FSoftObjectPath>, which is the check that settles it.
    Off::FArrayProperty::Inner          = V::FPROP_SIZEOF + 8;
    Off::FSetProperty::ElementProp      = V::FPROP_SIZEOF;
    Off::FSoftObjectProperty::PropertyClass = V::FPROP_SIZEOF;
    Off::FMapProperty::KeyProp          = V::FPROP_SIZEOF;
    Off::FMapProperty::ValueProp        = V::FPROP_SIZEOF + 8;
    Off::FStructProperty::Struct        = V::FPROP_SIZEOF;
    Off::FObjectProperty::PropertyClass = V::FPROP_SIZEOF;
    Off::FEnumProperty::UnderlyingProp  = V::FPROP_SIZEOF;
    Off::FEnumProperty::Enum            = V::FPROP_SIZEOF + 8;
}


// The CL-1341255 layout. Same role as ApplyOffsets811 and applied at the same
// two points: once on adoption, and again after auto_offsets runs, because the
// generic probes need a working FField name decode to score candidates and
// overwrite these on their way out.
inline void ApplyOffsets818() {
    namespace V = v20260818;
    namespace Off = Offsets;
    Off::FField::NamePrivate        = g_Sheet.FFieldName818Off;
    Off::FField::NameEncrypted      = g_Sheet.FFieldName818Off;
    Off::FField::Next               = g_Sheet.FField818Next;
    Off::FField::Owner              = g_Sheet.FField818Owner;
    Off::FField::ClassPrivate       = V::FFIELD_CLASS_OFF;
    Off::UStruct::ChildProperties   = g_Sheet.UStruct818ChildProps;
    Off::UStruct::PropertiesSize    = V::USTRUCT_PROPSIZE_OFF;
    Off::UStruct::SuperStruct       = g_Sheet.UStruct818Super;
    Off::UEnum::Names               = V::UENUM_NAMES_OFF;
    Off::FProperty::ArrayDim        = V::FPROP_ARRAYDIM_OFF;
    Off::FProperty::ElementSize     = V::FPROP_ELEMSIZE_OFF;
    Off::FProperty::PropertyFlags   = V::FPROP_PROPFLAGS_OFF;
    if (!g_Sheet.PropOff818Resolved) {
        g_Sheet.PropOffsetInternal = V::FPROP_OFFSETINT_OFF;
        g_Sheet.PropOffsetXor      = V::FPROP_OFFSET_XOR;
    }
    Off::FProperty::Offset_Internal = g_Sheet.PropOffsetInternal;
    Off::FProperty::Offset_XOR      = g_Sheet.PropOffsetXor;
    Off::FBoolProperty::FieldSize   = g_Sheet.FProp818Sizeof;
    Off::FBoolProperty::ByteOffset  = g_Sheet.FProp818Sizeof + 1;
    Off::FBoolProperty::ByteMask    = g_Sheet.FProp818Sizeof + 2;
    Off::FBoolProperty::FieldMask   = g_Sheet.FProp818Sizeof + 3;
    Patch20260421::g_PropertyOffsetXor = g_Sheet.PropOffsetXor;

    // sizeof(FProperty) is 0x100 here, fixed by FBoolProperty's four bytes
    // landing at +0x100..+0x103 (the FieldMask read at +0x103 in
    // FBoolProperty::GetCPPType pins it exactly).
    const uint64_t Sz = g_Sheet.FProp818Sizeof;
    Off::FArrayProperty::Inner          = Sz + 8;
    Off::FSetProperty::ElementProp      = Sz;
    Off::FSoftObjectProperty::PropertyClass = Sz;
    Off::FMapProperty::KeyProp          = Sz;
    Off::FMapProperty::ValueProp        = Sz + 8;
    Off::FStructProperty::Struct        = Sz;
    Off::FObjectProperty::PropertyClass = Sz;
    Off::FEnumProperty::UnderlyingProp  = Sz;
    Off::FEnumProperty::Enum            = Sz + 8;

    // ClassCastFlags has no slot in Offsets; the metaclass oracle reads it
    // out of the sheet, so it is stamped there.
    g_Sheet.ClassCastFlagsOff       = V::UCLASS_CASTFLAGS_OFF;
    g_Sheet.StructPropSizeOff       = V::USTRUCT_PROPSIZE_OFF;
    g_Sheet.BoolFieldBase           = g_Sheet.FProp818Sizeof;
}


// The CL-1372005 (UE 5.7) layout. Same rule as ApplyOffsets818 — applied on
// adoption and again after auto_offsets runs, since the generic probes need a
// working FField name decode to score candidates and overwrite these on the way
// out.
inline void ApplyOffsets908() {
    namespace V = v20260908;
    namespace Off = Offsets;
    Off::FField::NamePrivate        = g_Sheet.FFieldName908Off;
    Off::FField::NameEncrypted      = g_Sheet.FFieldName908Off;
    Off::FField::Next               = g_Sheet.FField908Next;
    Off::FField::Owner              = g_Sheet.FField908Owner;
    Off::FField::ClassPrivate       = g_Sheet.FField908Class;
    Off::UStruct::ChildProperties   = g_Sheet.UStruct908ChildProps;
    Off::UStruct::PropertiesSize    = V::USTRUCT_PROPSIZE_OFF;
    Off::UStruct::SuperStruct       = g_Sheet.UStruct908Super;
    Off::UEnum::Names               = V::UENUM_NAMES_OFF;
    Off::FProperty::ArrayDim        = V::FPROP_ARRAYDIM_OFF;
    Off::FProperty::ElementSize     = V::FPROP_ELEMSIZE_OFF;
    Off::FProperty::PropertyFlags   = V::FPROP_PROPFLAGS_OFF;
    if (!g_Sheet.PropOff908Resolved) {
        g_Sheet.PropOffsetInternal = V::FPROP_OFFSETINT_OFF;
        g_Sheet.PropOffsetXor      = V::FPROP_OFFSET_XOR;
    }
    Off::FProperty::Offset_Internal = g_Sheet.PropOffsetInternal;
    Off::FProperty::Offset_XOR      = g_Sheet.PropOffsetXor;
    Off::FBoolProperty::FieldSize   = V::FBOOLPROP_FIELDSIZE;
    Off::FBoolProperty::ByteOffset  = V::FBOOLPROP_BYTEOFFSET;
    Off::FBoolProperty::ByteMask    = V::FBOOLPROP_BYTEMASK;
    Off::FBoolProperty::FieldMask   = V::FBOOLPROP_FIELDMASK;
    Patch20260421::g_PropertyOffsetXor = g_Sheet.PropOffsetXor;

    // Subclass data starts right after the FProperty base (sizeof=0x100).
    // Inner sits at +0x108 (KeyProp at +0x100) — probed live on the Windows
    // port; TArray<FName> element size at +0x108 came out at 8 and TArray
    // <FSoftObjectPath> at 32, which is the check that settles it.
    const uint64_t Sz = g_Sheet.FProp908Sizeof;
    Off::FArrayProperty::Inner          = Sz + 8;
    Off::FSetProperty::ElementProp      = Sz;
    Off::FSoftObjectProperty::PropertyClass = Sz;
    Off::FMapProperty::KeyProp          = Sz;
    Off::FMapProperty::ValueProp        = Sz + 8;
    Off::FStructProperty::Struct        = Sz;
    Off::FObjectProperty::PropertyClass = Sz;
    Off::FEnumProperty::UnderlyingProp  = Sz;
    Off::FEnumProperty::Enum            = Sz + 8;

    // Not yet extracted for v908 — leave the metaclass oracle off until then.
    // Callers must use ReadClassCastFlagsChecked so a zero verdict does not
    // silently promote instances to classes.
    g_Sheet.ClassCastFlagsOff       = 0;
    g_Sheet.StructPropSizeOff       = V::USTRUCT_PROPSIZE_OFF;
    g_Sheet.BoolFieldBase           = V::FBOOLPROP_FIELDSIZE;
}
} // namespace ArcDecrypt
