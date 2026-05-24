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
    namespace UObject {
        inline uint64_t VTable       = 0x00;
        inline uint64_t InternalIndex= 0x0C;
        inline uint64_t FieldsSlots  = 0x20;
    }
    namespace FField {
        // CL-1201801: FField layout re-verified via live memory probe of two
        // adjacent FFields whose Owner backref matched the hosting UScriptStruct.
        // FField base grew from ~0x60 to ~0x80 (+0x20 added after vtable at
        // +0x08..+0x3F as encrypted/pool block). All offsets confirmed by
        // cross-referencing Owner pointer and chain continuity.
        inline uint64_t VTable        = 0x00;
        inline uint64_t ClassPrivate  = 0x60;     // CL-1201801 (was 0x08)
        inline uint64_t Next          = 0x50;     // CL-1201801 (was 0x20)
        inline uint64_t Owner         = 0x70;     // CL-1201801 (was 0x10)
        inline uint64_t NameEncrypted = 0x40;     // CL-1201801 (was 0x50)
        inline uint64_t NamePrivate   = 0x40;     // CL-1201801 (was 0x50)
        inline uint64_t SaltSentinel  = 0x48;     // CL-1201801 (was 0x58); live value = 9D2351A95B47E79F
    }
    namespace FFieldClass {
        inline uint64_t ElementSize  = 0x70;
    }
    namespace FProperty {
        // CL-1195482: FProperty layout. Verified via IDA encode-site analysis
        // (5 sites with `xor eax,imm32; bswap eax; mov [rbx+0x64]; ... mov ecx,
        // [rbx+0x68]; imul ecx, [rbx+0x6C]`):
        //   +0x64 = Offset_Internal (encoded)
        //   +0x68 = ElementSize (int32, also serves as FBoolProperty::FieldSize)
        //   +0x6C = ArrayDim (int32, multiplied with ElementSize)
        // FField body ends ~+0x60; +0x60..+0x63 is some FField tail field
        // (could be PropertyFlags low 32, or FlagsPrivate).
        inline uint64_t ArrayDim        = 0xC0;   // CL-1201801 (verified sub_140433460 ctor +0xC0=1 init)
        inline uint64_t ElementSize     = 0xC8;   // CL-1201801 (verified sub_140433460 ctor +0xC8=0 init)
        inline uint64_t Offset_Internal = 0x94;   // CL-1201801 (verified sub_140433460 ctor +0x94 = bswap(src^0xBAB939DB))
        inline uint32_t Offset_XOR      = 0xBAB939DBu;  // CL-1201801 (was 0xCCCCACBB; 0 hits in binary for old key)
        inline uint64_t PropertyFlags   = 0x88;   // CL-1201801 (verified sub_140433460 ctor +0x88 = flags qword)
    }
    namespace FBoolProperty {
        // CL-1201801: verified sub_140434670 ctor.
        // +0xF0 = FieldSize (byte copy of ElementSize: 1, 2, 4, or 8)
        // +0xF1 = ByteOffset (byte index within field)
        // +0xF2 = ByteMask (1-bit mask: 0x01..0x80)
        // +0xF3 = FieldMask (all-bools-in-byte mask)
        inline uint64_t FieldSize  = 0xF0;   // CL-1201801 (was 0x88/ElementSize; now distinct byte field)
        inline uint64_t ByteOffset = 0xF1;   // CL-1201801 (was 0xF0)
        inline uint64_t ByteMask   = 0xF2;   // unchanged
        inline uint64_t FieldMask  = 0xF3;   // unchanged
    }
    // CL-1201801: FProperty sub-class fields shifted +0x20 (FField base grew from ~0x60 to ~0x80).
    namespace FStructProperty  { inline uint64_t Struct        = 0xE8; }   // was 0xC8
    namespace FObjectProperty  { inline uint64_t PropertyClass = 0xE8; }   // was 0xC8
    namespace FEnumProperty    {
        inline uint64_t UnderlyingProp = 0xE8;                              // was 0xC8
        inline uint64_t Enum           = 0xF0;                              // was 0xD0
    }
    namespace FArrayProperty   { inline uint64_t Inner         = 0xF8; }   // CL-1201801 (auto-fixed 17/18 hits; was 0xF0)
    namespace FSetProperty     { inline uint64_t ElementProp   = 0xE8; }   // was 0xC8
    namespace FSoftObjectProperty { inline uint64_t PropertyClass = 0xE8; } // was 0xC8
    namespace FMapProperty {
        inline uint64_t KeyProp   = 0xE8;                                  // was 0xC8
        inline uint64_t ValueProp = 0xF0;                                  // was 0xD0
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
        inline uint64_t SuperStruct     = 0xB0;    // CL-1201801 (live-verified: Actor+0xB0=Object, Pawn+0xB0=Actor, Object+0xB0=0)
        inline uint64_t Children        = 0x178;   // unverified — not critical for FField walk
        inline uint64_t ChildProperties = 0x108;   // CL-1201801 (was 0x168; confirmed via FField.Owner backref)
        inline uint64_t PropertiesSize  = 0x110;   // CL-1201801 (auto-fixed 100/200 hits)
        inline uint64_t MinAlignment    = 0x114;   // CL-1201801 (follows PropertiesSize)
    }
    namespace UEnum {
        inline uint64_t Names = 0xB0;
    }
    namespace UFunction {
        inline uint64_t VTable        = 0x000;
        inline uint64_t NextPtr       = 0x098;
        inline uint64_t FunctionFlags = 0x154;   // CL-1201801 (auto-fixed 100/100 hits)
        inline uint64_t NativeFunc    = 0x178;   // CL-1201801 (auto-fixed 99/100 hits)
        inline uint64_t NumParms      = 0xE0;
    }
    namespace UClass {
        inline uint64_t FuncMap_PairsData = 0x268;
        inline uint64_t FuncMap_Num       = 0x270;
        inline uint64_t FuncMap_Max       = 0x274;
        inline uint64_t FuncMap_PairStride = 24;
        inline uint64_t FuncMapPair_FName    = 0x00;
        inline uint64_t FuncMapPair_UFunction = 0x08;
    }
    namespace UWorld {
        inline uint64_t PersistentLevel = 0x0F0;
        inline uint64_t Levels          = 0x3B0;
    }
    namespace USceneComponent {
        inline uint64_t ComponentToWorld = 0x330;
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
inline uint64_t RVA_GWORLD              = 0xE706C58;   // 20260519 (CL-1177146: 0xDFDB4D8, 20260428: 0xE024F68)
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
    // body during BootEmuFNameFallback (see find_fname_func.h::ExtractEntryHandleXor).
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
    inline uint32_t g_PropertyOffsetXor = 0xBAB939DBu;   // CL-1201801 (IDA-verified sub_140433460).
                                                          // Found via signature `35 ?? ?? ?? ?? 0F C8`
                                                          // (xor eax, imm32; bswap eax) — 5 sites use
                                                          // 0xD632B3E9, 4 use its bswap 0xE9B332D6.
                                                          // Was 0x40277448 on CL-1177146.

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
    constexpr uint64_t FFIELD_CLASS_NAME_KEY = 0x08EA69F63989FC99ULL;
    constexpr int      FFIELD_CLASS_NAME_ROL64 = 27;
    constexpr uint32_t FFIELD_CLASS_NAME_OFF   = 0x40;

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

} // namespace ArcDecrypt
