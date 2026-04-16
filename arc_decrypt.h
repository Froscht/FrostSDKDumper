#pragma once

#include <cstdint>
#include <cstring>
#include <immintrin.h>

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
    constexpr int32_t  HASH_ADD    = -1072765379;  // 0xC00C3C3D (from other person's confirmed code)
}

// Hash + slot index (patch 20260414, confirmed from other person's working code)
// ROL32(15) → P*h+ADD → ROL32(24) → P*h+hi+ADD → ROL32(15) → v8
// Complex index: (-109 * ((uint16)(403*v8-6595) >> 8) + 61) ^ ((P*((P*v8+ADD)>>8)+ADD) >> 16) & 3 ^ 2
inline uint32_t ComputeHashAndIndex(uintptr_t obj_base, uint32_t& out_idx) {
    constexpr uint32_t P = ActorFName::FNV_PRIME;
    constexpr int32_t  K = ActorFName::HASH_ADD;
    uint64_t ptr = obj_base + 0x10;
    uint32_t lo = static_cast<uint32_t>(ptr);
    uint32_t hi = static_cast<uint32_t>(ptr >> 32);
    uint32_t h = ROL32(lo, 15);
    h = static_cast<uint32_t>(P * h + K);
    h = ROL32(h, 24);
    h = static_cast<uint32_t>(P * h + hi + K);
    uint32_t v8 = ROL32(h, 15);

    uint16_t temp1 = static_cast<uint16_t>(403u * v8 - 6595u);
    uint8_t left = static_cast<uint8_t>(-109 * (temp1 >> 8) + 61);
    uint32_t temp2 = static_cast<uint32_t>(P * v8 + K) >> 8;
    uint32_t v6eq = static_cast<uint32_t>(P * temp2 + K);
    uint8_t right = static_cast<uint8_t>(v6eq >> 16);
    out_idx = ((left ^ right) & 3u) ^ 2u;
    return v8;
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
namespace Offsets {
    namespace UObject {
        constexpr uint64_t VTable       = 0x00;
        constexpr uint64_t InternalIndex= 0x0C; // plain uint32 at obj+0x0C (was 0x90 encrypted, patch 20260409)
        constexpr uint64_t FieldsSlots  = 0x20; // slots at obj+0x20,+0x40,+0x60,+0x80 (stride 0x20)
    }
    namespace FField {
        // Patch 20260414: FField layout (compacted from 0x160)
        constexpr uint64_t VTable       = 0x00;
        constexpr uint64_t NameEncrypted = 0x90;  // 16B encrypted FName (was 0xA0)
        constexpr uint64_t Next         = 0xA8;   // plain FField* (was 0xB8)
        constexpr uint64_t ClassPrivate = 0xB0;   // FFieldClass* (was 0x150)
        constexpr uint64_t NamePrivate  = 0x90;   // encrypted, use DecryptFFieldName (was 0xA0)
    }
    namespace FFieldClass {
        // Confirmed from live FFieldClass objects (e.g. 0xBDF31C00), patch 20260402
        constexpr uint64_t ElementSize  = 0x70;  // uint32 – per-class element size (e.g. 4, 8) — CONFIRMED from live reads of 0xBD5AF300 and 0xBDF31C00
        // NamePrivate: no fixed SIMD slot found; type identified via vtable map instead
    }
    namespace FProperty {
        // Patch 20260414: FField compacted
        constexpr uint64_t ArrayDim        = 0xD8;   // uint32 (was 0x11C)
        constexpr uint64_t ElementSize     = 0xDC;   // uint32 (was 0x120)
        constexpr uint64_t Offset_Internal = 0xEC;   // encrypted uint32 → bswap32(stored ^ Offset_XOR) (was 0xE0)
        constexpr uint32_t Offset_XOR      = 0x2AB03FD6u;  // XOR key for offset decrypt (was 0x8CCB9FAD)
        constexpr uint64_t PropertyFlags   = 0xE0;   // uint32 property flags (was 0x110) — TODO: verify with IDA
    }
    namespace FBoolProperty {
        // TODO: re-verify for patch 20260402; previous values assumed UE5 default layout
        constexpr uint64_t FieldSize  = 0x130;
        constexpr uint64_t ByteOffset = 0x131;
        constexpr uint64_t ByteMask   = 0x132;
        constexpr uint64_t FieldMask  = 0x133;
    }
    // Sub-property offsets for inner type resolution: TODO re-verify for 20260402
    namespace FStructProperty  { constexpr uint64_t Struct        = 0x130; }
    namespace FObjectProperty  { constexpr uint64_t PropertyClass = 0x130; }
    namespace FEnumProperty    { constexpr uint64_t Enum          = 0x130; }
    namespace FArrayProperty   { constexpr uint64_t Inner         = 0x138; }
    namespace FSetProperty     { constexpr uint64_t ElementProp   = 0x130; }
    namespace FSoftObjectProperty { constexpr uint64_t PropertyClass = 0x130; }
    namespace FMapProperty {
        constexpr uint64_t KeyProp   = 0x130;
        constexpr uint64_t ValueProp = 0x138;
    }
    // Old UField/UProperty system (UObject subclasses, in GUObjectArray).
    // Used by legacy structs: FVector, FRotator, FLinearColor, etc.
    // Name: use GetCompIndex(obj)/GetName(obj) via UObject SIMD slot decrypt.
    namespace UField {
        constexpr uint64_t Next            = 0x90;  // was 0x30 (patch 20260409)
    }
    namespace UProperty {
        constexpr uint64_t Next            = 0x90;  // same as UField::Next (was 0x30)
        constexpr uint64_t Offset_Internal = 0x64;  // bswap32(stored) ^ 0xC43565C9 (confirmed sub_140441080)
        constexpr uint64_t ElementSize     = 0x68;  // plain uint32 (= 8 for FVector doubles)
        constexpr uint64_t ArrayDim        = 0x6C;  // plain uint32 (= 1 for FVector components)
        constexpr uint64_t PropertyFlags   = 0x70;  // plain uint64
    }
    namespace UStruct {
        constexpr uint64_t SuperStruct     = 0x0A8;
        constexpr uint64_t Children        = 0x0E0;  // UField* chain (was 0xD0)
        constexpr uint64_t ChildProperties = 0x100;  // FField* chain (was 0xC0)
        constexpr uint64_t PropertiesSize  = 0x108;  // was 0xD8
    }
    namespace UEnum {
        constexpr uint64_t Names = 0xB0;  // patch 20260414 (was 0xA8 in 20260409). +0xA0 holds CppType FString.
    }
    namespace UFunction {
        constexpr uint64_t VTable        = 0x000;
        constexpr uint64_t NextPtr       = 0x098;
        constexpr uint64_t FunctionFlags = 0x128;
        constexpr uint64_t NativeFunc    = 0x1C8;
    }
    namespace UWorld {
        constexpr uint64_t PersistentLevel = 0x0F0;  // user-verified 20260414 (was 0x0F8)
        constexpr uint64_t Levels          = 0x3B0;  // TArray<ULevel*>
    }
    namespace USceneComponent {
        constexpr uint64_t ComponentToWorld = 0x330;  // user-provided 20260414
    }
}

// =============================================================================
// 4. Global Address Constants (patch 20260409)
// =============================================================================
constexpr uint64_t MODULE_BASE = 0x140000000;

// GWorld (single-deref: *(uint64_t*)(MODULE_BASE + RVA_GWORLD) = UWorld* heap ptr)
constexpr uint64_t RVA_GWORLD  = 0xE011D18;   // patch 20260414 (was 0xE8C28A0)

// FNamePool + XOR key table (patch 20260409)
constexpr uint64_t RVA_GNAMES_BASE     = 0xDB48E80;   // FNamePool global (was 0xDAF5070 cipher state)
constexpr uint64_t RVA_FNAME_KEY_TABLE = 0xDA8D854;   // FNameXorKey base (64 uint16 entries, was 0xD9947F4)
                                                        // Access: key_table[key+36]

// GUObjectArray struct base (patch 20260414)
// Struct at this RVA; encrypted qword at struct+0x30 decrypts to chunk array ptr
constexpr uint64_t RVA_GOBJECT_ARRAY_BASE = 0xDE04650;   // struct base (was 0xDD0B5A0)
constexpr uint64_t GOBJ_ENCRYPTED_OFF     = 0x30;         // encrypted xmmword within struct

// SIMD runtime tables (GUObjectArray decrypt — patch 20260414)
// Pipeline CHANGED: ROL32(20) → XOR(key) → ROL16(12) [no PSHUFB step]
constexpr uint64_t RVA_SIMD_OBJARRAY_XOR  = 0xAD2FC50;  // XOR key (replaces old PSHUFB mask)
// Element count: AND/ANDNOT blend → XOR → ROL16(12) → PSHUFB(constant)
constexpr uint64_t RVA_ELEM_MASK_A        = 0xAD8EE10;  // ANDNOT mask (0x00E4 repeating)
constexpr uint64_t RVA_ELEM_MASK_B        = 0xAD8EE20;  // AND mask (0xFF1B repeating)
constexpr uint64_t RVA_ELEM_XOR_KEY       = 0xAD8EE30;  // XOR key

// SIMD runtime tables (CIdx → FName address resolve — patch 20260414)
// Level 1 CIdx decode CHANGED: CI → ROL16(14) → PSHUFLW(0x93) → PXOR(cidxXor1)  [no PSHUFB]
constexpr uint64_t RVA_CIDX_XOR1         = 0xAD30540;  // CIdx pxor key (was 0xAC64940)
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

} // namespace ArcDecrypt
