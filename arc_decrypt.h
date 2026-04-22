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
        // Patch 20260421 authoritative layout (verified via UStruct_Link / FField_GetFName IDA pass):
        //   +0x00  vtable
        //   +0x30  ClassPrivate (FFieldClass*)
        //   +0x38  Owner ptr (bit 0 = tag) — walking chain via +0x40 also works (aliased)
        //   +0x40  Next (FField*)
        //   +0x60  NameEncrypted — 16-byte SIMD slot; decode with FField_GetFName pipeline
        constexpr uint64_t VTable        = 0x00;
        constexpr uint64_t ClassPrivate  = 0x30;
        constexpr uint64_t Next          = 0x40;
        constexpr uint64_t NameEncrypted = 0x60;   // encrypted 16B
        constexpr uint64_t NamePrivate   = 0x60;   // alias
    }
    namespace FFieldClass {
        // Confirmed from live FFieldClass objects (e.g. 0xBDF31C00), patch 20260402
        constexpr uint64_t ElementSize  = 0x70;  // uint32 – per-class element size (e.g. 4, 8) — CONFIRMED from live reads of 0xBD5AF300 and 0xBDF31C00
        // NamePrivate: no fixed SIMD slot found; type identified via vtable map instead
    }
    namespace FProperty {
        // Patch 20260421 authoritative layout (verified via UStruct_Link / sub_456A40 IDA pass
        // and empirical live probe on ActorComponent/SceneComponent/PrimitiveComponent/ControlRigComponent):
        //   +0xA8 ArrayDim (u32)
        //   +0xAC ElementSize (u32)
        //   +0xC0 Offset_Internal (ENCRYPTED u32): real = bswap32(stored) ^ 0x59B8C401
        //   +0xB0..+0xB7 PropertyFlags (u64 — best guess)
        constexpr uint64_t ArrayDim        = 0xA8;
        constexpr uint64_t ElementSize     = 0xAC;
        constexpr uint64_t Offset_Internal = 0xC0;
        constexpr uint32_t Offset_XOR      = 0x59B8C401u;  // XOR after bswap32
        constexpr uint64_t PropertyFlags   = 0xB0;
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
        // Patch 20260421 authoritative layout (verified via UStruct_Link @ sub_33E480):
        //   +0xB0  SuperStruct (UStruct*)
        //   +0xD0  Children (UField* chain — UFunctions)
        //   +0xE0  ChildProperties (FField* chain — real FProperty members)
        //   +0xF8  MinAlignment-ish u32
        //   +0x118 PropertiesSize (u32 — the running sum UStruct_Link writes)
        constexpr uint64_t SuperStruct     = 0x0B0;
        constexpr uint64_t Children        = 0x0D0;  // UField* (UFunctions)
        constexpr uint64_t ChildProperties = 0x0E0;  // FField* (FProperty chain)
        constexpr uint64_t PropertiesSize  = 0x118;
        constexpr uint64_t MinAlignment    = 0x0F8;
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

// Runtime-overridable anchors (sig-scan may rewrite these at Init; hardcoded
// values are the fallback and the "known good for current patch" default).
// Values updated to patch 20260421; older patch values kept inline as comments.
inline uint64_t RVA_GWORLD              = 0xE011D18;
inline uint64_t RVA_GNAMES_BASE         = 0xDB0FE00;   // 20260421 (was 0xDB48E80)
inline uint64_t RVA_FNAME_KEY_TABLE     = 0xDA547F4;   // 20260421 keystream (was 0xDA8D854)
inline uint64_t RVA_GOBJECT_ARRAY_BASE  = 0xDDCB420;   // 20260421 (was 0xDE04650); enc xmmword at +0x00 for new pipeline
constexpr uint64_t GOBJ_ENCRYPTED_OFF   = 0x30;        // legacy pipeline offset

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
// 5. Patch 20260421 additions (from IDA instance 0dpx / 3sw0 rename pass)
//    Binary: Arc_Raiders_Binary_20260421_213315.exe (100% coverage dump)
//    Keep prior constants intact for cross-patch fallback.
// =============================================================================
namespace Patch20260421 {
    // FName_ToString @ RVA 0x24C8130 recovers the entry pointer from the
    // public FName handle via:
    //     entry_ptr = bswap64(handle_qword ^ ENTRY_HANDLE_XOR)
    constexpr uint64_t ENTRY_HANDLE_XOR      = 0x59B07C3D00000000ULL;

    // Secondary XOR seen on (entry + 192) field in FName_ToString:
    //     field_dec = bswap32(*(u32*)(entry+0xC0) ^ ENTRY_FIELD_XOR)
    constexpr uint32_t ENTRY_FIELD_XOR       = 0x01C4B859u;

    // FNamePool base moved from RVA_GNAMES_BASE (0xDB48E80) to 0xDB0FE00
    // (verify with probe_live_rvas before trusting for live sessions).
    constexpr uint64_t RVA_GNAMES_BASE_NEW   = 0xDB0FE00;

    // Per-byte XOR keystream for FNameEntry content encryption.
    constexpr uint64_t RVA_FNAME_KEYSTREAM   = 0xDA547F4;

    // FField NamePrivate decrypt SIMD constants moved:
    //   PSHUFB mask (`07 02 03 06 05 00 01 04`) — was 0xAD85670
    //   XOR const  (`31 7E 97 77 56 27 31 31`) — was 0xAD85690
    constexpr uint64_t RVA_FFIELD_PSHUFB_MASK = 0xB59FDF0;
    constexpr uint64_t RVA_FFIELD_XOR_CONST   = 0xB59FE00;

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
    constexpr uint64_t RVA_GUOBJECT_ARRAY_NEW   = 0xDDCB420;
    constexpr uint64_t RVA_GOBJ_PSHUFB_MASK     = 0xACBFCA0;
    constexpr uint64_t RVA_GOBJ_MAX_XOR_KEY     = 0xAD12960;
    constexpr int      GOBJ_PIPELINE_ROL32_A    = 23;
    constexpr int      GOBJ_PIPELINE_ROL32_B    = 13;
    constexpr int      GOBJ_MAX_PSHUFLW_IMM     = 0xA3;
    constexpr int      GOBJ_MAX_ROL64           = 15;
    constexpr uint64_t GOBJ_MANAGER_MAX_OFFSET  = 0x70;
    constexpr int      FUOBJECTITEM_STRIDE      = 20;
    constexpr int      OBJECTS_PER_CHUNK        = 0x10000;

    // FName CityHash64 entry point (moved from 0xC0C80).
    constexpr uint64_t RVA_FNAME_CITYHASH64   = 0xC1960;

    // FName_ToString entry.
    constexpr uint64_t RVA_FNAME_TOSTRING     = 0x24C8130;

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
        constexpr uint64_t RVA_XOR_CONST = 0xAD15750;
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
    inline uint32_t DecryptPropertyOffsetNew(uint32_t stored) {
        return __builtin_bswap32(stored) ^ 0x59B8C401u;
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
        constexpr uint64_t RVA_SHUF_MASK = 0xAD128C0;  // 05 03 01 04 02 07 00 06
        constexpr uint64_t RVA_XOR_CONST = 0xAD128D0;  // 09 43 BD C8 4B 4B BC FF
        constexpr int      PSHUFLW_IMM   = 0xB1;
        constexpr int      ROL32_AMT     = 15;
        // Slot base offset and stride (same as older patches).
        constexpr int      SLOT_BASE_OFF = 0x20;
        constexpr int      SLOT_STRIDE   = 0x20;
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
        // Inside each chunk:
        //   +25968 (= 0x6570): 16-byte region hashed by FNV32 to pick a slot
        //   +25984 (= 0x6580): 8-slot array of 32-byte entries (2x 16-byte blocks)
        constexpr uint64_t CHUNK_FNV_SEED_OFF = 25968;
        constexpr uint64_t CHUNK_SLOT_BASE    = 25984;

        // CI decode (from si128): PSHUFLW(57)→PSRLD(6)→PSHUFB(mask)→cvtsi128_si32
        // Then name_offset = v5 & 0xFFFF, chunk_off_in_pool = (v5 >> 8) & 0xFFFF00
        constexpr uint64_t RVA_CI_PSHUFB_MASK = 0xACF8D20;  // {06,00,01,04, 00*12}

        // FNV32 hash constants (pick slot_idx)
        constexpr uint32_t FNV32_PRIME = 0x01000193u;
        constexpr uint32_t FNV32_K     = 0xCA3F9BE2u;        // (signed) -901800990

        // Slot decrypt: PSHUFLW(0x93) → ROL32(25) → lo64 → XOR(SLOT_XOR)
        constexpr uint64_t SLOT_XOR    = 0x662CF9C2408E7B59ULL;
        constexpr int      SLOT_ROL32  = 25;
        constexpr int      SLOT_PSHUFLW_IMM = 0x93;

        // FNV64 fold on v11 (first slot decrypted):
        //   fnv = P64 * ROL64(P64 * ROL64(v11, 51) + OFF, 38) + OFF
        constexpr uint64_t FNV64_PRIME  = 0x100000001B3ULL;
        constexpr uint64_t FNV64_OFF    = 0xA369D63928ACD6A2ULL; // -0x5C9629C6D753295E
        constexpr int      FNV64_ROL1   = 51;
        constexpr int      FNV64_ROL2   = 38;

        // Final: result = v11 + (fnv ^ v13) + 2*name_offset_word
        // sub_242FC0 writes:    var_50 = bswap64(result ^ 0x3517B019)
        // sub_23B380 computes:  v19 = var_50 ^ 0x40006B0800000000
        // FName_ToString:       entry_ptr = bswap64(v19 ^ 0x59B07C3D00000000)
        // All XORs collapse: entry_ptr = result
        //   bswap64(S) for S=0x40006B0800000000 = 0x086B0040
        //   bswap64(T) for T=0x59B07C3D00000000 = 0x3D7CB059
        //   0x3517B019 ^ 0x086B0040 ^ 0x3D7CB059 = 0  → entry_ptr == result
        constexpr uint64_t RESULT_TO_ENTRY_XOR = 0;
    }

    // =========================================================================
    // FNameEntry string decrypt (patch 20260421) — from FNameEntry_AppendNameToString
    //
    // Header layout CHANGED (bits scrambled):
    //   length  = (hdr & 3) | ((hdr >> 5) & 0x3FC)
    //   isWide  = (hdr >> 15) & 1   (unchanged)
    //
    // Key table base offset 0xDA547F4 (unchanged), but decrypt accesses
    //   key_table[52 + ((key_start + i) & 0x3F)]
    // i.e. 52*2 = 104 bytes into the table symbol. Starting key = length-17564.
    // =========================================================================
    namespace FNameEntry20260421 {
        constexpr int      KEY_TABLE_UINT16_OFFSET = 52;
        constexpr int32_t  KEY_START_BIAS          = -17564;
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

} // namespace ArcDecrypt
