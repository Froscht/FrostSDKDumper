#pragma once

#include <cstdint>
#include <cstring>
#include <immintrin.h>

// =============================================================================
// ARC Raiders – central decrypt constants & inline helpers (newest patch)
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
// 1. UObject Slot Hash Constants
// =============================================================================
namespace ActorFName {
    constexpr uint32_t HASH_PRIME     = 16777619u;
    constexpr uint32_t HASH_ADD       = 1668103848u;
    constexpr uint32_t SLOT_XOR_CONST = 0x2C158u;
}

// Slot index for UObject::GetNamePrivate  (hash & 3) ^ 2
inline uint32_t GetFNameSlotIndex(uintptr_t obj_base) {
    uint64_t addr = obj_base + 0x10;
    uint32_t lo = static_cast<uint32_t>(addr);
    uint32_t hi = static_cast<uint32_t>(addr >> 32);

    uint32_t s0 = ActorFName::HASH_PRIME * ROL32(lo, 26) - ActorFName::HASH_ADD;
    uint32_t s1 = ROL32(s0, 19);
    uint32_t s2 = hi + ActorFName::HASH_PRIME * s1 - ActorFName::HASH_ADD;
    uint32_t s3 = ROL32(s2, 26);
    uint32_t s4 = ActorFName::HASH_PRIME * s3 - ActorFName::HASH_ADD;
    uint32_t v  = ActorFName::HASH_PRIME * (s4 >> 13);

    return (((uint8_t)v ^ (uint8_t)((ActorFName::SLOT_XOR_CONST + v) >> 16)) & 3u) ^ 2u;
}

// Slot index for UObject::GetClassPrivate  (hash & 3) – no ^2
inline uint32_t GetClassSlotIndex(uintptr_t obj_base) {
    uint64_t addr = obj_base + 0x10;
    uint32_t lo = static_cast<uint32_t>(addr);
    uint32_t hi = static_cast<uint32_t>(addr >> 32);

    uint32_t s0 = ActorFName::HASH_PRIME * ROL32(lo, 26) - ActorFName::HASH_ADD;
    uint32_t s1 = ROL32(s0, 19);
    uint32_t s2 = hi + ActorFName::HASH_PRIME * s1 - ActorFName::HASH_ADD;
    uint32_t s3 = ROL32(s2, 26);
    uint32_t s4 = ActorFName::HASH_PRIME * s3 - ActorFName::HASH_ADD;
    uint32_t v  = ActorFName::HASH_PRIME * (s4 >> 13);

    return (((uint8_t)v ^ (uint8_t)((uint32_t)(ActorFName::SLOT_XOR_CONST + v) >> 16)) & 3u);
}

// =============================================================================
// 2. FProperty Offset Decryption
//    Game: _byteswap_ulong(Read<u32>(this + 0xC4) ^ 0x46F1DEE5)
// =============================================================================
inline int32_t DecryptPropertyOffset(uint32_t raw) {
    return static_cast<int32_t>(bswap32(raw ^ 0x46F1DEE5u));
}

// =============================================================================
// 3. Key Structure Offsets (newest patch)
// =============================================================================
namespace Offsets {
    namespace UObject {
        constexpr uint64_t VTable       = 0x00;
        constexpr uint64_t InternalIndex= 0x08;
        constexpr uint64_t FieldsSlots  = 0x20; // 0x20-0x80: 4 slots of 32 bytes
    }
    namespace FField {
        constexpr uint64_t VTable       = 0x00;
        constexpr uint64_t Next         = 0x90;
        constexpr uint64_t NamePrivate  = 0xB0;  // 11 * 16
        constexpr uint64_t ClassPrivate = 0x130;
    }
    namespace FFieldClass {
        constexpr uint64_t NamePrivate  = 0x50;   // TODO: verify for new patch
    }
    namespace FProperty {
        constexpr uint64_t Offset_Internal = 0xC4; // Encrypted: bswap32(raw ^ 0x46F1DEE5)
        constexpr uint64_t ElementSize     = 0xC8; // from reference code FPROP_SIZE
        constexpr uint64_t ArrayDim        = 0xCC; // follows ElementSize
    }
    namespace FBoolProperty {
        constexpr uint64_t FieldSize  = 0x130;     // uint8: 1=bitfield, 4=native bool
        constexpr uint64_t ByteOffset = 0x131;     // uint8: offset within property byte
        constexpr uint64_t ByteMask   = 0x132;     // uint8: bitmask for reading (0x01..0x80)
        constexpr uint64_t FieldMask  = 0x133;     // uint8: bitmask for field (= ByteMask for bitfields)
    }
    namespace FStructProperty  { constexpr uint64_t Struct        = 0x130; } // verified: PrimaryActorTick→ActorTickFunction, BasedMovement→BasedMovementInfo
    namespace FObjectProperty  { constexpr uint64_t PropertyClass = 0x130; } // verified: Owner→Actor, Mesh→SkeletalMeshComponent
    namespace FEnumProperty    { constexpr uint64_t Enum          = 0x130; } // verified: AutoPossessPlayer→EAutoReceiveInput
    namespace FArrayProperty   { constexpr uint64_t Inner         = 0x138; } // verified: Children→ObjectProperty, Tags→NameProperty
    namespace FSetProperty     { constexpr uint64_t ElementProp   = 0x130; } // shifted from 0xD8
    namespace FSoftObjectProperty { constexpr uint64_t PropertyClass = 0x130; } // shifted from 0xD8
    namespace FMapProperty {
        constexpr uint64_t KeyProp   = 0x130; // shifted from 0xD8
        constexpr uint64_t ValueProp = 0x138; // shifted from 0xE0 (same +0x58 delta)
    }
    namespace UStruct {
        constexpr uint64_t SuperStruct     = 0x0B0;
        constexpr uint64_t Children        = 0x0D0;
        constexpr uint64_t ChildProperties = 0x0D8;
        constexpr uint64_t PropertiesSize  = 0x0E8; // verified: Actor=0x3B0, ActorComponent=0x190
        constexpr uint64_t MinAlignment    = 0x0C0;
    }
    namespace UEnum {
        constexpr uint64_t Names = 0xB0;
    }
    namespace UFunction {
        constexpr uint64_t VTable        = 0x000;
        constexpr uint64_t NextPtr       = 0x098;  // UField::Next
        constexpr uint64_t FunctionFlags = 0x128;   // TODO: verify
        constexpr uint64_t NativeFunc    = 0x1C8;   // TODO: verify
    }
}

// =============================================================================
// 4. Global Address Constants (newest patch)
// =============================================================================
constexpr uint64_t MODULE_BASE = 0x140000000;
constexpr uint64_t RVA_GWORLD  = 0xDCB9AB8;

// FNamePool (unchanged from previous – verify if names break)
constexpr uint64_t RVA_GNAMES_BASE     = 0xD8FD870;
constexpr uint64_t RVA_FNAME_KEY_TABLE = 0xD841864;

// SIMD runtime tables – read from process memory once during init
constexpr uint64_t RVA_SIMD_ACTOR_SHUF    = 0xAAF4770;  // UObject name/class shuffle_epi8 mask
constexpr uint64_t RVA_SIMD_FFIELD_SHUF   = 0xAAF74B0;  // FField name shuffle_epi8 mask
constexpr uint64_t RVA_SIMD_NUMELEM_MASK2 = 0xAAF4740;  // NumElements andnot mask
constexpr uint64_t RVA_SIMD_NUMELEM_MASK1 = 0xAAF4750;  // NumElements and mask
constexpr uint64_t RVA_SIMD_NUMELEM_SHUF  = 0xAAF4760;  // NumElements shuffle_epi8 mask
constexpr uint64_t RVA_SIMD_OBJARRAY_XOR  = 0xAAA18A0;  // ObjectArray XOR key
constexpr uint64_t RVA_SIMD_OBJARRAY_SHUF = 0xAAA18B0;  // ObjectArray shuffle_epi8 mask

// FChunkedFixedUObjectArray encrypted global data
constexpr uint64_t RVA_GOBJECT_ARRAY_DATA = 0xDB4DD20;
constexpr uint64_t GOBJECT_ARRAY_XOR      = 0xAB8F9C79978619C2ULL;

} // namespace ArcDecrypt
