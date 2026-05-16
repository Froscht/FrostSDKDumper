#pragma once
// =============================================================================
// unreal_containers.h — Canonical UE5 container layouts as READ-ONLY views over
// /dev/memreader. Layouts follow Fischsalat/UnrealContainersNoAlloc.h (the
// Dumper-7 reference). Every class takes IMemoryReader& + a runtime address
// and reads lazily; no in-process pointer is ever dereferenced. PascalCase.
//
// Verified offsets from Fischsalat reference:
//   TArray<T>     = { T* Data @+0x00, int32 Num @+0x08, int32 Max @+0x0C }  size 0x10
//   FString       = TArray<wchar_t>                                          size 0x10
//   FBitArray     = { int32 Inline[4] @+0x00, int32* Secondary @+0x10,
//                     int32 NumBits @+0x18, int32 MaxBits @+0x1C }          size 0x20
//   TSparseArray  = { TArray<Elem> Data @+0x00, FBitArray Flags @+0x10,
//                     int32 FirstFree @+0x30, int32 NumFree @+0x34 }        size 0x38
//   TSet          = { TSparseArray Elements @+0x00,
//                     int32 HashInline @+0x38, int32* HashSecondary @+0x40,
//                     int32 HashSize @+0x48 }                                size 0x50
//   TMap<K,V>     = TSet< TPair<K,V> >                                       size 0x50
//   SetElement<T> = { T Value, int32 HashNextId, int32 HashIndex }
//   FSparseLink   = union { T Element; struct{int32 Prev,Next;}; }
//
// FreeIndex sentinel = -1. NumBitsPerDWORD = 32.
// =============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "KernelDriver/include/memreader_iface.h"

namespace UC {

using int32  = int32_t;
using uint32 = uint32_t;
using uint64 = uint64_t;

static constexpr int32 NumBitsPerDWORD        = 32;
static constexpr int32 NumBitsPerDWORDLogTwo  = 5;
static constexpr int32 SparseArrayFreeSentinel = -1;

// ---- helpers ---------------------------------------------------------------

inline bool ReadPtr(IMemoryReader& Reader, uint64 Addr, uint64& Out) {
    return Reader.Read(Addr, &Out, sizeof(uint64));
}
inline bool ReadI32(IMemoryReader& Reader, uint64 Addr, int32& Out) {
    return Reader.Read(Addr, &Out, sizeof(int32));
}
inline bool ReadU32(IMemoryReader& Reader, uint64 Addr, uint32& Out) {
    return Reader.Read(Addr, &Out, sizeof(uint32));
}

// ---- TArray<T> -------------------------------------------------------------
// Layout: T* Data; int32 Num; int32 Max;   sizeof == 0x10
template<typename T>
class TArray {
public:
    static constexpr uint64 OFF_DATA = 0x00;
    static constexpr uint64 OFF_NUM  = 0x08;
    static constexpr uint64 OFF_MAX  = 0x0C;
    static constexpr uint64 SIZE     = 0x10;

    IMemoryReader* Reader = nullptr;
    uint64         Addr   = 0;

    TArray() = default;
    TArray(IMemoryReader& InReader, uint64 InAddr) : Reader(&InReader), Addr(InAddr) {}

    uint64 DataPtr() const {
        uint64 P = 0;
        if (Reader) ReadPtr(*Reader, Addr + OFF_DATA, P);
        return P;
    }
    int32 Num() const {
        int32 N = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_NUM, N);
        return N;
    }
    int32 Max() const {
        int32 M = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_MAX, M);
        return M;
    }
    bool IsValidIndex(int32 Idx) const { return Idx >= 0 && Idx < Num(); }

    bool At(int32 Idx, T& Out) const {
        if (!Reader || Idx < 0) return false;
        const uint64 P = DataPtr();
        if (!P) return false;
        return Reader->Read(P + (uint64)Idx * sizeof(T), &Out, sizeof(T));
    }
    T operator[](int32 Idx) const {
        T V = {};
        At(Idx, V);
        return V;
    }

    // Bulk read — single memreader call for the whole array contents.
    std::vector<T> ReadAll() const {
        std::vector<T> Out;
        if (!Reader) return Out;
        const int32 N = Num();
        if (N <= 0) return Out;
        const uint64 P = DataPtr();
        if (!P) return Out;
        Out.resize((size_t)N);
        if (!Reader->Read(P, Out.data(), (size_t)N * sizeof(T))) Out.clear();
        return Out;
    }

    // Batched cursor for range-based iteration without re-reading per element.
    class Iterator {
    public:
        const TArray*  Owner = nullptr;
        int32          Idx   = 0;
        int32          N     = 0;
        uint64         Base  = 0;
        std::vector<T> Batch;
        int32          BatchStart = 0;
        static constexpr int32 BatchSize = 256;

        Iterator() = default;
        Iterator(const TArray* InOwner, int32 InIdx)
            : Owner(InOwner), Idx(InIdx) {
            if (Owner) { N = Owner->Num(); Base = Owner->DataPtr(); }
        }

        void Fill() {
            if (!Owner || !Owner->Reader || !Base) { Batch.clear(); return; }
            BatchStart = Idx;
            int32 Take = N - Idx; if (Take > BatchSize) Take = BatchSize;
            if (Take <= 0) { Batch.clear(); return; }
            Batch.assign((size_t)Take, T{});
            if (!Owner->Reader->Read(Base + (uint64)Idx * sizeof(T),
                                     Batch.data(), (size_t)Take * sizeof(T))) {
                Batch.clear();
            }
        }
        T operator*() {
            if (Batch.empty() || Idx < BatchStart || Idx >= BatchStart + (int32)Batch.size())
                Fill();
            if (Batch.empty()) return T{};
            return Batch[(size_t)(Idx - BatchStart)];
        }
        Iterator& operator++() { ++Idx; return *this; }
        bool operator!=(const Iterator& Rhs) const { return Idx != Rhs.Idx; }
    };
    Iterator begin() const { return Iterator(this, 0); }
    Iterator end()   const { return Iterator(this, Num()); }
};

// ---- FString : TArray<wchar_t> --------------------------------------------
class FString : public TArray<wchar_t> {
public:
    FString() = default;
    FString(IMemoryReader& InReader, uint64 InAddr) : TArray<wchar_t>(InReader, InAddr) {}

    std::wstring ToWString() const {
        std::wstring Out;
        const int32 N = Num();
        if (N <= 0) return Out;
        const uint64 P = DataPtr();
        if (!P || !Reader) return Out;
        std::vector<uint16_t> Buf((size_t)N);
        if (!Reader->Read(P, Buf.data(), (size_t)N * sizeof(uint16_t))) return Out;
        Out.reserve((size_t)N);
        for (uint16_t Ch : Buf) {
            if (Ch == 0) break;
            Out.push_back((wchar_t)Ch);
        }
        return Out;
    }

    std::string ToUtf8() const {
        std::string Out;
        const int32 N = Num();
        if (N <= 0) return Out;
        const uint64 P = DataPtr();
        if (!P || !Reader) return Out;
        std::vector<uint16_t> Buf((size_t)N);
        if (!Reader->Read(P, Buf.data(), (size_t)N * sizeof(uint16_t))) return Out;
        Out.reserve((size_t)N);
        size_t Lim = Buf.size();
        for (size_t I = 0; I < Lim; ++I) {
            uint32_t Cp = Buf[I];
            if (Cp == 0) break;
            if (Cp >= 0xD800 && Cp <= 0xDBFF && I + 1 < Lim) {
                uint32_t Lo = Buf[I + 1];
                if (Lo >= 0xDC00 && Lo <= 0xDFFF) {
                    Cp = 0x10000 + (((Cp - 0xD800) << 10) | (Lo - 0xDC00));
                    ++I;
                }
            }
            if (Cp < 0x80) {
                Out.push_back((char)Cp);
            } else if (Cp < 0x800) {
                Out.push_back((char)(0xC0 | (Cp >> 6)));
                Out.push_back((char)(0x80 | (Cp & 0x3F)));
            } else if (Cp < 0x10000) {
                Out.push_back((char)(0xE0 | (Cp >> 12)));
                Out.push_back((char)(0x80 | ((Cp >> 6) & 0x3F)));
                Out.push_back((char)(0x80 | (Cp & 0x3F)));
            } else {
                Out.push_back((char)(0xF0 | (Cp >> 18)));
                Out.push_back((char)(0x80 | ((Cp >> 12) & 0x3F)));
                Out.push_back((char)(0x80 | ((Cp >> 6) & 0x3F)));
                Out.push_back((char)(0x80 | (Cp & 0x3F)));
            }
        }
        return Out;
    }
};

// ---- FBitArray -------------------------------------------------------------
// TInlineAllocator<4>::ForElementType<int32>: 4 inline DWORDs (16 bytes) +
// SecondaryData pointer (8 bytes) = 24 bytes, then NumBits, MaxBits.
class FBitArray {
public:
    static constexpr uint64 OFF_INLINE     = 0x00;
    static constexpr uint64 OFF_SECONDARY  = 0x10;
    static constexpr uint64 OFF_NUM_BITS   = 0x18;
    static constexpr uint64 OFF_MAX_BITS   = 0x1C;
    static constexpr uint64 SIZE           = 0x20;
    static constexpr int32  InlineDwords   = 4;

    IMemoryReader* Reader = nullptr;
    uint64         Addr   = 0;

    FBitArray() = default;
    FBitArray(IMemoryReader& InReader, uint64 InAddr) : Reader(&InReader), Addr(InAddr) {}

    int32 NumBits() const {
        int32 N = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_NUM_BITS, N);
        return N;
    }
    int32 MaxBits() const {
        int32 M = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_MAX_BITS, M);
        return M;
    }

    // True if stored inline (≤ 4*32=128 bits), false if heap-allocated.
    bool IsInline() const { return MaxBits() <= InlineDwords * NumBitsPerDWORD; }

    uint64 DataAddr() const {
        if (!Reader) return 0;
        if (IsInline()) return Addr + OFF_INLINE;
        uint64 P = 0;
        ReadPtr(*Reader, Addr + OFF_SECONDARY, P);
        return P;
    }

    bool GetBit(int32 Idx) const {
        if (!Reader || Idx < 0 || Idx >= NumBits()) return false;
        const int32 Word = Idx >> NumBitsPerDWORDLogTwo;
        const uint32 Mask = 1u << (Idx & (NumBitsPerDWORD - 1));
        const uint64 Base = DataAddr();
        if (!Base) return false;
        uint32 W = 0;
        if (!ReadU32(*Reader, Base + (uint64)Word * sizeof(uint32), W)) return false;
        return (W & Mask) != 0;
    }

    // Returns a snapshot of every set-bit index.
    std::vector<int32> Iterate() const {
        std::vector<int32> Out;
        const int32 N = NumBits();
        if (N <= 0 || !Reader) return Out;
        const uint64 Base = DataAddr();
        if (!Base) return Out;
        const int32 Words = (N + NumBitsPerDWORD - 1) / NumBitsPerDWORD;
        std::vector<uint32> Buf((size_t)Words, 0);
        if (!Reader->Read(Base, Buf.data(), (size_t)Words * sizeof(uint32))) return Out;
        Out.reserve((size_t)N / 4);
        for (int32 W = 0; W < Words; ++W) {
            uint32 Bits = Buf[(size_t)W];
            while (Bits) {
                const int32 Bit = __builtin_ctz(Bits);
                const int32 Idx = W * NumBitsPerDWORD + Bit;
                if (Idx >= N) break;
                Out.push_back(Idx);
                Bits &= Bits - 1u;
            }
        }
        return Out;
    }

    // Snapshot the entire bit buffer once for tight loops over both
    // TSparseArray::AllocationFlags and the sparse Data.
    std::vector<uint32> Snapshot() const {
        std::vector<uint32> Buf;
        const int32 N = NumBits();
        if (N <= 0 || !Reader) return Buf;
        const uint64 Base = DataAddr();
        if (!Base) return Buf;
        const int32 Words = (N + NumBitsPerDWORD - 1) / NumBitsPerDWORD;
        Buf.assign((size_t)Words, 0);
        if (!Reader->Read(Base, Buf.data(), (size_t)Words * sizeof(uint32))) Buf.clear();
        return Buf;
    }
};

// ---- TSparseArray<T> -------------------------------------------------------
// Underlying slot is a union of T or { int32 PrevFree, int32 NextFree }.
// AllocationFlags bit i tells whether slot i holds an Element (1) or is in
// the free-list (0). FirstFreeIndex == -1 when full.
template<typename T>
class TSparseArray {
public:
    union FElementOrFreeListLink {
        T Element;
        struct { int32 PrevFreeIndex; int32 NextFreeIndex; } Link;
    };

    static constexpr uint64 OFF_DATA       = 0x00;
    static constexpr uint64 OFF_FLAGS      = 0x10;
    static constexpr uint64 OFF_FIRST_FREE = 0x30;
    static constexpr uint64 OFF_NUM_FREE   = 0x34;
    static constexpr uint64 SIZE           = 0x38;

    IMemoryReader* Reader = nullptr;
    uint64         Addr   = 0;

    TSparseArray() = default;
    TSparseArray(IMemoryReader& InReader, uint64 InAddr) : Reader(&InReader), Addr(InAddr) {}

    TArray<FElementOrFreeListLink> RawData() const {
        return TArray<FElementOrFreeListLink>(*Reader, Addr + OFF_DATA);
    }
    FBitArray Flags() const {
        return FBitArray(*Reader, Addr + OFF_FLAGS);
    }
    int32 FirstFreeIndex() const {
        int32 V = SparseArrayFreeSentinel;
        if (Reader) ReadI32(*Reader, Addr + OFF_FIRST_FREE, V);
        return V;
    }
    int32 NumFreeIndices() const {
        int32 V = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_NUM_FREE, V);
        return V;
    }

    // Live element count == capacity - free.
    int32 Num() const {
        const TArray<FElementOrFreeListLink> D = RawData();
        return D.Num() - NumFreeIndices();
    }
    int32 Capacity() const { return RawData().Num(); }

    bool IsAllocated(int32 SlotIdx) const {
        return Flags().GetBit(SlotIdx);
    }

    bool At(int32 SlotIdx, T& Out) const {
        if (!Reader) return false;
        if (!IsAllocated(SlotIdx)) return false;
        const TArray<FElementOrFreeListLink> D = RawData();
        const uint64 P = D.DataPtr();
        if (!P) return false;
        return Reader->Read(P + (uint64)SlotIdx * sizeof(FElementOrFreeListLink),
                            &Out, sizeof(T));
    }
    T operator[](int32 SlotIdx) const {
        T V = {};
        At(SlotIdx, V);
        return V;
    }

    // Walk every allocated slot in capacity order, honoring the free-list.
    // Pairs (SlotIndex, Element).
    std::vector<std::pair<int32, T>> Enumerate() const {
        std::vector<std::pair<int32, T>> Out;
        if (!Reader) return Out;
        const TArray<FElementOrFreeListLink> D = RawData();
        const int32 Cap = D.Num();
        if (Cap <= 0) return Out;
        const uint64 P = D.DataPtr();
        if (!P) return Out;

        const FBitArray F = Flags();
        const std::vector<uint32> Bits = F.Snapshot();
        if (Bits.empty()) return Out;

        std::vector<FElementOrFreeListLink> Slots((size_t)Cap);
        if (!Reader->Read(P, Slots.data(), (size_t)Cap * sizeof(FElementOrFreeListLink)))
            return Out;

        Out.reserve((size_t)Cap);
        for (int32 I = 0; I < Cap; ++I) {
            const int32 Word = I >> NumBitsPerDWORDLogTwo;
            const uint32 Mask = 1u << (I & (NumBitsPerDWORD - 1));
            if ((size_t)Word >= Bits.size()) break;
            if (Bits[(size_t)Word] & Mask) {
                Out.emplace_back(I, Slots[(size_t)I].Element);
            }
        }
        return Out;
    }
};

// ---- TPair<K,V> ------------------------------------------------------------
template<typename K, typename V>
struct TPair {
    K Key;
    V Value;
};

// ---- TSet<T> ---------------------------------------------------------------
// Slot type inside TSparseArray is SetElement<T> = { T Value; int32 HashNextId; int32 HashIndex; }.
// Hash table is an inline-or-heap int32 array of length HashSize whose entries
// are slot indices (-1 terminated chains).
template<typename T>
class TSet {
public:
    struct SetElement {
        T     Value;
        int32 HashNextId;
        int32 HashIndex;
    };

    static constexpr uint64 OFF_ELEMENTS       = 0x00;
    static constexpr uint64 OFF_HASH_INLINE    = 0x38;
    static constexpr uint64 OFF_HASH_SECONDARY = 0x40;
    static constexpr uint64 OFF_HASH_SIZE      = 0x48;
    static constexpr uint64 SIZE               = 0x50;
    static constexpr int32  HashInlineCount    = 1;

    IMemoryReader* Reader = nullptr;
    uint64         Addr   = 0;

    TSet() = default;
    TSet(IMemoryReader& InReader, uint64 InAddr) : Reader(&InReader), Addr(InAddr) {}

    TSparseArray<SetElement> Elements() const {
        return TSparseArray<SetElement>(*Reader, Addr + OFF_ELEMENTS);
    }
    int32 HashSize() const {
        int32 V = 0;
        if (Reader) ReadI32(*Reader, Addr + OFF_HASH_SIZE, V);
        return V;
    }
    uint64 HashDataAddr() const {
        if (!Reader) return 0;
        const int32 Sz = HashSize();
        if (Sz <= HashInlineCount) return Addr + OFF_HASH_INLINE;
        uint64 P = 0;
        ReadPtr(*Reader, Addr + OFF_HASH_SECONDARY, P);
        return P;
    }

    int32 Num() const { return Elements().Num(); }

    bool At(int32 SlotIdx, T& Out) const {
        SetElement SE = {};
        if (!Elements().At(SlotIdx, SE)) return false;
        Out = SE.Value;
        return true;
    }
    T operator[](int32 SlotIdx) const {
        T V = {};
        At(SlotIdx, V);
        return V;
    }

    std::vector<std::pair<int32, T>> Enumerate() const {
        std::vector<std::pair<int32, T>> Out;
        const auto Raw = Elements().Enumerate();
        Out.reserve(Raw.size());
        for (const auto& Pr : Raw) Out.emplace_back(Pr.first, Pr.second.Value);
        return Out;
    }
};

// ---- TMap<K,V> -------------------------------------------------------------
// Identical layout to TSet< TPair<K,V> >.
template<typename K, typename V>
class TMap {
public:
    using PairT = TPair<K, V>;
    using SetT  = TSet<PairT>;

    static constexpr uint64 SIZE = SetT::SIZE;

    IMemoryReader* Reader = nullptr;
    uint64         Addr   = 0;

    TMap() = default;
    TMap(IMemoryReader& InReader, uint64 InAddr) : Reader(&InReader), Addr(InAddr) {}

    SetT AsSet() const { return SetT(*Reader, Addr); }
    int32 Num() const  { return AsSet().Num(); }

    bool At(int32 SlotIdx, PairT& Out) const { return AsSet().At(SlotIdx, Out); }
    PairT operator[](int32 SlotIdx) const    { return AsSet()[SlotIdx]; }

    std::vector<std::pair<int32, PairT>> Enumerate() const { return AsSet().Enumerate(); }

    // Linear scan — UE's hash bucket walk requires a project-supplied hasher
    // and key-comparator, which the caller can layer on top via Enumerate().
    bool Find(const K& Key, V& Out) const {
        for (const auto& Pr : Enumerate()) {
            if (Pr.second.Key == Key) { Out = Pr.second.Value; return true; }
        }
        return false;
    }
};

} // namespace UC
