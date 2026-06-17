#pragma once

// =============================================================================
// auto_offsets.h — Live-probe structure offsets (Phase 9-15)
//
// Runs AFTER auto_discovery.h Phases 0-8 (vtables, FName resolver, FField
// NamePrivate XOR, FFieldClass globals). For each layout offset, samples a
// few known-vtable objects, scans the candidate offset range, and scores each
// against a type-shape oracle (heap ptr / module ptr / TArray shape /
// parent-backref / vtable-match). Writes winning offsets directly into the
// `inline` globals in `arc_decrypt.h::Offsets::*` so all 108 consumer sites
// pick them up at runtime with no other change.
//
// Probes (in dependency order):
//   1.  UStruct::ChildProperties        (FField head — ptr-to-heap-FField)
//   2.  FField::Next                    (chain walk validation)
//   3.  FField::ClassPrivate            (matches discovered FFieldClass globals)
//   4.  FField::NamePrivate             (validate by XOR-decode → printable CI)
//   5.  UStruct::SuperStruct            (UClass → parent UClass)
//   6.  UStruct::PropertiesSize         (u32 in plausible range, 4-aligned)
//   7.  UEnum::Names                    (TArray<TPair<FName,int64>>)
//   8.  UClass::FuncMap_*               (TArray of TPair<FName,UFunction*>)
//   9.  UFunction::NativeFunc/Flags/NumParms
//   10. FProperty subclass sub-pointers (Struct/PropertyClass/Inner/...)
//   11. FProperty::ArrayDim / ElementSize
//
// Each probe demands ≥N consensus hits before overwriting a global; weak
// probes log loudly and leave the compile-time fallback alone.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <algorithm>

#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "auto_discovery.h"
#include "fname_decrypt.h"

namespace AutoOffsets {

// ─────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────
inline bool IsHeapPtr(uint64_t p) {
    return p > 0x10000ULL && p < 0x800000000000ULL;
}
inline bool IsModulePtr(uint64_t p, uint64_t base, uint64_t size) {
    return p >= base && p < base + size;
}
inline bool IsTextPtr(uint64_t p, uint64_t base, const AutoDiscovery::ModuleBounds& b) {
    return p >= base + b.TextRva && p < base + b.TextEnd();
}
inline bool IsHeapNonModule(uint64_t p, uint64_t base, uint64_t size) {
    return IsHeapPtr(p) && !IsModulePtr(p, base, size);
}

template <typename T>
inline bool R(IMemoryReader& reader, uint64_t addr, T& out) {
    return reader.Read(addr, &out, sizeof(T));
}

template <typename K>
inline std::pair<K, int> PickMode(const std::unordered_map<K, int>& counts) {
    K best{}; int best_cnt = 0;
    for (const auto& [k, c] : counts) if (c > best_cnt) { best_cnt = c; best = k; }
    return {best, best_cnt};
}

inline void ApplyOffset(const char* name, uint64_t& slot, uint64_t found,
                        int hits, int total, int min_hits)
{
    if (found == 0 || hits < min_hits) {
        std::printf("[autoff] %-32s probe weak (best=0x%llX hits=%d/%d, need %d) — keeping 0x%llX\n",
            name, (unsigned long long)found, hits, total, min_hits, (unsigned long long)slot);
        return;
    }
    if (found == slot) {
        std::printf("[autoff] %-32s matches constant 0x%llX (%d/%d hits)\n",
            name, (unsigned long long)found, hits, total);
    } else {
        std::printf("[autoff] %-32s drift: 0x%llX → 0x%llX (auto-fixed, %d/%d hits)\n",
            name, (unsigned long long)slot, (unsigned long long)found, hits, total);
        slot = found;
    }
}

// Same as ApplyOffset, but also factors in the compile-time slot's own
// probe score: if compile-time scores ≥ keep_threshold × winner_score,
// keep compile-time. Used by probes where multiple offsets can produce
// plausible chains (FField::Next via RefLink/DestructorLink, etc.) and
// drifting silently is more dangerous than missing a real drift.
inline void ApplyOffsetSticky(const char* name, uint64_t& slot, uint64_t found,
                              int found_hits, int slot_hits, int total,
                              int min_hits, double keep_threshold = 0.7)
{
    if (found == 0 || found_hits < min_hits) {
        std::printf("[autoff] %-32s probe weak (best=0x%llX hits=%d/%d, need %d) — keeping 0x%llX\n",
            name, (unsigned long long)found, found_hits, total, min_hits, (unsigned long long)slot);
        return;
    }
    if (found == slot) {
        std::printf("[autoff] %-32s matches constant 0x%llX (%d/%d hits)\n",
            name, (unsigned long long)found, found_hits, total);
        return;
    }
    if (slot_hits >= (int)(found_hits * keep_threshold)) {
        std::printf("[autoff] %-32s probe found 0x%llX (%d hits) but compile-time 0x%llX scores %d hits (%.0f%%) — keeping\n",
            name, (unsigned long long)found, found_hits,
            (unsigned long long)slot, slot_hits, 100.0 * slot_hits / found_hits);
        return;
    }
    std::printf("[autoff] %-32s drift: 0x%llX (%d) → 0x%llX (%d) (auto-fixed)\n",
        name, (unsigned long long)slot, slot_hits,
        (unsigned long long)found, found_hits);
    slot = found;
}

inline std::vector<uint64_t> FilterByVtable(
    const std::vector<uint64_t>& objs, IMemoryReader& reader,
    uint64_t want_vt_va, size_t max_n)
{
    std::vector<uint64_t> out;
    if (!want_vt_va) return out;
    out.reserve(max_n);
    for (uint64_t obj : objs) {
        if (out.size() >= max_n) break;
        uint64_t vt = 0;
        if (!reader.Read(obj, &vt, 8)) continue;
        if (vt == want_vt_va) out.push_back(obj);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────
// Context — passed to every probe
// ─────────────────────────────────────────────────────────────────
struct Context {
    IMemoryReader*                       reader = nullptr;
    uint64_t                             module_base = 0;
    AutoDiscovery::ModuleBounds          bounds;
    AutoDiscovery::VTableMap             vtables;
    FName::FNameDecryptor*               fname = nullptr;
    std::unordered_map<uint64_t, std::string> fclass_to_type;  // FFieldClass* → "FStructProperty"
};

// Build FFieldClass*→typename map.
//
// IMPORTANT: TargetRva IS the FFieldClass struct itself — an in-place .data
// static allocation populated by sub_3E80E0 ctor. NOT a pointer-holding slot.
// At runtime, FField::ClassPrivate reads exactly `module_base + TargetRva` —
// no extra dereference. Earlier version of this code dereferenced and got 0
// entries; see the matching comment in sdk_generator.h::SeedFClassMapFromGlobals.
inline void BuildFClassTypeMap(Context& ctx) {
    for (const auto& g : AutoDiscovery::g_DiscoveredFClassGlobals) {
        uint64_t fclass_addr = ctx.module_base + g.TargetRva;
        ctx.fclass_to_type[fclass_addr] = g.TypeName;
    }
}

// LooksLikeFField — strong oracle that distinguishes FFields from UObjects.
//
// An FField has an FFieldClass pointer somewhere in its first 0x180 bytes
// (the ClassPrivate field). UObjects/UClasses/UWorlds/UEnums/etc. do NOT
// have FFieldClass pointers anywhere — their per-instance class pointer is
// the encrypted UObject 4-slot pool, which never matches an FFieldClass
// global address.
//
// Without this, "heap-pointer-with-module-vtable" matches CDO, ClassWithin,
// SuperStruct, NetFields, and dozens of other UObject-ptr fields on UClass
// — silently drifting ChildProperties / Next / etc. to wrong offsets.
//
// Returns the offset where the FFieldClass match was found (-1 if none).
inline int FindFClassPointerOffset(uint64_t addr, Context& ctx) {
    if (ctx.fclass_to_type.empty()) return -1;
    uint8_t buf[0x180] = {};
    if (!ctx.reader->Read(addr, buf, sizeof(buf))) return -1;
    for (size_t off = 0; off + 8 <= sizeof(buf); off += 8) {
        uint64_t v = 0;
        std::memcpy(&v, buf + off, 8);
        if (ctx.fclass_to_type.count(v)) return (int)off;
    }
    return -1;
}
inline bool LooksLikeFField(uint64_t addr, Context& ctx) {
    return FindFClassPointerOffset(addr, ctx) >= 0;
}

// Walk a UStruct's FField chain (using the CURRENT ChildProperties + Next
// offsets) and return the FField pointers (capped).
//
// FField vtables live in .rdata (Microsoft x64 ABI: vtables are .rdata,
// only the function pointers they contain are in .text). So the vtable
// validity check is "anywhere in module" — IsModulePtr — NOT IsTextPtr.
// Earlier version with IsTextPtr rejected every legitimate FField.
inline std::vector<uint64_t> CollectFFields(Context& ctx,
                                            const std::vector<uint64_t>& ustructs,
                                            size_t max_n)
{
    std::vector<uint64_t> out;
    out.reserve(max_n);
    for (uint64_t uss : ustructs) {
        if (out.size() >= max_n) break;
        uint64_t cur = 0;
        if (!R(*ctx.reader, uss + ArcDecrypt::Offsets::UStruct::ChildProperties, cur)) continue;
        std::unordered_set<uint64_t> seen;
        int n = 0;
        while (cur && IsHeapNonModule(cur, ctx.module_base, ctx.bounds.ImageSize) && n < 64) {
            if (!seen.insert(cur).second) break;
            uint64_t vt = 0;
            if (!R(*ctx.reader, cur, vt)) break;
            if (!IsModulePtr(vt, ctx.module_base, ctx.bounds.ImageSize)) break;
            out.push_back(cur);
            if (out.size() >= max_n) break;
            uint64_t nxt = 0;
            if (!R(*ctx.reader, cur + ArcDecrypt::Offsets::FField::Next, nxt)) break;
            cur = nxt;
            ++n;
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────
// Probe 1+3 (joint): UStruct::ChildProperties + FField::ClassPrivate
//
// For each sample UStruct, scan candidate ChildProperties offsets in
// 0x80..0x180. At each offset, dereference and check if the result LooksLikeFField
// — i.e. contains an FFieldClass pointer (matching the discovered global table)
// somewhere in its first 0x180 bytes. The FFieldClass-pointer offset within
// the FField IS ClassPrivate. Both offsets fall out as the per-axis mode.
//
// Why joint: probing ChildProperties alone with "heap-ptr-module-vtable" oracle
// false-positives on every other UObject pointer in UClass (CDO, ClassWithin,
// NetFields[0], etc.). The FFieldClass match is the only oracle that uniquely
// identifies FField vs UObject.
// ─────────────────────────────────────────────────────────────────
inline void ProbeChildPropertiesAndClassPrivate(Context& ctx,
                                                const std::vector<uint64_t>& ustructs)
{
    if (ustructs.empty()) {
        std::printf("[autoff] UStruct::ChildProperties — no samples\n");
        return;
    }
    if (ctx.fclass_to_type.empty()) {
        std::printf("[autoff] UStruct::ChildProperties — no FFieldClass map; can't validate FFields\n");
        return;
    }
    std::unordered_map<uint64_t, int> cp_counts;
    std::unordered_map<uint64_t, int> cpriv_counts;
    int joint_hits = 0;
    for (uint64_t uss : ustructs) {
        for (uint64_t cp_off = 0x80; cp_off <= 0x180; cp_off += 8) {
            uint64_t ff = 0;
            if (!R(*ctx.reader, uss + cp_off, ff)) continue;
            if (!IsHeapNonModule(ff, ctx.module_base, ctx.bounds.ImageSize)) continue;
            uint64_t vt = 0;
            if (!R(*ctx.reader, ff, vt)) continue;
            if (!IsModulePtr(vt, ctx.module_base, ctx.bounds.ImageSize)) continue;
            int cpriv_off = FindFClassPointerOffset(ff, ctx);
            if (cpriv_off < 0) continue;  // Not an FField — skip
            cp_counts[cp_off]++;
            cpriv_counts[(uint64_t)cpriv_off]++;
            ++joint_hits;
        }
    }
    std::printf("[autoff] joint FField probe: %d (UStruct, ChildProperties, FFieldClass) triples found\n",
                joint_hits);
    auto [cp_best, cp_hits] = PickMode(cp_counts);
    auto [cpriv_best, cpriv_hits] = PickMode(cpriv_counts);
    const uint64_t cp_slot = ArcDecrypt::Offsets::UStruct::ChildProperties;
    const uint64_t cpriv_slot = ArcDecrypt::Offsets::FField::ClassPrivate;
    int cp_slot_hits = cp_counts.count(cp_slot) ? cp_counts[cp_slot] : 0;
    int cpriv_slot_hits = cpriv_counts.count(cpriv_slot) ? cpriv_counts[cpriv_slot] : 0;
    ApplyOffsetSticky("UStruct::ChildProperties", ArcDecrypt::Offsets::UStruct::ChildProperties,
                      cp_best, cp_hits, cp_slot_hits, (int)ustructs.size(), 5);
    ArcDecrypt::Offsets::UStruct::Children = ArcDecrypt::Offsets::UStruct::ChildProperties;
    ApplyOffsetSticky("FField::ClassPrivate", ArcDecrypt::Offsets::FField::ClassPrivate,
                      cpriv_best, cpriv_hits, cpriv_slot_hits, (int)ustructs.size(), 5);
}

// ─────────────────────────────────────────────────────────────────
// Probe 2: FField::Next
// For each confirmed FField head (LooksLikeFField), try every Next-offset
// candidate, walk the chain, count valid FFields. Each chain element MUST
// also LooksLikeFField — eliminates false positives where any heap-ptr +
// module-vtable would form a fake "chain" through unrelated UObjects.
// ─────────────────────────────────────────────────────────────────
inline void ProbeFFieldNext(Context& ctx, const std::vector<uint64_t>& ustructs) {
    if (ustructs.empty() || ctx.fclass_to_type.empty()) return;
    const uint64_t slot_off = ArcDecrypt::Offsets::FField::Next;
    std::unordered_map<uint64_t, int> chain_total;
    for (uint64_t uss : ustructs) {
        uint64_t head = 0;
        if (!R(*ctx.reader, uss + ArcDecrypt::Offsets::UStruct::ChildProperties, head)) continue;
        if (!IsHeapNonModule(head, ctx.module_base, ctx.bounds.ImageSize)) continue;
        if (!LooksLikeFField(head, ctx)) continue;
        for (uint64_t off = 0x40; off <= 0x180; off += 8) {
            uint64_t cur = head;
            int len = 0;
            std::unordered_set<uint64_t> seen;
            while (cur && IsHeapNonModule(cur, ctx.module_base, ctx.bounds.ImageSize) && len < 64) {
                if (!seen.insert(cur).second) break;
                if (!LooksLikeFField(cur, ctx)) break;
                ++len;
                uint64_t nxt = 0;
                if (!R(*ctx.reader, cur + off, nxt)) break;
                if (nxt == cur) break;  // self-loop
                cur = nxt;
            }
            if (len >= 2) chain_total[off] += len;
        }
    }
    auto [best, score] = PickMode(chain_total);
    int slot_score = chain_total.count(slot_off) ? chain_total[slot_off] : 0;
    ApplyOffsetSticky("FField::Next", ArcDecrypt::Offsets::FField::Next,
                      best, score, slot_score, (int)ustructs.size(), 10);
}

// (FField::ClassPrivate is discovered jointly with ChildProperties — see
// ProbeChildPropertiesAndClassPrivate above. No standalone probe needed.)

// ─────────────────────────────────────────────────────────────────
// Probe 4: FField::NamePrivate
// Two-pass scan:
//   (a) Structural: at each candidate 16-byte slot, the upper 8 bytes are
//       session-wide constant across all FFields (since Number==0 means the
//       hi64 cancels XOR_CONST during decrypt). Pick the offset where the
//       most samples agree on the SAME upper-8-byte value.
//   (b) If Phase 2 produced an XOR const, additionally validate that the
//       chosen offset's lo64 decodes to a plausible CompIndex.
// ─────────────────────────────────────────────────────────────────
inline void ProbeFFieldNamePrivate(Context& ctx, const std::vector<uint64_t>& ustructs) {
    auto ffields = CollectFFields(ctx, ustructs, 100);
    if (ffields.empty()) return;

    // Structural pass: at each offset, count samples agreeing on hi64.
    // Map: offset → (hi64 → count).
    // Scan starts at 0x20 to cover CL-1177678's +0x30 NamePrivate slot
    // (was missing from the old 0x40+ range). Step 8 (not 16) so we don't
    // skip the +0x30 if scan starts at 0x20.
    // Real FField NamePrivate slots on CL-1177678 are REPLICATED — lo64
    // equals hi64. Strongly bias toward replicated slots: count those
    // with weight 4, others with weight 1. Earlier "lo!=hi → skip"
    // filter killed ALL hits when CollectFFields returned UScriptStruct
    // children that didn't share the replicated pattern (different
    // FField subclass), regressing properties to 0.
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, int>> hi_agree;
    for (uint64_t ff : ffields) {
        for (uint64_t off = 0x20; off <= 0x180; off += 8) {
            uint8_t slot[16] = {};
            if (!R(*ctx.reader, ff + off, slot)) continue;
            uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, slot, 8);
            std::memcpy(&hi, slot + 8, 8);
            if (hi == 0 || hi == ~0ULL) continue;
            int weight = (lo == hi) ? 4 : 1;
            hi_agree[off][hi] += weight;
        }
    }

    // For each offset, take the most-agreed hi64 and its count.
    std::unordered_map<uint64_t, int> off_score;
    for (auto& [off, hmap] : hi_agree) {
        auto [hi_mode, hi_cnt] = PickMode(hmap);
        if (hi_cnt >= 3) off_score[off] = hi_cnt;
    }
    auto [best, hits] = PickMode(off_score);
    const uint64_t slot_off = ArcDecrypt::Offsets::FField::NamePrivate;
    int slot_hits = off_score.count(slot_off) ? off_score[slot_off] : 0;
    // CL-1177678: NamePrivate is HARDCODED at +0x30 (verified live in
    // sub_44E3DC FBoolProperty::GetCPPType which loads __m128i [a1+3]).
    // Earlier auto-disc moved it to +0xE0 because CollectFFields walked
    // UStruct::Children (UField list) instead of FField chain heads —
    // those non-FField objects have their session-constant hi64 at +0xE0
    // (probably a flag/version block), giving a misleading 70-hit signal.
    // Until CollectFFields is patched to walk +0xB0 ChildProperties on
    // CL-1177678, hard-pin NamePrivate to its compile-time value to
    // prevent the regression.
    std::printf("[autoff] FField::NamePrivate              pinned to 0x%llX (slot=%d, best=0x%llX@%d hits)\n",
        (unsigned long long)slot_off, slot_hits, (unsigned long long)best, hits);
    ArcDecrypt::Offsets::FField::NameEncrypted = ArcDecrypt::Offsets::FField::NamePrivate;
}

// ─────────────────────────────────────────────────────────────────
// Probe 5: UStruct::SuperStruct
//
// Scan for UClass-vtable pointer + dispersion gate: real SuperStruct varies
// per child class (Pawn::Super=Actor, Actor::Super=Object, Object::Super=null,
// ...) while ClassWithin / metaclass slots typically pin to a single value
// across most UClasses. Reject offsets where ≥80% of samples agree on a
// single pointer — those are class-meta fields, not parent-class refs.
// ─────────────────────────────────────────────────────────────────
inline void ProbeUStructSuperStruct(Context& ctx, const std::vector<uint64_t>& classes) {
    if (classes.empty() || !ctx.vtables.ClassNativeRVA) {
        std::printf("[autoff] UStruct::SuperStruct — no UClass samples or no Class vtable\n");
        return;
    }
    uint64_t want_vt = ctx.module_base + ctx.vtables.ClassNativeRVA;
    std::unordered_map<uint64_t, std::unordered_map<uint64_t, int>> off_values;
    std::unordered_map<uint64_t, int> off_passes;
    for (uint64_t cls : classes) {
        for (uint64_t off = 0x40; off <= 0x180; off += 8) {
            uint64_t super = 0;
            if (!R(*ctx.reader, cls + off, super)) continue;
            if (!IsHeapNonModule(super, ctx.module_base, ctx.bounds.ImageSize)) continue;
            uint64_t vt = 0;
            if (!R(*ctx.reader, super, vt)) continue;
            if (vt != want_vt) continue;
            if (super == cls) continue;
            off_values[off][super]++;
            off_passes[off]++;
        }
    }
    uint64_t best = 0; int best_score = 0; int best_passes = 0; int best_distinct = 0;
    for (auto& [off, vmap] : off_values) {
        int distinct = (int)vmap.size();
        int passes = off_passes[off];
        int max_count = 0;
        for (auto& [_, c] : vmap) if (c > max_count) max_count = c;
        if (max_count * 5 >= passes * 4) continue;  // 80% same value → ClassWithin-like
        int score = distinct * passes;
        if (score > best_score) {
            best_score = score; best = off; best_passes = passes; best_distinct = distinct;
        }
    }
    if (!best) {
        std::printf("[autoff] UStruct::SuperStruct           no offset passed dispersion gate — keeping 0x%llX\n",
            (unsigned long long)ArcDecrypt::Offsets::UStruct::SuperStruct);
        return;
    }
    std::printf("[autoff] UStruct::SuperStruct           candidate +0x%llX  distinct=%d passes=%d\n",
        (unsigned long long)best, best_distinct, best_passes);
    ApplyOffset("UStruct::SuperStruct", ArcDecrypt::Offsets::UStruct::SuperStruct,
                best, best_passes, (int)classes.size(), 5);
}

// ─────────────────────────────────────────────────────────────────
// Probe 6: UStruct::PropertiesSize
//
// u32 in plausible range, 4-aligned, AND showing dispersion across samples.
// The dispersion gate is critical: flag/version fields are also 4-aligned
// u32s in [8..0x100000] and would silently win — earlier version drifted
// 0xD8 → 0x12C because some flag word at +0x12C took 99/100 samples to a
// single constant. Real PropertiesSize varies per UStruct (different sizeof).
// Score = (count of distinct values) × (samples passing). Mode is now the
// offset whose values are ALL plausible AND varied.
// ─────────────────────────────────────────────────────────────────
inline void ProbeUStructPropertiesSize(Context& ctx, const std::vector<uint64_t>& ustructs) {
    if (ustructs.empty()) return;

    // Per-offset: collect the set of values seen across samples
    std::unordered_map<uint64_t, std::unordered_map<uint32_t, int>> off_values;
    std::unordered_map<uint64_t, int> off_passes;
    for (uint64_t uss : ustructs) {
        for (uint64_t off = 0xB0; off <= 0x140; off += 4) {
            uint32_t v = 0;
            if (!R(*ctx.reader, uss + off, v)) continue;
            if (v < 8 || v > 0x100000) continue;
            if (v & 3) continue;
            off_values[off][v]++;
            off_passes[off]++;
        }
    }

    // Score: (distinct values count) × (sample passes). A flag-like offset
    // with 99/100 same value gets distinct=1 → score=99. A real PropertiesSize
    // with 50 distinct values across 90 samples gets distinct=50 → score=4500.
    uint64_t best = 0;
    int best_score = 0;
    int best_passes = 0;
    int best_distinct = 0;
    for (auto& [off, vmap] : off_values) {
        int distinct = (int)vmap.size();
        int passes   = off_passes[off];
        // Reject offsets where ≥80% of samples agree on a single value
        // (flag/version, not size).
        int max_count = 0;
        for (auto& [_, c] : vmap) if (c > max_count) max_count = c;
        if (max_count * 5 >= passes * 4) continue;  // 80% same value → flag, not size
        int score = distinct * passes;
        if (score > best_score) {
            best_score = score; best = off; best_passes = passes; best_distinct = distinct;
        }
    }
    if (!best) {
        std::printf("[autoff] UStruct::PropertiesSize         no offset passed dispersion gate — keeping 0x%llX\n",
            (unsigned long long)ArcDecrypt::Offsets::UStruct::PropertiesSize);
        return;
    }
    std::printf("[autoff] UStruct::PropertiesSize         candidate +0x%llX  distinct=%d passes=%d\n",
        (unsigned long long)best, best_distinct, best_passes);
    ApplyOffset("UStruct::PropertiesSize", ArcDecrypt::Offsets::UStruct::PropertiesSize,
                best, best_passes, (int)ustructs.size(), 20);
}

// ─────────────────────────────────────────────────────────────────
// Probe 7: UEnum::Names
// TArray<TPair<FName,int64>> shape + FName-decode validation. Earlier version
// with shape-only check drifted to 0xD8 because some other field at +0xD8 had
// (heap-ptr, plausible-num, plausible-max, looks-like-FName-CI) by accident.
// FNameDecryptor validation (first entry must decode to printable name) gates
// out those false positives.
// ─────────────────────────────────────────────────────────────────
inline void ProbeUEnumNames(Context& ctx, const std::vector<uint64_t>& enums) {
    if (enums.empty()) {
        std::printf("[autoff] UEnum::Names — no UEnum samples\n");
        return;
    }
    auto is_printable = [](const std::string& s) {
        if (s.size() < 2 || s.size() > 96) return false;
        for (unsigned char c : s) if (c < 0x20 || c >= 0x7F) return false;
        return true;
    };
    std::unordered_map<uint64_t, int> counts;
    for (uint64_t en : enums) {
        for (uint64_t off = 0x40; off <= 0x100; off += 8) {
            uint64_t data = 0;
            uint32_t num = 0, mx = 0;
            if (!R(*ctx.reader, en + off,      data)) continue;
            if (!R(*ctx.reader, en + off + 8,  num))  continue;
            if (!R(*ctx.reader, en + off + 12, mx))   continue;
            if (!IsHeapPtr(data)) continue;
            if (num < 1 || num > 1024) continue;
            if (mx < num || mx > 4096) continue;
            uint32_t fname_lo = 0;
            if (!R(*ctx.reader, data, fname_lo)) continue;
            if (fname_lo < 2 || fname_lo > 0x2000000u) continue;
            // FName-decode validation: first entry must produce a printable name.
            if (ctx.fname) {
                std::string n = ctx.fname->CompIndexToNameLenient((int32_t)fname_lo);
                if (!is_printable(n)) continue;
            }
            counts[off]++;
        }
    }
    auto [best, hits] = PickMode(counts);
    int slot_hits = 0;
    auto it = counts.find(ArcDecrypt::Offsets::UEnum::Names);
    if (it != counts.end()) slot_hits = it->second;
    ApplyOffsetSticky("UEnum::Names", ArcDecrypt::Offsets::UEnum::Names,
                best, hits, slot_hits, (int)enums.size(), 3);
}

// ─────────────────────────────────────────────────────────────────
// Probe 8: UClass::FuncMap_*
// TSparseArray (inside TSet inside TMap) of TPair<FName, UFunction*>.
// Layout at FuncMap base:
//   +0x00: Data ptr (TSparseArray::Data::Data)
//   +0x08: Num (int32, total slots incl. free)
//   +0x0C: Max (int32)
//   +0x10: AllocationFlags ptr (TBitArray::Data)
//   +0x18: AllocationFlags Num (int32)
//   +0x1C: AllocationFlags Max (int32)
//   +0x20: FirstFreeIndex (int32, -1 if no free)
//   +0x24: NumFreeIndices (int32)
// Each element is stride 0x18: TPair<FName(8),UFunction*(8)> + HashNextId(4) + HashIndex(4).
// Probe for shape where first valid element's Value (at data+0x08) has
// module vtable AND a .text NativeFunc at +0x178 (confirms UFunction,
// not UClass/UScriptStruct which share the same vtable on CL-1233465).
// ─────────────────────────────────────────────────────────────────
inline void ProbeUClassFuncMap(Context& ctx, const std::vector<uint64_t>& classes) {
    if (classes.empty() || !ctx.vtables.FunctionRVA) {
        std::printf("[autoff] UClass::FuncMap_* — no UClass samples or no Function vtable\n");
        return;
    }
    uint64_t WantVt = ctx.module_base + ctx.vtables.FunctionRVA;
    std::unordered_map<uint64_t, int> Counts;
    for (uint64_t Cls : classes) {
        for (uint64_t Off = 0x180; Off <= 0x320; Off += 8) {
            uint64_t Data = 0;
            uint32_t Num = 0, Mx = 0;
            if (!R(*ctx.reader, Cls + Off,      Data)) continue;
            if (!R(*ctx.reader, Cls + Off + 8,  Num))  continue;
            if (!R(*ctx.reader, Cls + Off + 12, Mx))   continue;
            if (!IsHeapPtr(Data)) continue;
            if (Num < 1 || Num > 1024) continue;
            if (Mx < Num || Mx > 4096) continue;
            uint64_t AllocFlagsPtr = 0;
            if (!R(*ctx.reader, Cls + Off + 0x10, AllocFlagsPtr)) continue;
            if (!IsHeapPtr(AllocFlagsPtr)) continue;
            bool FoundValidEntry = false;
            uint32_t ScanLimit = std::min(Num, (uint32_t)8);
            for (uint32_t I = 0; I < ScanLimit; ++I) {
                uint64_t Fn = 0;
                if (!R(*ctx.reader, Data + (uint64_t)I * 0x18 + 8, Fn)) continue;
                if (!IsHeapNonModule(Fn, ctx.module_base, ctx.bounds.ImageSize)) continue;
                uint64_t Vt = 0;
                if (!R(*ctx.reader, Fn, Vt)) continue;
                if (!IsModulePtr(Vt, ctx.module_base, ctx.bounds.ImageSize)) continue;
                uint64_t NativeFunc = 0;
                R(*ctx.reader, Fn + ArcDecrypt::Offsets::UFunction::NativeFunc, NativeFunc);
                bool HasNative = IsTextPtr(NativeFunc, ctx.module_base, ctx.bounds);
                uint64_t QNumParms = 0;
                R(*ctx.reader, Fn + ArcDecrypt::Offsets::UFunction::NumParms, QNumParms);
                bool ParmShape = (QNumParms >> 8) == 0 && (QNumParms & 0xFF) <= 64;
                if (HasNative || ParmShape) {
                    FoundValidEntry = true;
                    break;
                }
            }
            if (!FoundValidEntry) continue;
            Counts[Off]++;
        }
    }
    auto [Best, Hits] = PickMode(Counts);
    if (Best == 0 || Hits < 3) {
        std::printf("[autoff] UClass::FuncMap_PairsData      probe weak (best=0x%llX hits=%d) — keeping 0x%llX\n",
            (unsigned long long)Best, Hits,
            (unsigned long long)ArcDecrypt::Offsets::UClass::FuncMap_PairsData);
        return;
    }
    ApplyOffset("UClass::FuncMap_PairsData", ArcDecrypt::Offsets::UClass::FuncMap_PairsData,
                Best, Hits, (int)classes.size(), 3);
    ArcDecrypt::Offsets::UClass::FuncMap_Num            = Best + 8;
    ArcDecrypt::Offsets::UClass::FuncMap_Max            = Best + 12;
    ArcDecrypt::Offsets::UClass::FuncMap_AllocFlags     = Best + 0x10;
    ArcDecrypt::Offsets::UClass::FuncMap_AllocFlagsNum  = Best + 0x18;
    ArcDecrypt::Offsets::UClass::FuncMap_FirstFreeIdx   = Best + 0x20;
    ArcDecrypt::Offsets::UClass::FuncMap_NumFreeIndices = Best + 0x24;
    std::printf("[autoff] UClass::FuncMap_Num/Max set to +0x%llX/+0x%llX (derived)\n",
        (unsigned long long)ArcDecrypt::Offsets::UClass::FuncMap_Num,
        (unsigned long long)ArcDecrypt::Offsets::UClass::FuncMap_Max);
    std::printf("[autoff] UClass::FuncMap_AllocFlags set to +0x%llX, NumFreeIndices at +0x%llX\n",
        (unsigned long long)ArcDecrypt::Offsets::UClass::FuncMap_AllocFlags,
        (unsigned long long)ArcDecrypt::Offsets::UClass::FuncMap_NumFreeIndices);
}

// ─────────────────────────────────────────────────────────────────
// Probe 9: UFunction internals — NativeFunc, FunctionFlags, NumParms
// ─────────────────────────────────────────────────────────────────
inline void ProbeUFunctionInternals(Context& ctx, const std::vector<uint64_t>& functions) {
    if (functions.empty()) {
        std::printf("[autoff] UFunction probes — no UFunction samples\n");
        return;
    }

    // NativeFunc — pointer in .text
    {
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t fn : functions) {
            for (uint64_t off = 0x100; off <= 0x180; off += 8) {
                uint64_t p = 0;
                if (!R(*ctx.reader, fn + off, p)) continue;
                if (IsTextPtr(p, ctx.module_base, ctx.bounds)) counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        const uint64_t slot = ArcDecrypt::Offsets::UFunction::NativeFunc;
        int slot_hits = counts.count(slot) ? counts[slot] : 0;
        ApplyOffsetSticky("UFunction::NativeFunc", ArcDecrypt::Offsets::UFunction::NativeFunc,
                          best, hits, slot_hits, (int)functions.size(), 10);
    }

    // FunctionFlags — u32 with sane FUNC_* bits.
    // FUNC_Native=0x400 / FUNC_Public=0x4 / FUNC_BlueprintCallable=0x4000000 / etc.
    // Unknown value, but common: < 0x10000000 and != 0 / != 0xFFFFFFFF.
    {
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t fn : functions) {
            for (uint64_t off = 0xC0; off <= 0x158; off += 4) {
                uint32_t v = 0;
                if (!R(*ctx.reader, fn + off, v)) continue;
                if (v == 0 || v == 0xFFFFFFFFu) continue;
                if ((v & 0xFFFFu) == 0) continue;  // most flag bits in low 16
                if (v > 0x10000000u) continue;
                counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        const uint64_t slot = ArcDecrypt::Offsets::UFunction::FunctionFlags;
        int slot_hits = counts.count(slot) ? counts[slot] : 0;
        ApplyOffsetSticky("UFunction::FunctionFlags", ArcDecrypt::Offsets::UFunction::FunctionFlags,
                          best, hits, slot_hits, (int)functions.size(), 10);
    }

    // NumParms is intentionally NOT probed.
    //
    // The available oracle is "u8 matches counted FField chain length", but
    // the chain at ChildProperties walks ALL FProperty children — input
    // params + return value + locals — while NumParms counts ONLY input
    // params. To distinguish, you'd need the FProperty PropertyFlags bits
    // (CPF_ReturnParm / CPF_OutParm / CPF_Parm), which themselves require a
    // verified FProperty layout. Earlier version of this probe drifted
    // 0xE0 → 0x12E because chain_len ≠ NumParms but some unrelated u8 byte
    // happened to match the inflated chain count by coincidence.
    //
    // Compile-time fallback (0xE0 on CL-1177146) is far safer than a wrong
    // auto-fix. If NumParms moves on a future patch the SDK function param
    // counts will be off but everything else still works.
    std::printf("[autoff] UFunction::NumParms             skipped (no reliable oracle — keeping 0x%llX)\n",
        (unsigned long long)ArcDecrypt::Offsets::UFunction::NumParms);
}

// ─────────────────────────────────────────────────────────────────
// Probe 10: FProperty subclass sub-pointers
// Bucket FFields by their FFieldClass type (FStructProperty, FObjectProperty,
// FArrayProperty, etc.), then probe per-type:
//   FStructProperty::Struct        → ptr to UScriptStruct (vtable match)
//   FObjectProperty::PropertyClass → ptr to UClass (vtable match)
//   FSoftObjectProperty::PropertyClass → ptr to UClass (vtable match)
//   FEnumProperty::Enum            → ptr to UEnum (vtable match)
//   FArrayProperty::Inner          → ptr to FField (vtable in module)
//   FSetProperty::ElementProp      → ptr to FField (vtable in module)
//   FMapProperty::KeyProp/ValueProp→ two consecutive FField ptrs
// ─────────────────────────────────────────────────────────────────
inline void ProbeFPropertySubPointers(Context& ctx, const std::vector<uint64_t>& ustructs) {
    if (ctx.fclass_to_type.empty()) {
        std::printf("[autoff] FProperty sub-pointers — no FFieldClass type map; skipping\n");
        return;
    }
    auto ffields = CollectFFields(ctx, ustructs, 800);
    if (ffields.empty()) return;

    // Bucket by FProperty subclass type
    std::unordered_map<std::string, std::vector<uint64_t>> by_type;
    for (uint64_t ff : ffields) {
        uint64_t fc = 0;
        if (!R(*ctx.reader, ff + ArcDecrypt::Offsets::FField::ClassPrivate, fc)) continue;
        auto it = ctx.fclass_to_type.find(fc);
        if (it != ctx.fclass_to_type.end()) by_type[it->second].push_back(ff);
    }
    std::printf("[autoff] FProperty sub-pointer buckets:");
    for (const auto& [t, v] : by_type) std::printf(" %s=%zu", t.c_str(), v.size());
    std::printf("\n");

    auto probe_to_vtable = [&](uint64_t want_vt_va, const std::vector<uint64_t>& ffs,
                               uint64_t& slot, const char* label, int min_hits)
    {
        if (ffs.empty() || !want_vt_va) {
            std::printf("[autoff] %-32s no samples or no vtable — skipping\n", label);
            return;
        }
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t ff : ffs) {
            for (uint64_t off = 0xD0; off <= 0x180; off += 8) {
                uint64_t p = 0;
                if (!R(*ctx.reader, ff + off, p)) continue;
                if (!IsHeapNonModule(p, ctx.module_base, ctx.bounds.ImageSize)) continue;
                uint64_t vt = 0;
                if (!R(*ctx.reader, p, vt)) continue;
                if (vt != want_vt_va) continue;
                counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        int slot_hits = counts.count(slot) ? counts[slot] : 0;
        ApplyOffsetSticky(label, slot, best, hits, slot_hits, (int)ffs.size(), min_hits);
    };

    auto probe_to_ffield = [&](const std::vector<uint64_t>& ffs,
                               uint64_t& slot, const char* label, int min_hits)
    {
        if (ffs.empty()) {
            std::printf("[autoff] %-32s no samples — skipping\n", label);
            return;
        }
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t ff : ffs) {
            for (uint64_t off = 0xD0; off <= 0x180; off += 8) {
                uint64_t p = 0;
                if (!R(*ctx.reader, ff + off, p)) continue;
                if (!IsHeapNonModule(p, ctx.module_base, ctx.bounds.ImageSize)) continue;
                uint64_t vt = 0;
                if (!R(*ctx.reader, p, vt)) continue;
                if (!IsModulePtr(vt, ctx.module_base, ctx.bounds.ImageSize)) continue;
                counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        int slot_hits = counts.count(slot) ? counts[slot] : 0;
        ApplyOffsetSticky(label, slot, best, hits, slot_hits, (int)ffs.size(), min_hits);
    };

    uint64_t struct_vt = ctx.vtables.ScriptStructRVA ? (ctx.module_base + ctx.vtables.ScriptStructRVA) : 0;
    uint64_t class_vt  = ctx.vtables.ClassNativeRVA  ? (ctx.module_base + ctx.vtables.ClassNativeRVA)  : 0;
    uint64_t enum_vt   = ctx.vtables.EnumRVA         ? (ctx.module_base + ctx.vtables.EnumRVA)         : 0;

    probe_to_vtable(struct_vt, by_type["FStructProperty"],
        ArcDecrypt::Offsets::FStructProperty::Struct, "FStructProperty::Struct", 3);
    probe_to_vtable(class_vt,  by_type["FObjectProperty"],
        ArcDecrypt::Offsets::FObjectProperty::PropertyClass, "FObjectProperty::PropertyClass", 3);
    probe_to_vtable(class_vt,  by_type["FObjectPtrProperty"],
        ArcDecrypt::Offsets::FObjectProperty::PropertyClass, "FObjectPtrProperty::PropertyClass", 2);
    probe_to_vtable(class_vt,  by_type["FSoftObjectProperty"],
        ArcDecrypt::Offsets::FSoftObjectProperty::PropertyClass, "FSoftObjectProperty::PropertyClass", 2);
    probe_to_vtable(enum_vt,   by_type["FEnumProperty"],
        ArcDecrypt::Offsets::FEnumProperty::Enum, "FEnumProperty::Enum", 2);
    probe_to_ffield(by_type["FArrayProperty"],
        ArcDecrypt::Offsets::FArrayProperty::Inner, "FArrayProperty::Inner", 2);
    probe_to_ffield(by_type["FSetProperty"],
        ArcDecrypt::Offsets::FSetProperty::ElementProp, "FSetProperty::ElementProp", 2);

    // FMapProperty: two consecutive FField ptrs.
    if (auto& maps = by_type["FMapProperty"]; !maps.empty()) {
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t ff : maps) {
            for (uint64_t off = 0xD0; off <= 0x178; off += 8) {
                uint64_t k = 0, v = 0;
                if (!R(*ctx.reader, ff + off,     k)) continue;
                if (!R(*ctx.reader, ff + off + 8, v)) continue;
                if (!IsHeapNonModule(k, ctx.module_base, ctx.bounds.ImageSize)) continue;
                if (!IsHeapNonModule(v, ctx.module_base, ctx.bounds.ImageSize)) continue;
                uint64_t kvt = 0, vvt = 0;
                if (!R(*ctx.reader, k, kvt)) continue;
                if (!R(*ctx.reader, v, vvt)) continue;
                if (!IsModulePtr(kvt, ctx.module_base, ctx.bounds.ImageSize)) continue;
                if (!IsModulePtr(vvt, ctx.module_base, ctx.bounds.ImageSize)) continue;
                counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        if (best && hits >= 2) {
            ApplyOffset("FMapProperty::KeyProp", ArcDecrypt::Offsets::FMapProperty::KeyProp,
                        best, hits, (int)maps.size(), 2);
            ArcDecrypt::Offsets::FMapProperty::ValueProp = best + 8;
            std::printf("[autoff] FMapProperty::ValueProp set to +0x%llX (= KeyProp + 8)\n",
                (unsigned long long)ArcDecrypt::Offsets::FMapProperty::ValueProp);
        } else {
            std::printf("[autoff] FMapProperty::KeyProp           probe weak (best=0x%llX hits=%d)\n",
                (unsigned long long)best, hits);
        }
    }

    // FEnumProperty::UnderlyingProp — sits 8 bytes BEFORE Enum on UE5.
    if (!by_type["FEnumProperty"].empty() && ArcDecrypt::Offsets::FEnumProperty::Enum >= 8) {
        ArcDecrypt::Offsets::FEnumProperty::UnderlyingProp =
            ArcDecrypt::Offsets::FEnumProperty::Enum - 8;
        std::printf("[autoff] FEnumProperty::UnderlyingProp set to +0x%llX (= Enum - 8)\n",
            (unsigned long long)ArcDecrypt::Offsets::FEnumProperty::UnderlyingProp);
    }
}

// ─────────────────────────────────────────────────────────────────
// Probe 11: FProperty::ArrayDim + ElementSize
// ArrayDim almost always = 1; ElementSize is a small power of 2.
// Demands a high consensus floor because u32-equals-1 happens by accident a lot.
// ─────────────────────────────────────────────────────────────────
inline void ProbeFPropertyScalars(Context& ctx, const std::vector<uint64_t>& ustructs) {
    auto ffields = CollectFFields(ctx, ustructs, 400);
    if (ffields.empty()) return;

    // ArrayDim — almost all = 1
    {
        std::unordered_map<uint64_t, int> counts;
        for (uint64_t ff : ffields) {
            for (uint64_t off = 0xC0; off <= 0x100; off += 4) {
                uint32_t v = 0;
                if (!R(*ctx.reader, ff + off, v)) continue;
                if (v != 1) continue;
                counts[off]++;
            }
        }
        auto [best, hits] = PickMode(counts);
        // Need a strong majority — u32==1 is very common
        int min_hits = std::max(50, (int)ffields.size() / 2);
        ApplyOffset("FProperty::ArrayDim", ArcDecrypt::Offsets::FProperty::ArrayDim,
                    best, hits, (int)ffields.size(), min_hits);
    }

    // ElementSize — small, power-of-2 or struct-stride. Distinguished from
    // ArrayDim by DISPERSION: real ElementSize varies per property type
    // (1 byte for bool, 4 for int/float, 12 for FVector, etc.) while ArrayDim
    // is almost always 1. Without this gate, both probes pick the SAME offset
    // (e.g. +0xF0 — the ArrayDim slot — passes the value filter because 1
    // is in the accepted set).
    {
        const uint64_t arrayDimOff = ArcDecrypt::Offsets::FProperty::ArrayDim;
        std::unordered_map<uint64_t, std::unordered_map<uint32_t, int>> off_values;
        std::unordered_map<uint64_t, int> off_passes;
        for (uint64_t ff : ffields) {
            for (uint64_t off = 0xC0; off <= 0x100; off += 4) {
                if (off == arrayDimOff) continue;  // mutual exclusion
                uint32_t v = 0;
                if (!R(*ctx.reader, ff + off, v)) continue;
                if (v != 1 && v != 2 && v != 4 && v != 8 && v != 12 && v != 16 &&
                    v != 24 && v != 32 && v != 40 && v != 48 && v != 64 && v != 96 &&
                    v != 128 && v != 256) continue;
                off_values[off][v]++;
                off_passes[off]++;
            }
        }
        // Score = passes × distinct_values. ElementSize has multiple sizes
        // observed across property types. A field that's always 1 (or always
        // some other constant) gets distinct=1 and loses to a varied field.
        uint64_t best = 0; int best_score = 0; int best_passes = 0; int best_distinct = 0;
        for (auto& [off, vmap] : off_values) {
            int passes = off_passes[off];
            int distinct = (int)vmap.size();
            if (distinct < 2) continue;  // single-valued offsets are flag-like
            int score = passes * distinct;
            if (score > best_score) {
                best_score = score; best = off; best_passes = passes; best_distinct = distinct;
            }
        }
        if (best) {
            std::printf("[autoff] FProperty::ElementSize         candidate +0x%llX  distinct=%d passes=%d\n",
                (unsigned long long)best, best_distinct, best_passes);
        }
        int min_hits = std::max(50, (int)ffields.size() / 2);
        ApplyOffset("FProperty::ElementSize", ArcDecrypt::Offsets::FProperty::ElementSize,
                    best, best_passes, (int)ffields.size(), min_hits);
    }
}

// ─────────────────────────────────────────────────────────────────
// Driver — runs every probe in dependency order.
// Call AFTER auto_discovery.h Phase 0 (bounds), Phase 1 (vtables),
// Phase 2 (FField NamePrivate XOR), Phase 8 (FFieldClass globals).
// Object list = m_gobj.GetSeedObjects() (or any UObject pointer list).
// ─────────────────────────────────────────────────────────────────
inline void DiscoverAll(IMemoryReader& reader, uint64_t module_base,
                        const std::vector<uint64_t>& objects,
                        FName::FNameDecryptor& fname)
{
    std::printf("\n[autoff] ────────────────────────────────────────────────────────────\n");
    std::printf("[autoff] Live structure-offset probe (auto_offsets.h)\n");
    std::printf("[autoff] ────────────────────────────────────────────────────────────\n");

    Context ctx;
    ctx.reader      = &reader;
    ctx.module_base = module_base;
    ctx.bounds      = AutoDiscovery::g_DiscoveredBounds;
    ctx.vtables     = AutoDiscovery::g_DiscoveredVTables;
    ctx.fname       = &fname;

    if (!ctx.bounds.Valid) {
        std::printf("[autoff] module bounds invalid — aborting\n");
        return;
    }

    BuildFClassTypeMap(ctx);
    std::printf("[autoff] FFieldClass→type live map: %zu entries\n", ctx.fclass_to_type.size());

    auto u_classes = FilterByVtable(objects, reader,
        ctx.vtables.ClassNativeRVA ? module_base + ctx.vtables.ClassNativeRVA : 0, 100);
    auto u_structs = FilterByVtable(objects, reader,
        ctx.vtables.ScriptStructRVA ? module_base + ctx.vtables.ScriptStructRVA : 0, 100);
    auto u_enums = FilterByVtable(objects, reader,
        ctx.vtables.EnumRVA ? module_base + ctx.vtables.EnumRVA : 0, 50);
    auto u_funcs = FilterByVtable(objects, reader,
        ctx.vtables.FunctionRVA ? module_base + ctx.vtables.FunctionRVA : 0, 100);

    bool SharedVtable = !ctx.vtables.ClassNativeRVA && ctx.vtables.FunctionRVA;
    if (u_classes.empty()) {
        std::vector<uint64_t> ClassLikeRvas;
        if (ctx.vtables.ASClassRVA)  ClassLikeRvas.push_back(ctx.vtables.ASClassRVA);
        if (ctx.vtables.BPGCRVA)     ClassLikeRvas.push_back(ctx.vtables.BPGCRVA);
        if (ctx.vtables.WBPGCRVA)    ClassLikeRvas.push_back(ctx.vtables.WBPGCRVA);
        if (ctx.vtables.AnimBPGCRVA) ClassLikeRvas.push_back(ctx.vtables.AnimBPGCRVA);
        if (ctx.vtables.SMBPGCRVA)   ClassLikeRvas.push_back(ctx.vtables.SMBPGCRVA);
        if (SharedVtable)            ClassLikeRvas.push_back(ctx.vtables.FunctionRVA);
        for (uint64_t Rva : ClassLikeRvas) {
            auto Batch = FilterByVtable(objects, reader, module_base + Rva, 200);
            u_classes.insert(u_classes.end(), Batch.begin(), Batch.end());
        }
        std::printf("[autoff] UClass fallback: collected %zu candidates from %zu vtable families\n",
            u_classes.size(), ClassLikeRvas.size());
    }

    if (u_structs.empty() && ctx.vtables.ASStructRVA) {
        u_structs = FilterByVtable(objects, reader, module_base + ctx.vtables.ASStructRVA, 100);
        std::printf("[autoff] UStruct fallback via ASStruct: %zu candidates\n", u_structs.size());
    }

    std::vector<uint64_t> ustructs_all;
    ustructs_all.reserve(u_structs.size() + u_classes.size());
    ustructs_all.insert(ustructs_all.end(), u_structs.begin(), u_structs.end());
    ustructs_all.insert(ustructs_all.end(), u_classes.begin(), u_classes.end());
    if (SharedVtable && u_funcs.size() > 0) {
        ustructs_all.insert(ustructs_all.end(), u_funcs.begin(), u_funcs.end());
    }

    std::printf("[autoff] samples: classes=%zu structs=%zu enums=%zu funcs=%zu (combined=%zu)\n",
        u_classes.size(), u_structs.size(), u_enums.size(), u_funcs.size(), ustructs_all.size());

    if (ustructs_all.empty()) {
        std::printf("[autoff] no UStruct samples — every probe will skip\n");
        return;
    }

    ProbeChildPropertiesAndClassPrivate(ctx, ustructs_all);
    ProbeFFieldNext(ctx, ustructs_all);
    ProbeFFieldNamePrivate(ctx, ustructs_all);
    ProbeUStructSuperStruct(ctx, u_classes);
    ProbeUStructPropertiesSize(ctx, ustructs_all);
    ProbeUEnumNames(ctx, u_enums);
    ProbeUClassFuncMap(ctx, u_classes);
    ProbeUFunctionInternals(ctx, u_funcs);
    ProbeFPropertySubPointers(ctx, ustructs_all);
    ProbeFPropertyScalars(ctx, ustructs_all);

    std::printf("[autoff] ────────────────────────────────────────────────────────────\n\n");
}

}  // namespace AutoOffsets
