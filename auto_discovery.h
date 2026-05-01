#pragma once

// =============================================================================
// auto_discovery.h — Zydis-backed runtime discovery of every patch-specific
// value the dumper depends on. No hardcoded RVAs/offsets — only AOB signatures
// that anchor onto distinctive instruction shapes.
//
// Mirrors the architecture of /media/frost/Coding Stuf/Linux/ArcAutoDiscovery/
// (sig_scanner.h + insn_decoder.h + auto_config_*.h) adapted for FrostSDKDumper's
// IMemoryReader.
//
// Pipeline:
//   1. SigScanV2::Scanner caches the entire module (with per-page validity).
//   2. AOB signatures locate ANCHOR instructions (each one's `??` wildcards
//      cover the immediates / RIP-rel disps that change per patch).
//   3. Each phase Zydis-decodes the surrounding function body, walks the
//      decoded instruction stream looking for the pattern shape (PSHUFB →
//      ROL32 → XOR → ROL64, etc.), and extracts the live constants:
//         - imm32 / imm64 from MOV / XOR instructions
//         - PSHUFLW / PSHUFB / PSLLD / PSRLD imm8 amounts
//         - RIP-rel LEA / PSHUFB / PXOR target RVAs (.rdata SIMD tables)
//   4. Discovered values land in g_Discovered* globals; the existing decrypt
//      sites read them at runtime instead of compile-time constants.
//
// Phases (ordered):
//   Phase 0   — Module bounds         (PE header parse — runs FIRST)
//   Phase 0.5 — World actor probe     (GWorld → UWorld → ULevel → Actors;
//                                     auto-probes PersistentLevel & Actors offsets)
//   Phase 0.6 — FName sanity check    (resolve names on the actor sample;
//                                     fail-loud bootstrap before trusting FName)
//   Phase 1   — Engine vtable map     (name-cluster after FName + GObjects up)
//   Phase 2   — FField NamePrivate    (live data math — no fn parse needed)
//   Phase 3   — FProperty Offset XOR  (sig-scan + Zydis-validate)
//   Phase 4   — UObject slot decrypt  (sig-scan + Zydis instruction stream)
//   Phase 5   — FNamePool resolver    (sig-scan + Zydis instruction stream)
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "sig_scanner_v2.h"
#include "insn_decoder.h"
#include "func_analyzer.h"

namespace AutoDiscovery {

// ─────────────────────────────────────────────────────────────────────────────
// Phase 0: Module bounds (PE header parse)
// ─────────────────────────────────────────────────────────────────────────────
struct ModuleBounds {
    uint64_t TextRva     = 0;
    uint64_t TextSize    = 0;
    uint64_t RDataRva    = 0;
    uint64_t RDataSize   = 0;
    uint64_t DataRva     = 0;
    uint64_t DataSize    = 0;
    uint64_t ImageSize   = 0;
    bool     Valid       = false;

    uint64_t TextEnd()  const { return TextRva  + TextSize;  }
    uint64_t RDataEnd() const { return RDataRva + RDataSize; }
    uint64_t DataEnd()  const { return DataRva  + DataSize;  }

    bool InText(uint64_t rva)  const { return rva >= TextRva  && rva < TextEnd();  }
    bool InRData(uint64_t rva) const { return rva >= RDataRva && rva < RDataEnd(); }
    bool InData(uint64_t rva)  const { return rva >= DataRva  && rva < DataEnd();  }
};

inline ModuleBounds DiscoverModuleBoundsFromScanner(const SigScanV2::Scanner& scanner) {
    ModuleBounds out;
    const auto* tx = scanner.FindSection(".text");
    const auto* rd = scanner.FindSection(".rdata");
    const auto* dt = scanner.FindSection(".data");
    if (!tx || !rd || !dt) return out;
    out.TextRva   = tx->VA;   out.TextSize  = tx->VSize;
    out.RDataRva  = rd->VA;   out.RDataSize = rd->VSize;
    out.DataRva   = dt->VA;   out.DataSize  = dt->VSize;
    out.ImageSize = scanner.ModuleSize();
    out.Valid     = true;
    std::printf("[autodisc] PE bounds: .text=0x%llX..0x%llX  .rdata=0x%llX..0x%llX  .data=0x%llX..0x%llX  size=0x%llX\n",
        (unsigned long long)out.TextRva,  (unsigned long long)out.TextEnd(),
        (unsigned long long)out.RDataRva, (unsigned long long)out.RDataEnd(),
        (unsigned long long)out.DataRva,  (unsigned long long)out.DataEnd(),
        (unsigned long long)out.ImageSize);
    return out;
}

// Legacy entry for callers that don't have a Scanner yet — does its own
// minimal PE parse. Used for the very first sig-scan before we boot the
// full SigScanV2.
inline ModuleBounds DiscoverModuleBounds(IMemoryReader& reader, uint64_t module_base) {
    ModuleBounds out;
    uint8_t hdr[0x1000] = {};
    if (!reader.Read(module_base, hdr, sizeof(hdr))) return out;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return out;
    uint32_t e_lfanew = *(uint32_t*)(hdr + 0x3C);
    if (e_lfanew >= sizeof(hdr) - 0x100) return out;
    if (*(uint32_t*)(hdr + e_lfanew) != 0x00004550) return out;

    uint16_t numSections   = *(uint16_t*)(hdr + e_lfanew + 6);
    uint16_t optHeaderSize = *(uint16_t*)(hdr + e_lfanew + 0x14);
    uint32_t optHdrOff     = e_lfanew + 0x18;
    uint32_t sectStart     = optHdrOff + optHeaderSize;
    out.ImageSize          = *(uint32_t*)(hdr + optHdrOff + 0x38);

    for (uint16_t i = 0; i < numSections && sectStart + (i+1)*0x28 <= sizeof(hdr); ++i) {
        const uint8_t* s = hdr + sectStart + i * 0x28;
        char name[9] = {};
        std::memcpy(name, s, 8);
        uint32_t virtSize = *(uint32_t*)(s + 8);
        uint32_t virtAddr = *(uint32_t*)(s + 12);
        if (std::strncmp(name, ".text", 5) == 0) {
            out.TextRva = virtAddr; out.TextSize = virtSize;
        } else if (std::strncmp(name, ".rdata", 6) == 0) {
            out.RDataRva = virtAddr; out.RDataSize = virtSize;
        } else if (std::strncmp(name, ".data", 5) == 0 && out.DataRva == 0) {
            out.DataRva = virtAddr; out.DataSize = virtSize;
        }
    }
    if (!out.TextRva || !out.RDataRva || !out.DataRva || !out.ImageSize) return out;
    out.Valid = true;
    std::printf("[autodisc] PE bounds: .text=0x%llX..0x%llX  .rdata=0x%llX..0x%llX  .data=0x%llX..0x%llX  size=0x%llX\n",
        (unsigned long long)out.TextRva,  (unsigned long long)out.TextEnd(),
        (unsigned long long)out.RDataRva, (unsigned long long)out.RDataEnd(),
        (unsigned long long)out.DataRva,  (unsigned long long)out.DataEnd(),
        (unsigned long long)out.ImageSize);
    return out;
}

using NameResolver = std::function<std::string(uint64_t obj_ptr)>;

// ─────────────────────────────────────────────────────────────────────────────
// Phase 0.5: GWorld + actor probe (full discovery, ported from ArcAutoDiscovery)
//
// REWRITTEN 2026-05-01 after the dumper's legacy `applyTrusted("GWorld", ...)`
// auto-fixed RVA_GWORLD from the working `0xDFDB4D8` to a wrong `0xE07CFD8`
// (close enough to bypass the ±0x1000000 tolerance gate). Same family of bug
// as Phase 3/4/6: single sigscan match overwrote a known-good const without
// validating the result actually leads to a UWorld.
//
// Strategy (mirrors /media/frost/Coding Stuf/Linux/ArcAutoDiscovery/
//          src/auto_config_gworld.h):
//
//   1. Sig-scan for the canonical UWorld access shape:
//          48 8B 05 ?? ?? ?? ??     mov rax, [rip+gworld]
//          48 8B 00                 mov rax, [rax]                ; double-deref
//      (UE5 always uses this shape for GWorld access. Many false-positive
//      patterns the dumper had before just used `mov rax, [rip+disp]`
//      without the second deref.)
//
//   2. For each candidate's RIP-rel target (resolved via disp32):
//        a. Skip if not in .data
//        b. Read ptr1 = *(module + targetRVA); skip if not heap
//        c. Read ptr2 = *ptr1 (double-deref); skip if not heap
//        d. Validate ptr2 as a UWorld via PersistentLevel→Actors chain
//           (probe UWorld+0x30..+0x400 for PL slot, ULevel+0x80..+0x300 for
//            Actors TArray, every actor entry must have a heap vtable in .text)
//        e. Cross-check: find Levels TArray on UWorld where Levels[0] == PL
//           (rejects coincidentally-shaped pointers that aren't real UWorlds)
//
//   3. Pick the candidate with the most actors. If zero candidates validate
//      (game in menu / no world loaded), Valid stays false and the dumper
//      keeps its compile-time RVA_GWORLD.
//
// Replaces six hardcoded / sigscan-trusted values:
//   - ArcDecrypt::RVA_GWORLD                       (auto-discovered)
//   - GWorld double-deref convention               (auto-detected)
//   - UWorld::PersistentLevel offset               (probed)
//   - ULevel::Actors data offset                   (probed)
//   - ULevel::Actors count offset                  (probed)
//   - Actor sample for Phase 0.6 FName sanity check
// ─────────────────────────────────────────────────────────────────────────────
struct WorldDiscovery {
    uint64_t GWorldRva               = 0;     // RVA of the UWorld* slot in .data
    uint64_t GWorldAbs               = 0;     // resolved UWorld* (post double-deref)
    uint64_t PersistentLevelAbs      = 0;     // ULevel*
    uint32_t PersistentLevelOffset   = 0;     // UWorld → PersistentLevel
    uint32_t ActorsDataOffset        = 0;     // ULevel → Actors.Data
    uint32_t ActorsCountOffset       = 0;     // ULevel → Actors.Num
    uint32_t ActorsCount             = 0;
    bool     DoubleDeref             = true;  // UE5: always double-deref on this build
    std::vector<uint64_t> Actors;             // capped sample (~256)
    bool     Valid                   = false;
};

// ── Helper: validate that `level` is a ULevel — find its Actors TArray. ──
// Returns the TArray's actor count (0 if no plausible Actors slot found).
inline int ValidateLevelActors(IMemoryReader& reader, uint64_t module_base,
                               uint64_t level, const ModuleBounds& bounds,
                               uint32_t& outActorsDataOff, uint32_t& outActorsCountOff)
{
    auto isHeap = [](uint64_t p) {
        return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
    };
    auto isInModule = [&](uint64_t p) {
        return p >= module_base && p < module_base + bounds.ImageSize;
    };
    auto hasTextVtable = [&](uint64_t obj) -> bool {
        if (!isHeap(obj)) return false;
        uint64_t vt = 0;
        if (!reader.Read(obj, &vt, 8)) return false;
        if (vt < module_base + bounds.TextRva) return false;
        if (vt >= module_base + bounds.TextEnd()) return false;
        return true;
    };

    int bestCount = 0;
    uint32_t bestData = 0, bestCnt = 0;
    for (uint32_t off = 0x80; off <= 0x300; off += 8) {
        uint64_t aData = 0;
        int32_t  aNum  = 0;
        int32_t  aMax  = 0;
        if (!reader.Read(level + off,     &aData, 8)) continue;
        if (!reader.Read(level + off + 8, &aNum,  4)) continue;
        if (!reader.Read(level + off + 12,&aMax,  4)) continue;
        if (!isHeap(aData))                continue;
        if (aNum < 3 || aNum > 200000)     continue;
        if (aMax < aNum || aMax > 500000)  continue;

        // Verify the first N actors are heap UObjects (vtable in .text,
        // pointer NOT in module range — actors are heap-allocated).
        int probe_n = aNum < 10 ? aNum : 10;
        int validActors = 0;
        for (int i = 0; i < probe_n; ++i) {
            uint64_t actor = 0;
            if (!reader.Read(aData + 8ULL * i, &actor, 8)) continue;
            if (!isHeap(actor) || isInModule(actor))       continue;
            if (!hasTextVtable(actor))                     continue;
            ++validActors;
        }
        if (validActors < 3) continue;  // demand ≥3 well-formed actors

        if (aNum > bestCount) {
            bestCount = aNum;
            bestData  = off;
            bestCnt   = off + 8;
        }
    }
    if (bestCount > 0) {
        outActorsDataOff  = bestData;
        outActorsCountOff = bestCnt;
    }
    return bestCount;
}

// ── Helper: validate UWorld candidate by finding (PL, Actors) + Levels[0]==PL.
inline bool ValidateUWorldCandidate(
    IMemoryReader& reader, uint64_t module_base, uint64_t uworld,
    const ModuleBounds& bounds,
    uint32_t& outPLOff, uint32_t& outALOff, uint32_t& outACOff, int& outActors)
{
    auto isHeap = [](uint64_t p) {
        return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
    };
    auto hasTextVtable = [&](uint64_t obj) -> bool {
        if (!isHeap(obj)) return false;
        uint64_t vt = 0;
        if (!reader.Read(obj, &vt, 8)) return false;
        if (vt < module_base + bounds.TextRva)  return false;
        if (vt >= module_base + bounds.TextEnd()) return false;
        return true;
    };

    // UWorld must have a .text vtable.
    if (!hasTextVtable(uworld)) return false;

    int bestActors = 0;
    uint32_t bestPL = 0, bestAL = 0, bestAC = 0;

    // Probe UWorld+0x30..+0x400 for PersistentLevel slot.
    for (uint32_t plOff = 0x30; plOff <= 0x400; plOff += 8) {
        uint64_t pl = 0;
        if (!reader.Read(uworld + plOff, &pl, 8)) continue;
        if (!hasTextVtable(pl)) continue;

        uint32_t alOff = 0, acOff = 0;
        int count = ValidateLevelActors(reader, module_base, pl, bounds, alOff, acOff);
        if (count <= bestActors) continue;

        // Cross-check: find a Levels TArray on UWorld where Levels[0] == pl.
        // Real UWorlds satisfy `UWorld::Levels[0] == PersistentLevel`. This
        // is the strongest disambiguator — eliminates pointer chains that
        // happen to pass the basic shape checks but aren't real worlds.
        bool hasLevelsTArray = false;
        for (uint32_t lvlOff = plOff + 8; lvlOff <= 0x500; lvlOff += 8) {
            uint64_t levelsPtr = 0;
            int32_t  levelsCount = 0;
            int32_t  levelsMax   = 0;
            if (!reader.Read(uworld + lvlOff,     &levelsPtr,   8)) continue;
            if (!reader.Read(uworld + lvlOff + 8, &levelsCount, 4)) continue;
            if (!reader.Read(uworld + lvlOff + 12,&levelsMax,   4)) continue;
            if (!isHeap(levelsPtr))                       continue;
            if (levelsCount < 1 || levelsCount > 1000)    continue;
            if (levelsMax < levelsCount || levelsMax > 10000) continue;
            uint64_t firstLevel = 0;
            if (!reader.Read(levelsPtr, &firstLevel, 8)) continue;
            if (firstLevel == pl) { hasLevelsTArray = true; break; }
        }
        if (!hasLevelsTArray) continue;

        bestActors = count;
        bestPL = plOff;
        bestAL = alOff;
        bestAC = acOff;
    }

    if (bestActors > 0) {
        outPLOff  = bestPL;
        outALOff  = bestAL;
        outACOff  = bestAC;
        outActors = bestActors;
        return true;
    }
    return false;
}

inline WorldDiscovery DiscoverGWorld(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader,
    uint64_t module_base, const ModuleBounds& bounds,
    size_t max_actor_sample = 256)
{
    WorldDiscovery out;
    if (!bounds.Valid) return out;

    struct Candidate {
        uint64_t rva;       // GWorld RVA in .data
        uint64_t uworld;    // resolved UWorld* (post double-deref)
        uint32_t plOff, alOff, acOff;
        int      actors;
    };
    std::vector<Candidate> validated;
    std::unordered_set<uint64_t> testedRVAs;

    auto isHeap = [](uint64_t p) {
        return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
    };

    auto tryCandidate = [&](uint64_t rva) {
        if (!testedRVAs.insert(rva).second) return;
        uint64_t ptr1 = 0;
        if (!reader.Read(module_base + rva, &ptr1, 8)) return;
        if (!isHeap(ptr1)) return;
        uint64_t ptr2 = 0;
        if (!reader.Read(ptr1, &ptr2, 8)) return;
        if (!isHeap(ptr2)) return;  // game in menu — UWorld* not yet resolved

        Candidate c{};
        c.rva    = rva;
        c.uworld = ptr2;
        if (ValidateUWorldCandidate(reader, module_base, ptr2, bounds,
                                    c.plOff, c.alOff, c.acOff, c.actors))
        {
            validated.push_back(c);
        }
    };

    // ── Strategy 1: sig-scan for `mov rax, [rip+disp]; mov rax, [rax]` ──
    // (canonical UE5 GWorld access — the second `mov` is the giveaway).
    auto movHits = scanner.ScanSection("48 8B 05 ?? ?? ?? ?? 48 8B 00", ".text");
    std::printf("[autodisc-gworld] MOV-deref-deref sig hits: %zu\n", movHits.size());
    for (uint64_t hitRva : movHits) {
        const uint8_t* p = scanner.GetLocalPtr(hitRva);
        if (!p) continue;
        int32_t disp = 0;
        std::memcpy(&disp, p + 3, 4);
        uint64_t targetRva = hitRva + 7 + (int64_t)disp;
        if (!scanner.IsDataRVA(targetRva)) continue;
        tryCandidate(targetRva);
    }

    // ── Strategy 2: also try other-register MOV forms (RCX/RDX/RBX/RSI/RDI/R8/R9). ──
    // Some UE5 builds compile `GWorld->Foo()` with RCX/RDX as the first deref.
    // Only run if Strategy 1 found nothing (avoid wasting time when we have
    // a winner).
    if (validated.empty()) {
        const char* otherFormPats[] = {
            "48 8B 0D ?? ?? ?? ?? 48 8B 09",  // RCX
            "48 8B 15 ?? ?? ?? ?? 48 8B 12",  // RDX
            "48 8B 1D ?? ?? ?? ?? 48 8B 1B",  // RBX
            "48 8B 35 ?? ?? ?? ?? 48 8B 36",  // RSI
            "48 8B 3D ?? ?? ?? ?? 48 8B 3F",  // RDI
            "4C 8B 05 ?? ?? ?? ?? 4D 8B 00",  // R8
            "4C 8B 0D ?? ?? ?? ?? 4D 8B 09",  // R9
        };
        for (const char* pat : otherFormPats) {
            auto hits = scanner.ScanSection(pat, ".text");
            for (uint64_t hitRva : hits) {
                const uint8_t* p = scanner.GetLocalPtr(hitRva);
                if (!p) continue;
                int32_t disp = 0;
                std::memcpy(&disp, p + 3, 4);
                uint64_t targetRva = hitRva + 7 + (int64_t)disp;
                if (!scanner.IsDataRVA(targetRva)) continue;
                tryCandidate(targetRva);
            }
            if (!validated.empty()) break;
        }
    }

    // ── Strategy 3: broad MOV reg, [rip+disp32] scan — drops the adjacent ──
    // ── deref requirement. Catches builds where the compiler interleaves   ──
    // ── extra instructions between the two derefs (e.g. arg setup, prefetch). ──
    // Each candidate is validated by full UWorld walk, so even tens of
    // thousands of false-positive MOV sites get filtered to the real GWorld.
    // Per-pattern hit cap of 20000 keeps runtime bounded; the .data filter
    // and testedRVAs dedupe shrink the validation funnel further.
    if (validated.empty()) {
        std::printf("[autodisc-gworld] strategy 1+2 found nothing; running broad MOV [rip+disp32] scan...\n");
        const char* broadPats[] = {
            "48 8B 05 ?? ?? ?? ??",  // RAX
            "48 8B 0D ?? ?? ?? ??",  // RCX
            "48 8B 15 ?? ?? ?? ??",  // RDX
            "48 8B 1D ?? ?? ?? ??",  // RBX
            "48 8B 2D ?? ?? ?? ??",  // RBP
            "48 8B 35 ?? ?? ?? ??",  // RSI
            "48 8B 3D ?? ?? ?? ??",  // RDI
            "4C 8B 05 ?? ?? ?? ??",  // R8
            "4C 8B 0D ?? ?? ?? ??",  // R9
            "4C 8B 15 ?? ?? ?? ??",  // R10
            "4C 8B 1D ?? ?? ?? ??",  // R11
            "4C 8B 25 ?? ?? ?? ??",  // R12
            "4C 8B 2D ?? ?? ?? ??",  // R13
            "4C 8B 35 ?? ?? ?? ??",  // R14
            "4C 8B 3D ?? ?? ?? ??",  // R15
        };
        constexpr int kMaxPerPattern = 20000;
        size_t totalScanned = 0;
        for (const char* pat : broadPats) {
            auto hits = scanner.ScanSection(pat, ".text");
            int checked = 0;
            for (uint64_t hitRva : hits) {
                if (checked++ >= kMaxPerPattern) break;
                const uint8_t* p = scanner.GetLocalPtr(hitRva);
                if (!p) continue;
                int32_t disp = 0;
                std::memcpy(&disp, p + 3, 4);
                uint64_t targetRva = hitRva + 7 + (int64_t)disp;
                if (!scanner.IsDataRVA(targetRva)) continue;
                if (testedRVAs.count(targetRva)) continue;
                ++totalScanned;
                tryCandidate(targetRva);
            }
            // Don't early-exit per pattern — we want the BEST candidate
            // (highest actor count) across all register forms.
        }
        std::printf("[autodisc-gworld] broad scan: %zu unique RVAs probed, %zu validated\n",
            totalScanned, validated.size());
    }

    if (validated.empty()) {
        std::printf("[autodisc-gworld] no validated GWorld candidates "
                    "(game may be in menu / no world loaded) — keeping compile-time constant\n");
        return out;
    }

    // Pick the candidate with the most actors (real PersistentLevel typically
    // has 100s; main-menu-only GWorlds tend to have <10).
    std::sort(validated.begin(), validated.end(),
        [](const Candidate& a, const Candidate& b) { return a.actors > b.actors; });
    const auto& best = validated[0];

    out.GWorldRva             = best.rva;
    out.GWorldAbs             = best.uworld;
    out.PersistentLevelOffset = best.plOff;
    out.ActorsDataOffset      = best.alOff;
    out.ActorsCountOffset     = best.acOff;
    out.ActorsCount           = (uint32_t)best.actors;
    out.DoubleDeref           = true;

    // Resolve PersistentLevel for the actor sample.
    uint64_t pl = 0;
    reader.Read(best.uworld + best.plOff, &pl, 8);
    out.PersistentLevelAbs = pl;

    // Pull actor sample.
    uint64_t aData = 0;
    if (pl) reader.Read(pl + best.alOff, &aData, 8);
    if (aData) {
        size_t take = (size_t)best.actors;
        if (take > max_actor_sample) take = max_actor_sample;
        out.Actors.reserve(take);
        for (size_t i = 0; i < take; ++i) {
            uint64_t a = 0;
            if (!reader.Read(aData + 8ULL * i, &a, 8)) continue;
            if (!isHeap(a)) continue;
            out.Actors.push_back(a);
        }
    }
    out.Valid = !out.Actors.empty();

    std::printf("[autodisc-gworld] GWorld RVA=0x%llX (UWorld=0x%llX, %zu validated candidates) — "
                "PL@+0x%X Actors@+0x%X/+0x%X actors=%d sampled=%zu\n",
        (unsigned long long)out.GWorldRva, (unsigned long long)out.GWorldAbs,
        validated.size(), out.PersistentLevelOffset, out.ActorsDataOffset,
        out.ActorsCountOffset, best.actors, out.Actors.size());

    if (validated.size() > 1) {
        std::printf("[autodisc-gworld] other validated candidates:\n");
        for (size_t i = 1; i < validated.size() && i < 5; ++i) {
            std::printf("[autodisc-gworld]   rva=0x%llX  actors=%d\n",
                (unsigned long long)validated[i].rva, validated[i].actors);
        }
    }
    return out;
}

// Legacy-compatible wrapper (kept for callers that only have a Reader+RVA).
// Just dereferences the supplied gworld_rva and walks; doesn't sig-scan or
// pick among candidates. Prefer DiscoverGWorld() above for new code.
inline WorldDiscovery DiscoverWorldActors(
    IMemoryReader& reader, uint64_t module_base, uint64_t gworld_rva,
    const ModuleBounds& bounds, size_t max_actor_sample = 256)
{
    WorldDiscovery out;
    if (!gworld_rva || !bounds.Valid) return out;

    auto isHeap = [](uint64_t p) {
        return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL;
    };

    uint64_t ptr1 = 0;
    if (!reader.Read(module_base + gworld_rva, &ptr1, 8) || !isHeap(ptr1)) {
        std::printf("[autodisc-world] GWorld stage1 read failed (rva=0x%llX)\n",
            (unsigned long long)gworld_rva);
        return out;
    }
    uint64_t ptr2 = 0;
    if (!reader.Read(ptr1, &ptr2, 8) || !isHeap(ptr2)) {
        std::printf("[autodisc-world] GWorld 0x%llX double-deref failed\n",
            (unsigned long long)ptr1);
        return out;
    }

    uint32_t plOff = 0, alOff = 0, acOff = 0;
    int actors = 0;
    if (!ValidateUWorldCandidate(reader, module_base, ptr2, bounds,
                                 plOff, alOff, acOff, actors)) {
        std::printf("[autodisc-world] GWorld 0x%llX did not validate as UWorld\n",
            (unsigned long long)ptr2);
        return out;
    }

    out.GWorldRva             = gworld_rva;
    out.GWorldAbs             = ptr2;
    out.PersistentLevelOffset = plOff;
    out.ActorsDataOffset      = alOff;
    out.ActorsCountOffset     = acOff;
    out.ActorsCount           = (uint32_t)actors;
    out.DoubleDeref           = true;

    uint64_t pl = 0;
    reader.Read(ptr2 + plOff, &pl, 8);
    out.PersistentLevelAbs = pl;
    uint64_t aData = 0;
    if (pl) reader.Read(pl + alOff, &aData, 8);
    if (aData) {
        size_t take = (size_t)actors;
        if (take > max_actor_sample) take = max_actor_sample;
        out.Actors.reserve(take);
        for (size_t i = 0; i < take; ++i) {
            uint64_t a = 0;
            if (!reader.Read(aData + 8ULL * i, &a, 8)) continue;
            if (!isHeap(a)) continue;
            out.Actors.push_back(a);
        }
    }
    out.Valid = !out.Actors.empty();
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 0.6: FName sanity check on the actor sample
//
// Resolves names for each actor in the sample and classifies the result:
//   - NonEmpty: resolver returned a string
//   - LooksLikeName: ASCII-printable, length 2..96, no control chars / weird
//                    bytes — heuristic for "this looks like a UE class name"
//
// Result.Valid means ≥ 50% of the sample produced LooksLikeName output.
// On failure, diagnostic counts are printed so the user can see whether the
// FName pipeline is broken end-to-end (0 non-empty) or returning garbage
// (high non-empty but low looks-like-name).
// ─────────────────────────────────────────────────────────────────────────────
struct FNameSanityResult {
    int Sampled       = 0;
    int NonEmpty      = 0;
    int LooksLikeName = 0;
    std::vector<std::string> ExampleGood;   // first 8 plausible names
    std::vector<std::string> ExampleBad;    // first 4 garbage names
    bool Valid = false;
};

inline FNameSanityResult ValidateFNameOnActors(
    const std::vector<uint64_t>& actors,
    NameResolver name_of, size_t sample_size = 32)
{
    FNameSanityResult out;
    if (actors.empty() || !name_of) {
        std::printf("[autodisc-fnchk] no actors / no resolver\n");
        return out;
    }
    auto looks_like_name = [](const std::string& s) -> bool {
        if (s.size() < 2 || s.size() > 96) return false;
        for (unsigned char c : s) {
            if (c < 0x20 || c >= 0x7F) return false;        // ASCII printable only
        }
        if (!((s[0] >= 'A' && s[0] <= 'Z') ||
              (s[0] >= 'a' && s[0] <= 'z') ||
              s[0] == '_' || s[0] == '/')) return false;
        return true;
    };

    size_t step = (actors.size() + sample_size - 1) / sample_size;
    if (step == 0) step = 1;

    for (size_t i = 0; i < actors.size() && (size_t)out.Sampled < sample_size; i += step) {
        uint64_t a = actors[i];
        ++out.Sampled;
        std::string n = name_of(a);
        if (n.empty()) continue;
        ++out.NonEmpty;
        if (looks_like_name(n)) {
            ++out.LooksLikeName;
            if (out.ExampleGood.size() < 8) out.ExampleGood.push_back(n);
        } else {
            if (out.ExampleBad.size() < 4) out.ExampleBad.push_back(n);
        }
    }

    out.Valid = out.Sampled > 0 &&
                out.LooksLikeName * 2 >= out.Sampled;
    std::printf("[autodisc-fnchk] sampled %d actors: non_empty=%d  looks_like_name=%d  → %s\n",
        out.Sampled, out.NonEmpty, out.LooksLikeName,
        out.Valid ? "PASS" : "FAIL");
    if (!out.ExampleGood.empty()) {
        std::printf("[autodisc-fnchk]   good examples:");
        for (const auto& s : out.ExampleGood) std::printf(" %s", s.c_str());
        std::printf("\n");
    }
    if (!out.ExampleBad.empty()) {
        std::printf("[autodisc-fnchk]   garbage examples:");
        for (const auto& s : out.ExampleBad) std::printf(" \"%s\"", s.c_str());
        std::printf("\n");
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1: Engine type-pool vtable map (name-based clustering)
// ─────────────────────────────────────────────────────────────────────────────
struct VTableMap {
    uint64_t ScriptStructRVA = 0;
    uint64_t ClassNativeRVA  = 0;
    uint64_t FunctionRVA     = 0;
    uint64_t EnumRVA         = 0;
    uint64_t PackageRVA      = 0;
    uint64_t BPGCRVA         = 0;
    uint64_t WBPGCRVA        = 0;
    uint64_t SMBPGCRVA       = 0;
    uint64_t AnimBPGCRVA     = 0;
    uint64_t ASClassRVA      = 0;
    uint64_t ASStructRVA     = 0;
    std::vector<uint64_t> ASFunctionRVAs;

    uint32_t ScriptStructStride = 0x130;
    uint32_t ClassNativeStride  = 0x300;
    uint32_t FunctionStride     = 0x200;
    uint32_t EnumStride         = 0x130;
    uint32_t BPGCStride         = 0x490;
    uint32_t WBPGCStride        = 0x5D0;
    uint32_t SMBPGCStride       = 0x490;
    uint32_t AnimBPGCStride     = 0x7F0;
    uint32_t ASClassStride      = 0x340;
    uint32_t ASStructStride     = 0x150;
    uint32_t ASFunctionStride   = 0x200;

    bool Valid() const {
        return ScriptStructRVA && ClassNativeRVA && FunctionRVA && EnumRVA;
    }
};

namespace VTableOracles {

    inline const char* const ScriptStruct[] = {
        "Vector", "Rotator", "Transform", "Quat", "Color",
        "LinearColor", "Vector2D", "Vector4", "IntPoint", "IntVector",
        "Plane", "Box", "Box2D", "BoxSphereBounds", "DateTime", "Timespan",
        "Guid", "FrameNumber", "FrameRate", "FrameTime", "Matrix",
        "PostProcessSettings", "RigidBodyState", "HitResult", "OverlapResult",
        "Margin", "RandomStream", "InterpCurvePointFloat",
    };
    inline const char* const ClassNative[] = {
        "Actor", "Pawn", "Object", "ActorComponent", "SceneComponent",
        "World", "Level", "GameInstance", "GameMode", "GameState",
        "PlayerController", "PlayerState", "Character", "CharacterMovementComponent",
        "StaticMeshComponent", "SkeletalMeshComponent", "PrimitiveComponent",
        "Texture2D", "Material", "MaterialInstance", "StaticMesh", "SkeletalMesh",
        "Engine", "GameEngine", "Package", "UserDefinedStruct", "UserDefinedEnum",
        "Function", "Class", "ScriptStruct", "Enum", "Struct",
    };
    inline const char* const Function[] = {
        "ReceiveTick", "ReceiveBeginPlay", "ReceiveEndPlay",
        "ReceiveActorBeginOverlap", "ReceiveActorEndOverlap", "ReceiveHit",
        "GetActorLocation", "GetActorRotation", "K2_DestroyActor",
        "K2_AddActorWorldOffset", "K2_OnReset", "OnConstruction",
        "BlueprintModifyEditorNotifyOptions", "UserConstructionScript",
        "GetController",
    };
    inline const char* const Enum[] = {
        "ETeleportType", "EAttachmentRule", "EBlendMode", "EObjectTypeQuery",
        "ESlateVisibility", "EAxis", "EDrawDebugTrace", "EDetailMode",
        "ETraceTypeQuery", "ECollisionChannel", "ECollisionResponse",
        "EPixelFormat", "ERHIFeatureLevel", "ETickingGroup",
    };

    inline bool LooksLikePackage(const std::string& s) {
        if (s.empty()) return false;
        if (s[0] == '/') return true;
        static const char* const pkgNames[] = {
            "Engine", "CoreUObject", "EngineMessages", "Slate", "UMG",
            "AssetRegistry", "DeveloperSettings", "GameplayTags",
            "InputCore", "EnhancedInput", "AnimGraphRuntime",
        };
        for (const char* n : pkgNames) if (s == n) return true;
        return false;
    }
    inline bool LooksLikeBPGC(const std::string& s) {
        if (s.size() < 3) return false;
        return s.compare(s.size() - 2, 2, "_C") == 0;
    }
    inline bool LooksLikeWBPGC(const std::string& s) {
        return LooksLikeBPGC(s) && s.find("WBP_") != std::string::npos;
    }
    inline bool LooksLikeSMBPGC(const std::string& s) {
        return LooksLikeBPGC(s) && s.find("SK_") != std::string::npos;
    }
    inline bool LooksLikeAnimBPGC(const std::string& s) {
        if (!LooksLikeBPGC(s)) return false;
        return s.find("ABP_")    != std::string::npos ||
               s.find("AnimBP")  != std::string::npos ||
               s.find("AnimBlueprint") != std::string::npos;
    }

    template <size_t N>
    inline bool InList(const std::string& s, const char* const (&list)[N]) {
        for (size_t i = 0; i < N; ++i) if (s == list[i]) return true;
        return false;
    }
}  // namespace VTableOracles

inline VTableMap DiscoverEngineVTables(const std::vector<uint64_t>& objects,
                                       NameResolver name_of,
                                       IMemoryReader& reader,
                                       uint64_t module_base,
                                       const ModuleBounds& bounds)
{
    VTableMap out;
    if (objects.empty()) {
        std::printf("[autodisc-vt] no objects to cluster\n");
        return out;
    }

    struct Cluster {
        std::vector<std::string> names;
        size_t total_count = 0;
    };
    std::unordered_map<uint64_t, Cluster> clusters;
    clusters.reserve(64);

    constexpr size_t kMaxSample = 8000;
    size_t step = (objects.size() + kMaxSample - 1) / kMaxSample;
    if (step == 0) step = 1;

    size_t resolved = 0, sampled = 0;
    for (size_t i = 0; i < objects.size(); i += step) {
        uint64_t obj = objects[i];
        if (!obj) continue;
        ++sampled;

        uint64_t vt = 0;
        if (!reader.Read(obj, &vt, 8)) continue;
        if (vt < module_base || vt >= module_base + bounds.ImageSize) continue;

        Cluster& c = clusters[vt];
        c.total_count++;
        if (c.names.size() < 50) {
            std::string n = name_of(obj);
            if (!n.empty()) {
                c.names.push_back(std::move(n));
                ++resolved;
            }
        }
    }
    std::printf("[autodisc-vt] sampled %zu objects, resolved %zu names, %zu unique vtables\n",
        sampled, resolved, clusters.size());
    if (clusters.empty()) return out;

    enum KindIdx {
        KSCRIPT_STRUCT = 0, KCLASS_NATIVE = 1, KFUNCTION = 2, KENUM = 3,
        KPACKAGE = 4, KBPGC = 5, KWBPGC = 6, KSMBPGC = 7, KANIM_BPGC = 8,
        KASCLASS = 9, KASSTRUCT = 10, KASFUNCTION = 11, KIND_COUNT = 12,
    };

    auto score_name = [](const std::string& n) -> std::array<int, KIND_COUNT> {
        std::array<int, KIND_COUNT> sc{};
        if (n.empty()) return sc;
        if (VTableOracles::LooksLikeWBPGC(n))      { sc[KWBPGC] += 5; return sc; }
        if (VTableOracles::LooksLikeSMBPGC(n))     { sc[KSMBPGC] += 5; return sc; }
        if (VTableOracles::LooksLikeAnimBPGC(n))   { sc[KANIM_BPGC] += 5; return sc; }
        if (VTableOracles::LooksLikePackage(n))    { sc[KPACKAGE] += 5; return sc; }
        if (VTableOracles::LooksLikeBPGC(n))       { sc[KBPGC] += 3; }
        if (VTableOracles::InList(n, VTableOracles::ScriptStruct)) sc[KSCRIPT_STRUCT] += 5;
        if (VTableOracles::InList(n, VTableOracles::ClassNative))  sc[KCLASS_NATIVE]  += 5;
        if (VTableOracles::InList(n, VTableOracles::Function))     sc[KFUNCTION]      += 5;
        if (VTableOracles::InList(n, VTableOracles::Enum))         sc[KENUM]          += 5;
        if (n.size() >= 2 && n[0] == 'E' && n[1] >= 'A' && n[1] <= 'Z') sc[KENUM] += 1;
        return sc;
    };

    struct ClusterScore {
        uint64_t vtable = 0;
        size_t   count  = 0;
        std::array<int, KIND_COUNT> scores{};
    };
    std::vector<ClusterScore> scored;
    scored.reserve(clusters.size());
    for (auto& [vt, c] : clusters) {
        ClusterScore cs; cs.vtable = vt; cs.count = c.total_count;
        for (const auto& n : c.names) {
            auto sc = score_name(n);
            for (int k = 0; k < KIND_COUNT; ++k) cs.scores[k] += sc[k];
        }
        scored.push_back(std::move(cs));
    }

    auto pick_best_for_kind = [&](int kind) -> uint64_t {
        uint64_t best_vt = 0; int best_score = 0; size_t best_count = 0;
        for (const auto& cs : scored) {
            int s = cs.scores[kind];
            if (s == 0) continue;
            if (s > best_score || (s == best_score && cs.count > best_count)) {
                best_score = s; best_count = cs.count; best_vt = cs.vtable;
            }
        }
        return best_vt;
    };
    auto rva_of = [&](uint64_t vt) -> uint64_t { return vt ? (vt - module_base) : 0; };

    // Min-cluster gate: a "winning" cluster with only a handful of objects
    // is almost always a misidentification (e.g. cluster_count=2 picked over
    // the real 600-object Class cluster because of name-oracle scoring noise).
    // The compile-time fallback in gobjects.h::InitPatch20260428 produces
    // far better results than a wrong auto-discovered RVA, so we'd rather
    // emit NOT FOUND and let the fallback win than ship a bogus value.
    //
    // Per-kind floors are loose because cluster_count depends on (a) sample
    // size, (b) what's loaded in the live game state. Engine-core kinds
    // (Class/ScriptStruct/Enum/Function/Package) should always have ≥30
    // instances loaded; rare kinds like AnimBPGC may have only 2-5.
    auto pick_gated = [&](int kind, size_t min_count) -> uint64_t {
        uint64_t vt = pick_best_for_kind(kind);
        if (!vt) return 0;
        // Inline lookup of cluster count.
        size_t got = 0;
        for (const auto& cs : scored)
            if (cs.vtable == vt) { got = cs.count; break; }
        if (got < min_count) {
            std::printf("[autodisc-vt]   kind=%d best vtable rva=0x%llX cluster_count=%zu < min %zu — dropping\n",
                kind, (unsigned long long)(vt - module_base), got, min_count);
            return 0;  // caller writes RVA=0 → "NOT FOUND" → compile-time fallback
        }
        return vt;
    };

    // Engine-core types: lots of instances always loaded. Demand ≥20.
    out.ScriptStructRVA = rva_of(pick_gated(KSCRIPT_STRUCT, 20));
    out.ClassNativeRVA  = rva_of(pick_gated(KCLASS_NATIVE,  20));
    out.FunctionRVA     = rva_of(pick_gated(KFUNCTION,      20));
    out.EnumRVA         = rva_of(pick_gated(KENUM,          10));
    out.PackageRVA      = rva_of(pick_gated(KPACKAGE,       10));
    // Game/blueprint types: count varies wildly by content. Looser floors.
    out.BPGCRVA         = rva_of(pick_gated(KBPGC,          10));
    out.WBPGCRVA        = rva_of(pick_gated(KWBPGC,         5));
    out.SMBPGCRVA       = rva_of(pick_gated(KSMBPGC,        2));
    out.AnimBPGCRVA     = rva_of(pick_gated(KANIM_BPGC,     2));

    uint64_t as_lo = bounds.RDataRva + (bounds.RDataSize * 3 / 4);
    uint64_t as_hi = bounds.RDataEnd();
    for (const auto& cs : scored) {
        uint64_t rva = rva_of(cs.vtable);
        if (rva < as_lo || rva >= as_hi) continue;
        if (rva == out.ClassNativeRVA || rva == out.FunctionRVA ||
            rva == out.ScriptStructRVA || rva == out.EnumRVA ||
            rva == out.BPGCRVA) continue;
        int klass_hits  = cs.scores[KCLASS_NATIVE] + cs.scores[KBPGC];
        int struct_hits = cs.scores[KSCRIPT_STRUCT];
        int func_hits   = cs.scores[KFUNCTION];
        if (klass_hits >= struct_hits && klass_hits >= func_hits && cs.count > 100) {
            if (!out.ASClassRVA) out.ASClassRVA = rva;
        } else if (struct_hits > func_hits && cs.count > 50) {
            if (!out.ASStructRVA) out.ASStructRVA = rva;
        } else if (func_hits > 0 || (cs.count > 20 && cs.count < 5000)) {
            out.ASFunctionRVAs.push_back(rva);
        }
    }
    std::sort(out.ASFunctionRVAs.begin(), out.ASFunctionRVAs.end());

    auto count_for = [&](uint64_t rva) -> size_t {
        for (const auto& cs : scored) if (rva_of(cs.vtable) == rva) return cs.count;
        return 0;
    };
    auto fmt = [&](const char* name, uint64_t rva, uint32_t stride) {
        if (rva)
            std::printf("[autodisc-vt]   %-13s rva=0x%llX  stride=0x%X  cluster_count=%zu\n",
                name, (unsigned long long)rva, stride, count_for(rva));
        else
            std::printf("[autodisc-vt]   %-13s NOT FOUND\n", name);
    };
    std::printf("[autodisc-vt] Discovered vtables:\n");
    fmt("ScriptStruct", out.ScriptStructRVA, out.ScriptStructStride);
    fmt("Class",        out.ClassNativeRVA,  out.ClassNativeStride);
    fmt("Function",     out.FunctionRVA,     out.FunctionStride);
    fmt("Enum",         out.EnumRVA,         out.EnumStride);
    fmt("Package",      out.PackageRVA,      0);
    fmt("BPGC",         out.BPGCRVA,         out.BPGCStride);
    fmt("WBPGC",        out.WBPGCRVA,        out.WBPGCStride);
    fmt("SMBPGC",       out.SMBPGCRVA,       out.SMBPGCStride);
    fmt("AnimBPGC",     out.AnimBPGCRVA,     out.AnimBPGCStride);
    fmt("ASClass",      out.ASClassRVA,      out.ASClassStride);
    fmt("ASStruct",     out.ASStructRVA,     out.ASStructStride);
    for (uint64_t rva : out.ASFunctionRVAs)
        std::printf("[autodisc-vt]   ASFunction    rva=0x%llX  stride=0x%X  cluster_count=%zu\n",
            (unsigned long long)rva, out.ASFunctionStride, count_for(rva));
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: FField NamePrivate decrypt (live data math, no fn parse)
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldNameDecryptParams {
    uint64_t XorConst    = 0;
    int      Rol32Amount = 13;
    int      Rol64Amount = 7;
    bool     Valid       = false;
};

inline FFieldNameDecryptParams DiscoverFFieldNameDecrypt(
    IMemoryReader& reader, uint64_t module_base,
    const std::vector<uint64_t>& sample_uscriptstructs,
    uint64_t ustruct_childprops_offset = 0x100,
    uint64_t ffield_nameprivate_offset = 0x70)
{
    FFieldNameDecryptParams out;
    if (sample_uscriptstructs.empty()) {
        std::printf("[autodisc-ffield] no UScriptStructs to probe\n");
        return out;
    }

    auto rol32 = [](uint32_t v, int n) -> uint32_t {
        n &= 31;
        return (v << n) | (v >> ((32 - n) & 31));
    };

    int probed = 0;
    for (uint64_t uss : sample_uscriptstructs) {
        if (probed >= 8) break;
        ++probed;

        uint64_t ff_head = 0;
        if (!reader.Read(uss + ustruct_childprops_offset, &ff_head, 8)) continue;
        if (ff_head < module_base + 0x100000ULL || ff_head >= 0x800000000000ULL) continue;
        if (ff_head >= module_base && ff_head < module_base + 0x10000000ULL) continue;

        uint8_t slot[16] = {};
        if (!reader.Read(ff_head + ffield_nameprivate_offset, slot, 16)) continue;

        uint32_t hi_lo32 = 0, hi_hi32 = 0;
        std::memcpy(&hi_lo32, slot + 8,  4);
        std::memcpy(&hi_hi32, slot + 12, 4);
        uint32_t xor_lo32 = rol32(hi_lo32, 13);
        uint32_t xor_hi32 = rol32(hi_hi32, 13);
        uint64_t xor_const = (static_cast<uint64_t>(xor_hi32) << 32) | xor_lo32;
        if (xor_const == 0 || xor_const == ~0ULL) continue;

        uint32_t lo_lo32 = 0, lo_hi32 = 0;
        std::memcpy(&lo_lo32, slot + 0, 4);
        std::memcpy(&lo_hi32, slot + 4, 4);
        uint64_t pipe_lo64 = (static_cast<uint64_t>(rol32(lo_hi32, 13)) << 32) | rol32(lo_lo32, 13);
        uint64_t pipe_xored = pipe_lo64 ^ xor_const;
        uint64_t result = (pipe_xored << 7) | (pipe_xored >> (64 - 7));
        uint32_t ci = static_cast<uint32_t>(result);
        uint32_t num = static_cast<uint32_t>(result >> 32);
        if (ci < 2 || ci > 0x2000000u) continue;
        if (num > 0x10000u) continue;

        out.XorConst    = xor_const;
        out.Rol32Amount = 13;
        out.Rol64Amount = 7;
        out.Valid       = true;
        std::printf("[autodisc-ffield] NamePrivate XOR const = 0x%016llX (CI=%u Num=%u from FField 0x%llX)\n",
            (unsigned long long)xor_const, ci, num, (unsigned long long)ff_head);
        return out;
    }

    std::printf("[autodisc-ffield] no usable FField chain found in %d UScriptStructs\n", probed);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: FProperty Offset_Internal XOR key (Zydis-validated sig-scan)
//
// Anchor: `xor reg, imm32; bswap reg` — verified stable across 5+ patches
// (20260402 → CL-1177146). Hit count varies 9-15 on recent patches, 176 on
// 20260402 (older patches inlined the decoder per accessor). The Zydis
// filter narrows to actual property offset readers.
//
// AOB: 35 ?? ?? ?? ?? 0F C8   (xor eax, imm32; bswap eax)
//
// Validation strategy (HARDENED 2026-05-01 after Phase 3 silently auto-fixed
// to a wrong key on CL-1177146 from a single false-positive site at +0x188):
//   1. Decode the xor + bswap pair.
//   2. Walk backwards 16 bytes via Zydis to find a `mov r32, [reg+disp32]` or
//      `movzx r32, [reg+disp32]` load — that's the FProperty offset field
//      access. The disp32 is the field offset (FProperty::Offset_Internal).
//   3. RANGE GATE: drop sites whose load offset is outside [0x80..0x140].
//      FField/FProperty fields all live in this band; offsets like 0x188,
//      0x200, etc. belong to other classes' field readers using the same
//      xor+bswap idiom and would silently corrupt downstream decryption.
//   4. CONSENSUS GATE: require ≥ 2 sites with the SAME (offset, xor_key) pair.
//      A single validated hit is too weak — false positives sneak through.
//      Multiple FProperty subclasses (Bool/Float/Object/...) all read offsets
//      via the same encrypted-field idiom, so the real key shows up in
//      multiple accessors compiled inline at different call sites.
//   5. If consensus fails, leave the compile-time constant alone (Valid=false)
//      so the SDK dump uses the patch-baseline value rather than garbage.
// ─────────────────────────────────────────────────────────────────────────────
struct FPropertyDecryptParams {
    uint64_t OffsetReaderRva = 0;  // RVA of the first xor+bswap site validated
    uint32_t OffsetInternal  = 0;  // FProperty::Offset_Internal field offset
    uint32_t XorKey          = 0;  // bswap32(stored ^ XorKey) = real offset
    int      ValidatedHits   = 0;  // how many sites passed full validation
    bool     Valid           = false;
};

inline FPropertyDecryptParams DiscoverFPropertyOffsetXor(
    const SigScanV2::Scanner& scanner)
{
    FPropertyDecryptParams out;

    auto hits = scanner.ScanSection("35 ?? ?? ?? ?? 0F C8", ".text");
    std::printf("[autodisc-fprop] xor+bswap sig hits: %zu\n", hits.size());

    InsnDecoder dec;
    // Histogram of (offset, xor_key) pairs across all validated hits — the
    // mode is the property offset reader's parameters.
    std::unordered_map<uint64_t, int> pairCounts;  // (offset<<32)|xor_key
    uint64_t firstValidatedRva = 0;

    for (uint64_t rva : hits) {
        // Decode the xor+bswap pair (7 bytes).
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        auto xorBswap = dec.Decode(p, 7, rva);
        if (xorBswap.size() < 2) continue;
        if (xorBswap[0].type != INSN_XOR_EAX) continue;
        if (xorBswap[1].type != INSN_BSWAP)   continue;
        uint32_t xor_key = xorBswap[0].imm32;

        // Walk backwards up to 16 bytes via brute-force Zydis decode at every
        // possible boundary, looking for a memory load whose disp is the
        // FProperty offset field. The instruction lengths we expect:
        //   8B 81 disp32       (mov eax, [rcx+disp32])         = 6 bytes
        //   0F B7 87 disp32    (movzx eax, [rdi+disp32])       = 7 bytes
        //   0F B7 47 disp8     (movzx eax, [rdi+disp8])        = 4 bytes
        //   8B 41 disp8        (mov eax, [rcx+disp8])          = 3 bytes
        //   ...etc
        uint32_t offset_field = 0;
        bool foundLoad = false;
        for (int back = 16; back >= 3; --back) {
            uint64_t loadRva = rva - back;
            if (loadRva < scanner.ModuleSize() == false) continue;
            const uint8_t* lp = scanner.GetLocalPtr(loadRva);
            if (!lp) continue;
            auto loadInsn = dec.Decode(lp, back, loadRva);
            if (loadInsn.empty()) continue;
            // Must perfectly tile back to the xor.
            uint64_t totalLen = 0;
            for (const auto& ins : loadInsn) totalLen += ins.length;
            if (totalLen != (uint64_t)back) continue;
            // Last instruction must be a memory load with a disp.
            const auto& last = loadInsn.back();
            // Acceptable load shapes: MOV reg, mem ; MOVZX reg, m16
            // (Zydis maps both to INSN_MOV_REG since we don't track movzx
            // separately — but the disp is recorded the same way).
            if (last.type != INSN_MOV_REG) continue;
            if (last.hasRipRel) continue;  // we want [reg+disp], not RIP-rel
            // Extract disp by parsing the ModR/M ourselves — Zydis stores it
            // in disp32 but only when hasRipRel is true. For [reg+disp] we
            // need to fish it out of the bytes.
            uint32_t disp = 0;
            if (last.length == 7 && lp[totalLen - last.length] == 0x0F &&
                lp[totalLen - last.length + 1] == 0xB7)
            {
                // movzx r32, m16: 0F B7 modrm disp32
                std::memcpy(&disp, lp + totalLen - 4, 4);
            } else if (last.length == 6 &&
                lp[totalLen - last.length] == 0x8B)
            {
                // mov r32, m32: 8B modrm disp32
                std::memcpy(&disp, lp + totalLen - 4, 4);
            } else if (last.length == 4 && lp[totalLen - last.length] == 0x0F &&
                lp[totalLen - last.length + 1] == 0xB7)
            {
                // movzx r32, m16 disp8
                disp = lp[totalLen - 1];
            } else if (last.length == 3 && lp[totalLen - last.length] == 0x8B) {
                // mov r32, m32 disp8
                disp = lp[totalLen - 1];
            } else {
                continue;  // unhandled load shape
            }
            if (disp >= 0x1000) continue;
            offset_field = disp;
            foundLoad = true;
            break;
        }
        if (!foundLoad) continue;

        // Range gate: FProperty/FField fields cluster in 0x80..0x140 across
        // all UE5 patches we've tested. Anything outside is some other
        // class's encrypted-field getter that just happens to share the
        // xor+bswap shape — would corrupt downstream decryption silently.
        if (offset_field < 0x80 || offset_field > 0x140) continue;

        // Sanity: reject obviously-degenerate XOR keys.
        if (xor_key == 0u || xor_key == 0xFFFFFFFFu) continue;

        uint64_t key = ((uint64_t)offset_field << 32) | xor_key;
        if (pairCounts.empty()) firstValidatedRva = rva;
        ++pairCounts[key];
    }

    if (pairCounts.empty()) {
        std::printf("[autodisc-fprop] no validated load+xor+bswap sites in plausible range — keeping compile-time constant\n");
        return out;
    }

    // Pick the mode.
    uint64_t bestKey = 0;
    int      bestCount = 0;
    for (const auto& [k, c] : pairCounts) {
        if (c > bestCount) { bestCount = c; bestKey = k; }
    }

    // Consensus gate: a single validated hit could be a coincidental shape
    // somewhere unrelated. Require at least 2 accessors agreeing on
    // (offset, xor_key) before we'll overwrite the compile-time constant.
    constexpr int kMinConsensus = 2;
    if (bestCount < kMinConsensus) {
        std::printf("[autodisc-fprop] insufficient consensus (best pair seen %d× — need ≥%d) — "
                    "keeping compile-time constant\n", bestCount, kMinConsensus);
        // Diagnostic: dump every (offset, xor) pair we saw, so the user can
        // see whether the validator is just being unlucky on this build.
        for (const auto& [k, c] : pairCounts) {
            uint32_t off = (uint32_t)(k >> 32);
            uint32_t xk  = (uint32_t)(k & 0xFFFFFFFFu);
            std::printf("[autodisc-fprop]   offset=+0x%X  xor=0x%08X  count=%d\n",
                off, xk, c);
        }
        return out;  // Valid stays false — main.cpp won't overwrite the constant
    }

    out.OffsetReaderRva = firstValidatedRva;
    out.OffsetInternal  = (uint32_t)(bestKey >> 32);
    out.XorKey          = (uint32_t)(bestKey & 0xFFFFFFFFu);
    out.ValidatedHits   = bestCount;
    out.Valid           = true;
    std::printf("[autodisc-fprop] validated %d sites; Offset_Internal=+0x%X  XorKey=0x%08X (first @ rva=0x%llX)\n",
        bestCount, out.OffsetInternal, out.XorKey,
        (unsigned long long)out.OffsetReaderRva);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: UObject 4-slot decrypt SIMD constants
//
// Anchor: any UObject getter that decrypts a slot. The CL-1177146 pipeline is
// `loadl_epi64(rdata_shuf_mask) → PSHUFB(slot, mask) → lo64 → XOR(scalar)
//  → ROL64(32)`. The slot index is hash-picked.
//
// AOB (slot decrypt loop body):
//   F2 0F 70 C8 ??         pshuflw xmm1, xmm0, ??     (NOT used on CL-1177146)
//   66 0F 38 00 ?? ?? ?? ?? ??   pshufb xmm0, [rip+disp32]
//   66 0F EF ?? ?? ?? ?? ??     pxor   xmm0, [rip+disp32]
//
// The cleaner anchor is a hash-pick: every slot decrypt site loads a known
// PSHUFB mask from .rdata (8 bytes, replicated to 16). We sig-scan for the
// PSHUFB instruction taking RIP-rel, then walk forward to find the PXOR.
// Both targets land in .rdata; reading them gives us SHUF_MASK and XOR_CONST.
//
// To narrow down to the slot decrypt (vs. some other PSHUFB+PXOR), we
// require a `pslld imm + psrld imm` ROL32 pair OR a `rol r64, imm` near the
// PSHUFB — the slot pipeline always finishes with ROL64(32).
// ─────────────────────────────────────────────────────────────────────────────
struct UObjSlotDecryptParams {
    uint64_t ShufMaskRVA = 0;     // 8-byte PSHUFB mask in .rdata
    uint64_t XorConstRVA = 0;     // 16-byte XOR const in .rdata
    uint64_t XorScalar   = 0;     // lo64 of the XOR const (read live)
    int      Rol64Amount = 32;    // post-XOR ROL64
    uint8_t  ShufMaskBytes[8] = {};  // copy of the 8-byte mask, for fast access
    bool     Valid       = false;
};

inline UObjSlotDecryptParams DiscoverUObjSlotDecrypt(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader)
{
    UObjSlotDecryptParams out;
    InsnDecoder dec;

    // HARDENED 2026-05-01 after Phase 4 silently auto-fixed XorScalar from
    // the working 0x5EA772D07F910744 to garbage 0x0C701474B4D138D7 on the
    // FIRST of 27354 PSHUFB hits — bricked the entire FName pipeline and
    // produced 0 named objects out of 77989. Same bug as Phase 3: single
    // hit declares victory with no consensus check.
    //
    // PSHUFB+PXOR is a generic SIMD shape used widely throughout the binary
    // (memcpy SIMD, hash functions, encryption, audio mixing, ...). The
    // UObject slot decrypt is one of MANY uses. To find it specifically:
    //
    //   1. Aggregate every PSHUFB site with a follow-up PXOR (both rip-rel
    //      to .rdata). Don't return on first match.
    //   2. Histogram by (ShufMaskRVA, XorConstRVA) pair — the slot decrypt
    //      is INLINED at every UObject getter call site (GetClass / GetOuter
    //      / GetName / etc.), so the SAME .rdata pair shows up 5-50× while
    //      false positives appear once each.
    //   3. Pick the most-referenced pair, require ≥ 3 sites for consensus.
    //   4. If no consensus, leave compile-time XOR_SCALAR alone.
    auto pshufbHits = scanner.ScanSection("66 0F 38 00 ?? ?? ?? ?? ??", ".text");
    std::printf("[autodisc-uobj] PSHUFB rip-rel hits: %zu\n", pshufbHits.size());

    struct PairInfo {
        int      count    = 0;
        uint64_t firstRva = 0;     // first .text site referencing this pair
        int      rol64Amt = 32;    // most-recent ROL64 amount seen
    };
    std::unordered_map<uint64_t, PairInfo> pairs;  // (shuf<<32)|xor → info

    for (uint64_t rva : pshufbHits) {
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        auto insns = dec.Decode(p, 96, rva);
        if (insns.empty() || insns[0].type != INSN_PSHUFB || !insns[0].hasRipRel) continue;

        // Subsequent PXOR with RIP-rel within 12 insns.
        int pxorIdx = -1;
        for (int i = 1; i < (int)insns.size() && i < 12; ++i) {
            if ((insns[i].type == INSN_PXOR || insns[i].type == INSN_XORPS) &&
                insns[i].hasRipRel) { pxorIdx = i; break; }
        }
        if (pxorIdx < 0) continue;

        uint64_t shufRva = insns[0].ResolveRipRVA();
        uint64_t xorRva  = insns[pxorIdx].ResolveRipRVA();
        if (!scanner.IsRDataRVA(shufRva)) continue;
        if (!scanner.IsRDataRVA(xorRva))  continue;

        // Optional: ROL r64, imm8 within 16 insns of PXOR (gold signal).
        int rolIdx = -1;
        for (int i = pxorIdx; i < (int)insns.size() && i < pxorIdx + 16; ++i) {
            if (insns[i].type == INSN_ROL && insns[i].hasImm8 && insns[i].hasREX_W) {
                rolIdx = i; break;
            }
        }

        uint64_t key = (shufRva << 32) | (xorRva & 0xFFFFFFFFu);
        auto& info  = pairs[key];
        if (info.count == 0) info.firstRva = rva;
        ++info.count;
        if (rolIdx >= 0) info.rol64Amt = insns[rolIdx].imm8;
    }

    if (pairs.empty()) {
        std::printf("[autodisc-uobj] no PSHUFB+PXOR pairs in .rdata — keeping compile-time constant\n");
        return out;
    }

    // Pick the most-referenced pair.
    uint64_t bestKey = 0;
    PairInfo bestInfo;
    for (const auto& [k, info] : pairs) {
        if (info.count > bestInfo.count) { bestInfo = info; bestKey = k; }
    }

    // Consensus gate: slot decrypt is inlined many times → ≥ 3 references.
    constexpr int kMinConsensus = 3;
    if (bestInfo.count < kMinConsensus) {
        std::printf("[autodisc-uobj] insufficient consensus (best pair seen %d× — need ≥%d) — "
                    "keeping compile-time constant\n", bestInfo.count, kMinConsensus);
        // Diagnostic: top 5 pairs by count.
        std::vector<std::pair<uint64_t, PairInfo>> sorted(pairs.begin(), pairs.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](auto& a, auto& b) { return a.second.count > b.second.count; });
        size_t shown = 0;
        for (const auto& [k, info] : sorted) {
            if (shown++ >= 5) break;
            uint64_t shuf = k >> 32;
            uint64_t xorR = k & 0xFFFFFFFFu;
            std::printf("[autodisc-uobj]   shuf=0x%llX xor=0x%llX count=%d\n",
                (unsigned long long)shuf, (unsigned long long)xorR, info.count);
        }
        return out;  // Valid stays false
    }

    uint64_t shufRva = bestKey >> 32;
    uint64_t xorRva  = bestKey & 0xFFFFFFFFu;

    const uint8_t* xorBytes = scanner.GetLocalPtr(xorRva);
    if (!xorBytes) {
        std::printf("[autodisc-uobj] cannot read xor const @ 0x%llX — keeping compile-time constant\n",
            (unsigned long long)xorRva);
        return out;
    }
    uint64_t xor_lo64 = 0;
    std::memcpy(&xor_lo64, xorBytes, 8);
    if (xor_lo64 == 0) {
        std::printf("[autodisc-uobj] xor const is zero — bogus, keeping compile-time constant\n");
        return out;
    }

    const uint8_t* shufBytes = scanner.GetLocalPtr(shufRva);
    if (!shufBytes) {
        std::printf("[autodisc-uobj] cannot read shuf mask @ 0x%llX — keeping compile-time constant\n",
            (unsigned long long)shufRva);
        return out;
    }

    out.ShufMaskRVA = shufRva;
    out.XorConstRVA = xorRva;
    out.XorScalar   = xor_lo64;
    out.Rol64Amount = bestInfo.rol64Amt;
    std::memcpy(out.ShufMaskBytes, shufBytes, 8);
    out.Valid       = true;
    std::printf("[autodisc-uobj] slot decrypt: %d sites agree on shuf=0x%llX xor=0x%llX (lo64=0x%016llX)  rol64=%d (first @ 0x%llX)\n",
        bestInfo.count, (unsigned long long)shufRva, (unsigned long long)xorRva,
        (unsigned long long)xor_lo64, out.Rol64Amount,
        (unsigned long long)bestInfo.firstRva);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 5: FNamePool resolver constants (extract via Zydis instruction walk)
//
// We already locate the outer FName function via find_fname_func.h. Once we
// have the function start RVA, walk its body and pull out:
//   - Every MOV r64, imm64        → candidates for ENTRY_HANDLE_XOR / FNV64_OFF
//   - Every PSHUFLW imm           → CI / slot transform shuffles
//   - Every ROL r64, imm          → FNV64 ROL amounts (51, 38, etc.)
//   - Every PSHUFB / PXOR rip-rel → SIMD constant table RVAs in .rdata
//
// This phase doesn't HARDCODE the constants — it just records them all and
// lets the caller pick by structural position (e.g. "the first imm64 after
// the BSWAP is ENTRY_HANDLE_XOR").
// ─────────────────────────────────────────────────────────────────────────────
struct FNameResolverConsts {
    uint64_t FunctionStartRva = 0;
    std::vector<uint64_t> AllImm64;       // every MOV r64, imm64 in fn body
    std::vector<uint8_t>  AllPshuflwImm;  // every PSHUFLW imm
    std::vector<uint8_t>  AllRolImm;      // every ROL r64, imm
    std::vector<uint64_t> AllRDataLeas;   // every LEA / PSHUFB / PXOR rip-rel in .rdata
    bool     Valid = false;
};

inline FNameResolverConsts DiscoverFNameResolverConsts(
    const SigScanV2::Scanner& scanner, uint64_t fname_func_rva)
{
    FNameResolverConsts out;
    if (!fname_func_rva) return out;
    out.FunctionStartRva = fname_func_rva;

    auto insns = FuncAnalyze::DecodeFunctionAt(scanner, fname_func_rva, 0x2000);
    if (insns.empty()) {
        std::printf("[autodisc-fname] couldn't decode fn @ 0x%llX\n",
            (unsigned long long)fname_func_rva);
        return out;
    }
    std::printf("[autodisc-fname] decoded %zu insns at fn 0x%llX\n",
        insns.size(), (unsigned long long)fname_func_rva);

    for (const auto& ins : insns) {
        if (ins.type == INSN_MOV_REG && ins.imm64 != 0 && ins.length == 10) {
            out.AllImm64.push_back(ins.imm64);
        }
        if (ins.type == INSN_PSHUFLW && ins.hasImm8) {
            out.AllPshuflwImm.push_back(ins.imm8);
        }
        if (ins.type == INSN_ROL && ins.hasImm8 && ins.hasREX_W) {
            out.AllRolImm.push_back(ins.imm8);
        }
        if (ins.hasRipRel &&
            (ins.type == INSN_PSHUFB || ins.type == INSN_PXOR ||
             ins.type == INSN_XORPS  || ins.type == INSN_LEA  ||
             ins.type == INSN_MOVDQA || ins.type == INSN_MOVQ ||
             ins.type == INSN_LOADL_EPI64))
        {
            uint64_t t = ins.ResolveRipRVA();
            if (scanner.IsRDataRVA(t)) out.AllRDataLeas.push_back(t);
        }
    }
    std::sort(out.AllRDataLeas.begin(), out.AllRDataLeas.end());
    out.AllRDataLeas.erase(std::unique(out.AllRDataLeas.begin(), out.AllRDataLeas.end()),
                           out.AllRDataLeas.end());

    std::printf("[autodisc-fname] extracted: %zu imm64, %zu pshuflw_imm, %zu rol_imm, %zu rdata_leas\n",
        out.AllImm64.size(), out.AllPshuflwImm.size(),
        out.AllRolImm.size(), out.AllRDataLeas.size());

    if (!out.AllImm64.empty()) {
        std::printf("[autodisc-fname]   imm64 candidates:\n");
        size_t shown = 0;
        for (uint64_t v : out.AllImm64) {
            if (shown++ >= 8) break;
            std::printf("[autodisc-fname]     0x%016llX\n", (unsigned long long)v);
        }
    }
    if (!out.AllRDataLeas.empty()) {
        std::printf("[autodisc-fname]   .rdata table candidates:\n");
        size_t shown = 0;
        for (uint64_t v : out.AllRDataLeas) {
            if (shown++ >= 8) break;
            std::printf("[autodisc-fname]     0x%llX\n", (unsigned long long)v);
        }
    }

    out.Valid = !out.AllImm64.empty() || !out.AllRDataLeas.empty();
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 6: GNamePool RVA via FName-fn body walk
//
// The legacy AOB anchor (`48 8D 1D ?? ?? ?? ?? 48 8D 3C 1E 48 81 C7 C0 00 00 00`)
// only fires on Apr-14 — verified DEAD on 5 of 6 cross-patch tests. The
// FNamePool global isn't referenced from the FName outer function directly;
// it sits 2 calls deep:
//   FName_Resolve_Outer (entry — anchor #1) →
//   FName_Resolve_Stage2_XOR              →
//   FName_Resolve_Core_BlockFNV  (← `lea rcx, unk_FNamePool` here, 2 refs)
//
// HARDENED 2026-05-01 after Phase 6 silently auto-fixed RVA_GNAMES_BASE to
// the keystream-table base (RVA_FNAME_KEY_TABLE - 0xF8 = 0xDAF87F4) on
// CL-1177146 — that's referenced 13× from the entry decoder loop, vs 4×
// for the actual FNamePool. Wrong base → wrong chunk → all 77K names empty.
//
// Strategy (post-hardening):
//   1. Decode the outer fn body via Zydis.
//   2. Collect all `lea r64, [rip+disp32]` targets that land in .data.
//   3. Follow the FIRST load-bearing `call rel32` (skipping compiler
//      intrinsics like __security_check_cookie / __alloca_probe — heuristic:
//      target's body must be ≥ 0x40 bytes).
//   4. Recurse up to `max_depth` levels.
//   5. EXCLUDE any candidate within ±0x200 of known non-FNamePool globals
//      (the keystream table — passed in as `exclude_zones`). The keystream
//      out-references FNamePool in the FName fn body, so without exclusion
//      the mode pick lands on it.
//   6. (Optional) STRUCTURAL VALIDATE: live-read at the candidate; FNamePool
//      starts with a chunks-array pointer / count area. We don't bind to
//      a specific layout here (it's patch-dependent), so the ±0x200 zone
//      exclusion is the primary gate.
//   7. Return the MODE of remaining .data targets — GNamePool is the most-
//      referenced .data global once the keystream is removed.
// ─────────────────────────────────────────────────────────────────────────────
struct GNamesDiscovery {
    uint64_t GNamesRva = 0;
    int      RefCount  = 0;   // how many LEAs across the walk pointed at it
    bool     Valid     = false;
};

// One known-non-FNamePool zone: a centerpoint RVA + half-width radius.
// Phase 6 rejects any candidate whose RVA falls within [center - radius,
// center + radius]. Used to mask out the keystream / SIMD constant tables /
// any other heavily-referenced .data global that lives near a known anchor.
struct GNamesExcludeZone {
    uint64_t CenterRva = 0;
    uint64_t Radius    = 0x200;
};

inline GNamesDiscovery DiscoverGNamesViaFNameWalk(
    const SigScanV2::Scanner& scanner, uint64_t fname_fn_rva,
    const std::vector<GNamesExcludeZone>& exclude_zones = {},
    int max_depth = 4)
{
    GNamesDiscovery out;
    if (!fname_fn_rva || !scanner.IsTextRVA(fname_fn_rva)) {
        std::printf("[autodisc-gnames] no FName fn rva supplied\n");
        return out;
    }

    InsnDecoder dec;
    std::unordered_map<uint64_t, int> targetCounts;
    std::unordered_set<uint64_t>      visited;

    // Heuristic: a load-bearing callee has a body of at least 0x40 bytes
    // before its first CC sled. Compiler intrinsics (alloca_probe,
    // __security_check_cookie) are ~6-30 bytes total, fail this check.
    auto IsLoadBearing = [&](uint64_t fn_rva) -> bool {
        if (!scanner.IsTextRVA(fn_rva)) return false;
        const uint8_t* p = scanner.GetLocalPtr(fn_rva);
        if (!p) return false;
        // Scan forward for first CC; reject if found within 0x40 bytes.
        for (int i = 0; i < 0x40; ++i) {
            if (p[i] == 0xCC) return false;
        }
        return true;
    };

    std::function<void(uint64_t, int)> walk = [&](uint64_t rva, int depth) {
        if (depth >= max_depth) return;
        if (!visited.insert(rva).second) return;

        auto insns = FuncAnalyze::DecodeFunctionAt(scanner, rva, 0x1000);
        if (insns.empty()) return;

        // Collect all .data LEA targets in this function body.
        for (const auto& ins : insns) {
            if (ins.type == INSN_LEA && ins.hasRipRel) {
                uint64_t t = ins.ResolveRipRVA();
                if (scanner.IsDataRVA(t)) targetCounts[t]++;
            }
        }

        // Follow the first load-bearing CALL rel32 in body order.
        // INSN_CALL_RIP covers ALL CALL forms (rel32 / [mem] / reg); the
        // hasImm32 && !hasRipRel filter narrows to the direct rel32 form.
        // Zydis stores the rel32 as raw bits in `imm32`; cast to int32_t
        // for sign-extension when computing the absolute target.
        for (const auto& ins : insns) {
            if (ins.type != INSN_CALL_RIP) continue;
            if (!ins.hasImm32 || ins.hasRipRel) continue;  // skip indirect CALL
            int32_t  rel    = (int32_t)ins.imm32;
            uint64_t target = ins.rva + ins.length + (int64_t)rel;
            if (!scanner.IsTextRVA(target))     continue;
            if (!IsLoadBearing(target))         continue;
            if (visited.count(target))          continue;
            walk(target, depth + 1);
            break;  // first load-bearing call only
        }
    };

    walk(fname_fn_rva, 0);

    if (targetCounts.empty()) {
        std::printf("[autodisc-gnames] no .data LEAs found in FName call chain\n");
        return out;
    }

    // Apply exclude zones — drop any candidate within ±radius of a known
    // non-FNamePool global (typically the keystream table, which the entry
    // decoder hits dozens of times per call and would out-vote the real
    // FNamePool reference count).
    auto inExcludeZone = [&](uint64_t target) -> bool {
        for (const auto& z : exclude_zones) {
            uint64_t lo = z.CenterRva > z.Radius ? (z.CenterRva - z.Radius) : 0;
            uint64_t hi = z.CenterRva + z.Radius;
            if (target >= lo && target <= hi) return true;
        }
        return false;
    };

    // Diagnostic: rank ALL targets first (so the user can see the full picture
    // including excluded ones), then mark which were skipped.
    std::vector<std::pair<uint64_t, int>> sorted(targetCounts.begin(), targetCounts.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) { return a.second > b.second; });

    // Mode pick — first non-excluded candidate by descending refs.
    uint64_t best = 0; int bestCount = 0;
    for (const auto& [t, c] : sorted) {
        if (inExcludeZone(t)) continue;
        best = t;
        bestCount = c;
        break;
    }
    if (!best) {
        std::printf("[autodisc-gnames] all candidates fell into exclude zones — keeping compile-time constant\n");
        for (const auto& [t, c] : sorted) {
            std::printf("[autodisc-gnames]   0x%llX  refs=%d  EXCLUDED\n",
                (unsigned long long)t, c);
        }
        return out;  // Valid stays false
    }

    out.GNamesRva = best;
    out.RefCount  = bestCount;
    out.Valid     = true;
    std::printf("[autodisc-gnames] GNamePool RVA = 0x%llX (%d refs across walk)\n",
        (unsigned long long)best, bestCount);

    int shown = 0;
    for (const auto& [t, c] : sorted) {
        if (shown++ >= 8) break;
        const char* tag = inExcludeZone(t) ? "  EXCLUDED" : "";
        std::printf("[autodisc-gnames]   0x%llX  refs=%d%s\n",
            (unsigned long long)t, c, tag);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 7: FFieldClass NamePrivate decode pipeline (sig-scan + Zydis walk)
//
// FFieldClass on UE5 builds embeds an FName slot at a discoverable offset.
// On 20260421 IDA in FProperty_GetNameCPP @ 0x3AFE70:
//
//   48 8B 41 30                    mov rax, [rcx+0x30]   ; FProperty.FFieldClass*
//   F2 0F 70 40 20 4B              pshuflw xmm0, [rax+0x20], 0x4B
//                                                           ^^^^ FFieldClass NamePrivate offset
//   ...                            (junk: arg shuffle, movdqa)
//   66 0F 72 D1 1D                 psrld xmm1, 0x1D
//   66 0F 72 F0 03                 pslld xmm0, 3        ; together = ROL32(3) per uint32 lane
//   66 0F EB C1                    por   xmm0, xmm1
//   F2 0F 70 C0 72                 pshuflw xmm0, xmm0, 0x72
//   66 0F EF 05 ?? ?? ?? ??        pxor  xmm0, [rip+disp32]   ; XOR const RVA
//   66 48 0F 7E C0                 movq  rax, xmm0
//   48 C1 C0 20                    rol   rax, 0x20      ; ROL64(32)
//
// Pipeline result: lo32 = CompIndex (Number in hi32 typically 0).
//
// Anchor strategy:
//   1. Sig-scan the SIMD body shape (PSRLD 0x1D + PSLLD 3 + POR + PSHUFLW 0x72
//      + PXOR rip-rel) — verified 25 inlined sites on 20260421, all targeting
//      the same .rdata constant (`xmmword_ACF8900` = RVA 0xACF8900). High
//      consensus = patch-resilient.
//   2. For each hit, resolve the PXOR rip-rel target → XOR const RVA.
//   3. Histogram the targets — the mode is the FFieldClass XOR const.
//   4. Walk back via Zydis from each hit to find the PSHUFLW load
//      `F2 0F 70 ?? disp8 4B` and extract disp8 = FFieldClass NamePrivate offset.
//   5. Walk further back to find the FFieldClass-pointer load
//      `48 8B ?? disp8` and extract disp8 = FProperty FFieldClass offset.
//   6. Read 16 bytes at the discovered XOR const RVA → that's the live
//      decrypt key (16 bytes, lo64 used in the scalar XOR step).
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldClassNameParams {
    uint64_t XorConstRva           = 0;     // rdata RVA of 16-byte XOR const
    uint64_t XorLo64               = 0;     // first 8 bytes of XOR const (live-read)
    uint32_t FFieldClassOffset     = 0;     // FProperty → FFieldClass*
    uint32_t NamePrivateOffset     = 0;     // FFieldClass → NamePrivate slot
    uint8_t  PshuflwImm1           = 0x4B;  // 75
    uint8_t  PshuflwImm2           = 0x72;  // 114
    uint8_t  Rol32Amount           = 3;
    uint8_t  Rol64Amount           = 32;
    int      ConsensusSiteCount    = 0;
    bool     Valid                 = false;
};

inline FFieldClassNameParams DiscoverFFieldClassNameDecrypt(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader,
    uint64_t module_base)
{
    FFieldClassNameParams out;

    // Sig: PSRLD 0x1D + PSLLD 3 + POR + PSHUFLW 0x72 + PXOR rip-rel.
    // 23 bytes, very specific to the FFieldClass NamePrivate decode.
    static constexpr const char* kSig =
        "66 0F 72 D1 1D 66 0F 72 F0 03 66 0F EB C1 F2 0F 70 C0 72 66 0F EF 05";
    auto hits = scanner.ScanSection(kSig, ".text");
    std::printf("[autodisc-fcname] FFieldClass decode pipeline sig hits: %zu\n", hits.size());
    if (hits.empty()) return out;

    InsnDecoder dec;

    // Histograms across all hits.
    std::unordered_map<uint64_t, int> xorRvaCounts;
    std::unordered_map<uint32_t, int> nameOffCounts;
    std::unordered_map<uint32_t, int> fclassOffCounts;
    int validatedSites = 0;

    for (uint64_t hitRva : hits) {
        // Step 1: PXOR rip-rel target. The PXOR is the final 8 bytes of the sig
        // (4 opcode + 4 disp32). Hit starts at `66 0F 72 D1 1D`, the PXOR is
        // at hit + 19, ends at hit + 27.
        const uint8_t* p = scanner.GetLocalPtr(hitRva);
        if (!p) continue;
        int32_t disp = 0;
        std::memcpy(&disp, p + 19 + 4, 4);  // PXOR opcode 4 bytes + disp32
        uint64_t xorRva = (hitRva + 27) + (int64_t)disp;
        if (!scanner.IsRDataRVA(xorRva)) continue;

        // Step 2: walk back ~24 bytes via Zydis to find
        //   F2 0F 70 ?? disp8 4B   ; pshuflw xmmN, [reg+disp8], 0x4B
        // The PSHUFLW imm = 0x4B (75) is the giveaway.
        //
        // We brute-force decode at every possible boundary in [hit-24, hit-6].
        uint32_t namePrivateOff = 0;
        bool foundNameLoad = false;
        for (int back = 24; back >= 6 && !foundNameLoad; --back) {
            uint64_t startRva = hitRva - back;
            const uint8_t* lp = scanner.GetLocalPtr(startRva);
            if (!lp) continue;
            // Walk the decoded instruction stream looking for a PSHUFLW with
            // memory operand (load form) and imm 0x4B.
            auto insns = dec.Decode(lp, back, startRva);
            for (size_t i = 0; i < insns.size(); ++i) {
                const auto& ins = insns[i];
                if (ins.type != INSN_PSHUFLW) continue;
                if (!ins.hasImm8 || ins.imm8 != 0x4B) continue;
                // Manually parse the PSHUFLW prefix to find a [reg+disp8] form.
                // Encoding: F2 0F 70 modrm [disp] imm8
                //   modrm 0x40..0x47 = [reg+disp8] dest reg in low 3 bits of modrm
                //   F2 0F 70 40 disp8 imm8 = pshuflw xmm0, [rax+disp8], imm8
                // Length = 6 (3 opcode + 1 modrm + 1 disp8 + 1 imm8)
                if (ins.length != 6) continue;
                const uint8_t* ip = lp + (ins.rva - startRva);
                uint8_t modrm = ip[3];
                if ((modrm & 0xC0) != 0x40) continue;  // require mod=01 ([reg+disp8])
                int8_t  d8     = (int8_t)ip[4];
                if (d8 < 0 || d8 > 0x80) continue;
                namePrivateOff = (uint32_t)d8;
                foundNameLoad = true;
                break;
            }
        }
        if (!foundNameLoad) continue;

        // Step 3: walk further back ~16 bytes to find the FFieldClass-pointer
        // load `mov rN, [rM+disp8]` (REX.W=1, opcode 0x8B).
        // Encoding: 48 8B modrm disp8 = mov reg64, [reg64+disp8] (length 4)
        // The disp8 is the FProperty.FFieldClass offset (0x30 on 20260421).
        uint32_t fclassOff = 0;
        bool foundFcLoad = false;
        // Look in the 16 bytes BEFORE the PSHUFLW load, which sits at hit-back.
        for (int extraBack = 4; extraBack <= 32 && !foundFcLoad; extraBack += 1) {
            uint64_t fcLoadRva = hitRva - 24 - extraBack;
            const uint8_t* fp = scanner.GetLocalPtr(fcLoadRva);
            if (!fp) continue;
            // Look for `48 8B modrm disp8` exact length 4.
            if (fp[0] != 0x48 || fp[1] != 0x8B) continue;
            uint8_t modrm = fp[2];
            if ((modrm & 0xC0) != 0x40) continue;  // mod=01
            int8_t d8 = (int8_t)fp[3];
            if (d8 < 0 || d8 > 0x100) continue;
            fclassOff = (uint32_t)d8;
            foundFcLoad = true;
            break;
        }
        // FFieldClass offset is best-effort — if it can't be found via the
        // simple back-walk (multiple register variants, register reuse, etc.),
        // we still want to record xorRva and nameOff. The fclassOff is later
        // used as a hint; the dumper can probe FProperty for it independently.

        ++validatedSites;
        ++xorRvaCounts[xorRva];
        ++nameOffCounts[namePrivateOff];
        if (foundFcLoad) ++fclassOffCounts[fclassOff];
    }

    if (validatedSites < 3) {
        std::printf("[autodisc-fcname] insufficient validated sites (%d < 3) — keeping fallback\n",
            validatedSites);
        return out;
    }

    // Mode-pick each parameter independently.
    auto pick_mode = [](auto& counts) {
        typename std::decay_t<decltype(counts)>::key_type best{};
        int bestCount = 0;
        for (const auto& [k, c] : counts) {
            if (c > bestCount) { bestCount = c; best = k; }
        }
        return std::pair{best, bestCount};
    };
    auto [bestXor, xorHits]      = pick_mode(xorRvaCounts);
    auto [bestNameOff, nameHits] = pick_mode(nameOffCounts);

    out.XorConstRva       = bestXor;
    out.NamePrivateOffset = bestNameOff;
    out.ConsensusSiteCount = validatedSites;

    if (!fclassOffCounts.empty()) {
        auto [bestFcOff, fcHits] = pick_mode(fclassOffCounts);
        out.FFieldClassOffset = bestFcOff;
    }

    // Live-read the 16-byte XOR const from .rdata (we only need lo64 for the
    // scalar XOR step in DecryptFFieldClassNameSlot).
    uint8_t xorBytes[16] = {};
    if (reader.Read(module_base + bestXor, xorBytes, 16)) {
        std::memcpy(&out.XorLo64, xorBytes, 8);
    }
    if (out.XorLo64 == 0) {
        std::printf("[autodisc-fcname] could not read XOR const @ rva 0x%llX — keeping fallback\n",
            (unsigned long long)bestXor);
        return out;
    }

    out.PshuflwImm1 = 0x4B;
    out.PshuflwImm2 = 0x72;
    out.Rol32Amount = 3;
    out.Rol64Amount = 32;
    out.Valid       = true;

    std::printf("[autodisc-fcname] consensus across %d sites: xor_rva=0x%llX (lo64=0x%016llX, %d×) "
                "name_off=+0x%X (%d×) fclass_off=+0x%X\n",
        validatedSites, (unsigned long long)bestXor, (unsigned long long)out.XorLo64,
        xorHits, out.NamePrivateOffset, nameHits, out.FFieldClassOffset);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Globals — populated by main.cpp::Init() during the discovery phase, read
// at decrypt sites (gobjects.h, fname_decrypt.h, arc_decrypt.h).
// ─────────────────────────────────────────────────────────────────────────────
inline VTableMap                 g_DiscoveredVTables;
inline ModuleBounds              g_DiscoveredBounds;
inline WorldDiscovery            g_DiscoveredWorld;
inline FNameSanityResult         g_DiscoveredFNameSanity;
inline FFieldNameDecryptParams   g_DiscoveredFFieldName;
inline FPropertyDecryptParams    g_DiscoveredFProperty;
inline UObjSlotDecryptParams     g_DiscoveredUObjSlot;
inline FNameResolverConsts       g_DiscoveredFName;
inline GNamesDiscovery           g_DiscoveredGNames;
inline FFieldClassNameParams     g_DiscoveredFFieldClassName;

}  // namespace AutoDiscovery
