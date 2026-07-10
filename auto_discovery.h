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
#include <immintrin.h>

#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "sig_scanner_v2.h"
#include "insn_decoder.h"
#include "func_analyzer.h"
#include "pe_reader.h"

namespace AutoDiscovery {

static inline uint64_t fn_rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

inline std::vector<uint64_t> ScanCodeSections(
    const SigScanV2::Scanner& Scanner, const char* Sig)
{
    auto Hits = Scanner.ScanSection(Sig, ".text");
    for (const char* VmpSec : {"dnv0", "dnv1", "dnv4"}) {
        auto Extra = Scanner.ScanSection(Sig, VmpSec);
        Hits.insert(Hits.end(), Extra.begin(), Extra.end());
    }
    return Hits;
}

inline std::vector<uint64_t> ScanCodeSections(
    const SigScanV2::Scanner& Scanner, const SigScanV2::Pattern& Pat)
{
    auto Hits = Scanner.ScanSection(Pat, ".text");
    for (const char* VmpSec : {"dnv0", "dnv1", "dnv4"}) {
        auto Extra = Scanner.ScanSection(Pat, VmpSec);
        Hits.insert(Hits.end(), Extra.begin(), Extra.end());
    }
    return Hits;
}

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
    auto movHits = ScanCodeSections(scanner, "48 8B 05 ?? ?? ?? ?? 48 8B 00");
    std::printf("[autodisc-gworld] MOV-deref-deref sig hits (.text+dnv): %zu\n", movHits.size());
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
            auto hits = ScanCodeSections(scanner, pat);
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
        int Found = 0;
        if (ScriptStructRVA) Found++;
        if (ClassNativeRVA)  Found++;
        if (FunctionRVA)     Found++;
        if (EnumRVA)         Found++;
        if (PackageRVA)      Found++;
        if (BPGCRVA)         Found++;
        return Found >= 2;
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
        if (!LooksLikeBPGC(s)) return false;
        if (s.find("WBP_")    != std::string::npos) return true;
        if (s.find("WBP")     == 0)                 return true;
        if (s.find("_WBP_")   != std::string::npos) return true;
        if (s.find("Widget")  != std::string::npos) return true;
        if (s.find("_W_")     != std::string::npos) return true;
        if (s.size() >= 4 && s.compare(0, 2, "W_") == 0)                  return true;
        if (s.size() >= 5 && s.compare(s.size() - 4, 4, "_W_C") == 0)     return true;
        if (s.find("UMG_")    != std::string::npos) return true;
        if (s.find("_UMG_")   != std::string::npos) return true;
        if (s.find("HUD_")    != std::string::npos) return true;
        if (s.find("_HUD_")   != std::string::npos) return true;
        if (s.find("Menu_")   != std::string::npos) return true;
        if (s.find("_Menu_")  != std::string::npos) return true;
        if (s.find("Popup")   != std::string::npos) return true;
        if (s.find("Overlay") != std::string::npos) return true;
        if (s.find("Screen")  != std::string::npos) return true;
        if (s.find("Modal")   != std::string::npos) return true;
        if (s.find("Panel_")  != std::string::npos) return true;
        if (s.find("UserWidget")  != std::string::npos) return true;
        return false;
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
        if (c.names.size() < 200) {
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

    auto rva_of = [&](uint64_t vt) -> uint64_t { return vt ? (vt - module_base) : 0; };

    auto as_density_score = [&](uint64_t vt_addr) -> int {
        if (!vt_addr || vt_addr < module_base) return 0;
        uint64_t rva = vt_addr - module_base;
        if (!bounds.InRData(rva)) return 0;
        uint64_t qbuf[64] = {};
        if (!reader.Read(vt_addr, qbuf, sizeof(qbuf))) return 0;
        int textCount = 0;
        for (int i = 0; i < 64; ++i) {
            if (!qbuf[i]) continue;
            if (qbuf[i] < module_base) continue;
            uint64_t r = qbuf[i] - module_base;
            if (bounds.InText(r)) ++textCount;
        }
        return textCount;
    };

    {
        uint64_t AsLo = bounds.RDataRva + (bounds.RDataSize * 3 / 4);
        uint64_t AsHi = bounds.RDataEnd();
        for (const auto& cs : scored) {
            uint64_t rva = rva_of(cs.vtable);
            if (rva < AsLo || rva >= AsHi) continue;
            int KlassHits  = cs.scores[KCLASS_NATIVE] + cs.scores[KBPGC];
            int StructHits = cs.scores[KSCRIPT_STRUCT];
            int FuncHits   = cs.scores[KFUNCTION];
            if (KlassHits >= StructHits && KlassHits >= FuncHits && cs.count > 100) {
                if (!out.ASClassRVA) out.ASClassRVA = rva;
            } else if (StructHits > FuncHits && cs.count > 50) {
                if (!out.ASStructRVA) out.ASStructRVA = rva;
            }
        }
        if (!out.ASClassRVA) {
            uint64_t BestVt = 0; size_t BestCount = 0; int BestDensity = 0;
            for (const auto& cs : scored) {
                uint64_t rva = rva_of(cs.vtable);
                if (!rva || rva == out.ASStructRVA) continue;
                if (cs.count < 100 || cs.count > 100000) continue;
                int d = as_density_score(cs.vtable);
                if (d < 10) continue;
                if (cs.count > BestCount || (cs.count == BestCount && d > BestDensity)) {
                    BestVt = cs.vtable; BestCount = cs.count; BestDensity = d;
                }
            }
            if (BestVt) {
                out.ASClassRVA = rva_of(BestVt);
                std::printf("[autodisc-vt]   ASClass early structural fallback: picked rva=0x%llX cluster_count=%zu density=%d\n",
                    (unsigned long long)out.ASClassRVA, BestCount, BestDensity);
            }
        }
        if (!out.ASStructRVA) {
            uint64_t BestVt = 0; size_t BestCount = 0; int BestDensity = 0;
            for (const auto& cs : scored) {
                uint64_t rva = rva_of(cs.vtable);
                if (!rva || rva == out.ASClassRVA) continue;
                if (cs.count < 50 || cs.count > 100000) continue;
                int d = as_density_score(cs.vtable);
                if (d < 10) continue;
                if (cs.count > BestCount || (cs.count == BestCount && d > BestDensity)) {
                    BestVt = cs.vtable; BestCount = cs.count; BestDensity = d;
                }
            }
            if (BestVt) {
                out.ASStructRVA = rva_of(BestVt);
                std::printf("[autodisc-vt]   ASStruct early structural fallback: picked rva=0x%llX cluster_count=%zu density=%d\n",
                    (unsigned long long)out.ASStructRVA, BestCount, BestDensity);
            }
        }
        if (out.ASClassRVA || out.ASStructRVA)
            std::printf("[autodisc-vt]   pre-identified ASClass=0x%llX ASStruct=0x%llX (excluded from engine-type scoring)\n",
                (unsigned long long)out.ASClassRVA, (unsigned long long)out.ASStructRVA);
    }

    auto pick_best_for_kind = [&](int kind) -> uint64_t {
        uint64_t best_vt = 0; double best_density = 0; int best_score = 0;
        for (const auto& cs : scored) {
            uint64_t rva = rva_of(cs.vtable);
            if (rva == out.ASClassRVA || rva == out.ASStructRVA) continue;
            int s = cs.scores[kind];
            if (s == 0) continue;
            auto It = clusters.find(cs.vtable);
            size_t NNames = (It != clusters.end()) ? It->second.names.size() : 0;
            if (NNames == 0) NNames = 1;
            double Density = (double)s / (double)NNames;
            if (Density > best_density || (Density == best_density && s > best_score)) {
                best_density = Density; best_score = s; best_vt = cs.vtable;
            }
        }
        return best_vt;
    };

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
    out.WBPGCRVA        = rva_of(pick_gated(KWBPGC,         2));
    out.SMBPGCRVA       = rva_of(pick_gated(KSMBPGC,        2));
    out.AnimBPGCRVA     = rva_of(pick_gated(KANIM_BPGC,     2));

    // Structural fallback for WBPGC: if the name oracle didn't fire (e.g. menu
    // state with few widgets loaded, or non-standard naming), pick the largest
    // unclassified _C cluster — widget blueprints almost always form the
    // second-largest _C-suffix cluster after the generic BPGC bucket.
    auto cluster_is_bp_style = [&](const ClusterScore& cs) -> bool {
        const auto it = clusters.find(cs.vtable);
        if (it == clusters.end() || it->second.names.empty()) return false;
        size_t bp_hits = 0;
        for (const auto& n : it->second.names)
            if (VTableOracles::LooksLikeBPGC(n)) ++bp_hits;
        return bp_hits * 2 >= it->second.names.size();
    };
    auto already_assigned = [&](uint64_t rva) -> bool {
        return rva == out.ScriptStructRVA || rva == out.ClassNativeRVA ||
               rva == out.FunctionRVA     || rva == out.EnumRVA        ||
               rva == out.PackageRVA      || rva == out.BPGCRVA        ||
               rva == out.WBPGCRVA        || rva == out.SMBPGCRVA      ||
               rva == out.AnimBPGCRVA     || rva == out.ASClassRVA     ||
               rva == out.ASStructRVA;
    };
    if (!out.WBPGCRVA) {
        uint64_t best_vt = 0; size_t best_count = 0;
        for (const auto& cs : scored) {
            uint64_t r = rva_of(cs.vtable);
            if (!r || already_assigned(r)) continue;
            if (cs.count < 2) continue;
            if (!cluster_is_bp_style(cs)) continue;
            if (cs.count > best_count) { best_count = cs.count; best_vt = cs.vtable; }
        }
        if (best_vt) {
            out.WBPGCRVA = rva_of(best_vt);
            std::printf("[autodisc-vt]   WBPGC structural fallback: picked rva=0x%llX cluster_count=%zu (no name-oracle hit)\n",
                (unsigned long long)out.WBPGCRVA, best_count);
        } else {
            // Surface every _C-style cluster so the user can see what's available.
            std::printf("[autodisc-vt]   WBPGC unresolved — unclassified _C-style clusters:\n");
            size_t shown = 0;
            for (const auto& cs : scored) {
                uint64_t r = rva_of(cs.vtable);
                if (!r || already_assigned(r)) continue;
                if (!cluster_is_bp_style(cs)) continue;
                const auto it = clusters.find(cs.vtable);
                const char* sample0 = (it != clusters.end() && !it->second.names.empty())
                                      ? it->second.names[0].c_str() : "?";
                const char* sample1 = (it != clusters.end() && it->second.names.size() > 1)
                                      ? it->second.names[1].c_str() : "?";
                std::printf("[autodisc-vt]     rva=0x%llX  count=%zu  e.g. \"%s\", \"%s\"\n",
                    (unsigned long long)r, cs.count, sample0, sample1);
                if (++shown >= 8) break;
            }
        }
    }

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

    // ── Structural-density fallback for SMBPGC / ASClass / ASStruct ─────────
    // When the wide-string anchors are stripped (CL-1177678) and the name
    // oracles can't tie a cluster to a kind, fall back to pure structure:
    // a cluster's vtable lives in .rdata and looks like an engine type-pool
    // vtable (≥10 text-pointer entries in its first 0x200 bytes), with a
    // kind-specific cluster-size band. Picks the largest unassigned cluster
    // that satisfies each gate. Logged distinctly so the user can see when
    // structural fallback fires.
    auto density_score_local = [&](uint64_t vt_addr) -> int {
        if (!vt_addr || vt_addr < module_base) return 0;
        uint64_t rva = vt_addr - module_base;
        if (!bounds.InRData(rva)) return 0;
        uint64_t qbuf[64] = {};
        if (!reader.Read(vt_addr, qbuf, sizeof(qbuf))) return 0;
        int textCount = 0;
        for (int i = 0; i < 64; ++i) {
            if (!qbuf[i]) continue;
            if (qbuf[i] < module_base) continue;
            uint64_t r = qbuf[i] - module_base;
            if (bounds.InText(r)) ++textCount;
        }
        return textCount;
    };
    auto already_assigned_full = [&](uint64_t rva) -> bool {
        if (!rva) return true;
        if (rva == out.ScriptStructRVA || rva == out.ClassNativeRVA ||
            rva == out.FunctionRVA     || rva == out.EnumRVA        ||
            rva == out.PackageRVA      || rva == out.BPGCRVA        ||
            rva == out.WBPGCRVA        || rva == out.SMBPGCRVA      ||
            rva == out.AnimBPGCRVA     || rva == out.ASClassRVA     ||
            rva == out.ASStructRVA) return true;
        for (uint64_t f : out.ASFunctionRVAs) if (f == rva) return true;
        return false;
    };
    auto pick_structural = [&](const char* label, size_t min_count, size_t max_count) -> uint64_t {
        uint64_t bestVt = 0; size_t bestCount = 0; int bestDensity = 0;
        for (const auto& cs : scored) {
            uint64_t rva = rva_of(cs.vtable);
            if (already_assigned_full(rva)) continue;
            if (cs.count < min_count || cs.count > max_count) continue;
            int d = density_score_local(cs.vtable);
            if (d < 10) continue;
            // Prefer larger clusters first; tiebreak by higher density.
            if (cs.count > bestCount ||
                (cs.count == bestCount && d > bestDensity)) {
                bestVt = cs.vtable; bestCount = cs.count; bestDensity = d;
            }
        }
        if (bestVt) {
            std::printf("[autodisc-vt]   %s structural fallback: picked rva=0x%llX cluster_count=%zu density=%d\n",
                label, (unsigned long long)(bestVt - module_base), bestCount, bestDensity);
        }
        return bestVt;
    };
    if (!out.ASClassRVA) {
        uint64_t vt = pick_structural("ASClass", 100, 100000);
        if (vt) out.ASClassRVA = rva_of(vt);
    }
    if (!out.ASStructRVA) {
        uint64_t vt = pick_structural("ASStruct", 50, 100000);
        if (vt) out.ASStructRVA = rva_of(vt);
    }
    if (!out.SMBPGCRVA) {
        uint64_t vt = pick_structural("SMBPGC", 2, 10);
        if (vt) out.SMBPGCRVA = rva_of(vt);
    }

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
// Phase 1.5: Engine type-pool vtable discovery via wide-string anchor
//
// Phase 1 (name-cluster) fails when live FName resolution is weak — too few
// canonical names match per cluster, gates reject real vtables. Phase 1.5
// runs as a fallback: it anchors on the kind's UTF-16 wide string in .rdata
// (e.g. L"ScriptStruct") and walks the containing function looking for the
// vtable write.
//
// Two patterns observed across CL-1177146:
//   A. Z_Construct shape (ScriptStruct/Function/Class):
//        lea rXX, [rip + L"<Kind>"]      ; wide-string LEA
//        ...
//        lea rax, [rip + class_ctor]      ; class-constructor function ptr
//        mov [reg + 0x140], rax           ; UClass.ClassConstructor
//      → Class-ctor function (small, <0x200 bytes) writes the vtable as:
//        lea rax, [rip + vtable]
//        mov [rdi], rax
//
//   B. Self-contained shape (Enum/Package):
//        lea rXX, [rip + L"<Kind>"]      ; in registration callsite
//        ...
//        lea rax, [rip + vtable]          ; direct vtable LEA
//        mov [rdi], rax                   ; vtable write at offset 0
//
// Algorithm per kind:
//   1. Find UTF-16 L"<Kind>\0\0" in .rdata.
//   2. Find LEA xrefs to it in .text (sigscan `48 8D ?? d32` where d32 →
//      string RVA).
//   3. For each xref's containing function, scan ≤0x300 bytes forward for:
//      (a) Direct vtable write `48 8D 05 d32 48 89 ??` where d32 → .rdata
//          AND first qword at d32 → .text (vtable[0] is dtor).
//      (b) Class-ctor pointer write `48 8D 05 d32 48 89 ?? 40 01 00 00`
//          (mov [reg+0x140], rax) where d32 → .text. Recurse 1 level into
//          the target function and apply (a).
//   4. Mode-pick across xrefs.
//
// This is patch-resilient: the wide strings, vtable-write idiom, and
// UClass.ClassConstructor offset (0x140) are all UE5-stable. UnrealHeaderTool
// emits these patterns mechanically from UCLASS macros every build.
// ─────────────────────────────────────────────────────────────────────────────
struct EngineVTableAnchorResult {
    uint64_t ScriptStructRVA = 0;
    uint64_t ClassNativeRVA  = 0;
    uint64_t FunctionRVA     = 0;
    uint64_t EnumRVA         = 0;
    uint64_t PackageRVA      = 0;
    uint64_t BPGCRVA         = 0;
    uint64_t AnimBPGCRVA     = 0;
    uint64_t WBPGCRVA        = 0;

    int      Found           = 0;  // count of resolved kinds (max 8)
};

inline EngineVTableAnchorResult DiscoverEngineVTablesByWideStringAnchor(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader,
    uint64_t module_base, const ModuleBounds& bounds)
{
    EngineVTableAnchorResult out;
    if (!bounds.Valid) return out;

    // Helper: validate a candidate vtable RVA. Engine type-pool vtables
    // (UScriptStruct/UClass/UFunction/UEnum/UPackage) are LARGE — typically
    // 100+ qword entries each pointing into .text (the class's virtual
    // method table). Property class globals (FEnumProperty etc.) and other
    // small structures share the "first qword → .text" pattern but have far
    // fewer text entries. Require ≥24 text-pointer entries in the first
    // 0x200 bytes (64 qwords) to filter out non-pool .rdata structures.
    auto density_score = [&](uint64_t vt_rva) -> int {
        if (!bounds.InRData(vt_rva)) return 0;
        uint64_t first_qword = 0;
        if (!reader.Read(module_base + vt_rva, &first_qword, 8)) return 0;
        if (first_qword < module_base) return 0;
        uint64_t first_rva = first_qword - module_base;
        if (!bounds.InText(first_rva)) return 0;
        // Read 0x200 bytes (64 qwords) and count text-pointer entries.
        // Engine type-pool vtables (UClass, UScriptStruct, UFunction, UEnum,
        // UPackage) all have ≥10 text-pointer entries in their first 0x200
        // bytes; many have 30+. Property-class globals and other small
        // structures have <8.
        uint64_t qbuf[64] = {};
        if (!reader.Read(module_base + vt_rva, qbuf, sizeof(qbuf))) return 0;
        int textCount = 0;
        for (int i = 0; i < 64; ++i) {
            if (!qbuf[i]) continue;
            if (qbuf[i] < module_base) continue;
            uint64_t r = qbuf[i] - module_base;
            if (bounds.InText(r)) ++textCount;
        }
        return textCount;
    };
    auto looks_like_vtable = [&](uint64_t vt_rva) -> bool {
        return density_score(vt_rva) >= 10;
    };

    // Helper: scan `window` bytes from `fn_start_rva` for RIP-relative LEAs
    // followed shortly by a same-register MOV that stores the LEA target
    // into memory. The LEA can use ANY 64-bit destination register (rax,
    // rcx, rdx, rbx, rsi, rdi, rsp/rbp impossible due to ModR/M, r8-r15
    // via REX.R bit).
    //
    // require_140=true variant additionally requires the MOV's disp32
    // immediate to equal 0x140 (UClass.ClassConstructor offset = 320).
    //
    // Returns the LEA-target RVAs in code order (so callers can pick "first"
    // or "last" to handle Package's intermediate→final two-write shape).
    auto scan_lea_mov_targets = [&](uint64_t fn_start_rva, size_t window,
                                    bool require_140 = false) -> std::vector<uint64_t> {
        std::vector<uint64_t> hits;
        const uint8_t* p = scanner.GetLocalPtr(fn_start_rva);
        if (!p) return hits;
        size_t bound = window;
        if (fn_start_rva + window > bounds.TextEnd())
            bound = bounds.TextEnd() - fn_start_rva;
        // Detect function end: stop at first `C3` (retn) followed by a `CC`
        // (int3 padding) within the next 16 bytes. MSVC-style stack-cookie
        // emit interleaves `retn ; call __security_check_cookie ; int3` —
        // the CC isn't immediately after the retn. Plain `C3 CC` (no
        // cookie) and `CC CC` runs are both subsumed by this rule.
        // Without this, the scan walks PAST a small class-ctor (e.g.
        // sub_389E94 / UEnum) into the next function and "last write"
        // semantics pick up unrelated vtables (ADA18A0 from sub_38A000).
        for (size_t s = 0; s + 1 < bound; ++s) {
            if (p[s] == 0xC3) {
                // Look ahead ≤16 bytes for a CC.
                size_t look = std::min<size_t>(16, bound - s);
                for (size_t t = 1; t < look; ++t) {
                    if (p[s+t] == 0xCC) { bound = s + 1; goto bound_set; }
                }
            }
            if (p[s] == 0xCC && p[s+1] == 0xCC) { bound = s; break; }
        }
        bound_set: ;
        for (size_t i = 0; i + 10 <= bound; ++i) {
            // REX.W prefix: 0x48 (low reg) or 0x4C (high reg via REX.R).
            if (p[i] != 0x48 && p[i] != 0x4C) continue;
            if (p[i+1] != 0x8D) continue;            // LEA opcode
            uint8_t modrm = p[i+2];
            // mod=00 + rm=101 → RIP-relative disp32.
            if ((modrm & 0xC7) != 0x05) continue;
            // Extract destination register. reg field = (modrm >> 3) & 7,
            // extended by REX.R (high bit of REX byte).
            uint8_t lea_dst = ((modrm >> 3) & 7) | ((p[i] & 4) ? 8 : 0);
            int32_t disp = 0;
            std::memcpy(&disp, p + i + 3, 4);
            uint64_t target = (fn_start_rva + i + 7) + (int64_t)disp;

            // Look for a MOV [mem], <lea_dst> within the next ~16 bytes.
            // MOV r/m64, r64 with REX.W: opcode 0x89, REX prefix 0x48..0x4F.
            // ModR/M's reg field is the SOURCE register; rm field/SIB is dest.
            // We accept any addressing form for the destination — `[reg]`,
            // `[reg+disp8]`, `[reg+disp32]`, etc.
            bool matched = false;
            uint64_t mov_disp_imm = 0;
            for (size_t j = i + 7; j + 3 <= bound && j < i + 7 + 24; ++j) {
                if ((p[j] & 0xF0) != 0x40) continue;       // not REX
                if (!(p[j] & 0x08)) continue;              // need REX.W=1
                if (p[j+1] != 0x89) continue;              // not MOV r/m, r64
                uint8_t mr = p[j+2];
                uint8_t mov_src = ((mr >> 3) & 7) | ((p[j] & 4) ? 8 : 0);
                if (mov_src != lea_dst) continue;
                // mod==00,01,10 = memory dest (mod==11 is reg-reg, skip).
                uint8_t mod = mr >> 6;
                if (mod == 3) continue;
                // For require_140 we need to read the MOV's disp32. Decode
                // the operand size to find it.
                uint8_t rm = mr & 7;
                size_t op_pos = j + 3;
                // SIB byte if rm == 4 (mod != 11).
                if (rm == 4) {
                    if (op_pos >= bound) break;
                    ++op_pos;  // skip SIB
                }
                // Special case: mod==00 + rm==101 = RIP-rel — skip (MOV from
                // REG into [rip+disp32] is rare and not what we want).
                if (mod == 0 && rm == 5) continue;
                if (mod == 1) {
                    if (op_pos >= bound) break;
                    mov_disp_imm = (int8_t)p[op_pos];
                    op_pos += 1;
                } else if (mod == 2) {
                    if (op_pos + 4 > bound) break;
                    int32_t d = 0;
                    std::memcpy(&d, p + op_pos, 4);
                    mov_disp_imm = (uint64_t)(int64_t)d;
                    op_pos += 4;
                }
                if (require_140 && !(mov_disp_imm >= 0x130 && mov_disp_imm <= 0x150 && (mov_disp_imm & 7) == 0)) continue;
                matched = true;
                break;
            }
            if (matched) hits.push_back(target);
        }
        return hits;
    };

    // Build the UTF-16 (LE) byte pattern for a wide string + NUL.
    auto wide_pattern = [](const char* kind) -> std::vector<uint8_t> {
        std::vector<uint8_t> bytes;
        for (const char* c = kind; *c; ++c) {
            bytes.push_back(static_cast<uint8_t>(*c));
            bytes.push_back(0x00);
        }
        // Trailing NUL terminator.
        bytes.push_back(0x00);
        bytes.push_back(0x00);
        return bytes;
    };

    // Helper: locate the start of the function containing the given xref RVA
    // by walking back to the previous CC padding (or .text section start).
    auto walk_to_fn_start = [&](uint64_t xref_rva) -> uint64_t {
        const uint8_t* p = scanner.GetLocalPtr(xref_rva);
        if (!p) return 0;
        uint64_t lo = bounds.TextRva;
        // Walk back ≤0x800 bytes looking for runs of 0xCC (function padding)
        // immediately followed by a function prologue byte.
        for (size_t back = 1; back < 0x800 && xref_rva - back > lo; ++back) {
            const uint8_t* q = scanner.GetLocalPtr(xref_rva - back);
            if (!q) break;
            if (q[0] == 0xCC && q[1] != 0xCC) {
                // skip CC padding
                return xref_rva - back + 1;
            }
        }
        return 0;
    };

    // Resolve the vtable for one kind.
    auto resolve_kind = [&](const char* kind) -> uint64_t {
        std::vector<uint8_t> wpat = wide_pattern(kind);
        // Find .rdata occurrences of the wide string.
        std::string rdataSig;
        char buf[8];
        for (size_t i = 0; i < wpat.size(); ++i) {
            std::snprintf(buf, sizeof(buf), "%02X", wpat[i]);
            if (i) rdataSig += ' ';
            rdataSig += buf;
        }
        auto strHits = scanner.ScanSection(rdataSig.c_str(), ".rdata");
        if (strHits.empty()) {
            std::printf("[autodisc-vt-anchor] %s: wide string not found in .rdata\n", kind);
            return 0;
        }

        // For each wide-string occurrence, scan .text for `48 8D ?? d32` LEAs
        // whose disp32 → that string. Record xref RVAs.
        std::vector<uint64_t> xref_rvas;
        // The LEA `48 8D ?? d32` is 7 bytes. Mod-RM byte's reg field varies
        // (rax/rcx/rdx/rsi/rdi/r8/...), but the mod=00 + rm=101 (RIP-rel)
        // requires modrm byte AND 0xC7 == 0x05.
        // We do a coarse byte sweep over .text; for each candidate, decode the
        // disp32 and check if it points to one of the string RVAs.
        const uint8_t* tx_ptr = scanner.GetLocalPtr(bounds.TextRva);
        if (!tx_ptr) return 0;
        size_t tx_size = bounds.TextSize;
        for (size_t i = 0; i + 7 <= tx_size; ++i) {
            if (tx_ptr[i] != 0x48 || tx_ptr[i+1] != 0x8D) continue;
            uint8_t modrm = tx_ptr[i+2];
            if ((modrm & 0xC7) != 0x05) continue;  // not RIP-rel
            int32_t disp = 0;
            std::memcpy(&disp, tx_ptr + i + 3, 4);
            uint64_t target = (bounds.TextRva + i + 7) + (int64_t)disp;
            for (uint64_t s : strHits) {
                if (target == s) {
                    xref_rvas.push_back(bounds.TextRva + i);
                    break;
                }
            }
        }
        if (xref_rvas.empty()) {
            std::printf("[autodisc-vt-anchor] %s: no LEA xrefs to %zu wide-string occurrences\n",
                kind, strHits.size());
            return 0;
        }

        // For each xref site, find the containing function and scan it for
        // vtable writes / class-ctor pointer writes. Per xref site, only
        // count the LAST direct-write candidate (handles Package's two-write
        // shape: intermediate UObject vtable then final UPackage vtable;
        // last write is the keep). For class-ctor recursion, also keep only
        // the last write found inside the recursed body.
        std::unordered_map<uint64_t, int> vtCounts;
        for (uint64_t xref : xref_rvas) {
            // Pivot scan around the xref site itself rather than from the
            // function start. Big outer functions (e.g. the 16KB Enum
            // registration helper) would push fn_start far back; scanning
            // forward 0x400 from there could overshoot or miss the xref's
            // immediate context. Anchoring at the xref keeps focus on the
            // local construct that actually uses the wide string.
            uint64_t scan_lo = xref;
            size_t   scan_sz = 0x300;

            // Pattern A — direct vtable write inside this fn. Keep last only.
            uint64_t lastDirect = 0;
            for (uint64_t cand : scan_lea_mov_targets(scan_lo, scan_sz, false)) {
                if (looks_like_vtable(cand)) lastDirect = cand;
            }
            if (lastDirect) ++vtCounts[lastDirect];

            // Pattern B — class-ctor pointer write at +0x140; recurse 1 lvl.
            for (uint64_t ctor_rva : scan_lea_mov_targets(scan_lo, scan_sz, true)) {
                if (!bounds.InText(ctor_rva)) continue;
                uint64_t lastSub = 0;
                for (uint64_t cand : scan_lea_mov_targets(ctor_rva, 0x200, false)) {
                    if (looks_like_vtable(cand)) lastSub = cand;
                }
                // Weight class-ctor matches double — they're more specific
                // than self-contained matches.
                if (lastSub) vtCounts[lastSub] += 2;
            }
        }
        if (vtCounts.empty()) {
            std::printf("[autodisc-vt-anchor] %s: no vtable candidates from %zu xrefs\n",
                kind, xref_rvas.size());
            return 0;
        }
        // Score = (xref count) × 100 + density. Density tiebreak picks the
        // FAT engine pool vtable over thin look-alikes (FEnumProperty
        // globals etc. that share the prefix shape but only have ~3-5
        // text-pointer entries vs UEnum's 30+).
        uint64_t bestVt = 0;
        int bestScore = 0;
        int bestDensity = 0;
        for (const auto& [vt, c] : vtCounts) {
            int density = density_score(vt);
            int total = c * 100 + density;
            if (total > bestScore) {
                bestScore = total; bestVt = vt; bestDensity = density;
            }
        }
        std::printf("[autodisc-vt-anchor] %s: vtable_rva=0x%llX (xref_count=%d, density=%d, %zu candidates from %zu xrefs)\n",
            kind, (unsigned long long)bestVt, bestScore / 100, bestDensity,
            vtCounts.size(), xref_rvas.size());
        return bestVt;
    };

    out.ScriptStructRVA = resolve_kind("ScriptStruct");
    out.ClassNativeRVA  = resolve_kind("Class");
    out.FunctionRVA     = resolve_kind("Function");
    out.EnumRVA         = resolve_kind("Enum");
    out.PackageRVA      = resolve_kind("Package");
    // Blueprint-generated class kinds. Only the BPGC wide string is reliably
    // present across patches (CL-1177678 strips L"WidgetBlueprintGeneratedClass"
    // / L"AnimBlueprintGeneratedClass" / L"SkeletalMeshBlueprintGeneratedClass"
    // from .rdata). The calls below still try the long names so future patches
    // that restore the strings light up automatically; resolve_kind gracefully
    // returns 0 with a "wide string not found" log when absent.
    out.BPGCRVA      = resolve_kind("BlueprintGeneratedClass");
    out.AnimBPGCRVA  = resolve_kind("AnimBlueprintGeneratedClass");
    out.WBPGCRVA     = resolve_kind("WidgetBlueprintGeneratedClass");
    {
        uint64_t* EngineRvas[] = {
            &out.ScriptStructRVA, &out.ClassNativeRVA, &out.FunctionRVA,
            &out.EnumRVA, &out.PackageRVA, &out.BPGCRVA,
            &out.AnimBPGCRVA, &out.WBPGCRVA
        };
        const char* EngineNames[] = {
            "ScriptStruct", "Class", "Function", "Enum", "Package",
            "BPGC", "AnimBPGC", "WBPGC"
        };
        for (int I = 0; I < 8; ++I) {
            if (!*EngineRvas[I]) continue;
            for (int J = I + 1; J < 8; ++J) {
                if (*EngineRvas[I] == *EngineRvas[J]) {
                    std::printf("[autodisc-vt-anchor] dedup: %s and %s share vtable 0x%llX — clearing both\n",
                        EngineNames[I], EngineNames[J], (unsigned long long)*EngineRvas[I]);
                    *EngineRvas[I] = 0;
                    *EngineRvas[J] = 0;
                }
            }
        }
    }
    out.Found = (out.ScriptStructRVA ? 1 : 0) + (out.ClassNativeRVA ? 1 : 0) +
                (out.FunctionRVA ? 1 : 0) + (out.EnumRVA ? 1 : 0) +
                (out.PackageRVA ? 1 : 0) + (out.BPGCRVA ? 1 : 0) +
                (out.AnimBPGCRVA ? 1 : 0) + (out.WBPGCRVA ? 1 : 0);
    std::printf("[autodisc-vt-anchor] resolved %d/8 engine vtables\n", out.Found);
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
    bool     TwoShuffle  = false;
    uint8_t  ShufImm1    = 0;
    uint8_t  ShufImm2    = 0;
    int      TsRol64     = 0;
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

    auto try_decrypt_slot = [&](const uint8_t* slot,
                                uint64_t& xor_const, uint32_t& ci, uint32_t& num) -> bool {
        // Attempt -1 — CL-1233465 pipeline (8-byte slot):
        // PSHUFLW(0x1E) → XOR(0x365789E8756FBA38) → ROL16(1) → lo64 → ROL64(32)
        {
            using namespace ArcDecrypt::v20260616;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(slot));
            V = _mm_shufflelo_epi16(V, FFIELD_NAME_SHUF_IMM);
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_XOR_KEY)));
            V = _mm_or_si128(_mm_add_epi16(V, V), _mm_srli_epi16(V, 15));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << FFIELD_NAME_ROL64) | (Lo >> (64 - FFIELD_NAME_ROL64));
            uint32_t CiN = static_cast<uint32_t>(Out);
            uint32_t NumN = static_cast<uint32_t>(Out >> 32);
            if (CiN >= 2 && CiN <= 0x2000000u && NumN <= 0x10000u) {
                xor_const = FFIELD_NAME_XOR_KEY;
                ci = CiN; num = NumN;
                return true;
            }
        }

        // Attempt 0 — CL-1201801 pipeline (8-byte slot):
        // lo64 -> XOR(KEY1) -> ROL32(17)/lane -> PSHUFLW(0x1E) -> XOR(KEY2) -> ROL64(32)
        {
            using namespace ArcDecrypt::v20260519;
            __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(slot));
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_KEY1)));
            V = _mm_or_si128(_mm_slli_epi32(V, FFIELD_NAME_ROL32), _mm_srli_epi32(V, 32 - FFIELD_NAME_ROL32));
            V = _mm_shufflelo_epi16(V, FFIELD_NAME_SHUF);
            V = _mm_xor_si128(V, _mm_set_epi64x(0, static_cast<int64_t>(FFIELD_NAME_KEY2)));
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), V);
            uint64_t Out = (Lo << FFIELD_NAME_ROL64) | (Lo >> (64 - FFIELD_NAME_ROL64));
            uint32_t Ci0 = static_cast<uint32_t>(Out);
            uint32_t Num0 = static_cast<uint32_t>(Out >> 32);
            if (Ci0 >= 2 && Ci0 <= 0x2000000u && Num0 <= 0x10000u) {
                xor_const = FFIELD_NAME_KEY1;
                ci = Ci0; num = Num0;
                return true;
            }
        }

        // Attempt 0b — generalized keyless brute: try common (ROL32, PSHUFLW, ROL64)
        // combos without XOR keys. PSHUFLW requires a compile-time immediate,
        // so each shuffle variant is inlined via a lambda+switch.
        {
            auto ApplyShuf = [](__m128i V, int Imm) -> __m128i {
                switch (Imm) {
                    case 0x1E: return _mm_shufflelo_epi16(V, 0x1E);
                    case 0x4B: return _mm_shufflelo_epi16(V, 0x4B);
                    case 0x39: return _mm_shufflelo_epi16(V, 0x39);
                    case 0x93: return _mm_shufflelo_epi16(V, 0x93);
                    case 0xB1: return _mm_shufflelo_epi16(V, 0xB1);
                    case 0x2E: return _mm_shufflelo_epi16(V, 0x2E);
                    case 0x1B: return _mm_shufflelo_epi16(V, 0x1B);
                    case 0x4E: return _mm_shufflelo_epi16(V, 0x4E);
                    case 0x8D: return _mm_shufflelo_epi16(V, 0x8D);
                    case 0xD8: return _mm_shufflelo_epi16(V, 0xD8);
                    case 0xE1: return _mm_shufflelo_epi16(V, 0xE1);
                    case 0x72: return _mm_shufflelo_epi16(V, 0x72);
                    default:   return V;
                }
            };
            static const int kRol32s[] = { 17, 13, 1, 9, 7, 11, 15, 19, 21, 23, 25 };
            static const int kShufs[] = { 0x1E, 0x4B, 0x39, 0x93, 0xB1, 0x2E, 0x1B, 0x4E, 0x8D, 0xD8, 0xE1, 0x72 };
            static const int kRol64s[] = { 32, 18, 27, 7, 37, 55 };
            for (int R : kRol32s) {
                for (int S : kShufs) {
                    __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(slot));
                    V = _mm_or_si128(_mm_slli_epi32(V, R), _mm_srli_epi32(V, 32 - R));
                    V = ApplyShuf(V, S);
                    uint64_t AfterMath;
                    _mm_storel_epi64(reinterpret_cast<__m128i*>(&AfterMath), V);
                    for (int R64 : kRol64s) {
                        uint64_t Out = fn_rotl64(AfterMath, R64);
                        uint32_t TrialCi = static_cast<uint32_t>(Out);
                        uint32_t TrialNum = static_cast<uint32_t>(Out >> 32);
                        if (TrialCi >= 2 && TrialCi <= 0x2000000u && TrialNum <= 0x10000u) {
                            xor_const = (static_cast<uint64_t>(R) << 16) | (static_cast<uint64_t>(S) << 8) | R64;
                            ci = TrialCi; num = TrialNum;
                            return true;
                        }
                    }
                }
            }

            // Attempt 0c — two-shuffle pipeline: PSHUFLW(S1) → ROL64(R) → PSHUFLW(S2)
            // New on CL-120xxxx: no ROL32 step, two shuffles around a ROL64.
            for (int S1 : kShufs) {
                for (int R64 : kRol64s) {
                    for (int S2 : kShufs) {
                        __m128i V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(slot));
                        V = ApplyShuf(V, S1);
                        uint64_t Mid;
                        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Mid), V);
                        Mid = fn_rotl64(Mid, R64);
                        V = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(&Mid));
                        V = ApplyShuf(V, S2);
                        uint64_t Out2;
                        _mm_storel_epi64(reinterpret_cast<__m128i*>(&Out2), V);
                        uint32_t TrialCi = static_cast<uint32_t>(Out2);
                        uint32_t TrialNum = static_cast<uint32_t>(Out2 >> 32);
                        if (TrialCi >= 2 && TrialCi <= 0x2000000u && TrialNum <= 0x10000u) {
                            xor_const = 0xCC000000ULL | (static_cast<uint64_t>(S1) << 16) |
                                        (static_cast<uint64_t>(R64) << 8) | S2;
                            ci = TrialCi; num = TrialNum;
                            return true;
                        }
                    }
                }
            }
        }

        // Attempt 1 — CL-1195482 pipeline (PSHUFLW(0x4B) -> ROL32(1)/lane ->
        // PSHUFB(B34DF20-mask) -> XOR(0x5C61A9C2230CDE97) -> ROL64(32)).
        {
            __m128i V    = _mm_loadu_si128(reinterpret_cast<const __m128i*>(slot));
            __m128i Sh   = _mm_shufflelo_epi16(V, 0x4B);
            __m128i Rot  = _mm_or_si128(_mm_add_epi32(Sh, Sh), _mm_srli_epi32(Sh, 31));
            alignas(16) static const uint8_t MaskBytes[16] = {
                0x04, 0x06, 0x07, 0x05, 0x02, 0x01, 0x00, 0x03,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            __m128i Mask = _mm_load_si128(reinterpret_cast<const __m128i*>(MaskBytes));
            __m128i Sft  = _mm_shuffle_epi8(Rot, Mask);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Sft);
            uint64_t Xored = Lo ^ 0x5C61A9C2230CDE97ULL;
            uint64_t Out   = (Xored << 32) | (Xored >> 32);
            uint32_t Ci2   = static_cast<uint32_t>(Out);
            uint32_t Num2  = static_cast<uint32_t>(Out >> 32);
            if (Ci2 >= 2 && Ci2 <= 0x2000000u && Num2 <= 0x10000u) {
                xor_const = 0x5C61A9C2230CDE97ULL;
                ci = Ci2; num = Num2;
                return true;
            }
        }

        // Attempt 2 — CL-1177678 pipeline (ROL64(55) -> PSHUFB -> PXOR -> ROL64(32)).
        {
            __m128i V   = _mm_loadu_si128(reinterpret_cast<const __m128i*>(slot));
            __m128i Rot = _mm_or_si128(_mm_slli_epi64(V, 55), _mm_srli_epi64(V, 9));
            alignas(16) static const uint8_t MB[16] = {
                0x06, 0x05, 0x03, 0x01, 0x02, 0x07, 0x00, 0x04,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            alignas(16) static const uint8_t XB[16] = {
                0x3B, 0x3F, 0xA4, 0x49, 0xC8, 0xC8, 0x82, 0x48,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            };
            __m128i MaskV = _mm_load_si128(reinterpret_cast<const __m128i*>(MB));
            __m128i XorK  = _mm_load_si128(reinterpret_cast<const __m128i*>(XB));
            __m128i Shuf  = _mm_shuffle_epi8(Rot, MaskV);
            __m128i Xored = _mm_xor_si128(Shuf, XorK);
            uint64_t Lo;
            _mm_storel_epi64(reinterpret_cast<__m128i*>(&Lo), Xored);
            uint64_t Out = (Lo << 32) | (Lo >> 32);
            uint32_t Ci3 = static_cast<uint32_t>(Out);
            uint32_t Num3 = static_cast<uint32_t>(Out >> 32);
            if (Ci3 >= 2 && Ci3 <= 0x2000000u && Num3 <= 0x10000u) {
                xor_const = 0x4882C8C849A43F3BULL;
                ci = Ci3; num = Num3;
                return true;
            }
        }

        // Attempt 3 — legacy CL-1177146 pipeline (ROL32(13)/lane -> lo64 ->
        // XOR(const auto-derived from slot+8..+15) -> ROL64(7)).
        uint32_t hi_lo32 = 0, hi_hi32 = 0;
        std::memcpy(&hi_lo32, slot + 8,  4);
        std::memcpy(&hi_hi32, slot + 12, 4);
        uint32_t xor_lo32 = rol32(hi_lo32, 13);
        uint32_t xor_hi32 = rol32(hi_hi32, 13);
        xor_const = (static_cast<uint64_t>(xor_hi32) << 32) | xor_lo32;
        if (xor_const == 0 || xor_const == ~0ULL) return false;

        uint32_t lo_lo32 = 0, lo_hi32 = 0;
        std::memcpy(&lo_lo32, slot + 0, 4);
        std::memcpy(&lo_hi32, slot + 4, 4);
        uint64_t pipe_lo64 = (static_cast<uint64_t>(rol32(lo_hi32, 13)) << 32) | rol32(lo_lo32, 13);
        uint64_t pipe_xored = pipe_lo64 ^ xor_const;
        uint64_t result = (pipe_xored << 7) | (pipe_xored >> (64 - 7));
        ci  = static_cast<uint32_t>(result);
        num = static_cast<uint32_t>(result >> 32);
        if (ci < 2 || ci > 0x2000000u) return false;
        if (num > 0x10000u) return false;
        return true;
    };
    auto looks_like_heap_ptr = [&](uint64_t p) -> bool {
        if (p < module_base + 0x100000ULL || p >= 0x800000000000ULL) return false;
        if (p >= module_base && p < module_base + 0x10000000ULL) return false;
        return true;
    };
    // Walk up to `hops` FField-chain steps from `head` using `next_off` as the
    // "Next" pointer offset. Each link must stay in heap. Returns the count of
    // valid hops (0 if the head itself is bogus). Used as a structural gate to
    // distinguish a real FField chain from a TArray data pointer (e.g. UEnum::
    // Names) that also reads "heap-shaped" but doesn't form a singly-linked
    // list when chased.
    auto chain_length = [&](uint64_t head, uint64_t next_off, int hops) -> int {
        int n = 0;
        uint64_t cur = head;
        for (int i = 0; i < hops; ++i) {
            uint64_t nx = 0;
            if (!reader.Read(cur + next_off, &nx, 8)) break;
            if (nx == 0) { ++n; break; }
            if (!looks_like_heap_ptr(nx)) break;
            if (nx == cur) break;
            cur = nx; ++n;
        }
        return n;
    };

    // Broad-scan: sweep candidate ChildProps offsets and candidate NamePrivate
    // offsets, validate by (a) the decrypt math producing a plausible CI/Num
    // AND (b) the candidate having a Next-chain of ≥1 heap hop at one of the
    // common FField::Next offsets seen across patches (0x48, 0x68, 0x70, 0x80).
    // Requires the SAME (childprops_off, nameprivate_off, xor_const) tuple to
    // succeed across ≥2 different sample objects — single-object agreement is
    // not enough (enum bodies + spurious heap-looking globals can pass once).
    struct Candidate {
        uint64_t childprops_off = 0;
        uint64_t nameprivate_off = 0;
        uint64_t xor_const = 0;
        int votes = 0;
        uint64_t example_head = 0;
        uint32_t example_ci = 0;
        uint32_t example_num = 0;
    };
    std::vector<Candidate> cands;
    std::vector<uint64_t> cpOffs;
    cpOffs.push_back(ustruct_childprops_offset);
    for (uint64_t v = 0x20; v <= 0x180; v += 8)   // widened for CL-1195482 (0x138)
        if (v != ustruct_childprops_offset) cpOffs.push_back(v);
    std::vector<uint64_t> npOffs;
    npOffs.push_back(ffield_nameprivate_offset);
    for (uint64_t v : {0x08ULL, 0x10ULL, 0x18ULL, 0x20ULL, 0x28ULL,
                       0x30ULL, 0x38ULL, 0x40ULL, 0x48ULL, 0x50ULL, 0x58ULL, 0x60ULL,
                       0x68ULL, 0x70ULL, 0x78ULL, 0x80ULL, 0x88ULL, 0x90ULL,
                       0xA0ULL, 0xA8ULL, 0xB0ULL, 0xB8ULL, 0xC0ULL, 0xC8ULL,
                       0xD0ULL, 0xD8ULL, 0xE0ULL, 0xE8ULL, 0xF0ULL, 0xF8ULL})
        if (v != ffield_nameprivate_offset) npOffs.push_back(v);
    static const uint64_t kNextOffs[] = {
        0xB0, 0x48, 0x80, 0x70, 0x68, 0x58, 0x50, 0x60,
        0x90, 0x98, 0xA0, 0xA8, 0xB8, 0xC0, 0xC8, 0xD0,
        0xE0, 0xE8, 0xF0, 0xF8, 0x100, 0x108, 0x110, 0x118,
    };
    int probed = 0;
    // Per-offset "saw a heap pointer here" histogram. The most-popular offset
    // is almost certainly ChildProperties even if its FFields don't validate.
    std::unordered_map<uint64_t, int> heap_hits_per_cpoff;
    for (uint64_t uss : sample_uscriptstructs) {
        if (probed >= 32) break;   // raised from 16 to surface more candidates
        ++probed;
        for (uint64_t cp : cpOffs) {
            uint64_t ff_head = 0;
            if (!reader.Read(uss + cp, &ff_head, 8)) continue;
            if (!looks_like_heap_ptr(ff_head)) continue;
            heap_hits_per_cpoff[cp]++;
            for (uint64_t np : npOffs) {
                uint8_t slot[16] = {};
                if (!reader.Read(ff_head + np, slot, 16)) continue;
                uint64_t xor_const = 0; uint32_t ci = 0, num = 0;
                if (!try_decrypt_slot(slot, xor_const, ci, num)) continue;
                // Structural gate: try to find a Next-hop. CL-1195482's FField
                // layout shifted significantly; if no kNextOffs candidate yields
                // a valid hop we now KEEP the candidate but log it (was: skip).
                int best_hops = 0;
                uint64_t best_next_off = 0;
                for (uint64_t nxo : kNextOffs) {
                    int h = chain_length(ff_head, nxo, 3);
                    if (h > best_hops) { best_hops = h; best_next_off = nxo; }
                }
                (void)best_next_off;
                // Relaxed: don't reject on missing chain. The decoded CI is
                // strong enough validation by itself.

                // Merge into cands by (cp, np, xor_const).
                bool merged = false;
                for (auto& c : cands) {
                    if (c.childprops_off == cp && c.nameprivate_off == np &&
                        c.xor_const == xor_const) {
                        ++c.votes; merged = true; break;
                    }
                }
                if (!merged) {
                    cands.push_back({cp, np, xor_const, 1, ff_head, ci, num});
                }
            }
        }
    }
    if (!cands.empty()) {
        std::sort(cands.begin(), cands.end(),
            [](const Candidate& a, const Candidate& b) { return a.votes > b.votes; });
        const Candidate& best = cands.front();
        if (best.votes >= 2) {
            out.Valid = true;
            uint64_t X = best.xor_const;
            if ((X & 0xFF000000ULL) == 0xCC000000ULL) {
                out.TwoShuffle = true;
                out.ShufImm1   = static_cast<uint8_t>((X >> 16) & 0xFF);
                out.TsRol64    = static_cast<int>((X >> 8) & 0xFF);
                out.ShufImm2   = static_cast<uint8_t>(X & 0xFF);
                out.XorConst   = 0;
                out.Rol32Amount = 0;
                out.Rol64Amount = out.TsRol64;
                std::printf("[autodisc-ffield] broad-scan TWO-SHUFFLE: PSHUFLW(0x%02X)->ROL64(%d)->PSHUFLW(0x%02X) "
                    "childprops_off=0x%llX nameprivate_off=0x%llX votes=%d (CI=%u Num=%u from FField 0x%llX)\n",
                    out.ShufImm1, out.TsRol64, out.ShufImm2,
                    (unsigned long long)best.childprops_off,
                    (unsigned long long)best.nameprivate_off,
                    best.votes, best.example_ci, best.example_num,
                    (unsigned long long)best.example_head);
            } else if (X > 0xFFFFFFULL) {
                out.XorConst    = X;
                out.Rol32Amount = 13;
                out.Rol64Amount = 7;
                std::printf("[autodisc-ffield] broad-scan picked childprops_off=0x%llX nameprivate_off=0x%llX votes=%d XOR=0x%016llX (CI=%u Num=%u from FField 0x%llX)\n",
                    (unsigned long long)best.childprops_off,
                    (unsigned long long)best.nameprivate_off,
                    best.votes, (unsigned long long)best.xor_const,
                    best.example_ci, best.example_num,
                    (unsigned long long)best.example_head);
            } else {
                int R32 = static_cast<int>((X >> 16) & 0xFF);
                int S   = static_cast<int>((X >> 8) & 0xFF);
                int R64 = static_cast<int>(X & 0xFF);
                out.XorConst    = 0;
                out.Rol32Amount = R32;
                out.Rol64Amount = R64;
                out.ShufImm1    = static_cast<uint8_t>(S);
                std::printf("[autodisc-ffield] broad-scan KEYLESS: ROL32(%d)->PSHUFLW(0x%02X)->ROL64(%d) "
                    "childprops_off=0x%llX nameprivate_off=0x%llX votes=%d (CI=%u Num=%u from FField 0x%llX)\n",
                    R32, S, R64,
                    (unsigned long long)best.childprops_off,
                    (unsigned long long)best.nameprivate_off,
                    best.votes, best.example_ci, best.example_num,
                    (unsigned long long)best.example_head);
            }
            return out;
        }
        // Surface the top-3 candidates so the user can eyeball drift.
        std::printf("[autodisc-ffield] broad-scan top candidates (need votes>=2):\n");
        size_t shown = 0;
        for (const auto& c : cands) {
            std::printf("[autodisc-ffield]   cp=0x%llX np=0x%llX votes=%d XOR=0x%016llX (CI=%u Num=%u)\n",
                (unsigned long long)c.childprops_off,
                (unsigned long long)c.nameprivate_off,
                c.votes, (unsigned long long)c.xor_const,
                c.example_ci, c.example_num);
            if (++shown >= 3) break;
        }
    }

    std::printf("[autodisc-ffield] no usable FField chain found in %d UScriptStructs (broad-scan exhausted)\n", probed);
    {
        std::vector<std::pair<uint64_t,int>> ranked(heap_hits_per_cpoff.begin(), heap_hits_per_cpoff.end());
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b){ return a.second > b.second; });
        std::printf("[autodisc-ffield] heap-ptr histogram (top offsets w/ heap-ptr across %d samples):\n", probed);
        for (size_t I = 0; I < std::min<size_t>(ranked.size(), 8); ++I) {
            std::printf("[autodisc-ffield]   off=+0x%llX hits=%d/%d\n",
                (unsigned long long)ranked[I].first, ranked[I].second, probed);
        }

        if (!ranked.empty()) {
            uint64_t BestCpOff = ranked[0].first;
            for (uint64_t Uss : sample_uscriptstructs) {
                uint64_t FfHead = 0;
                if (!reader.Read(Uss + BestCpOff, &FfHead, 8)) continue;
                if (!looks_like_heap_ptr(FfHead)) continue;
                std::printf("[autodisc-ffield] DIAG: strongest cp_off=+0x%llX, sample UStruct=0x%llX, FField head=0x%llX\n",
                    (unsigned long long)BestCpOff, (unsigned long long)Uss, (unsigned long long)FfHead);

                std::printf("[autodisc-ffield] DIAG: FField raw bytes at key offsets:\n");
                for (uint64_t DiagNp : {0x08ULL, 0x10ULL, 0x18ULL, 0x20ULL, 0x28ULL, 0x30ULL, 0x38ULL,
                                        0x40ULL, 0x48ULL, 0x50ULL, 0x58ULL, 0x60ULL, 0x68ULL, 0x70ULL, 0x78ULL, 0x80ULL}) {
                    uint8_t Buf[16] = {};
                    if (reader.Read(FfHead + DiagNp, Buf, 16)) {
                        uint64_t V0 = 0, V1 = 0;
                        std::memcpy(&V0, Buf, 8);
                        std::memcpy(&V1, Buf + 8, 8);
                        bool IsHeap = looks_like_heap_ptr(V0);
                        std::printf("[autodisc-ffield]   +0x%02llX: %016llX %016llX%s\n",
                            (unsigned long long)DiagNp, (unsigned long long)V0, (unsigned long long)V1,
                            IsHeap ? " [heap-ptr]" : "");
                    }
                }

                for (uint64_t NxOff : kNextOffs) {
                    int Hops = chain_length(FfHead, NxOff, 5);
                    if (Hops > 0) {
                        std::printf("[autodisc-ffield] DIAG: chain_length(head, next_off=0x%llX) = %d hops\n",
                            (unsigned long long)NxOff, Hops);
                    }
                }
                break;
            }
        }
    }
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

    // ENCODE-side anchor: FProperty_SetupOffset writes the encrypted offset.
    // The pipeline is `xor eax, imm32 ; bswap eax ; mov [reg+disp32], eax`
    // where disp32 is the FProperty Offset_Internal slot (0xC4 on CL-1177146,
    // 0xB4 on 20260428, etc.). Decode is `bswap32(stored ^ key)` where the
    // imm32 here equals bswap32(key) (because `bswap32(real ^ key) =
    // bswap32(real) ^ bswap32(key)`, so storing `bswap32(real ^ key)` after
    // an `xor + bswap` requires the imm to be bswap32 of the decode key).
    //
    // Decode-site sigscan was previously tried but the decoders use a
    // dynamically-computed register XOR (the key is generated via FNV+SIMD
    // per-call), not an imm32 — so it can't be matched bytewise. The encode
    // site is the cleanest anchor: 5 sites on lh74, 0x48742740 imm =
    // bswap32(0x40277448).
    auto hits = ScanCodeSections(scanner,
        "35 ?? ?? ?? ?? 0F C8 89 ?? ?? ?? 00 00");
    std::printf("[autodisc-fprop] encode sig hits (xor+bswap+mov[reg+disp32], .text+dnv): %zu\n",
        hits.size());

    // Histogram of (offset, xor_key) pairs across all validated hits — the
    // mode is the property offset writer's parameters.
    std::unordered_map<uint64_t, int> pairCounts;  // (offset<<32)|xor_key
    uint64_t firstValidatedRva = 0;

    for (uint64_t rva : hits) {
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        // Layout per the sigscan template:
        //   p[0]    = 0x35           XOR EAX opcode
        //   p[1..4] = imm32          XOR key (encoded — bswap32 of decode key)
        //   p[5..6] = 0F C8          BSWAP EAX
        //   p[7]    = 0x89           MOV r/m32, r32 opcode
        //   p[8]    = ModR/M         must be mod=10 + reg=000 (eax) + rm!=100,101
        //   p[9..12]= disp32         FProperty Offset_Internal slot
        if (p[0] != 0x35 || p[5] != 0x0F || p[6] != 0xC8 || p[7] != 0x89) continue;
        uint8_t modrm = p[8];
        if ((modrm & 0xC0) != 0x80) continue;  // need mod=10 (disp32 form)
        if ((modrm & 0x38) != 0x00) continue;  // need src reg = eax
        uint8_t rm = modrm & 0x07;
        if (rm == 4 || rm == 5) continue;       // no SIB, no RIP-rel
        uint32_t xor_imm = 0;
        std::memcpy(&xor_imm, p + 1, 4);
        uint32_t disp32 = 0;
        std::memcpy(&disp32, p + 9, 4);
        if (xor_imm == 0u || xor_imm == 0xFFFFFFFFu) continue;
        if (disp32 < 0x80 || disp32 > 0x140) continue;

        // The dumper decodes as `real = bswap32(stored) ^ key`, where key is
        // the raw imm32 from the encode-side `xor eax, imm32; bswap eax`.
        uint32_t decode_key = xor_imm;
        uint64_t key = ((uint64_t)disp32 << 32) | decode_key;
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
    auto pshufbHits = ScanCodeSections(scanner, "66 0F 38 00 ?? ?? ?? ?? ??");
    std::printf("[autodisc-uobj] PSHUFB rip-rel hits (.text+dnv): %zu\n", pshufbHits.size());

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
    const SigScanV2::Scanner& scanner, uint64_t fname_func_rva,
    int max_depth = 4)
{
    FNameResolverConsts out;
    if (!fname_func_rva) return out;
    out.FunctionStartRva = fname_func_rva;

    std::unordered_set<uint64_t> Visited;
    size_t TotalInsns = 0;

    auto IsLoadBearing = [&](uint64_t FnRva) -> bool {
        if (!scanner.IsTextRVA(FnRva)) return false;
        const uint8_t* P = scanner.GetLocalPtr(FnRva);
        if (!P) return false;
        for (int I = 0; I < 0x40; ++I) {
            if (P[I] == 0xCC) return false;
        }
        return true;
    };

    std::function<void(uint64_t, int)> Walk = [&](uint64_t Rva, int Depth) {
        if (Depth >= max_depth) return;
        if (!Visited.insert(Rva).second) return;

        auto Insns = FuncAnalyze::DecodeFunctionAt(scanner, Rva, 0x2000);
        if (Insns.empty()) return;
        TotalInsns += Insns.size();

        for (const auto& Ins : Insns) {
            if (Ins.type == INSN_MOV_REG && Ins.imm64 != 0 && Ins.length == 10) {
                out.AllImm64.push_back(Ins.imm64);
            }
            if (Ins.type == INSN_PSHUFLW && Ins.hasImm8) {
                out.AllPshuflwImm.push_back(Ins.imm8);
            }
            if (Ins.type == INSN_ROL && Ins.hasImm8 && Ins.hasREX_W) {
                out.AllRolImm.push_back(Ins.imm8);
            }
            if (Ins.hasRipRel &&
                (Ins.type == INSN_PSHUFB || Ins.type == INSN_PXOR ||
                 Ins.type == INSN_XORPS  || Ins.type == INSN_LEA  ||
                 Ins.type == INSN_MOVDQA || Ins.type == INSN_MOVQ ||
                 Ins.type == INSN_LOADL_EPI64 || Ins.type == INSN_PAND ||
                 Ins.type == INSN_PANDN  || Ins.type == INSN_POR ||
                 Ins.type == INSN_MOVAPS))
            {
                uint64_t T = Ins.ResolveRipRVA();
                if (scanner.IsRDataRVA(T)) out.AllRDataLeas.push_back(T);
            }
        }

        for (const auto& Ins : Insns) {
            if (Ins.type != INSN_CALL_RIP) continue;
            if (!Ins.hasImm32 || Ins.hasRipRel) continue;
            int32_t Rel = (int32_t)Ins.imm32;
            uint64_t Target = Ins.rva + Ins.length + (int64_t)Rel;
            if (!scanner.IsTextRVA(Target)) continue;
            if (!IsLoadBearing(Target)) continue;
            if (Visited.count(Target)) continue;
            Walk(Target, Depth + 1);
        }
    };

    Walk(fname_func_rva, 0);

    std::sort(out.AllRDataLeas.begin(), out.AllRDataLeas.end());
    out.AllRDataLeas.erase(std::unique(out.AllRDataLeas.begin(), out.AllRDataLeas.end()),
                           out.AllRDataLeas.end());

    std::printf("[autodisc-fname] deep walk: %zu fns visited, %zu total insns\n",
        Visited.size(), TotalInsns);
    std::printf("[autodisc-fname] extracted: %zu imm64, %zu pshuflw_imm, %zu rol_imm, %zu rdata_leas\n",
        out.AllImm64.size(), out.AllPshuflwImm.size(),
        out.AllRolImm.size(), out.AllRDataLeas.size());

    if (!out.AllImm64.empty()) {
        std::printf("[autodisc-fname]   imm64 candidates:\n");
        size_t Shown = 0;
        for (uint64_t V : out.AllImm64) {
            if (Shown++ >= 12) break;
            std::printf("[autodisc-fname]     0x%016llX\n", (unsigned long long)V);
        }
    }
    if (!out.AllRDataLeas.empty()) {
        std::printf("[autodisc-fname]   .rdata table candidates (%zu total):\n",
            out.AllRDataLeas.size());
        size_t Shown = 0;
        for (uint64_t V : out.AllRDataLeas) {
            if (Shown++ >= 16) break;
            std::printf("[autodisc-fname]     0x%llX\n", (unsigned long long)V);
        }
        if (out.AllRDataLeas.size() > 16) {
            std::printf("[autodisc-fname]     ... and %zu more\n",
                out.AllRDataLeas.size() - 16);
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
    // Bonus output: the FName SIMD-constants block (highest-ref non-FNamePool
    // candidate). RVA_FNAME_KEY_TABLE = SimdBlockRva + 0xA0.
    uint64_t SimdBlockRva  = 0;
    int      SimdBlockRefs = 0;
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

    // Tie-break heuristic: FNamePool (the global we want) is runtime-
    // initialized — its FNameBlock[0] header is at low offsets and at
    // +0x18 inside the struct it stores a heap-allocated chunk pointer
    // (the first FNameBlock's data buffer). The other heavily-referenced
    // .data globals near the FName fn — keystream tables, SIMD constants
    // blocks — are pure compile-time data with no heap pointers anywhere.
    // Probe the first 0x40 bytes of each candidate for ANY value in the
    // Wine heap range (0x100000000 ≤ x < 0x800000000000). Real FNamePool
    // returns true; SIMD/keystream blocks return false.
    //
    // Why: on CL-1177146 the FNamePool was the unique mode by ref count;
    // on CL-1177678 a SIMD constants block tied at 10 refs and the
    // sort-stable order flipped the wrong way, breaking name resolution.
    auto LooksLikeFNamePool = [&](uint64_t rva) -> bool {
        if (!scanner.IsValidRVA(rva)) return false;
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) return false;
        // Read first 8 qwords; check if any is a Wine heap pointer.
        for (int i = 0; i < 8; ++i) {
            uint64_t qw = 0;
            std::memcpy(&qw, p + i * 8, 8);
            if (qw >= 0x100000000ULL && qw < 0x800000000000ULL)
                return true;
        }
        return false;
    };

    // Diagnostic: rank ALL targets first (so the user can see the full picture
    // including excluded ones), then mark which were skipped.
    std::vector<std::pair<uint64_t, int>> sorted(targetCounts.begin(), targetCounts.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) { return a.second > b.second; });

    // Mode pick — highest-ref candidate that ALSO looks like FNamePool
    // (has a heap pointer). Falls back to highest-ref non-excluded if no
    // candidate has a heap pointer (e.g. game in pre-init state).
    uint64_t best = 0; int bestCount = 0;
    bool best_via_heap_probe = false;
    for (const auto& [t, c] : sorted) {
        if (inExcludeZone(t)) continue;
        if (LooksLikeFNamePool(t)) {
            best = t;
            bestCount = c;
            best_via_heap_probe = true;
            break;
        }
    }
    if (!best) {
        for (const auto& [t, c] : sorted) {
            if (inExcludeZone(t)) continue;
            best = t;
            bestCount = c;
            break;
        }
        if (best) {
            std::printf("[autodisc-gnames] no candidate had a heap pointer in first 0x40 bytes — "
                        "falling back to highest-ref non-excluded (game may not be fully booted)\n");
        }
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
    std::printf("[autodisc-gnames] GNamePool RVA = 0x%llX (%d refs across walk%s)\n",
        (unsigned long long)best, bestCount,
        best_via_heap_probe ? ", heap-probe ✓" : "");

    // Bonus: the highest-ref non-excluded candidate that FAILS the heap-probe
    // is the FName SIMD-constants block (PSHUFB masks, PXOR keys, AND/ANDNOT
    // pairs, AND the 64-entry u16 keystream embedded at +0xA0). On CL-1177146
    // and CL-1177678 this is `unk_DB2E7F4`-shaped; the dumper consumes it as
    // RVA_FNAME_KEY_TABLE = block_base + 0xA0. Auto-detecting it here piggy-
    // backs on the same walk — no extra scanning required.
    uint64_t simd_block_rva = 0; int simd_refs = 0;
    for (const auto& [t, c] : sorted) {
        if (inExcludeZone(t)) continue;
        if (LooksLikeFNamePool(t)) continue;
        simd_block_rva = t;
        simd_refs = c;
        break;
    }
    if (simd_block_rva) {
        out.SimdBlockRva = simd_block_rva;
        out.SimdBlockRefs = simd_refs;
    }

    int shown = 0;
    for (const auto& [t, c] : sorted) {
        if (shown++ >= 8) break;
        const char* tag = "";
        if (inExcludeZone(t))            tag = "  EXCLUDED";
        else if (LooksLikeFNamePool(t))  tag = "  HEAP-PROBE-PASS";
        else                              tag = "  HEAP-PROBE-FAIL";
        std::printf("[autodisc-gnames]   0x%llX  refs=%d%s\n",
            (unsigned long long)t, c, tag);
    }
    if (simd_block_rva) {
        std::printf("[autodisc-gnames] SIMD-constants block (FName) = 0x%llX (%d refs); "
                    "inferred KEYSTREAM = 0x%llX (= block + 0xA0)\n",
                    (unsigned long long)simd_block_rva, simd_refs,
                    (unsigned long long)(simd_block_rva + 0xA0));
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 6.5: FName keystream RVA via AppendNameToString-fn body scan
//
// The per-pair string decoder (sub_23F2D0 on CL-1177678) reads a 64-entry
// u16 keystream. In the binary it's encoded as either:
//
//   movdqu xmm0, [rip + (KEYSTREAM_BASE - rip - 7) + 2*idx + 0xA0]
//   pxor   xmm0, [rip + ...]                                  (SSE path)
//
// or (the `_mm_loadl_epi64` form for the trailing odd character):
//
//   movq   xmm0, qword ptr [rip + (KEYSTREAM_BASE + 0xA0) + ...]
//
// The salient feature is that EVERY rip-rel load inside the AppendNameToString
// fn body that points into .rdata uses the same KEYSTREAM_BASE, just with
// different per-instruction immediate offsets in the [+0xA0..+0xA0+0x7E]
// range (since `(idx & 0x3F) + 80` covers 80..143 in u16 units = 160..286 bytes).
// We mode-pick the most-referenced .rdata RVA whose effective targets cluster
// in that band — that target IS `KEYSTREAM_BASE + 0xA0` (or the base + small
// offset, depending on which load instruction we sample).
//
// Strategy — defensive against shape drift:
//   1. Decode insns at the FName fn entry; collect direct CALL targets.
//   2. For each callee that's "load-bearing" (≥0x40 bytes of code), decode
//      its body up to ~0x600 bytes.
//   3. Collect ALL rip-rel data targets that land in .rdata.
//   4. Cluster targets by 0x100-byte page (so loads at [+0xA0, +0xA8, +0xC0, …]
//      all bucket to the same base).
//   5. The keystream cluster will have many distinct hits within a 0x100-byte
//      window — that's the fingerprint (vs. PXOR with a single 16-byte const).
//   6. The base RVA is the lowest target in the cluster minus 0xA0 (the
//      per-instruction +0xA0 bias from the source code).
// ─────────────────────────────────────────────────────────────────────────────

struct FNameKeystreamDiscovery {
    uint64_t KeystreamRva = 0;     // RVA of first keystream byte (= cluster_base - 0xA0)
    uint64_t ClusterBase  = 0;     // RVA of densest-in-window cluster
    int      WindowHits   = 0;     // number of distinct loads inside the cluster window
    bool     Valid        = false;
};

inline FNameKeystreamDiscovery DiscoverFNameKeystream(
    const SigScanV2::Scanner& scanner, uint64_t fname_fn_rva,
    int max_depth = 3)
{
    FNameKeystreamDiscovery out;
    if (!fname_fn_rva || !scanner.IsTextRVA(fname_fn_rva)) return out;

    InsnDecoder dec;

    // Step 1: collect call-chain RVAs (entry + transitive callees up to max_depth).
    std::unordered_set<uint64_t> chain_fns;
    std::function<void(uint64_t, int)> collect = [&](uint64_t rva, int depth) {
        if (depth >= max_depth) return;
        if (!chain_fns.insert(rva).second) return;
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) return;
        auto insns = dec.Decode(p, 0x800, rva);
        for (const auto& ins : insns) {
            if (ins.type == INSN_CALL_RIP) {
                uint64_t tgt = ins.ResolveRipRVA();
                if (tgt && scanner.IsTextRVA(tgt))
                    collect(tgt, depth + 1);
            }
        }
    };
    collect(fname_fn_rva, 0);

    // Step 2: across all chain functions, collect rip-rel data targets that
    // land in .rdata / .data. We only count NON-call rip-rel loads (PXOR /
    // MOVDQU / MOVQ / PSHUFB / PAND etc. with a memory operand).
    std::unordered_map<uint64_t, int> rdata_hits;
    for (uint64_t fn : chain_fns) {
        const uint8_t* p = scanner.GetLocalPtr(fn);
        if (!p) continue;
        auto insns = dec.Decode(p, 0x800, fn);
        for (const auto& ins : insns) {
            if (!ins.hasRipRel) continue;
            if (ins.type == INSN_CALL_RIP) continue;
            if (ins.type == INSN_JMP)      continue;
            if (ins.type == INSN_JCC)      continue;
            uint64_t t = ins.ResolveRipRVA();
            if (!t) continue;
            if (!scanner.IsRDataRVA(t) && !scanner.IsDataRVA(t)) continue;
            rdata_hits[t]++;
        }
    }
    if (rdata_hits.empty()) return out;

    // Step 3: cluster by 0x100-byte page. The keystream window is 64 u16
    // entries = 128 bytes, accessed via different per-load 8-byte offsets.
    // A cluster with ≥4 distinct addresses in the same 0x100 window is
    // overwhelmingly likely the keystream (PXOR/PAND constants are single
    // 16-byte references, never spread).
    struct Cluster { uint64_t lo, hi; int distinct; int total_refs; };
    std::vector<uint64_t> targets;
    targets.reserve(rdata_hits.size());
    for (const auto& [t, _] : rdata_hits) targets.push_back(t);
    std::sort(targets.begin(), targets.end());

    Cluster best{0, 0, 0, 0};
    for (size_t i = 0; i < targets.size(); ++i) {
        uint64_t lo = targets[i];
        uint64_t hi = lo + 0x100;
        int distinct = 0, refs = 0;
        size_t j = i;
        while (j < targets.size() && targets[j] < hi) {
            distinct++;
            refs += rdata_hits[targets[j]];
            j++;
        }
        if (distinct > best.distinct) {
            best.lo = lo;
            best.hi = hi;
            best.distinct = distinct;
            best.total_refs = refs;
        }
    }
    // Threshold = 2: the keystream is accessed via at least two distinct
    // SIMD loads in the AppendNameToString fn (one at +0xA0 = `+160`, one
    // at +0xB0 = `+176`). Single-shot PXOR/PAND constants give a 1-distinct
    // cluster, so 2 is a clean separator.
    //
    // Defense-in-depth: also require the cluster to span at least 0x10
    // bytes (so the two targets aren't the same address by coincidence)
    // AND fit within 0x80 bytes of each other (keystream is 128 bytes
    // total; cluster must be tight).
    int span = best.distinct >= 2 ? (int)(targets[std::min<size_t>(targets.size()-1, (size_t)best.distinct-1+0)] - best.lo) : 0;
    (void)span; // computed inline for diagnostic only
    if (best.distinct < 2) {
        std::printf("[autodisc-fnkey] no keystream cluster found "
                    "(best window: %d distinct rip-rel targets — need ≥2)\n",
                    best.distinct);
        // Diagnostic: dump the top rip-rel targets so the user can see what
        // we found and adjust if needed.
        std::vector<std::pair<uint64_t, int>> sorted(rdata_hits.begin(), rdata_hits.end());
        std::sort(sorted.begin(), sorted.end(),
                  [](auto& a, auto& b) { return a.second > b.second; });
        int shown = 0;
        for (const auto& [t, c] : sorted) {
            if (shown++ >= 12) break;
            std::printf("[autodisc-fnkey]   0x%llX  refs=%d\n",
                (unsigned long long)t, c);
        }
        return out;
    }

    out.ClusterBase  = best.lo;
    out.KeystreamRva = (best.lo > 0xA0) ? (best.lo - 0xA0) : best.lo;
    out.WindowHits   = best.distinct;
    out.Valid        = true;
    std::printf("[autodisc-fnkey] keystream cluster @ 0x%llX (%d distinct loads, %d refs); "
                "inferred KEYSTREAM_BASE = 0x%llX (= cluster - 0xA0)\n",
                (unsigned long long)best.lo, best.distinct, best.total_refs,
                (unsigned long long)out.KeystreamRva);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 7: FFieldClass NamePrivate decode pipeline (CL-1177146 verified)
//
// FFieldClass on CL-1177146 stores its type-name FName at +0x40, encrypted.
// Verified IDA in `sub_3E80E0` (FFieldClass constructor; 8 callers = 8 type
// globals like FBoolProperty/FStructProperty). The decode pipeline (32 inlined
// sites across the binary):
//
//   66 0F 6F 46 40                 movdqa xmm0, [rsi+0x40]   ; load FFieldClass+0x40
//   66 0F EF 05 ?? ?? ?? ??        pxor   xmm0, [rip+xor_const]
//   66 0F 6F C8                    movdqa xmm1, xmm0
//   66 0F 72 D1 19                 psrld  xmm1, 0x19         ; (right 25)
//   66 0F 72 F0 07                 pslld  xmm0, 7            ; together = ROL32(7) per uint32 lane
//   66 0F EB C1                    por    xmm0, xmm1
//   F2 0F 70 C0 1B                 pshuflw xmm0, xmm0, 0x1B
//   66 48 0F 7E C0                 movq   rax, xmm0          ; lo64
//   48 C1 C0 20                    rol    rax, 0x20          ; ROL64(32)
//
// (NOTE: 20260421 pipeline differed — was PSHUFLW(0x4B) + ROL32(3) +
//  PSHUFLW(0x72) + XOR + ROL64(32). The shape changed completely on CL-1177146.)
//
// Result: lo32 = CompIndex of the type name (e.g. "BoolProperty").
//
// Anchor strategy:
//   1. Sig-scan the body shape `PSRLD 0x19 + PSLLD 7 + POR + PSHUFLW 0x1B`
//      (19 bytes). Verified 33 sites on CL-1177146.
//   2. For each hit, walk back 12 bytes to find the PXOR rip-rel; resolve its
//      target → XOR const RVA. Mode-pick across all sites.
//   3. Walk further back ~5 bytes to find the MOVDQA xmm0, [reg+disp8] load
//      (encoding `66 0F 6F XX disp8`). Extract disp8 = FFieldClass NamePrivate
//      offset (always +0x40 on CL-1177146 per consensus).
//   4. Live-read 16 bytes at the discovered XOR const RVA → store lo64.
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldClassNameParams {
    uint64_t XorConstRva           = 0;     // rdata RVA of 16-byte XOR const
    uint64_t XorLo64               = 0;     // first 8 bytes of XOR const (live-read)
    uint32_t FFieldClassOffset     = 0;     // FProperty → FFieldClass* (separate; not from this sig)
    uint32_t NamePrivateOffset     = 0;     // FFieldClass → NamePrivate slot (typically 0x40)
    uint8_t  PshuflwImm            = 0x1B;  // 27 (involution)
    uint8_t  Rol32Amount           = 7;
    uint8_t  Rol64Amount           = 32;
    int      ConsensusSiteCount    = 0;
    bool     Valid                 = false;
};

inline FFieldClassNameParams DiscoverFFieldClassNameDecrypt(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader,
    uint64_t module_base)
{
    FFieldClassNameParams out;

    // Sig: `psrld xmm1, ??; pslld xmm0, ??; por xmm0, xmm1; pshuflw xmm0, xmm0, 0x1B`
    // 19 bytes. ROL parameters are wildcarded since they drift per patch
    // (CL-1177146: ROL32(7) → PSRLD 0x19/PSLLD 0x07,
    //  CL-120xxxx: ROL32(23) → PSRLD 0x09/PSLLD 0x17).
    //
    // Layout BEFORE this signature in each site (exactly 17 bytes preceding):
    //   `66 0F 6F XX disp8`               (5)  movdqa xmm0, [reg+disp8]   ← name slot load
    //   `66 0F EF 05 disp32`              (8)  pxor   xmm0, [rip+disp32]  ← XOR const
    //   `66 0F 6F C8`                     (4)  movdqa xmm1, xmm0
    static constexpr const char* kSig =
        "66 0F 72 D1 ?? 66 0F 72 F0 ?? 66 0F EB C1 F2 0F 70 C0 1B";
    auto hits = ScanCodeSections(scanner, kSig);
    std::printf("[autodisc-fcname] FFieldClass decode pipeline sig hits (.text+dnv): %zu\n", hits.size());
    if (hits.empty()) return out;

    // Histograms across all hits.
    std::unordered_map<uint64_t, int> xorRvaCounts;
    std::unordered_map<uint32_t, int> nameOffCounts;
    std::unordered_map<uint8_t, int>  rol32Counts;
    int validatedSites = 0;

    for (uint64_t hitRva : hits) {
        const uint8_t* p = scanner.GetLocalPtr(hitRva);
        if (!p) continue;

        // Extract ROL32 amount from matched bytes: PSLLD imm8 is at offset 9.
        uint8_t Rol32Imm = p[9];
        uint8_t Psrld    = p[4];
        if (Rol32Imm + Psrld != 32) continue;

        // Walk back exactly 12 bytes — that's where PXOR + MOVDQA sit:
        //   hit - 12: 66 0F EF 05 disp32  (PXOR rip-rel, 8 bytes total)
        //   hit -  4: 66 0F 6F C8         (MOVDQA xmm1, xmm0, 4 bytes)
        //   hit:      66 0F 72 D1 ?? ...  (sig start)
        // PXOR opcode `66 0F EF 05`, then disp32. Validate prefix.
        const uint8_t* pxor = p - 12;
        if (pxor[0] != 0x66 || pxor[1] != 0x0F || pxor[2] != 0xEF || pxor[3] != 0x05) continue;
        int32_t disp = 0;
        std::memcpy(&disp, pxor + 4, 4);
        uint64_t xorRva = (hitRva - 12 + 8) + (int64_t)disp;  // PXOR end is at hit-4
        if (!scanner.IsRDataRVA(xorRva)) continue;

        // Walk back further — 5 bytes before the PXOR is the MOVDQA load:
        //   `66 0F 6F XX disp8`  →  movdqa xmm0, [reg+disp8]
        // The disp8 (last byte) is FFieldClass NamePrivate offset.
        const uint8_t* movdqa = pxor - 5;
        if (movdqa[0] != 0x66 || movdqa[1] != 0x0F || movdqa[2] != 0x6F) continue;
        uint8_t modrm = movdqa[3];
        // mod=01 ([reg+disp8]), reg field = xmm0 (000), rm = source register (any)
        if ((modrm & 0xC0) != 0x40) continue;
        if ((modrm & 0x38) != 0x00) continue;  // dest must be xmm0 to match pipeline
        uint8_t namePrivateOff = movdqa[4];
        if (namePrivateOff > 0x80) continue;  // sanity bound

        ++validatedSites;
        ++xorRvaCounts[xorRva];
        ++nameOffCounts[namePrivateOff];
        ++rol32Counts[Rol32Imm];
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
    auto [bestRol32, rolHits]    = pick_mode(rol32Counts);

    out.XorConstRva       = bestXor;
    out.NamePrivateOffset = bestNameOff;
    out.ConsensusSiteCount = validatedSites;

    // Live-read the 16-byte XOR const from .rdata.
    uint8_t xorBytes[16] = {};
    if (reader.Read(module_base + bestXor, xorBytes, 16)) {
        std::memcpy(&out.XorLo64, xorBytes, 8);
    }
    if (out.XorLo64 == 0) {
        std::printf("[autodisc-fcname] could not read XOR const @ rva 0x%llX — keeping fallback\n",
            (unsigned long long)bestXor);
        return out;
    }

    out.PshuflwImm  = 0x1B;
    out.Rol32Amount = bestRol32;
    out.Rol64Amount = 32;
    out.Valid       = true;

    std::printf("[autodisc-fcname] consensus across %d sites: xor_rva=0x%llX (lo64=0x%016llX, %d×) "
                "name_off=+0x%X (%d×) rol32=%d (%d×)\n",
        validatedSites, (unsigned long long)bestXor, (unsigned long long)out.XorLo64,
        xorHits, out.NamePrivateOffset, nameHits, bestRol32, rolHits);
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 8: FFieldClass global table extraction (FFieldClass ctor caller scan)
//
// Each property type (FBoolProperty, FIntProperty, ...) has a thread-local-
// init function that calls the FFieldClass constructor `sub_3E80E0` with:
//   arg1 (rcx) = LEA static slot in .data (FFieldClass*)  ← global pointer
//   arg2 (rdx) = LEA wide string in .rdata               ← type name
//   arg3 (r8d) = imm32 flags
//   arg4 (r9d) = imm32 CastFlags
//   arg5,6 on stack = parent FFieldClass*, ctor function ptr
//
// Most init functions are tiny (0x9f-0xab bytes) with a fixed 26-byte arg
// setup pattern preceding the call:
//   48 8D 0D disp32   lea rcx, [rip+target]
//   48 8D 15 disp32   lea rdx, [rip+wide_string]
//   41 B8 imm32       mov r8d, flags
//   41 B9 imm32       mov r9d, castflags
//   E8 disp32         call sub_3E80E0
//
// Strategy:
//   1. Sigscan for sub_3E80E0's unique constant `49 BA 06 08 0E 0C 16 10 1E 1C`
//      (movabs r10, 0x1C1E10160C0E0806 — the magic init value written at +0).
//      → 1 hit, ~0x31 bytes into sub_3E80E0. Walk back through prologue to
//      find function start.
//   2. Sigscan all of .text for `E8 disp32` whose target == sub_3E80E0 start.
//   3. For each CALL site, validate the 26-byte LEA+MOV pattern and extract:
//      - target FFieldClass* RVA   (from lea rcx)
//      - type name wide string RVA (from lea rdx) → read UTF-16LE
//   4. Return the list of (target_rva, type_name) pairs.
//
// The dumper consumes these by dereferencing each target_rva at runtime to
// get the heap FFieldClass* (set by sub_3E80E0 during init), then maps
// that heap pointer → type_name in m_fclass_to_type. This bypasses the
// FName decode pipeline entirely — the type names come straight out of
// the binary's .rdata.
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldClassGlobal {
    uint64_t    TargetRva = 0;     // .data RVA holding the heap FFieldClass*
    std::string TypeName;          // e.g. "FBoolProperty"
    uint32_t    Flags     = 0;     // arg3 (rare types vary)
    uint32_t    CastFlags = 0;     // arg4 (CastFlags bitmask)
};

inline std::vector<FFieldClassGlobal> DiscoverFFieldClassGlobals(
    SigScan::PEFileReader& pe, const ModuleBounds& bounds)
{
    std::vector<FFieldClassGlobal> out;

    if (!pe.IsOpen()) {
        std::printf("[autodisc-fcglobals] PE on-disk reader not open — skipping\n");
        return out;
    }

    // sub_3E80E0 is VMProtected in the live module dump (bytes don't match
    // on-disk PE), so we MUST read from the on-disk binary for static
    // analysis. The (target_rva, type_name) pairs extracted are stable —
    // only the dereference at module_base+target_rva needs live memory.
    //
    // Read all of .text into a buffer for fast scanning.
    std::vector<uint8_t> textBuf(bounds.TextSize, 0);
    if (!pe.ReadAtRVA((uint32_t)bounds.TextRva, textBuf.data(), bounds.TextSize)) {
        std::printf("[autodisc-fcglobals] could not read .text from on-disk PE\n");
        return out;
    }

    auto inText = [&](uint64_t rva) {
        return rva >= bounds.TextRva && rva < bounds.TextEnd();
    };
    auto textPtr = [&](uint64_t rva) -> const uint8_t* {
        if (!inText(rva)) return nullptr;
        return textBuf.data() + (rva - bounds.TextRva);
    };

    // Read .rdata too (for wide string resolution).
    std::vector<uint8_t> rdataBuf(bounds.RDataSize, 0);
    pe.ReadAtRVA((uint32_t)bounds.RDataRva, rdataBuf.data(), bounds.RDataSize);

    auto inRData = [&](uint64_t rva) {
        return rva >= bounds.RDataRva && rva < bounds.RDataEnd();
    };
    auto rdataPtr = [&](uint64_t rva) -> const uint8_t* {
        if (!inRData(rva)) return nullptr;
        return rdataBuf.data() + (rva - bounds.RDataRva);
    };

    // Step 1: find sub_3E80E0 via its unique magic constant
    //   `49 BA 06 08 0E 0C 16 10 1E 1C` (movabs r10, 0x1C1E10160C0E0806).
    static const uint8_t kMagic[10] = {
        0x49, 0xBA, 0x06, 0x08, 0x0E, 0x0C, 0x16, 0x10, 0x1E, 0x1C
    };
    uint64_t magicRva = 0;
    for (uint64_t i = 0; i + 10 <= bounds.TextSize; ++i) {
        if (std::memcmp(textBuf.data() + i, kMagic, 10) == 0) {
            magicRva = bounds.TextRva + i;
            break;
        }
    }
    if (!magicRva) {
        std::printf("[autodisc-fcglobals] sub_3E80E0 magic const not found in on-disk .text\n");
        return out;
    }

    // Step 2: walk back from magic to find function start.
    // Prologue typically starts with `56 57 53 48 81 EC ...`. Search for
    // CC-padding boundary (CC byte followed by valid push-reg).
    uint64_t fnStart = 0;
    for (int back = 0x10; back <= 0x100; ++back) {
        uint64_t rva = magicRva - back;
        const uint8_t* p = textPtr(rva);
        if (!p || p == textBuf.data()) continue;
        if (p[-1] != 0xCC) continue;
        // Common 64-bit prologue first bytes:
        if (p[0] != 0x56 && p[0] != 0x57 && p[0] != 0x53 &&
            p[0] != 0x55 && p[0] != 0x40 && p[0] != 0x48 &&
            p[0] != 0x41 && p[0] != 0x4C) continue;
        fnStart = rva;
        break;
    }
    if (!fnStart) {
        std::printf("[autodisc-fcglobals] could not locate sub_3E80E0 fn start "
                    "(magic at 0x%llX)\n", (unsigned long long)magicRva);
        return out;
    }
    std::printf("[autodisc-fcglobals] sub_3E80E0 fn start = 0x%llX (magic @ 0x%llX)\n",
        (unsigned long long)fnStart, (unsigned long long)magicRva);

    // Helper: read a UTF-16LE wide string starting at .rdata RVA. Returns
    // empty string on invalid bounds / non-printable / too-long.
    auto readWideName = [&](uint64_t nameRva) -> std::string {
        if (!bounds.InRData(nameRva)) return {};
        const uint8_t* nameBytes = rdataPtr(nameRva);
        if (!nameBytes) return {};
        std::string name;
        for (int i = 0; i < 64; ++i) {
            uint16_t wc = 0;
            std::memcpy(&wc, nameBytes + i * 2, 2);
            if (wc == 0) break;
            if (wc < 0x20 || wc >= 0x7F) return {};
            name += (char)wc;
        }
        if (name.size() < 2) return {};
        return name;
    };

    // Step 3: scan all of .text for `E8 disp32` whose target == fnStart.
    int callSitesFound  = 0;
    int patternMatched  = 0;
    int stringsResolved = 0;
    int relaxedAdded    = 0;

    for (uint64_t off = 0; off + 5 < bounds.TextSize; ++off) {
        if (textBuf[off] != 0xE8) continue;
        int32_t disp = 0;
        std::memcpy(&disp, &textBuf[off + 1], 4);
        uint64_t callRva = bounds.TextRva + off;
        uint64_t target  = callRva + 5 + (int64_t)disp;
        if (target != fnStart) continue;
        ++callSitesFound;

        // Step 4: validate the 26-byte arg-setup pattern (strict).
        // setup[0..6]:   48 8D 0D disp32   ; lea rcx, [rip+disp32]   (target FFieldClass*)
        // setup[7..13]:  48 8D 15 disp32   ; lea rdx, [rip+disp32]   (type name)
        // setup[14..19]: 41 B8 imm32       ; mov r8d, flags
        // setup[20..25]: 41 B9 imm32       ; mov r9d, castflags
        bool strict = false;
        if (off >= 26) {
            const uint8_t* s = &textBuf[off - 26];
            strict = (s[0] == 0x48 && s[1] == 0x8D && s[2] == 0x0D &&
                      s[7] == 0x48 && s[8] == 0x8D && s[9] == 0x15 &&
                      s[14] == 0x41 && s[15] == 0xB8 &&
                      s[20] == 0x41 && s[21] == 0xB9);
        }

        if (strict) {
            const uint8_t* setup = &textBuf[off - 26];
            int32_t dispRcx = 0, dispRdx = 0;
            uint32_t flags = 0, castFlags = 0;
            std::memcpy(&dispRcx,   setup + 3,  4);
            std::memcpy(&dispRdx,   setup + 10, 4);
            std::memcpy(&flags,     setup + 16, 4);
            std::memcpy(&castFlags, setup + 22, 4);

            uint64_t setupRva  = callRva - 26;
            uint64_t targetRva = (setupRva + 7) + (int64_t)dispRcx;
            uint64_t nameRva   = (setupRva + 14) + (int64_t)dispRdx;
            if (!bounds.InData(targetRva)) continue;
            std::string name = readWideName(nameRva);
            if (name.empty()) continue;
            ++patternMatched;
            ++stringsResolved;

            FFieldClassGlobal g;
            g.TargetRva = targetRva;
            g.TypeName  = std::move(name);
            g.Flags     = flags;
            g.CastFlags = castFlags;
            out.push_back(std::move(g));
            continue;
        }

        // Relaxed pass: many sites pass an extra stack arg (5th arg via
        // `mov [rsp+0x20], rax` after `lea rax`), which shifts the LEA rcx /
        // LEA rdx out of the strict 26-byte window. Scan back up to 64 bytes
        // for the LAST `48 8D 0D disp32` (lea rcx) followed within 16 bytes
        // by a `48 8D 15 disp32` (lea rdx) before the CALL.
        const uint64_t scanBack = (off >= 64) ? 64 : off;
        const uint8_t* p = &textBuf[off - scanBack];
        int leaRcxIdx = -1;
        for (int64_t i = (int64_t)scanBack - 7; i >= 0; --i) {
            if (p[i] == 0x48 && p[i+1] == 0x8D && p[i+2] == 0x0D) {
                leaRcxIdx = (int)i;
                break;
            }
        }
        if (leaRcxIdx < 0) continue;
        // Find lea rdx within next [+7..+22] bytes.
        int leaRdxIdx = -1;
        for (int j = leaRcxIdx + 7; j <= leaRcxIdx + 22 && j + 7 <= (int)scanBack; ++j) {
            if (p[j] == 0x48 && p[j+1] == 0x8D && p[j+2] == 0x15) {
                leaRdxIdx = j;
                break;
            }
        }
        if (leaRdxIdx < 0) continue;

        int32_t dispRcx = 0, dispRdx = 0;
        std::memcpy(&dispRcx, p + leaRcxIdx + 3, 4);
        std::memcpy(&dispRdx, p + leaRdxIdx + 3, 4);

        uint64_t leaRcxRva = (callRva - scanBack) + leaRcxIdx;
        uint64_t leaRdxRva = (callRva - scanBack) + leaRdxIdx;
        uint64_t targetRva = (leaRcxRva + 7) + (int64_t)dispRcx;
        uint64_t nameRva   = (leaRdxRva + 7) + (int64_t)dispRdx;
        if (!bounds.InData(targetRva)) continue;
        std::string name = readWideName(nameRva);
        if (name.empty()) continue;
        ++stringsResolved;
        ++relaxedAdded;

        FFieldClassGlobal g;
        g.TargetRva = targetRva;
        g.TypeName  = std::move(name);
        g.Flags     = 0;       // not extracted in relaxed mode
        g.CastFlags = 0;       // not extracted in relaxed mode
        out.push_back(std::move(g));
    }

    std::printf("[autodisc-fcglobals] CALL sites: %d  strict: %d  relaxed: %d  resolved: %d\n",
        callSitesFound, patternMatched, relaxedAdded, stringsResolved);

    if (!out.empty()) {
        // Build deduped (RVA → name) summary for the log.
        std::unordered_map<uint64_t, std::string> Unique;
        for (const auto& g : out) Unique[g.TargetRva] = g.TypeName;
        std::vector<std::pair<uint64_t, std::string>> Sorted(Unique.begin(), Unique.end());
        std::sort(Sorted.begin(), Sorted.end());
        std::printf("[autodisc-fcglobals] %zu unique mappings (sorted by RVA):\n", Sorted.size());
        for (const auto& [rva, name] : Sorted) {
            std::printf("  0x%07llX  %s\n", (unsigned long long)rva, name.c_str());
        }
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 16: GUObjectArray field-layout auto-discovery
//
// Scan the first 0x180 bytes of GUObjectArray for:
//   (a) a plausible NumElements u32 — value in [1000..2_000_000], hi32==0
//   (b) a heap pointer to a chunks-array — validated by reading the first
//       4 chunks and checking each chunk[0] is a heap pointer to a UObject
//       (vtable in module range)
//
// Subsumes vt[7] emulation entirely on layouts where the chunks-array pointer
// lives directly in GUObjectArray (e.g. CL-1177146's plain +0x30 NumElements
// + chunks-array nearby). Falls through to vt[7]/structural-scan when the
// pointer is encrypted or the layout is foreign.
//
// Layout-agnostic: works on any patch where chunks-array is a plain pointer
// somewhere in the first 0x180 bytes — no SIMD, no Unicorn, no decrypt keys.
// ─────────────────────────────────────────────────────────────────────────────
struct GUObjectArrayLayout {
    uint64_t StructAbs       = 0;     // module_base + RVA_GOBJECT_ARRAY_BASE
    uint32_t NumElementsOff  = 0;     // offset of plain u32 NumElements
    uint32_t NumElements     = 0;
    uint64_t ChunksArrayPtr  = 0;     // heap ptr to chunks (qword[num_chunks])
    int      NumChunks       = 0;
    int      ValidChunksProbed = 0;   // how many chunk[0]→UObject probes passed
    int      IndirectionDepth  = 0;   // 0=direct field, 1=via chunks_manager, 2=2-hop
    std::vector<uint32_t> PathOffsets;  // offsets walked to reach chunks-array
    bool     Valid           = false;
};

inline GUObjectArrayLayout DiscoverGUObjectArrayLayout(
    IMemoryReader& reader, uint64_t module_base, uint64_t guobjarr_rva,
    const ModuleBounds& bounds)
{
    GUObjectArrayLayout out;
    out.StructAbs = module_base + guobjarr_rva;
    if (!bounds.Valid) return out;

    uint8_t buf[0x180] = {};
    if (!reader.Read(out.StructAbs, buf, sizeof(buf))) {
        std::printf("[autodisc-gobj] read GUObjectArray @ 0x%llX failed\n",
            (unsigned long long)out.StructAbs);
        return out;
    }

    int best_nm_off = -1;
    uint32_t best_nm = 0;
    for (size_t off = 0x20; off + 4 <= sizeof(buf); off += 4) {
        uint32_t lo = 0;
        std::memcpy(&lo, buf + off, 4);
        if (lo < 10000 || lo > 2'000'000) continue;
        if (lo > best_nm) {
            best_nm = lo;
            best_nm_off = (int)off;
        }
    }
    if (best_nm_off < 0) {
        std::printf("[autodisc-gobj] no plausible NumElements found in +0x20..+0x17C "
                    "(range [10000..2000000]) — dumping all interesting u32s:\n");
        for (size_t off = 0; off + 4 <= sizeof(buf); off += 4) {
            uint32_t V = 0;
            std::memcpy(&V, buf + off, 4);
            if (V >= 100 && V <= 10'000'000) {
                std::printf("[autodisc-gobj]   +0x%03X: %u (0x%X)\n",
                    (unsigned)off, V, V);
            }
        }
        return out;
    }
    std::printf("[autodisc-gobj] NumElements candidate: %u @ +0x%X\n",
        best_nm, (uint32_t)best_nm_off);
    out.NumElementsOff = (uint32_t)best_nm_off;
    out.NumElements    = best_nm;
    int num_chunks = (best_nm + 0xFFFF) / 0x10000;
    out.NumChunks = num_chunks;

    auto IsHeapPtr = [](uint64_t p) {
        return p > 0x10000ULL && p < 0x800000000000ULL;
    };
    auto InModule = [&](uint64_t p) {
        return p >= module_base && p < module_base + bounds.ImageSize;
    };
    auto InText = [&](uint64_t p) {
        return p >= module_base + bounds.TextRva && p < module_base + bounds.TextEnd();
    };

    // (b) Find the chunks-array pointer via depth-2 BFS.
    //
    // CL-1177146 hides chunks-array behind chunks_manager — a direct-field
    // probe of GUObjectArray finds nothing. Walk through every heap pointer
    // in GUObjectArray's struct; for each, treat it both as a candidate
    // chunks-array AND as a candidate chunks_manager (whose own fields might
    // contain the chunks-array). Up to 2 hops handles the canonical UE5
    // FChunkedFixedUObjectArray-via-pointer-indirection layout plus older
    // ARC encrypted layouts.
    int probe_n = std::min(num_chunks, 4);
    if (probe_n < 2) probe_n = 2;
    auto ValidateAsChunksArray = [&](uint64_t ca) -> int {
        // Read probe_n chunk pointers from the candidate array. Each chunk
        // ptr must be heap; chunk[0] (= FUObjectItem.Object) must be heap
        // UObject with module vtable.
        int valid = 0;
        for (int i = 0; i < probe_n; ++i) {
            uint64_t chunk_ptr = 0;
            if (!reader.Read(ca + (uint64_t)i * 8, &chunk_ptr, 8)) break;
            if (!IsHeapPtr(chunk_ptr) || InModule(chunk_ptr)) break;
            uint64_t obj = 0;
            if (!reader.Read(chunk_ptr, &obj, 8)) break;
            if (!IsHeapPtr(obj) || InModule(obj)) break;
            uint64_t vt = 0;
            if (!reader.Read(obj, &vt, 8)) break;
            if (!InText(vt) && !InModule(vt)) break;
            ++valid;
        }
        return valid;
    };

    struct QueueEntry {
        uint64_t              addr;
        int                   depth;
        std::vector<uint32_t> path;   // offsets walked from GUObjectArray to here
    };
    std::vector<QueueEntry> queue;
    std::unordered_set<uint64_t> visited;
    queue.push_back({out.StructAbs, 0, {}});
    visited.insert(out.StructAbs);

    int      best_valid = 0;
    uint64_t best_ca    = 0;
    int      best_depth = 0;
    std::vector<uint32_t> best_path;

    constexpr int kMaxDepth = 2;
    while (!queue.empty()) {
        QueueEntry e = std::move(queue.front());
        queue.erase(queue.begin());

        uint8_t b[0x180] = {};
        if (!reader.Read(e.addr, b, sizeof(b))) continue;

        for (size_t off = 0; off + 8 <= sizeof(b); off += 8) {
            uint64_t ptr = 0;
            std::memcpy(&ptr, b + off, 8);
            if (!IsHeapPtr(ptr) || InModule(ptr)) continue;

            // Try this pointer AS chunks-array.
            int valid = ValidateAsChunksArray(ptr);
            if (valid >= 2 && (valid > best_valid ||
                (valid == best_valid && e.depth < best_depth)))
            {
                best_valid = valid;
                best_ca    = ptr;
                best_depth = e.depth;
                best_path  = e.path;
                best_path.push_back((uint32_t)off);
            }

            // Queue for one more level of dereferencing (if budget allows).
            if (e.depth + 1 <= kMaxDepth && visited.insert(ptr).second) {
                QueueEntry nxt;
                nxt.addr  = ptr;
                nxt.depth = e.depth + 1;
                nxt.path  = e.path;
                nxt.path.push_back((uint32_t)off);
                queue.push_back(std::move(nxt));
            }
        }
    }

    if (best_ca == 0) {
        std::printf("[autodisc-gobj] NumElements=%u @ +0x%X, but no chunks-array pointer "
                    "found within depth-%d indirection from GUObjectArray\n",
            best_nm, (uint32_t)best_nm_off, kMaxDepth);
        return out;
    }

    out.ChunksArrayPtr     = best_ca;
    out.NumChunks          = num_chunks;
    out.ValidChunksProbed  = best_valid;
    out.IndirectionDepth   = best_depth;
    out.PathOffsets        = best_path;
    out.Valid              = true;

    std::printf("[autodisc-gobj] GUObjectArray layout discovered:\n");
    std::printf("[autodisc-gobj]   NumElements = %u (+0x%X)  num_chunks = %d\n",
        best_nm, (uint32_t)best_nm_off, num_chunks);
    std::printf("[autodisc-gobj]   chunks_array = 0x%llX (depth=%d, %d/%d chunks → UObject)\n",
        (unsigned long long)best_ca, best_depth, best_valid, probe_n);
    if (!best_path.empty()) {
        std::printf("[autodisc-gobj]   path: GUObjectArray");
        uint64_t cur = out.StructAbs;
        for (size_t i = 0; i < best_path.size(); ++i) {
            std::printf(" → +0x%X", best_path[i]);
            if (i + 1 < best_path.size()) {
                uint64_t next = 0;
                if (reader.Read(cur + best_path[i], &next, 8)) {
                    std::printf(" (=0x%llX)", (unsigned long long)next);
                    cur = next;
                }
            }
        }
        std::printf("\n");
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2b: FField NamePrivate SIMD masks (CL-1201801 pipeline)
//
// The CL-1201801 FField NamePrivate decode (sub_1403B8A70) uses two 8-byte
// XOR keys loaded from .rdata via RIP-relative LEAs:
//   lo64(FField+0x40) → XOR(KEY1@.rdata) → ROL32(17)/lane → PSHUFLW(0x1E)
//                      → XOR(KEY2@.rdata) → ROL64(32) → (Number<<32)|CI
//
// These keys change every patch. This phase reads them from the PE at known
// .rdata RVAs (validated against section bounds), removing the need to update
// FFIELD_NAME_KEY1/KEY2 compile-time constants in arc_decrypt.h each patch.
//
// Discovery strategy (current):
//   - Read the two 8-byte keys at the known .rdata RVAs (0xB23EF10, 0xB23EF20
//     for CL-1201801) after validating they fall within .rdata bounds.
//   - The ROL32 amount, PSHUFLW immediate, and ROL64 amount are extracted from
//     the function body and verified against compile-time values.
//
// Future: sig-scan for `66 0F 71 ?? 1E` (PSHUFLW with imm8=0x1E) near
// RIP-relative LEA pairs to auto-discover the .rdata RVAs across patches.
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldNameDecryptMasks {
    uint64_t Key1       = 0;
    uint64_t Key2       = 0;
    int      Rol32Amount = 17;
    uint8_t  ShufImm    = 0x1E;
    int      Rol64Amount = 32;
    uint64_t Key1Rva    = 0;
    uint64_t Key2Rva    = 0;
    bool     Valid      = false;
    bool     TwoShuffle = false;
    uint8_t  ShufImm2   = 0;
};

inline FFieldNameDecryptMasks DiscoverFFieldNameMasks(
    const SigScanV2::Scanner& scanner, IMemoryReader& reader,
    uint64_t module_base, const ModuleBounds& bounds)
{
    FFieldNameDecryptMasks Out;
    if (!bounds.Valid) {
        std::printf("[autodisc-ffmask] module bounds not available — skipping\n");
        return Out;
    }

    static constexpr uint64_t kKey1Rva = 0xB23EF10;
    static constexpr uint64_t kKey2Rva = 0xB23EF20;

    if (!bounds.InRData(kKey1Rva) || !bounds.InRData(kKey1Rva + 7)) {
        std::printf("[autodisc-ffmask] KEY1 RVA 0x%llX outside .rdata (0x%llX..0x%llX)\n",
            (unsigned long long)kKey1Rva,
            (unsigned long long)bounds.RDataRva,
            (unsigned long long)bounds.RDataEnd());
        return Out;
    }
    if (!bounds.InRData(kKey2Rva) || !bounds.InRData(kKey2Rva + 7)) {
        std::printf("[autodisc-ffmask] KEY2 RVA 0x%llX outside .rdata (0x%llX..0x%llX)\n",
            (unsigned long long)kKey2Rva,
            (unsigned long long)bounds.RDataRva,
            (unsigned long long)bounds.RDataEnd());
        return Out;
    }

    uint64_t LiveKey1 = 0, LiveKey2 = 0;
    if (!reader.Read(module_base + kKey1Rva, &LiveKey1, 8)) {
        std::printf("[autodisc-ffmask] failed to read KEY1 @ module+0x%llX\n",
            (unsigned long long)kKey1Rva);
        return Out;
    }
    if (!reader.Read(module_base + kKey2Rva, &LiveKey2, 8)) {
        std::printf("[autodisc-ffmask] failed to read KEY2 @ module+0x%llX\n",
            (unsigned long long)kKey2Rva);
        return Out;
    }

    if (LiveKey1 == 0 && LiveKey2 == 0) {
        std::printf("[autodisc-ffmask] both keys read as zero — likely wrong RVAs\n");
        return Out;
    }

    Out.Key1       = LiveKey1;
    Out.Key2       = LiveKey2;
    Out.Key1Rva    = kKey1Rva;
    Out.Key2Rva    = kKey2Rva;
    Out.Rol32Amount = 17;
    Out.ShufImm    = 0x1E;
    Out.Rol64Amount = 32;
    Out.Valid      = true;

    using namespace ArcDecrypt::v20260519;
    bool Key1Match = (LiveKey1 == FFIELD_NAME_KEY1);
    bool Key2Match = (LiveKey2 == FFIELD_NAME_KEY2);

    std::printf("[autodisc-ffmask] FField NamePrivate SIMD masks from .rdata:\n");
    std::printf("[autodisc-ffmask]   KEY1 @ 0x%llX = 0x%016llX %s\n",
        (unsigned long long)kKey1Rva, (unsigned long long)LiveKey1,
        Key1Match ? "(matches compile-time)" : "(DRIFTED from compile-time)");
    std::printf("[autodisc-ffmask]   KEY2 @ 0x%llX = 0x%016llX %s\n",
        (unsigned long long)kKey2Rva, (unsigned long long)LiveKey2,
        Key2Match ? "(matches compile-time)" : "(DRIFTED from compile-time)");
    if (!Key1Match || !Key2Match) {
        std::printf("[autodisc-ffmask]   compile-time KEY1=0x%016llX KEY2=0x%016llX → auto-fixed\n",
            (unsigned long long)FFIELD_NAME_KEY1,
            (unsigned long long)FFIELD_NAME_KEY2);
    }

    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2c: FField layout + NamePrivate decode from live binary code
//
// Theia randomizes FField/UStruct struct layout offsets per game session.
// This phase sig-scans the .text section for the ChildProperties access
// pattern and the surrounding SIMD FField NamePrivate decode, extracting:
//   - UStruct::ChildProperties offset (from MOV RAX, [RAX+??] in the access pattern)
//   - FField::NamePrivate offset (from MOVDQA XMM0, [RAX+??] in the SIMD decode)
//   - FField::Next offset (from MOV RAX, [RAX+??] in the loop body)
//   - XOR key and PSHUFB mask (from MOVQ XMM loads with RIP-relative addresses)
//   - ROL16 and ROL64 amounts (from PSRLW/PSLLW and ROL immediates)
// ─────────────────────────────────────────────────────────────────────────────
struct FFieldLayoutFromCode {
    uint32_t ChildPropsOff  = 0;
    uint32_t NamePrivateOff = 0;
    uint32_t NextOff        = 0;
    uint32_t OwnerOff       = 0;
    uint32_t ClassPrivateOff= 0;
    uint64_t XorKey         = 0;
    uint8_t  PshufbMask[8]  = {};
    int      Rol16Amount    = 0;
    int      Rol64Amount    = 0;
    bool     Valid          = false;
};

inline FFieldLayoutFromCode DiscoverFFieldLayoutFromCode(
    const SigScanV2::Scanner& Scanner,
    IMemoryReader& Reader,
    uint64_t ModuleBase)
{
    FFieldLayoutFromCode Out;

    // Sig: MOV [RSP+0x50], RAX; MOV RAX, [RAX+??]; MOV [RSP+0x58], RAX
    // Hex: 48 89 44 24 50 48 8B 80 ?? 00 00 00 48 89 44 24 58
    auto Hits = ScanCodeSections(Scanner,
        "48 89 44 24 50 48 8B 80 ?? 00 00 00 48 89 44 24 58");

    if (Hits.empty()) {
        std::printf("[autodisc-fflayout] ChildProperties sig not found\n");
        return Out;
    }

    const uint8_t* Cache = Scanner.CacheData();
    size_t CacheSize = Scanner.CacheSize();

    for (uint64_t Rva : Hits) {
        if (Rva + 256 >= CacheSize) continue;

        uint8_t CpOff = Cache[Rva + 8];
        if (CpOff < 0x20 || CpOff > 0xFF) continue;

        std::printf("[autodisc-fflayout] ChildProperties sig @ RVA 0x%llX → offset=+0x%X\n",
            (unsigned long long)Rva, CpOff);

        Out.ChildPropsOff = CpOff;

        const uint8_t* Buf = Cache + Rva;
        size_t BufLen = std::min<size_t>(CacheSize - Rva, 256);

        for (size_t I = 17; I + 8 < BufLen; ++I) {
            if (Buf[I] == 0x66 && Buf[I+1] == 0x0F && Buf[I+2] == 0x6F &&
                Buf[I+3] == 0x80 && Buf[I+5] == 0x00 && Buf[I+6] == 0x00 &&
                Buf[I+7] == 0x00) {
                Out.NamePrivateOff = Buf[I+4];
                std::printf("[autodisc-fflayout]   NamePrivate = +0x%X (MOVDQA @ sig+0x%X)\n",
                    Out.NamePrivateOff, (int)I);

                // Two MOVQ loads before the MOVDQA: first=XOR key, second=PSHUFB mask.
                // Search forward from start of function area to find them in order.
                int MovqCount = 0;
                for (int J = 0; J < (int)I && J + 8 < (int)BufLen; ++J) {
                    if (Buf[J] == 0xF3 && Buf[J+1] == 0x0F && Buf[J+2] == 0x7E &&
                        (Buf[J+3] & 0xC7) == 0x05) {
                        int32_t Rel32 = 0;
                        std::memcpy(&Rel32, &Buf[J+4], 4);
                        uint64_t TargetRva = Rva + J + 8 + Rel32;
                        if (TargetRva + 8 > CacheSize) { J += 7; continue; }

                        if (MovqCount == 0) {
                            std::memcpy(&Out.XorKey, Cache + TargetRva, 8);
                            std::printf("[autodisc-fflayout]   XOR key = 0x%016llX (MOVQ #1 @ sig+0x%X, .rdata RVA 0x%llX)\n",
                                (unsigned long long)Out.XorKey, J, (unsigned long long)TargetRva);
                        } else if (MovqCount == 1) {
                            std::memcpy(Out.PshufbMask, Cache + TargetRva, 8);
                            std::printf("[autodisc-fflayout]   PSHUFB mask = [%02X %02X %02X %02X %02X %02X %02X %02X] (MOVQ #2 @ sig+0x%X, .rdata RVA 0x%llX)\n",
                                Out.PshufbMask[0], Out.PshufbMask[1], Out.PshufbMask[2],
                                Out.PshufbMask[3], Out.PshufbMask[4], Out.PshufbMask[5],
                                Out.PshufbMask[6], Out.PshufbMask[7], J, (unsigned long long)TargetRva);
                        }
                        MovqCount++;
                        J += 7;
                        if (MovqCount >= 2) break;
                    }
                }

                for (size_t K = I + 8; K + 5 < BufLen; ++K) {
                    if (Buf[K] == 0x66 && Buf[K+1] == 0x0F && Buf[K+2] == 0x71 &&
                        (Buf[K+3] & 0xF8) == 0xD0) {
                        int ShiftR = Buf[K+4];
                        Out.Rol16Amount = 16 - ShiftR;
                        std::printf("[autodisc-fflayout]   ROL16 amount = %d (PSRLW %d @ sig+0x%X)\n",
                            Out.Rol16Amount, ShiftR, (int)K);
                    }
                    if (Buf[K] == 0x48 && Buf[K+1] == 0xC1 && Buf[K+2] == 0xC1) {
                        Out.Rol64Amount = Buf[K+3];
                        std::printf("[autodisc-fflayout]   ROL64 amount = %d (@ sig+0x%X)\n",
                            Out.Rol64Amount, (int)K);
                    }
                }

                for (size_t K = I + 8; K + 6 < BufLen; ++K) {
                    if (Buf[K] == 0x74 && K + 5 < BufLen &&
                        Buf[K+2] == 0x48 && Buf[K+3] == 0x8B && Buf[K+4] == 0x40) {
                        Out.NextOff = Buf[K+5];
                        std::printf("[autodisc-fflayout]   Next = +0x%X (MOV RAX,[RAX+%X] @ sig+0x%X)\n",
                            Out.NextOff, Out.NextOff, (int)(K+2));
                        break;
                    }
                }

                break;
            }
        }

        if (Out.ChildPropsOff && Out.NamePrivateOff) {
            Out.Valid = true;
            std::printf("[autodisc-fflayout] SUCCESS: ChildProperties=+0x%X NamePrivate=+0x%X Next=+0x%X\n",
                Out.ChildPropsOff, Out.NamePrivateOff, Out.NextOff);
            std::printf("[autodisc-fflayout]   XOR=0x%016llX ROL16=%d ROL64=%d\n",
                (unsigned long long)Out.XorKey, Out.Rol16Amount, Out.Rol64Amount);
            break;
        }
    }

    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2d: FProperty layout offsets from live binary code
//
// Scans for the FProperty Offset_Internal encode pattern (xor eax,imm32;
// bswap eax; mov [reg+off],eax) which yields:
//   - PropertyOffsetXor (imm32 from XOR EAX)
//   - Offset_Internal field offset (from MOV store destination)
// Then walks nearby instructions for ElementSize and ArrayDim accesses.
// ─────────────────────────────────────────────────────────────────────────────
struct FPropertyLayoutFromCode {
    uint32_t OffsetInternalOff  = 0;
    uint32_t OffsetXorKey       = 0;
    uint32_t ElementSizeOff     = 0;
    uint32_t ArrayDimOff        = 0;
    uint32_t SubPointerOff      = 0;
    bool     Valid              = false;
};

inline FPropertyLayoutFromCode DiscoverFPropertyLayoutFromCode(
    const SigScanV2::Scanner& Scanner,
    IMemoryReader& Reader,
    uint64_t ModuleBase)
{
    FPropertyLayoutFromCode Out;

    // Pattern: XOR EAX, imm32; BSWAP EAX → 35 ?? ?? ?? ?? 0F C8
    auto Hits = ScanCodeSections(Scanner, "35 ?? ?? ?? ?? 0F C8");

    if (Hits.empty()) {
        std::printf("[autodisc-fplayout] FProperty offset XOR sig not found\n");
        return Out;
    }

    const uint8_t* Cache = Scanner.CacheData();
    size_t CacheSize = Scanner.CacheSize();

    for (uint64_t Rva : Hits) {
        if (Rva < 16 || Rva + 48 >= CacheSize) continue;

        uint32_t XorKey = 0;
        std::memcpy(&XorKey, Cache + Rva + 1, 4);

        uint32_t OffIntOff = 0;
        const uint8_t* Post = Cache + Rva + 7;
        size_t PostLen = std::min<size_t>(CacheSize - (Rva + 7), 32);
        for (size_t I = 0; I + 6 < PostLen; ++I) {
            if (Post[I] == 0x89 && Post[I+1] == 0x83) {
                std::memcpy(&OffIntOff, &Post[I+2], 4);
                break;
            }
            if (Post[I] == 0x89 && Post[I+1] == 0x43) {
                OffIntOff = Post[I+2];
                break;
            }
        }

        if (!OffIntOff || OffIntOff > 0x200) continue;

        Out.OffsetXorKey = XorKey;
        Out.OffsetInternalOff = OffIntOff;
        std::printf("[autodisc-fplayout] FProperty Offset_Internal @ RVA 0x%llX: +0x%X, XOR=0x%08X\n",
            (unsigned long long)Rva, OffIntOff, XorKey);

        if (Rva >= 32 && Rva + 224 < CacheSize) {
            const uint8_t* Near = Cache + Rva - 32;
            size_t NearLen = 256;
            for (size_t I = 0; I + 7 < NearLen; ++I) {
                if (!Out.ElementSizeOff && Near[I] == 0x8B && Near[I+1] == 0x8B) {
                    uint32_t D = 0;
                    std::memcpy(&D, &Near[I+2], 4);
                    if (D > 0x40 && D < 0x200) {
                        Out.ElementSizeOff = D;
                        std::printf("[autodisc-fplayout]   ElementSize = +0x%X (MOV ECX @ off+0x%X)\n",
                            D, (int)(I - 32));
                    }
                }
                if (!Out.ArrayDimOff && Near[I] == 0x0F && Near[I+1] == 0xAF &&
                    Near[I+2] == 0x8B) {
                    uint32_t D = 0;
                    std::memcpy(&D, &Near[I+3], 4);
                    if (D > 0x40 && D < 0x200) {
                        Out.ArrayDimOff = D;
                        std::printf("[autodisc-fplayout]   ArrayDim = +0x%X (IMUL ECX @ off+0x%X)\n",
                            D, (int)(I - 32));
                    }
                }
            }
        }

        Out.Valid = true;
        break;
    }

    // SubPointer discovery disabled — too many false positives from generic
    // MOV [RBX+disp32],RSI patterns. Sub-pointer offsets (FStructProperty::Struct,
    // FArrayProperty::Inner, etc.) are found by live probing in auto_offsets.h
    // after ChildProperties is corrected.

    if (Out.Valid) {
        std::printf("[autodisc-fplayout] SUCCESS: Offset_Internal=+0x%X XOR=0x%08X ElementSize=+0x%X ArrayDim=+0x%X\n",
            Out.OffsetInternalOff, Out.OffsetXorKey, Out.ElementSizeOff,
            Out.ArrayDimOff);
    }
    return Out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2c.5: Live FField probing for Owner + ClassPrivate offsets
//
// Requires: ChildProperties and Next offsets already discovered.
// Strategy: Walk a few FField chains from known UClass objects, scan each
// FField's bytes for the Owner pointer (tagged with bit0, matches the UClass
// address) and the ClassPrivate pointer (in .data section of the module).
// ─────────────────────────────────────────────────────────────────────────────
inline void ProbeFFieldOwnerAndClassPrivate(
    FFieldLayoutFromCode& Layout,
    IMemoryReader& Reader,
    uint64_t ModuleBase,
    const ModuleBounds& Bounds,
    const std::vector<uint64_t>& SeedObjects,
    const VTableMap& VTables)
{
    if (!Layout.Valid || !Layout.ChildPropsOff || !Layout.NextOff) return;

    uint64_t ClassVt = VTables.ClassNativeRVA ? (ModuleBase + VTables.ClassNativeRVA) : 0;
    if (!ClassVt) {
        std::printf("[autodisc-fflayout] ClassPrivate probe — no Class vtable; skipping\n");
        return;
    }

    uint64_t DataStart = ModuleBase + Bounds.DataRva;
    uint64_t DataEnd   = ModuleBase + Bounds.DataRva + Bounds.DataSize;

    std::unordered_map<uint32_t, int> OwnerHits;
    std::unordered_map<uint32_t, int> ClassPrivateHits;
    int TotalFields = 0;

    for (uint64_t Obj : SeedObjects) {
        if (TotalFields >= 200) break;
        uint64_t Vt = 0;
        if (!Reader.Read(Obj, &Vt, 8)) continue;
        if (Vt != ClassVt) continue;

        uint64_t FieldPtr = 0;
        if (!Reader.Read(Obj + Layout.ChildPropsOff, &FieldPtr, 8)) continue;
        if (!FieldPtr || FieldPtr < 0x10000) continue;

        for (int Chain = 0; Chain < 10 && FieldPtr; ++Chain) {
            uint8_t FieldBuf[256] = {};
            if (!Reader.Read(FieldPtr, FieldBuf, 256)) break;

            uint64_t OwnerTagged = Obj | 1;
            for (uint32_t Off = 0x10; Off < 0xC0; Off += 8) {
                uint64_t Val = 0;
                std::memcpy(&Val, FieldBuf + Off, 8);
                if (Val == OwnerTagged) OwnerHits[Off]++;
                if (Val >= DataStart && Val < DataEnd) ClassPrivateHits[Off]++;
            }
            TotalFields++;

            uint64_t NextVal = 0;
            std::memcpy(&NextVal, FieldBuf + Layout.NextOff, 8);
            FieldPtr = NextVal;
        }
    }

    std::printf("[autodisc-fflayout] Probed %d FFields for Owner/ClassPrivate\n", TotalFields);

    auto PickBest = [](const std::unordered_map<uint32_t, int>& Map) -> std::pair<uint32_t, int> {
        uint32_t Best = 0;
        int BestHits = 0;
        for (auto& [Off, Hits] : Map) {
            if (Hits > BestHits) { Best = Off; BestHits = Hits; }
        }
        return {Best, BestHits};
    };

    auto [OwBest, OwHits] = PickBest(OwnerHits);
    if (OwHits >= 5) {
        Layout.OwnerOff = OwBest;
        std::printf("[autodisc-fflayout]   Owner = +0x%X (%d/%d hits)\n",
            OwBest, OwHits, TotalFields);
    }

    auto [CpBest, CpHits] = PickBest(ClassPrivateHits);
    if (CpHits >= 5 && CpBest != OwBest && CpBest != Layout.NextOff) {
        Layout.ClassPrivateOff = CpBest;
        std::printf("[autodisc-fflayout]   ClassPrivate = +0x%X (%d/%d hits)\n",
            CpBest, CpHits, TotalFields);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2c.6: FProperty sub-pointer offset auto-discovery
//
// Finds the offset where FStructProperty::Struct / FObjectProperty::PropertyClass
// / FArrayProperty::Inner live. Theia randomizes this per session.
// Strategy: walk ChildProperties chains from UClass objects, scan each FProperty
// for offsets 0xD0..0x200 where the value is a valid pointer whose vtable matches
// a known engine type (UScriptStruct, UClass, UEnum). The offset with the most
// hits wins.
// ─────────────────────────────────────────────────────────────────────────────
inline uint32_t DiscoverFPropertySubPointerOffset(
    IMemoryReader& Reader,
    uint64_t ModuleBase,
    const ModuleBounds& Bounds,
    const std::vector<uint64_t>& SeedObjects,
    const VTableMap& VTables)
{
    uint64_t ClassVt = VTables.ClassNativeRVA ? (ModuleBase + VTables.ClassNativeRVA) : 0;
    if (!ClassVt) {
        std::printf("[autodisc-subptr] No Class vtable; skipping\n");
        return 0;
    }

    uint64_t CpOff = ArcDecrypt::Offsets::UStruct::ChildProperties;
    uint64_t NextOff = ArcDecrypt::Offsets::FField::Next;

    std::unordered_set<uint64_t> KnownVtables;
    if (VTables.ScriptStructRVA) KnownVtables.insert(ModuleBase + VTables.ScriptStructRVA);
    if (VTables.ClassNativeRVA)  KnownVtables.insert(ModuleBase + VTables.ClassNativeRVA);
    if (VTables.EnumRVA)         KnownVtables.insert(ModuleBase + VTables.EnumRVA);
    if (VTables.BPGCRVA)         KnownVtables.insert(ModuleBase + VTables.BPGCRVA);
    if (VTables.WBPGCRVA)        KnownVtables.insert(ModuleBase + VTables.WBPGCRVA);
    if (VTables.SMBPGCRVA)       KnownVtables.insert(ModuleBase + VTables.SMBPGCRVA);
    if (VTables.AnimBPGCRVA)     KnownVtables.insert(ModuleBase + VTables.AnimBPGCRVA);
    if (VTables.ASClassRVA)      KnownVtables.insert(ModuleBase + VTables.ASClassRVA);
    if (VTables.ASStructRVA)     KnownVtables.insert(ModuleBase + VTables.ASStructRVA);

    if (KnownVtables.empty()) {
        std::printf("[autodisc-subptr] No known vtables; skipping\n");
        return 0;
    }

    uint64_t ModEnd = ModuleBase + Bounds.ImageSize;
    std::unordered_map<uint32_t, int> HitsByOffset;
    int TotalFields = 0;

    for (uint64_t Obj : SeedObjects) {
        if (TotalFields >= 500) break;
        uint64_t Vt = 0;
        if (!Reader.Read(Obj, &Vt, 8)) continue;
        if (Vt != ClassVt) continue;

        uint64_t FieldPtr = 0;
        if (!Reader.Read(Obj + CpOff, &FieldPtr, 8)) continue;
        if (!FieldPtr || FieldPtr < 0x10000) continue;

        for (int Chain = 0; Chain < 30 && FieldPtr; ++Chain) {
            uint8_t FieldBuf[0x210] = {};
            if (!Reader.Read(FieldPtr, FieldBuf, sizeof(FieldBuf))) break;

            for (uint32_t Off = 0xD0; Off <= 0x200; Off += 8) {
                uint64_t Val = 0;
                std::memcpy(&Val, FieldBuf + Off, 8);
                if (Val < 0x10000) continue;
                if (Val >= ModuleBase && Val < ModEnd) continue;

                uint64_t TargetVt = 0;
                if (!Reader.Read(Val, &TargetVt, 8)) continue;
                if (KnownVtables.count(TargetVt)) {
                    HitsByOffset[Off]++;
                }
            }

            TotalFields++;
            uint64_t NextVal = 0;
            std::memcpy(&NextVal, FieldBuf + NextOff, 8);
            FieldPtr = NextVal;
        }
    }

    std::printf("[autodisc-subptr] Scanned %d FFields across offsets 0xD0..0x200\n", TotalFields);

    uint32_t BestOff = 0;
    int BestHits = 0;
    for (auto& [Off, Hits] : HitsByOffset) {
        std::printf("[autodisc-subptr]   offset +0x%X: %d vtable hits\n", Off, Hits);
        if (Hits > BestHits) {
            BestOff = Off;
            BestHits = Hits;
        }
    }

    if (BestHits >= 10) {
        std::printf("[autodisc-subptr] SUCCESS: SubPointer offset = +0x%X (%d hits)\n",
            BestOff, BestHits);
        return BestOff;
    }

    std::printf("[autodisc-subptr] No clear winner (best: +0x%X with %d hits)\n",
        BestOff, BestHits);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2e: Apply discovered FField+FProperty layout to runtime offsets
// ─────────────────────────────────────────────────────────────────────────────
inline void ApplyDiscoveredLayouts(
    const FFieldLayoutFromCode& FF,
    const FPropertyLayoutFromCode& FP)
{
    namespace Off = ArcDecrypt::Offsets;

    if (FF.Valid) {
        auto Upd = [](const char* Name, uint64_t& Slot, uint64_t New) {
            if (New && New != Slot) {
                std::printf("[layout-apply] %s: 0x%llX → 0x%llX\n", Name,
                    (unsigned long long)Slot, (unsigned long long)New);
                Slot = New;
            }
        };
        Upd("UStruct::ChildProperties",   Off::UStruct::ChildProperties, FF.ChildPropsOff);
        Upd("UStruct::Children",          Off::UStruct::Children,        FF.ChildPropsOff);
        Upd("FField::NamePrivate",        Off::FField::NamePrivate,      FF.NamePrivateOff);
        Upd("FField::NameEncrypted",      Off::FField::NameEncrypted,    FF.NamePrivateOff);
        Upd("FField::Next",              Off::FField::Next,              FF.NextOff);
        if (FF.OwnerOff)
            Upd("FField::Owner",          Off::FField::Owner,            FF.OwnerOff);
        if (FF.ClassPrivateOff)
            Upd("FField::ClassPrivate",   Off::FField::ClassPrivate,     FF.ClassPrivateOff);
    }

    if (FP.Valid) {
        auto Upd = [](const char* Name, uint64_t& Slot, uint64_t New) {
            if (New && New != Slot) {
                std::printf("[layout-apply] %s: 0x%llX → 0x%llX\n", Name,
                    (unsigned long long)Slot, (unsigned long long)New);
                Slot = New;
            }
        };
        auto Upd32 = [](const char* Name, uint32_t& Slot, uint32_t New) {
            if (New && New != Slot) {
                std::printf("[layout-apply] %s: 0x%08X → 0x%08X\n", Name, Slot, New);
                Slot = New;
            }
        };
        Upd("FProperty::Offset_Internal", Off::FProperty::Offset_Internal, FP.OffsetInternalOff);
        Upd32("FProperty::Offset_XOR",    Off::FProperty::Offset_XOR,      FP.OffsetXorKey);
        Upd("FProperty::ElementSize",     Off::FProperty::ElementSize,     FP.ElementSizeOff);
        Upd("FProperty::ArrayDim",        Off::FProperty::ArrayDim,        FP.ArrayDimOff);

        ArcDecrypt::Patch20260421::g_PropertyOffsetXor = FP.OffsetXorKey;

        if (FP.SubPointerOff) {
            Upd("FStructProperty::Struct",       Off::FStructProperty::Struct,           (uint64_t)FP.SubPointerOff);
            Upd("FObjectProperty::PropertyClass", Off::FObjectProperty::PropertyClass,    (uint64_t)FP.SubPointerOff);
            Upd("FArrayProperty::Inner",         Off::FArrayProperty::Inner,              (uint64_t)FP.SubPointerOff);
            Upd("FBoolProperty::FieldSize",      Off::FBoolProperty::FieldSize,           (uint64_t)FP.SubPointerOff);
            Upd("FBoolProperty::ByteOffset",     Off::FBoolProperty::ByteOffset,          (uint64_t)(FP.SubPointerOff + 1));
            Upd("FBoolProperty::ByteMask",       Off::FBoolProperty::ByteMask,            (uint64_t)(FP.SubPointerOff + 2));
            Upd("FBoolProperty::FieldMask",      Off::FBoolProperty::FieldMask,           (uint64_t)(FP.SubPointerOff + 3));
            Upd("FEnumProperty::UnderlyingProp", Off::FEnumProperty::UnderlyingProp,      (uint64_t)FP.SubPointerOff);
            Upd("FEnumProperty::Enum",           Off::FEnumProperty::Enum,                (uint64_t)(FP.SubPointerOff + 8));
            Upd("FSetProperty::ElementProp",     Off::FSetProperty::ElementProp,          (uint64_t)FP.SubPointerOff);
            Upd("FSoftObjectProperty::PropertyClass", Off::FSoftObjectProperty::PropertyClass, (uint64_t)FP.SubPointerOff);
            Upd("FMapProperty::KeyProp",         Off::FMapProperty::KeyProp,              (uint64_t)FP.SubPointerOff);
            Upd("FMapProperty::ValueProp",       Off::FMapProperty::ValueProp,            (uint64_t)(FP.SubPointerOff + 8));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2f: Build live FFieldClass-to-type map from FField chains
//
// The hardcoded FFieldClass RVAs in SeedHardcodedFClassGlobals_CL1201801()
// are from an old patch and don't match the current binary. This function
// walks live FField chains from UClass objects, reads each FField's
// ClassPrivate pointer and ElementSize, then infers the FProperty subclass
// type from the ElementSize value. The resulting map lets Probe 10
// (ProbeFPropertySubPointers) bucket FProperties by type.
// ─────────────────────────────────────────────────────────────────────────────
inline std::unordered_map<uint64_t, std::string> BuildLiveFFieldClassMap(
    IMemoryReader& Reader,
    uint64_t ModuleBase,
    const ModuleBounds& Bounds,
    const std::vector<uint64_t>& SeedObjects,
    const VTableMap& VTables)
{
    std::unordered_map<uint64_t, std::string> Result;

    namespace Off = ArcDecrypt::Offsets;

    uint64_t ClassVt = VTables.ClassNativeRVA ? (ModuleBase + VTables.ClassNativeRVA) : 0;
    std::vector<uint64_t> ClassVtCandidates;
    if (ClassVt) ClassVtCandidates.push_back(ClassVt);
    if (VTables.ASClassRVA)  ClassVtCandidates.push_back(ModuleBase + VTables.ASClassRVA);
    if (VTables.BPGCRVA)     ClassVtCandidates.push_back(ModuleBase + VTables.BPGCRVA);
    if (VTables.WBPGCRVA)    ClassVtCandidates.push_back(ModuleBase + VTables.WBPGCRVA);
    if (VTables.AnimBPGCRVA) ClassVtCandidates.push_back(ModuleBase + VTables.AnimBPGCRVA);
    if (VTables.SMBPGCRVA)   ClassVtCandidates.push_back(ModuleBase + VTables.SMBPGCRVA);
    if (VTables.FunctionRVA) ClassVtCandidates.push_back(ModuleBase + VTables.FunctionRVA);

    if (ClassVtCandidates.empty()) {
        std::printf("[live-fclass] No class vtable candidates — cannot build live map\n");
        return Result;
    }

    std::unordered_set<uint64_t> ClassVtSet(ClassVtCandidates.begin(), ClassVtCandidates.end());

    uint64_t DataStart = ModuleBase + Bounds.DataRva;
    uint64_t DataEnd   = ModuleBase + Bounds.DataRva + Bounds.DataSize;
    uint64_t ModEnd    = ModuleBase + Bounds.ImageSize;
    uint64_t CpOff     = Off::UStruct::ChildProperties;
    uint64_t NextOff   = Off::FField::Next;
    uint64_t CprvOff   = Off::FField::ClassPrivate;
    uint64_t EsOff     = Off::FProperty::ElementSize;
    uint64_t BoolFsOff = Off::FBoolProperty::FieldSize;
    uint64_t SubPtrOff = Off::FStructProperty::Struct;

    struct ClassInfo {
        std::unordered_map<int32_t, int> ElemSizeCounts;
        int TotalSamples = 0;
        bool HasSubPointerToObject = false;
        bool HasBoolPattern = false;
    };
    std::unordered_map<uint64_t, ClassInfo> ClassMap;

    int TotalFields = 0;
    int TotalUStructs = 0;

    for (uint64_t Obj : SeedObjects) {
        if (TotalFields >= 2000) break;
        uint64_t Vt = 0;
        if (!Reader.Read(Obj, &Vt, 8)) continue;
        if (!ClassVtSet.count(Vt)) continue;
        TotalUStructs++;

        uint64_t FieldPtr = 0;
        if (!Reader.Read(Obj + CpOff, &FieldPtr, 8)) continue;
        if (!FieldPtr || FieldPtr < 0x10000) continue;
        if (FieldPtr >= ModuleBase && FieldPtr < ModEnd) continue;

        std::unordered_set<uint64_t> Seen;
        for (int Chain = 0; Chain < 64 && FieldPtr && TotalFields < 2000; ++Chain) {
            if (!Seen.insert(FieldPtr).second) break;

            uint64_t FFieldVt = 0;
            if (!Reader.Read(FieldPtr, &FFieldVt, 8)) break;
            if (FFieldVt < ModuleBase || FFieldVt >= ModEnd) break;

            uint64_t ClassPrivateVal = 0;
            if (!Reader.Read(FieldPtr + CprvOff, &ClassPrivateVal, 8)) break;

            if (ClassPrivateVal >= DataStart && ClassPrivateVal < DataEnd) {
                int32_t ElemSize = 0;
                Reader.Read(FieldPtr + EsOff, &ElemSize, 4);

                auto& Info = ClassMap[ClassPrivateVal];
                Info.ElemSizeCounts[ElemSize]++;
                Info.TotalSamples++;

                if (ElemSize >= 1 && ElemSize <= 8) {
                    uint8_t FieldSizeByte = 0;
                    Reader.Read(FieldPtr + BoolFsOff, &FieldSizeByte, 1);
                    uint8_t ByteMask = 0;
                    Reader.Read(FieldPtr + BoolFsOff + 2, &ByteMask, 1);
                    if ((FieldSizeByte == 1 || FieldSizeByte == 2 || FieldSizeByte == 4 || FieldSizeByte == 8) &&
                        (ByteMask & (ByteMask - 1)) == 0 && ByteMask != 0) {
                        Info.HasBoolPattern = true;
                    }
                }

                if (ElemSize == 8) {
                    uint64_t SubPtr = 0;
                    if (Reader.Read(FieldPtr + SubPtrOff, &SubPtr, 8) && SubPtr > 0x10000 && SubPtr < 0x800000000000ULL) {
                        uint64_t SubVt = 0;
                        if (Reader.Read(SubPtr, &SubVt, 8) && SubVt >= ModuleBase && SubVt < ModEnd) {
                            Info.HasSubPointerToObject = true;
                        }
                    }
                }

                TotalFields++;
            }

            uint64_t NextVal = 0;
            if (!Reader.Read(FieldPtr + NextOff, &NextVal, 8)) break;
            FieldPtr = NextVal;
        }
    }

    std::printf("[live-fclass] Walked %d FFields from %d UStructs, found %zu unique ClassPrivate addresses\n",
        TotalFields, TotalUStructs, ClassMap.size());

    for (auto& [ClassAddr, Info] : ClassMap) {
        int32_t DominantSize = 0;
        int DominantCount = 0;
        for (auto& [Sz, Cnt] : Info.ElemSizeCounts) {
            if (Cnt > DominantCount) {
                DominantCount = Cnt;
                DominantSize = Sz;
            }
        }

        std::string TypeName;
        switch (DominantSize) {
            case 0:  TypeName = "FBoolProperty"; break;
            case 1:
                if (Info.HasBoolPattern)
                    TypeName = "FBoolProperty";
                else
                    TypeName = "FByteProperty";
                break;
            case 2:  TypeName = "FUInt16Property"; break;
            case 4:  TypeName = "FIntProperty"; break;
            case 8:
                if (Info.HasSubPointerToObject)
                    TypeName = "FObjectProperty";
                else
                    TypeName = "FNameProperty";
                break;
            case 16: TypeName = "FStrProperty"; break;
            case 24: TypeName = "FTextProperty"; break;
            case 32: TypeName = "FDelegateProperty"; break;
            case 40: TypeName = "FSoftObjectProperty"; break;
            case 48: TypeName = "FMulticastInlineDelegateProperty"; break;
            case 80: TypeName = "FMapProperty"; break;
            default:
                if (DominantSize > 0 && DominantSize <= 0x400)
                    TypeName = "FStructProperty";
                break;
        }

        if (!TypeName.empty()) {
            Result[ClassAddr] = TypeName;
            std::printf("[live-fclass]   0x%llX → %s (elem_size=%d, samples=%d)\n",
                (unsigned long long)ClassAddr, TypeName.c_str(), DominantSize, Info.TotalSamples);
        }
    }

    std::printf("[live-fclass] Built live map: %zu type entries\n", Result.size());
    return Result;
}

inline std::unordered_map<uint64_t, std::string> g_LiveFClassMap;

// ─────────────────────────────────────────────────────────────────────────────
// Globals — populated by main.cpp::Init() during the discovery phase, read
// at decrypt sites (gobjects.h, fname_decrypt.h, arc_decrypt.h).
// ─────────────────────────────────────────────────────────────────────────────
inline FFieldLayoutFromCode      g_DiscoveredFFieldLayout;
inline FPropertyLayoutFromCode   g_DiscoveredFPropertyLayout;
inline VTableMap                 g_DiscoveredVTables;
inline ModuleBounds              g_DiscoveredBounds;
inline WorldDiscovery            g_DiscoveredWorld;
inline FNameSanityResult         g_DiscoveredFNameSanity;
inline FFieldNameDecryptParams   g_DiscoveredFFieldName;
inline FFieldNameDecryptMasks    g_DiscoveredFFieldMasks;
inline FPropertyDecryptParams    g_DiscoveredFProperty;
inline UObjSlotDecryptParams     g_DiscoveredUObjSlot;
inline bool                      g_UseV707SlotHash = false;
inline bool                      g_UseV709SlotHash = false;
inline FNameResolverConsts       g_DiscoveredFName;
inline GNamesDiscovery           g_DiscoveredGNames;
inline FNameKeystreamDiscovery   g_DiscoveredFNameKey;
inline FFieldClassNameParams     g_DiscoveredFFieldClassName;
inline std::vector<FFieldClassGlobal> g_DiscoveredFClassGlobals;
inline GUObjectArrayLayout       g_DiscoveredGObjLayout;

// Seed g_DiscoveredFClassGlobals with hardcoded CL-1201801 FFieldClass RVAs so
// AutoOffsets::DiscoverAll (Probe 10) has a populated fclass_to_type map even
// when Phase 8 (DiscoverFFieldClassGlobals) finds nothing.  Call this BEFORE
// AutoOffsets::DiscoverAll.
inline void SeedHardcodedFClassGlobals_CL1201801() {
    static const std::pair<uint64_t, const char*> kSeeds[] = {
        { 0xE3B4A80, "FArrayProperty" },
        { 0xE3B3DC0, "FArrayProperty" },
        { 0xE3B3930, "FArrayProperty" },
        { 0xE3B3A30, "FBoolProperty" },
        { 0xE3B3AB0, "FByteProperty" },
        { 0xE3ABBB0, "FByteProperty" },
        { 0xE3B3B30, "FClassProperty" },
        { 0xE3B3C30, "FDelegateProperty" },
        { 0xE3B44D0, "FDoubleProperty" },
        { 0xE3ABD20, "FFieldPathProperty" },
        { 0xE3B4450, "FFloatProperty" },
        { 0xE3B4150, "FInt16Property" },
        { 0xE3B4250, "FInt64Property" },
        { 0xE3B40D0, "FInt8Property" },
        { 0xE3B41D0, "FIntProperty" },
        { 0xE3B3CC0, "FInterfaceProperty" },
        { 0xE3B3D40, "FLazyObjectProperty" },
        { 0xE3B3ED0, "FMulticastInlineDelegateProperty" },
        { 0xE3B3F50, "FMulticastSparseDelegateProperty" },
        { 0xE3B3FD0, "FNameProperty" },
        { 0xE3B45E0, "FObjectProperty" },
        { 0xE3B3BB0, "FObjectProperty" },
        { 0xE3B4660, "FOptionalProperty" },
        { 0xE3B4B00, "FSoftClassProperty" },
        { 0xE3B4B80, "FSoftObjectProperty" },
        { 0xE3B4CD0, "FStructProperty" },
        { 0xE3B60A0, "FTextProperty" },
        { 0xE3B4C50, "FTextProperty" },
        { 0xE3B42D0, "FUInt16Property" },
        { 0xE3B4350, "FUInt32Property" },
        { 0xE3B43D0, "FUInt64Property" },
        { 0xE3B4D60, "FWeakObjectProperty" },
        { 0xE3B4550, "FWeakObjectProperty" },
    };
    std::unordered_map<uint64_t, bool> existing;
    for (const auto& g : g_DiscoveredFClassGlobals)
        existing[g.TargetRva] = true;
    for (auto [rva, type] : kSeeds) {
        if (existing.count(rva)) continue;
        FFieldClassGlobal g;
        g.TargetRva = rva;
        g.TypeName  = type;
        g_DiscoveredFClassGlobals.push_back(std::move(g));
    }
}

}  // namespace AutoDiscovery
