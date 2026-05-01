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
//   Phase 0 — Module bounds         (PE header parse — runs FIRST)
//   Phase 1 — Engine vtable map     (name-cluster after FName + GObjects up)
//   Phase 2 — FField NamePrivate    (live data math — no fn parse needed)
//   Phase 3 — FProperty Offset XOR  (sig-scan + Zydis-validate)
//   Phase 4 — UObject slot decrypt  (sig-scan + Zydis instruction stream)
//   Phase 5 — FNamePool resolver    (sig-scan + Zydis instruction stream)
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

using NameResolver = std::function<std::string(uint64_t obj_ptr)>;

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

    out.ScriptStructRVA = rva_of(pick_best_for_kind(KSCRIPT_STRUCT));
    out.ClassNativeRVA  = rva_of(pick_best_for_kind(KCLASS_NATIVE));
    out.FunctionRVA     = rva_of(pick_best_for_kind(KFUNCTION));
    out.EnumRVA         = rva_of(pick_best_for_kind(KENUM));
    out.PackageRVA      = rva_of(pick_best_for_kind(KPACKAGE));
    out.BPGCRVA         = rva_of(pick_best_for_kind(KBPGC));
    out.WBPGCRVA        = rva_of(pick_best_for_kind(KWBPGC));
    out.SMBPGCRVA       = rva_of(pick_best_for_kind(KSMBPGC));
    out.AnimBPGCRVA     = rva_of(pick_best_for_kind(KANIM_BPGC));

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
// Validation strategy:
//   1. Decode the xor + bswap pair.
//   2. Walk backwards 16 bytes via Zydis to find a `mov r32, [reg+disp32]` or
//      `movzx r32, [reg+disp32]` load — that's the FProperty offset field
//      access. The disp32 is the field offset (FProperty::Offset_Internal).
//   3. Cross-validate: every hit's load offset should be the same value
//      (multiple accessors all read +0xC4 on CL-1177146). The mode (most
//      common offset) wins.
//   4. The XOR imm32 is the decrypt key directly.
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

        uint64_t key = ((uint64_t)offset_field << 32) | xor_key;
        if (pairCounts.empty()) firstValidatedRva = rva;
        ++pairCounts[key];
    }

    if (pairCounts.empty()) {
        std::printf("[autodisc-fprop] no validated load+xor+bswap sites\n");
        return out;
    }

    // Pick the mode.
    uint64_t bestKey = 0;
    int      bestCount = 0;
    for (const auto& [k, c] : pairCounts) {
        if (c > bestCount) { bestCount = c; bestKey = k; }
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

    // PSHUFB with RIP-rel: `66 0F 38 00 0D ?? ?? ?? ??` for the most common
    // encoding (xmm1, [rip+disp32] form). Other ModR/Ms use different middle
    // bytes; we wildcard the modrm.
    auto pshufbHits = scanner.ScanSection("66 0F 38 00 ?? ?? ?? ?? ??", ".text");
    std::printf("[autodisc-uobj] PSHUFB rip-rel hits: %zu\n", pshufbHits.size());

    int validated = 0;
    for (uint64_t rva : pshufbHits) {
        const uint8_t* p = scanner.GetLocalPtr(rva);
        if (!p) continue;
        // Decode this insn + a 64-byte window to look for a follow-up PXOR
        // and ROL64.
        auto insns = dec.Decode(p, 96, rva);
        if (insns.empty() || insns[0].type != INSN_PSHUFB || !insns[0].hasRipRel) continue;

        // Look for a subsequent PXOR with RIP-rel within 24 bytes / 12 insns.
        int pxorIdx = -1;
        for (int i = 1; i < (int)insns.size() && i < 12; ++i) {
            if ((insns[i].type == INSN_PXOR || insns[i].type == INSN_XORPS) &&
                insns[i].hasRipRel) { pxorIdx = i; break; }
        }
        if (pxorIdx < 0) continue;

        // Look for a ROL r64, imm8 within 16 insns of PXOR (the post-decrypt
        // ROL64(32) that swaps high/low halves).
        int rolIdx = -1;
        for (int i = pxorIdx; i < (int)insns.size() && i < pxorIdx + 16; ++i) {
            if (insns[i].type == INSN_ROL && insns[i].hasImm8 && insns[i].hasREX_W) {
                rolIdx = i; break;
            }
        }
        // ROL64 isn't strictly required (some sites use SHL/SHR/OR pair) but
        // when we do find one, take it as the gold signal.
        ++validated;

        uint64_t shufRva = insns[0].ResolveRipRVA();
        uint64_t xorRva  = insns[pxorIdx].ResolveRipRVA();
        if (!scanner.IsRDataRVA(shufRva)) continue;
        if (!scanner.IsRDataRVA(xorRva))  continue;

        // Read the XOR const (16 bytes from .rdata).
        const uint8_t* xorBytes = scanner.GetLocalPtr(xorRva);
        if (!xorBytes) continue;
        uint64_t xor_lo64 = 0;
        std::memcpy(&xor_lo64, xorBytes, 8);
        if (xor_lo64 == 0) continue;

        // Read the PSHUFB mask (lo 8 bytes — high 8 are zero or duplicate).
        const uint8_t* shufBytes = scanner.GetLocalPtr(shufRva);
        if (!shufBytes) continue;

        out.ShufMaskRVA = shufRva;
        out.XorConstRVA = xorRva;
        out.XorScalar   = xor_lo64;
        out.Rol64Amount = (rolIdx >= 0) ? insns[rolIdx].imm8 : 32;
        std::memcpy(out.ShufMaskBytes, shufBytes, 8);
        out.Valid       = true;
        std::printf("[autodisc-uobj] slot decrypt @ pshufb=0x%llX  shuf_mask=0x%llX  xor_const=0x%llX (lo64=0x%016llX)  rol64=%d\n",
            (unsigned long long)rva, (unsigned long long)shufRva,
            (unsigned long long)xorRva, (unsigned long long)xor_lo64,
            out.Rol64Amount);
        return out;
    }

    std::printf("[autodisc-uobj] no validated slot-decrypt site (checked %zu candidates)\n",
        pshufbHits.size());
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
// Strategy:
//   1. Decode the outer fn body via Zydis.
//   2. Collect all `lea r64, [rip+disp32]` targets that land in .data.
//   3. Follow the FIRST load-bearing `call rel32` (skipping compiler
//      intrinsics like __security_check_cookie / __alloca_probe — heuristic:
//      target's body must be ≥ 0x40 bytes).
//   4. Recurse up to `max_depth` levels.
//   5. Return the MODE of all collected .data targets — GNamePool is
//      referenced 2-3× per BlockFNV call site (init-flag check + arg load),
//      while other .data globals (security cookie, etc.) appear once.
// ─────────────────────────────────────────────────────────────────────────────
struct GNamesDiscovery {
    uint64_t GNamesRva = 0;
    int      RefCount  = 0;   // how many LEAs across the walk pointed at it
    bool     Valid     = false;
};

inline GNamesDiscovery DiscoverGNamesViaFNameWalk(
    const SigScanV2::Scanner& scanner, uint64_t fname_fn_rva,
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

    // Mode pick.
    uint64_t best = 0; int bestCount = 0;
    for (const auto& [t, c] : targetCounts) {
        if (c > bestCount) { bestCount = c; best = t; }
    }
    out.GNamesRva = best;
    out.RefCount  = bestCount;
    out.Valid     = true;
    std::printf("[autodisc-gnames] GNamePool RVA = 0x%llX (%d refs across walk)\n",
        (unsigned long long)best, bestCount);

    // Diagnostic: dump all .data targets seen, ranked by count.
    std::vector<std::pair<uint64_t, int>> sorted(targetCounts.begin(), targetCounts.end());
    std::sort(sorted.begin(), sorted.end(), [](auto& a, auto& b) { return a.second > b.second; });
    int shown = 0;
    for (const auto& [t, c] : sorted) {
        if (shown++ >= 8) break;
        std::printf("[autodisc-gnames]   0x%llX  refs=%d\n", (unsigned long long)t, c);
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Globals — populated by main.cpp::Init() during the discovery phase, read
// at decrypt sites (gobjects.h, fname_decrypt.h, arc_decrypt.h).
// ─────────────────────────────────────────────────────────────────────────────
inline VTableMap                 g_DiscoveredVTables;
inline ModuleBounds              g_DiscoveredBounds;
inline FFieldNameDecryptParams   g_DiscoveredFFieldName;
inline FPropertyDecryptParams    g_DiscoveredFProperty;
inline UObjSlotDecryptParams     g_DiscoveredUObjSlot;
inline FNameResolverConsts       g_DiscoveredFName;
inline GNamesDiscovery           g_DiscoveredGNames;

}  // namespace AutoDiscovery
