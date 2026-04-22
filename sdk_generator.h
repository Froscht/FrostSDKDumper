#pragma once

// =============================================================================
// ARC Raiders – SDK Generator  (March 2026 patch)
//
// Walks GObjects, finds UClass/UScriptStruct objects, decodes ChildProperties
// chains to produce .h-style struct output, and enumerates UFunctions.
//
// All offsets / decrypt pipelines sourced from arc_decrypt.h (live-verified).
// Include this header from main.cpp AFTER including arc_decrypt.h and fname_decrypt.h.
// =============================================================================

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <cstdio>

// arc_decrypt.h, fname_decrypt.h, and gobjects.h must already be included by the TU.

namespace SDKGen {

// ─────────────────────────────────────────────────────────────────────────────
// 1. FFieldClass name resolution (structs/records only)
// ─────────────────────────────────────────────────────────────────────────────
// FieldClassToTypeName is a Generator member — see below.

// ─────────────────────────────────────────────────────────────────────────────
// 2. Struct property record
// ─────────────────────────────────────────────────────────────────────────────
struct PropertyRecord {
    std::string name;
    std::string type_name;   // from FFieldClass
    uint32_t    offset;      // decoded Offset_Internal
    uint32_t    elem_size;   // ElementSize (u32 at ff+0x7C)
    uint32_t    array_dim;   // ArrayDim (u32 at ff+0xC0)
    uint64_t    fclass_ptr;  // raw FFieldClass* for nested type resolution
    uint64_t    ff_addr;     // live address (for inner-type probing)
    bool        is_bool;     // true if FBoolProperty (byte-pack aware)
    bool        is_param;    // true if this is a UFunction parameter property
    uint8_t     bool_byte_mask = 0;  // FBoolProperty ByteMask (0x01..0x80)
    uint8_t     bool_field_size = 0; // FBoolProperty FieldSize (1=bitfield, 4=native)
};

// ─────────────────────────────────────────────────────────────────────────────
// 3. Function record
// ─────────────────────────────────────────────────────────────────────────────
struct FunctionRecord {
    std::string                name;
    uint64_t                   flags;       // UFunctionFlags
    uint64_t                   native_rva;  // RVA to native impl (0 if blueprint only)
    uint64_t                   fn_addr;     // live UFunction address
    std::vector<PropertyRecord> params;     // UFunction ChildProperties (parameters)
};

// ─────────────────────────────────────────────────────────────────────────────
// 4a. Struct record (a UClass or UScriptStruct)
// ─────────────────────────────────────────────────────────────────────────────
struct StructRecord {
    std::string              name;
    std::string              package;
    uint64_t                 addr;          // live UStruct address
    uint64_t                 super_addr;    // SuperStruct live addr (0 if none)
    std::string              super_name;
    uint32_t                 props_size;    // sizeof(struct) from UStruct::PropertiesSize
    std::vector<PropertyRecord>  properties;
    std::vector<FunctionRecord>  functions;
    bool                     is_class;      // UClass (vs UScriptStruct)
};

// ─────────────────────────────────────────────────────────────────────────────
// 4b. Enum record (a UEnum)
// ─────────────────────────────────────────────────────────────────────────────
struct EnumEntry {
    std::string name;
    int64_t     value;
};
struct EnumRecord {
    std::string            name;
    std::string            package;
    uint64_t               addr;
    std::vector<EnumEntry> entries;
};

// ─────────────────────────────────────────────────────────────────────────────
// 4c. Combined SDK result
// ─────────────────────────────────────────────────────────────────────────────
struct SDKResult {
    std::vector<StructRecord> structs;
    std::vector<EnumRecord>   enums;
};

// ─────────────────────────────────────────────────────────────────────────────
// 5. SDK generator core
// ─────────────────────────────────────────────────────────────────────────────
class Generator {
public:
    uint64_t MODULE_BASE;   // runtime module base (passed at construction)

    IMemoryReader& m_reader;
    FNameDecryptor& m_fname;

    // vtable RVA (relative to MODULE_BASE) → FProperty type name
    // NOTE: in patch 20260402 ALL FProperties share vtable 0x14AC40580, so this map
    // will have at most one entry and is effectively useless for type identification.
    // m_fclass_to_type is the authoritative map.
    std::unordered_map<uint64_t, std::string> m_vtable_to_type;

    // FFieldClass* → FProperty type name (authoritative, since all FProps share vtable)
    std::unordered_map<uint64_t, std::string> m_fclass_to_type;

    // Owner (UClass/UStruct addr) → list of UFunction addresses
    std::unordered_map<uint64_t, std::vector<uint64_t>> m_owner_to_funcs;

public:
    const std::unordered_map<uint64_t, std::vector<uint64_t>>& GetOwnerFuncMap() const {
        return m_owner_to_funcs;
    }
private:

public:
    Generator(IMemoryReader& reader, FNameDecryptor& fname, uint64_t mod_base = ArcDecrypt::MODULE_BASE)
        : MODULE_BASE(mod_base), m_reader(reader), m_fname(fname)
    {
        // Seed vtable map is populated at runtime by AutoDiscoverVTables().
        // No hardcoded RVAs — the discovery pass handles everything.
    }

    // ── Generic typed read ───────────────────────────────────────────────
    template<typename T>
    T Read(uint64_t addr) {
        T v{};
        m_reader.Read(addr, &v, sizeof(T));
        return v;
    }

    // ── Identify FProperty subtype by reading its vtable pointer ────────
    // Reads the vtable from ff_addr+FField::VTable, converts to an RVA,
    // and looks it up in m_vtable_to_type.  Falls back to ElementSize heuristic.
    std::string IdentifyPropertyType(uint64_t ff_addr) {
        uint64_t vtbl_abs = 0;
        if (!m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::VTable, &vtbl_abs, 8))
            return "UNKNOWN";

        uint64_t vtbl_rva = vtbl_abs - MODULE_BASE;
        auto it = m_vtable_to_type.find(vtbl_rva);
        if (it != m_vtable_to_type.end())
            return it->second;

        // Fallback: use ElementSize from FFieldClass+0x78
        uint32_t elem_size = 0;
        {
            uint64_t fc = 0;
            m_reader.Read(ff_addr + ArcDecrypt::Offsets::FField::ClassPrivate, &fc, 8);
            if (fc) m_reader.Read(fc + ArcDecrypt::Offsets::FFieldClass::ElementSize, &elem_size, 4);
        }
        switch (elem_size) {
            case 1:  return "FBoolProperty";    // only 1-byte props are bool/byte
            case 2:  return "FUInt16Property";
            // 4 and 8 are ambiguous (float vs int; double vs FName/pointer),
            // so return a size-annotated unknown rather than guessing wrong.
            default: return "UNKNOWN_" + std::to_string(elem_size) + "b";
        }
    }

    // ── Known property name → FProperty type lookup table ──────────────
    // Used by auto-discovery: when we see a property with a known UE5 name,
    // we can infer its FProperty subtype and map the vtable RVA automatically.
    static const std::unordered_map<std::string, std::string>& KnownPropertyTypes() {
        static const std::unordered_map<std::string, std::string> table = {
            // ── AActor ──
            {"PrimaryActorTick","StructProperty"},{"AttachmentReplication","StructProperty"},
            {"ReplicatedMovement","StructProperty"},{"BasedMovement","StructProperty"},
            {"bNetTemporary","BoolProperty"},{"bReplicateMovement","BoolProperty"},
            {"bAlwaysRelevant","BoolProperty"},{"bHidden","BoolProperty"},
            {"bTearOff","BoolProperty"},{"bCanBeDamaged","BoolProperty"},
            {"bReplicates","BoolProperty"},{"bBlockInput","BoolProperty"},
            {"bReplicateUsingRegisteredSubObjectList","BoolProperty"},
            {"bActorEnableCollision","BoolProperty"},{"bActorIsBeingDestroyed","BoolProperty"},
            {"bAsyncPhysicsTickEnabled","BoolProperty"},{"bCallPreReplication","BoolProperty"},
            {"bOnlyRelevantToOwner","BoolProperty"},{"bReplicateAttachment","BoolProperty"},
            {"bForceNetAddressable","BoolProperty"},{"bNetLoadOnClient","BoolProperty"},
            {"bNetUseOwnerRelevancy","BoolProperty"},{"bRelevantForNetworkReplays","BoolProperty"},
            {"bRelevantForLevelBounds","BoolProperty"},
            {"bGenerateOverlapEventsDuringLevelStreaming","BoolProperty"},
            {"bFindCameraComponentWhenViewTarget","BoolProperty"},
            {"bCollideWhenPlacing","BoolProperty"},{"bAutoDestroyWhenFinished","BoolProperty"},
            {"bAllowTickBeforeBeginPlay","BoolProperty"},{"bReplayRewindable","BoolProperty"},
            {"bCanBeInCluster","BoolProperty"},{"bActorSeamlessTraveled","BoolProperty"},
            {"bIsEditorOnlyActor","BoolProperty"},{"bEnableAutoLODGeneration","BoolProperty"},
            {"bIgnoresOriginShifting","BoolProperty"},{"bUseControllerRotationPitch","BoolProperty"},
            {"bIsInterface","BoolProperty"},
            {"UpdateOverlapsMethodDuringLevelStreaming","ByteProperty"},
            {"DefaultUpdateOverlapsMethodDuringLevelStreaming","ByteProperty"},
            {"RemoteRole","ByteProperty"},{"Role","ByteProperty"},{"NetDormancy","ByteProperty"},
            {"SpawnCollisionHandlingMethod","ByteProperty"},{"AutoReceiveInput","ByteProperty"},
            {"PhysicsReplicationMode","ByteProperty"},
            {"InitialLifeSpan","FloatProperty"},{"CustomTimeDilation","FloatProperty"},
            {"NetCullDistanceSquared","FloatProperty"},{"NetUpdateFrequency","FloatProperty"},
            {"MinNetUpdateFrequency","FloatProperty"},{"NetPriority","FloatProperty"},
            {"RenderOpacity","FloatProperty"},
            {"RayTracingGroupId","IntProperty"},{"NetTag","IntProperty"},{"InputPriority","IntProperty"},
            {"Owner","ObjectProperty"},{"InputComponent","ObjectProperty"},
            {"Instigator","ObjectProperty"},{"RootComponent","ObjectProperty"},
            {"PlayerState","ObjectProperty"},{"Controller","ObjectProperty"},
            {"LastHitBy","ObjectProperty"},{"Slot","ObjectProperty"},
            {"ClassWithin","ObjectProperty"},{"ClassDefaultObject","ObjectProperty"},
            {"MetaClass","ObjectProperty"},{"InterfaceClass","ObjectProperty"},
            {"NetDriverName","NameProperty"},{"RepNotifyFunc","NameProperty"},
            {"ParentComponent","WeakObjectProperty"},
            {"Children","ArrayProperty"},{"Layers","ArrayProperty"},{"Tags","ArrayProperty"},
            {"InstanceComponents","ArrayProperty"},{"BlueprintCreatedComponents","ArrayProperty"},
            {"OnTakeAnyDamage","MulticastSparseDelegateProperty"},
            {"OnActorBeginOverlap","MulticastSparseDelegateProperty"},
            {"OnActorEndOverlap","MulticastSparseDelegateProperty"},
            {"OnDestroyed","MulticastSparseDelegateProperty"},
            {"OnEndPlay","MulticastSparseDelegateProperty"},
            {"MovementModeChangedDelegate","MulticastInlineDelegateProperty"},
            {"OnComponentBeginOverlap","MulticastInlineDelegateProperty"},
            {"OnComponentEndOverlap","MulticastInlineDelegateProperty"},
            {"OnComponentHit","MulticastInlineDelegateProperty"},
            {"OnClicked","MulticastInlineDelegateProperty"},
            {"OnReleased","MulticastInlineDelegateProperty"},
            {"OnInputTouchBegin","MulticastInlineDelegateProperty"},
            // ── APawn / ACharacter ──
            {"BaseEyeHeight","DoubleProperty"},{"BlendedReplayViewPitch","DoubleProperty"},
            {"CrouchedEyeHeight","DoubleProperty"},
            {"AutoPossessPlayer","EnumProperty"},{"AutoPossessAI","EnumProperty"},
            {"Visibility","EnumProperty"},
            {"AIControllerClass","ClassProperty"},
            // ── UWidget / UMG ──
            {"RenderTransform","StructProperty"},{"Guid","StructProperty"},
            {"ToolTipText","TextProperty"},{"AccessibleText","TextProperty"},
            {"Description","TextProperty"},{"DisplayName","TextProperty"},
            // ── Common types from various engine classes ──
            {"PathName","StrProperty"},{"FriendlyName","StrProperty"},
            {"NodeComment","StrProperty"},{"Category","StrProperty"},
            {"ClassFlags","UInt32Property"},{"FunctionFlags","UInt32Property"},
            {"PropertyFlags","UInt64Property"},
            // ── Containers ──
            {"RowMap","MapProperty"},
            // ── Soft references ──
            {"SoftObjectPath","SoftObjectProperty"},
            // ── FText ──
            {"ToolTipDescription","TextProperty"},{"ErrorMessage","TextProperty"},
            // ── Int8/Int16/UInt16 ──
            {"BlueprintSystemVersion","Int16Property"},
            // ── FSet ──
            {"OnStateLeaveGameplayEffects","SetProperty"},
        };
        return table;
    }

    // ── VTable auto-discovery state ──────────────────────────────────────
    std::unordered_map<uint64_t, std::string> m_fclass_name_cache;
    bool m_vtables_discovered = false;

    // ── Auto-discover ALL vtable-to-type mappings at runtime ─────────────
    // 3-tier strategy (highest reliability first):
    //   Tier 1: Walk ALL type ChildProperties, match property names to known types
    //   Tier 2: Resolve FFieldClass name (plain FName + SIMD fallback)
    //   Tier 3: Element-size heuristic for truly unknown vtables
    void AutoDiscoverVTables(
            const std::vector<std::pair<int32_t, uint64_t>>& object_ptrs,
            const std::unordered_map<uint64_t, std::string>& addr_to_name,
            const std::unordered_set<uint64_t>& allTypeAddrs,
            uint64_t ssAddr)
    {
        if (m_vtables_discovered) return;

        const auto& known = KnownPropertyTypes();

        // Per-vtable observation for Tier 2/3: (fclass_ptr, elem_size)
        struct VTObs { uint64_t fclass; uint32_t elem; };
        std::unordered_map<uint64_t, VTObs> unresolved_vtbls;

        // ── Tier 1: Walk ALL type ChildProperties and reverse-map names ──
        int scanned = 0;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            bool is_type = allTypeAddrs.count(obj_ptr) > 0;
            if (!is_type) {
                uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
                if (cls != ssAddr && !allTypeAddrs.count(obj_ptr)) continue;
            }
            ++scanned;

            uint64_t ff = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::ChildProperties);
            std::unordered_set<uint64_t> vis;
            for (int c = 0; ff && c < 512; ++c) {
                if (vis.count(ff)) break;
                vis.insert(ff);

                uint64_t vtbl = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::VTable);
                uint64_t vtbl_rva = vtbl - MODULE_BASE;
                if (vtbl_rva < 0x1000 || vtbl_rva >= 0xF000000ULL) {
                    ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
                    continue;
                }

                // Skip only if this specific FFieldClass* is already resolved
                // (NOT by vtable RVA — all FProperties share one vtable in patch 20260402)
                uint64_t fc_early = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                if (fc_early && m_fclass_to_type.count(fc_early)) {
                    ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
                    continue;
                }

                // Tier 1: name-based identification → map fclass_ptr (not vtable RVA,
                // since all FProperties share the same vtable in patch 20260402)
                std::string pname = m_fname.GetFFieldName(ff);
                if (!pname.empty()) {
                    auto kit = known.find(pname);
                    if (kit != known.end()) {
                        std::string type_str = "F" + kit->second;
                        uint64_t fc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                        if (fc && !m_fclass_to_type.count(fc))
                            m_fclass_to_type[fc] = type_str;
                        // Also seed vtable map for Tier 2/3 sample probing
                        if (!m_vtable_to_type.count(vtbl_rva))
                            m_vtable_to_type[vtbl_rva] = type_str;
                        ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
                        continue;
                    }
                }

                // Record for Tier 2/3 — track fclass_ptr and ElementSize
                uint32_t elem = 0;
                uint64_t fc_ptr = 0;
                {
                    fc_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                    if (fc_ptr) elem = Read<uint32_t>(fc_ptr + ArcDecrypt::Offsets::FFieldClass::ElementSize);
                }
                if (!unresolved_vtbls.count(vtbl_rva))
                    unresolved_vtbls[vtbl_rva] = {fc_ptr, elem};

                ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
            }
        }

        size_t tier1_count = m_fclass_to_type.size();
        std::printf("[vtbl] Tier 1 (name-based): scanned %d types, resolved %zu fclass→type mappings\n",
            scanned, tier1_count);

        // ── Tier 2: Structural probing ─────────────────────────────────
        // FField::ClassPrivate is gone in this build — +0x130 stores subclass
        // data (Struct*, PropertyClass*, Enum*).  Probe the field to identify:
        //  - If +0x130 is a valid UObject* → object/struct/enum/class property
        //  - If +0x138 is also valid → map/class/array inner
        //  - Otherwise → primitive type (use element size)
        size_t tier2_resolved = 0;
        for (auto& [rva, obs] : unresolved_vtbls) {
            if (m_vtable_to_type.count(rva)) continue;
            // Need a sample FField with this vtable to probe
            // Re-scan to find one (first match is enough)
        }
        // Re-walk to find a sample FField for each unresolved vtable
        std::unordered_map<uint64_t, uint64_t> vtbl_sample; // rva → ff_addr
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            if (vtbl_sample.size() >= unresolved_vtbls.size()) break;
            bool is_type = allTypeAddrs.count(obj_ptr) > 0;
            if (!is_type) {
                uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
                if (cls != ssAddr && !allTypeAddrs.count(obj_ptr)) continue;
            }
            uint64_t ff = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::ChildProperties);
            std::unordered_set<uint64_t> vis;
            for (int c = 0; ff && c < 64; ++c) {
                if (vis.count(ff)) break;
                vis.insert(ff);
                uint64_t vtbl = Read<uint64_t>(ff) - MODULE_BASE;
                if (unresolved_vtbls.count(vtbl) && !vtbl_sample.count(vtbl))
                    vtbl_sample[vtbl] = ff;
                ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
            }
        }
        for (auto& [rva, sample_ff] : vtbl_sample) {
            if (m_vtable_to_type.count(rva)) continue;
            uint32_t elem = unresolved_vtbls[rva].elem;
            uint64_t ptr130 = Read<uint64_t>(sample_ff + 0x130);
            uint64_t ptr138 = Read<uint64_t>(sample_ff + 0x138);
            bool p130_valid = ptr130 >= 0x10000ULL && ptr130 < 0x7FFFFFFFFFFFULL &&
                              !(ptr130 >= MODULE_BASE && ptr130 < MODULE_BASE + 0x10000000ULL);
            bool p138_valid = ptr138 >= 0x10000ULL && ptr138 < 0x7FFFFFFFFFFFULL &&
                              !(ptr138 >= MODULE_BASE && ptr138 < MODULE_BASE + 0x10000000ULL);
            // Check if ptr130 has a vtable in module range (confirms UObject)
            bool p130_is_uobj = false;
            if (p130_valid) {
                uint64_t vt130 = Read<uint64_t>(ptr130);
                p130_is_uobj = (vt130 >= MODULE_BASE && vt130 < MODULE_BASE + 0x10000000ULL);
            }

            std::string tier2_type;
            if (elem == 40)
                tier2_type = p130_is_uobj ? "FSoftClassProperty" : "FSoftObjectProperty";
            else if (elem == 80 && p130_valid)
                tier2_type = p138_valid ? "FMapProperty" : "FSetProperty";
            else if (elem == 8 && p130_is_uobj)
                tier2_type = "FObjectProperty";
            else if (elem == 8 && !p130_is_uobj)
                tier2_type = (ptr130 < 0x1000 || ptr130 > 0x7FFFFFFFFFFFULL) ? "FDoubleProperty" : "FStrProperty";
            else if (elem == 4 && !p130_is_uobj)
                tier2_type = "FIntProperty";
            else if (elem == 4 && p130_is_uobj)
                tier2_type = "FEnumProperty";

            if (!tier2_type.empty()) {
                m_vtable_to_type[rva] = tier2_type;
                // Also map via FFieldClass* for reliable per-property lookup
                uint64_t sample_fc = Read<uint64_t>(sample_ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                if (sample_fc && !m_fclass_to_type.count(sample_fc))
                    m_fclass_to_type[sample_fc] = tier2_type;
                ++tier2_resolved;
            }
        }
        std::printf("[vtbl] Tier 2 (structural probe): resolved %zu more vtables\n", tier2_resolved);

        // ── Tier 3: Element-size heuristic (remaining) ──────────────────
        // Seeds m_fclass_to_type via the obs.fclass field populated during scan
        size_t tier3_resolved = 0;
        for (auto& [rva, obs] : unresolved_vtbls) {
            if (m_vtable_to_type.count(rva)) continue;
            std::string t3_type;
            switch (obs.elem) {
                case 1:  t3_type = "FBoolProperty";         break;
                case 2:  t3_type = "FUInt16Property";       break;
                case 16: t3_type = "FStructProperty";       break;
                case 24: t3_type = "FTextProperty";         break;
                case 32: t3_type = "FDelegateProperty";     break;
                case 40: t3_type = "FSoftObjectProperty";   break;
                case 80: t3_type = "FMapProperty";          break;
                default: continue;
            }
            m_vtable_to_type[rva] = t3_type;
            if (obs.fclass && !m_fclass_to_type.count(obs.fclass))
                m_fclass_to_type[obs.fclass] = t3_type;
            ++tier3_resolved;
        }
        std::printf("[vtbl] Tier 3 (heuristic): resolved %zu more\n", tier3_resolved);
        std::printf("[vtbl] Total fclass mappings: %zu\n", m_fclass_to_type.size());

        m_vtables_discovered = true;
    }

    // ── Dump discovered vtable map to file (for SIGNATURES.md updates) ──
    void DumpVTableMap(const std::string& path) const {
        std::FILE* f = std::fopen(path.c_str(), "w");
        if (!f) return;
        std::fprintf(f, "# Auto-discovered FProperty VTable RVAs\n");
        std::fprintf(f, "# Generated at runtime — paste into SIGNATURES.md section 5\n\n");
        std::fprintf(f, "| RVA | Type |\n|---|---|\n");
        // Sort by RVA for stable output
        std::vector<std::pair<uint64_t, std::string>> sorted(m_vtable_to_type.begin(), m_vtable_to_type.end());
        std::sort(sorted.begin(), sorted.end());
        for (const auto& [rva, type] : sorted)
            std::fprintf(f, "| `0x%07llX` | %s |\n", (unsigned long long)rva, type.c_str());
        std::fprintf(f, "\nTotal: %zu vtable mappings\n", sorted.size());
        std::fclose(f);
        std::printf("[vtbl] Wrote vtable map to %s\n", path.c_str());
    }

    // ── Resolve FFieldClass* -> type name ────────────────────────────────
    std::string FieldClassToTypeName(uint64_t fclass_ptr) {
        if (!fclass_ptr) return "None";
        // Primary: check fclass_to_type (populated by AutoDiscoverVTables)
        auto fc_it = m_fclass_to_type.find(fclass_ptr);
        if (fc_it != m_fclass_to_type.end()) return fc_it->second;
        // Fallback: name cache (rarely works since FFieldClass name CI is not known)
        auto cached = m_fclass_name_cache.find(fclass_ptr);
        if (cached != m_fclass_name_cache.end())
            return cached->second;
        std::string name = m_fname.GetFFieldClassName(fclass_ptr);
        if (name.empty())
            name = "FProperty_Unknown";
        m_fclass_name_cache[fclass_ptr] = name;
        return name;
    }

    // ── Read FField name via SIMD pipeline ──────────────────────────────
    std::string ReadFFieldName(uint64_t ff) {
        return m_fname.GetFFieldName(ff);
    }

    // ── Detect old-system UProperty nodes in UStruct::Children ──────────
    // UProperty (UObject subclass) stores UField::Next at +0x30.
    // For UProperty: +0x30 is null or a heap address.
    // For UFunction: +0x30 is slot 0 hi64 — always a module code address.
    bool IsOldStyleUProperty(uint64_t node) {
        if (!node) return false;
        uint64_t next30   = Read<uint64_t>(node + ArcDecrypt::Offsets::UField::Next);
        bool is_module    = (next30 >= MODULE_BASE && next30 < MODULE_BASE + 0x10000000ULL);
        bool next_ok      = (next30 == 0) || (!is_module && next30 >= 0x1000000ULL && next30 < 0x800000000ULL);
        if (!next_ok) return false;
        uint32_t elem = Read<uint32_t>(node + ArcDecrypt::Offsets::UProperty::ElementSize);
        uint32_t adim = Read<uint32_t>(node + ArcDecrypt::Offsets::UProperty::ArrayDim);
        return elem >= 1 && elem <= 128 && adim >= 1 && adim <= 64;
    }

    // ── Walk old UField/UProperty chain from UStruct::Children ──────────
    // For legacy structs (FVector, FRotator, FLinearColor) that use UObject-
    // subclass properties instead of the new FField system.
    std::vector<PropertyRecord> ReadUPropertyChain(uint64_t head, int max_props = 512) {
        std::vector<PropertyRecord> result;
        std::unordered_set<uint64_t> visited;
        uint64_t node = head;
        int count = 0;
        while (node && count < max_props) {
            if (visited.count(node)) break;
            visited.insert(node);
            // Validate: must have a vtable in module range
            uint64_t nvt = Read<uint64_t>(node);
            if (nvt < MODULE_BASE || nvt >= MODULE_BASE + 0x10000000ULL) break;

            PropertyRecord pr{};
            pr.ff_addr = node;

            // Name: UProperty stores its FName at +0x50 (not in the standard 4 UObject slots)
            // Use GetUPropertyName which reads the +0x50 slot with its own encrypt pipeline.
            pr.name = m_fname.GetUPropertyName(node);
            if (pr.name.empty()) {
                // Fallback: try standard slot decrypt in case pipeline differs by build
                pr.name = m_fname.GetName(node);
            }
            if (pr.name.empty()) {
                char buf[32]; snprintf(buf, sizeof(buf), "Prop_%d", count);
                pr.name = buf;
            }

            // Offset_Internal: bswap32(stored) ^ 0xC43565C9
            uint32_t stored_off = Read<uint32_t>(node + ArcDecrypt::Offsets::UProperty::Offset_Internal);
            pr.offset    = static_cast<uint32_t>(ArcDecrypt::DecryptUPropertyOffset(stored_off));
            pr.elem_size = Read<uint32_t>(node + ArcDecrypt::Offsets::UProperty::ElementSize);
            pr.array_dim = Read<uint32_t>(node + ArcDecrypt::Offsets::UProperty::ArrayDim);

            // Validate: reject bogus legacy UProperty entries
            if (pr.offset > 0x20000 || pr.array_dim > 1024 || pr.elem_size > 0x10000) {
                break;  // bad chain, stop
            }

            // Type: vtable lookup first, then ElementSize heuristic
            uint64_t vtbl_rva = Read<uint64_t>(node) - MODULE_BASE;
            auto vt_it = m_vtable_to_type.find(vtbl_rva);
            if (vt_it != m_vtable_to_type.end()) {
                pr.type_name = vt_it->second;
            } else {
                switch (pr.elem_size) {
                    case 1:  pr.type_name = "UByteProperty";   break;
                    case 2:  pr.type_name = "UUInt16Property"; break;
                    case 4:  pr.type_name = "UFloatProperty";  break;
                    case 8:  pr.type_name = "UDoubleProperty"; break;
                    default: pr.type_name = "UProperty_" + std::to_string(pr.elem_size) + "b"; break;
                }
            }

            result.push_back(std::move(pr));
            node = Read<uint64_t>(node + ArcDecrypt::Offsets::UField::Next);
            ++count;
        }
        std::sort(result.begin(), result.end(),
            [](const PropertyRecord& a, const PropertyRecord& b){ return a.offset < b.offset; });
        return result;
    }
    // ── Resolve sub-property type for Struct/Object/Enum/Class/Interface ────
    void ResolveSubPropertyType(uint64_t ff, std::string& type_name) {
        if (type_name == "FStructProperty") {
            uint64_t sp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FStructProperty::Struct);
            if (sp) {
                std::string sn = m_fname.GetName(sp);
                if (!sn.empty()) type_name = sn;
            } else {
                // No Struct pointer — likely FTextProperty misidentified via elem_size heuristic
                uint64_t fc2 = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                uint32_t elem = fc2 ? Read<uint32_t>(fc2 + ArcDecrypt::Offsets::FFieldClass::ElementSize) : 0;
                if (elem == 16) type_name = "FTextProperty";
            }
        }
        if (type_name == "FObjectProperty" || type_name == "FWeakObjectProperty" ||
            type_name == "FSoftObjectProperty" || type_name == "FLazyObjectProperty") {
            uint64_t cp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (cp) { std::string cn = m_fname.GetName(cp); if (!cn.empty()) type_name = cn + "*"; }
        }
        if (type_name == "FClassProperty" || type_name == "FSoftClassProperty") {
            uint64_t mc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass + 8);
            if (mc) {
                std::string cn = m_fname.GetName(mc);
                if (!cn.empty()) { type_name = "TSubclassOf<" + cn + ">"; return; }
            }
            uint64_t cp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (cp) { std::string cn = m_fname.GetName(cp); if (!cn.empty()) type_name = "TSubclassOf<" + cn + ">"; }
        }
        if (type_name == "FInterfaceProperty") {
            uint64_t ic = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (ic) { std::string cn = m_fname.GetName(ic); if (!cn.empty()) type_name = "TScriptInterface<" + cn + ">"; }
        }
        if (type_name == "FEnumProperty") {
            uint64_t ep = Read<uint64_t>(ff + ArcDecrypt::Offsets::FEnumProperty::Enum);
            if (ep) { std::string en = m_fname.GetName(ep); if (!en.empty()) type_name = en; }
        }
    }

    // ── Read a single FProperty chain from any FField* head pointer ─────────
    // Shared by ReadProperties (UStruct::ChildProperties) and UFunction params.
    std::vector<PropertyRecord> ReadPropertyChain(uint64_t ff_head, int max_props = 2048,
                                                   bool is_param = false) {
        std::vector<PropertyRecord> result;
        std::unordered_set<uint64_t> visited;
        std::vector<PropertyRecord> sub_props;  // Array Inner / Map Key+Val sub-properties

        uint64_t ff = ff_head;
        int count = 0;
        while (ff && count < max_props) {
            if (visited.count(ff)) break;
            visited.insert(ff);

            PropertyRecord pr{};
            pr.ff_addr   = ff;
            pr.is_param  = is_param;

            // Name
            pr.name = ReadFFieldName(ff);
            if (pr.name.empty()) {
                // Get CI for use in fallback name (unique per name)
                int32_t fci = m_fname.DecryptFFieldNameCI(ff);
                uint32_t stored_off2 = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                uint32_t off2 = ArcDecrypt::Patch20260421::DecryptPropertyOffsetNew(stored_off2);
                char buf[64];
                snprintf(buf, sizeof(buf), "Prop_CI%u_Off0x%X", static_cast<uint32_t>(fci), off2);
                pr.name = buf;
            }
            // Sanity: real names shouldn't have special characters beyond _
            bool name_ok = !pr.name.empty();
            for (char c : pr.name) {
                if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='<'||c=='>')) {
                    name_ok = false; break;
                }
            }
            if (!name_ok) {
                int32_t fci = m_fname.DecryptFFieldNameCI(ff);
                char buf[64];
                snprintf(buf, sizeof(buf), "Prop_CI%u_0x%llX",
                    static_cast<uint32_t>(fci), (unsigned long long)(ff & 0xFFFFF));
                pr.name = buf;
            }

            // Type identification: fclass_ptr FIRST (all FProperties share the same vtable
            // in patch 20260402, so vtable RVA is useless for discrimination)
            pr.fclass_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);

            auto fc_it = m_fclass_to_type.find(pr.fclass_ptr);
            if (fc_it != m_fclass_to_type.end()) {
                pr.type_name = fc_it->second;
            } else {
                // Fallback: element-size heuristic via IdentifyPropertyType
                std::string vt_type = IdentifyPropertyType(ff);
                pr.type_name = (vt_type.find("UNKNOWN") == std::string::npos)
                               ? vt_type : "FProperty_Unknown";
            }
            pr.is_bool = (pr.type_name == "FBoolProperty");
            if (pr.is_bool) {
                pr.bool_byte_mask  = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::ByteMask);
                pr.bool_field_size = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::FieldSize);
            }

            // Offset_Internal: encrypted at FProperty+0xC0 (patch 20260421)
            // real = bswap32(stored) ^ 0x59B8C401   (sentinel 0x01C4B859 → real=0)
            {
                uint32_t stored_off = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                pr.offset = ArcDecrypt::Patch20260421::DecryptPropertyOffsetNew(stored_off);
            }

            // ElementSize and ArrayDim stored directly in FProperty (patch 20260414)
            pr.elem_size = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);
            pr.array_dim = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ArrayDim);

            // Validate property: reject obviously garbage entries
            // Property offsets rarely exceed 0x10000 (64KB). Array dims rarely > 256.
            // Patch 20260421: Offset_Internal location not yet confirmed, so the
            // `offset` field is often 0 (or the old-patch decrypt of 0 produces a
            // huge bogus value). Don't bail out on offset alone — check only the
            // easy sanity checks (array_dim and elem_size) and zero the offset
            // if it looks out of range so the downstream writer doesn't print it.
            if (pr.array_dim > 1024 || pr.elem_size > 0x10000) {
                break;
            }
            if (pr.offset > 0x20000) pr.offset = 0;

            bool is_struct = pr.type_name == "FStructProperty";
            bool is_array  = pr.type_name == "FArrayProperty";
            bool is_map    = pr.type_name == "FMapProperty";
            bool is_set    = pr.type_name == "FSetProperty";
            bool is_enum   = pr.type_name == "FEnumProperty";
            bool is_class  = pr.type_name == "FClassProperty" ||
                             pr.type_name == "FSoftClassProperty";
            bool is_object = pr.type_name == "FObjectProperty" ||
                             pr.type_name == "FWeakObjectProperty" ||
                             pr.type_name == "FSoftObjectProperty" ||
                             pr.type_name == "FLazyObjectProperty";
            bool is_interface = pr.type_name == "FInterfaceProperty";

            // Resolve sub-property types (struct name, object class, enum, etc.)
            if (is_struct || is_object || is_class || is_interface || is_enum)
                ResolveSubPropertyType(ff, pr.type_name);

            // FArrayProperty: enrich parent + add Inner sub-property
            if (is_array) {
                uint64_t inner_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FArrayProperty::Inner);
                if (inner_ptr) {
                    PropertyRecord ipr{};
                    ipr.ff_addr    = inner_ptr;
                    ipr.name       = pr.name + "__Item";
                    ipr.is_param   = is_param;
                    ipr.fclass_ptr = Read<uint64_t>(inner_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                    {
                        auto ifc_it = m_fclass_to_type.find(ipr.fclass_ptr);
                        if (ifc_it != m_fclass_to_type.end()) {
                            ipr.type_name = ifc_it->second;
                        } else {
                            std::string vt = IdentifyPropertyType(inner_ptr);
                            ipr.type_name = (vt.find("UNKNOWN") == std::string::npos) ? vt : "FProperty_Unknown";
                        }
                    }
                    ipr.offset     = pr.offset;
                    { uint64_t ifc = Read<uint64_t>(inner_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                      ipr.elem_size = ifc ? Read<uint32_t>(ifc + ArcDecrypt::Offsets::FFieldClass::ElementSize) : 0; }
                    ipr.array_dim  = 1;
                    // Resolve inner sub-property type
                    ResolveSubPropertyType(inner_ptr, ipr.type_name);
                    std::string inner_t = ipr.type_name;
                    pr.type_name = (inner_t.empty() || inner_t == "FProperty_Unknown" ||
                                    inner_t.find("UNKNOWN") != std::string::npos)
                                   ? "TArray<?>" : "TArray<" + inner_t + ">";
                    sub_props.push_back(std::move(ipr));
                }
            }

            // FSetProperty: enrich parent + resolve element type
            if (is_set) {
                uint64_t elem_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FSetProperty::ElementProp);
                if (elem_ptr) {
                    PropertyRecord epr{};
                    epr.ff_addr    = elem_ptr;
                    epr.name       = pr.name + "__Elem";
                    epr.is_param   = is_param;
                    epr.fclass_ptr = Read<uint64_t>(elem_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                    {
                        auto efc_it = m_fclass_to_type.find(epr.fclass_ptr);
                        if (efc_it != m_fclass_to_type.end()) {
                            epr.type_name = efc_it->second;
                        } else {
                            std::string vt = IdentifyPropertyType(elem_ptr);
                            epr.type_name = (vt.find("UNKNOWN") == std::string::npos) ? vt : "FProperty_Unknown";
                        }
                    }
                    epr.offset    = pr.offset;
                    { uint64_t efc = Read<uint64_t>(elem_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                      epr.elem_size = efc ? Read<uint32_t>(efc + ArcDecrypt::Offsets::FFieldClass::ElementSize) : 0; }
                    epr.array_dim = 1;
                    ResolveSubPropertyType(elem_ptr, epr.type_name);
                    std::string elem_t = epr.type_name;
                    pr.type_name = (elem_t.empty() || elem_t.find("UNKNOWN") != std::string::npos)
                                   ? "TSet<?>" : "TSet<" + elem_t + ">";
                    sub_props.push_back(std::move(epr));
                }
            }

            // FMapProperty: enrich parent + add Key and Value sub-properties
            if (is_map) {
                uint64_t key_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FMapProperty::KeyProp);
                uint64_t val_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FMapProperty::ValueProp);
                std::string key_t, val_t;

                auto resolve_map_inner = [&](uint64_t mp, const std::string& suffix) -> PropertyRecord {
                    PropertyRecord mpr{};
                    if (!mp) return mpr;
                    mpr.ff_addr    = mp;
                    mpr.name       = pr.name + suffix;
                    mpr.is_param   = is_param;
                    mpr.fclass_ptr = Read<uint64_t>(mp + ArcDecrypt::Offsets::FField::ClassPrivate);
                    {
                        auto mfc_it = m_fclass_to_type.find(mpr.fclass_ptr);
                        if (mfc_it != m_fclass_to_type.end()) {
                            mpr.type_name = mfc_it->second;
                        } else {
                            std::string vt = IdentifyPropertyType(mp);
                            mpr.type_name = (vt.find("UNKNOWN") == std::string::npos) ? vt : "FProperty_Unknown";
                        }
                    }
                    mpr.offset    = pr.offset;
                    { uint64_t mfc = Read<uint64_t>(mp + ArcDecrypt::Offsets::FField::ClassPrivate);
                      mpr.elem_size = mfc ? Read<uint32_t>(mfc + ArcDecrypt::Offsets::FFieldClass::ElementSize) : 0; }
                    mpr.array_dim = 1;
                    // Resolve map inner sub-property type
                    ResolveSubPropertyType(mp, mpr.type_name);
                    return mpr;
                };

                PropertyRecord kpr = resolve_map_inner(key_ptr, "__Key");
                PropertyRecord vpr = resolve_map_inner(val_ptr, "__Value");
                key_t = kpr.type_name;
                val_t = vpr.type_name;
                pr.type_name = "TMap<" + key_t + "," + val_t + ">";
                if (key_ptr) sub_props.push_back(std::move(kpr));
                if (val_ptr) sub_props.push_back(std::move(vpr));
            }

            result.push_back(pr);
            ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
            // Validate next pointer
            if (ff && (ff < 0x10000 || ff >= 0x7FFFFFFFFFFFULL)) break;
            ++count;
        }

        // Merge sub-properties (Array Inner, Map Key/Val)
        for (auto& sp : sub_props)
            result.push_back(std::move(sp));

        std::sort(result.begin(), result.end(),
            [](const PropertyRecord& a, const PropertyRecord& b) {
                return a.offset < b.offset;
            });
        return result;
    }
    // ── Read FProperty chain from a UStruct — delegates to ReadPropertyChain ─
    std::vector<PropertyRecord> ReadProperties(uint64_t ustruct_addr, int max_props = 2048) {
        uint64_t ff_head = Read<uint64_t>(ustruct_addr + ArcDecrypt::Offsets::UStruct::ChildProperties);
        if (!ff_head) return {};
        return ReadPropertyChain(ff_head, max_props, /*is_param=*/false);
    }


    // ── Read UFunction records for a given owner from m_owner_to_funcs ─────
    // UFunctions are pre-discovered in BuildSDK (see 4-pass scan of GObjects)
    // and indexed by Outer (or owner=0 for orphans). For each function we read
    // FunctionFlags, NativeFunc RVA, name, and walk the FField chain at +0x100
    // to extract parameters (legacy UProperty chain at +0xE0 is the fallback
    // for older-style functions). UStruct::Children chain is NOT used; in this
    // build it holds old UProperty data, not UFunctions.
    std::vector<FunctionRecord> ReadFunctionsFromMap(uint64_t owner_addr) {
        std::vector<FunctionRecord> result;
        auto it = m_owner_to_funcs.find(owner_addr);
        if (it == m_owner_to_funcs.end()) return result;

        for (uint64_t fn_addr : it->second) {
            FunctionRecord fr{};
            fr.fn_addr    = fn_addr;
            fr.flags      = Read<uint64_t>(fn_addr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
            fr.native_rva = 0;

            uint64_t native = Read<uint64_t>(fn_addr + ArcDecrypt::Offsets::UFunction::NativeFunc);
            if (native >= MODULE_BASE && native < MODULE_BASE + 0x10000000ULL)
                fr.native_rva = native - MODULE_BASE;

            fr.name = m_fname.GetName(fn_addr);
            if (fr.name.empty()) fr.name = "<unnamed_func>";

            // UFunction params: for patch 20260421 the FField chain head is at +0xC8
            // (= UStruct::ChildProperties). Keep a range scan so we also catch 20260414-
            // style functions that put the param head at +0xE0..0x110.
            std::unordered_set<std::string> seen;
            for (int co = 0xC0; co <= 0x110; co += 8) {
                uint64_t head = Read<uint64_t>(fn_addr + co);
                if (head <= 0x10000 || head >= 0x800000000000ULL) continue;
                uint64_t hvt = Read<uint64_t>(head);
                if (hvt < MODULE_BASE || hvt >= MODULE_BASE + 0x10000000ULL) continue;
                auto chain = ReadPropertyChain(head, 64, /*is_param=*/true);
                for (auto& p : chain) {
                    std::string key = p.name + ":" + std::to_string(p.offset);
                    if (seen.insert(key).second)
                        fr.params.push_back(std::move(p));
                }
            }
            // Fallback: legacy old-style UProperty chain
            if (fr.params.empty()) {
                uint64_t param_head = Read<uint64_t>(fn_addr + ArcDecrypt::Offsets::UStruct::Children);
                if (param_head) {
                    uint64_t pvt = Read<uint64_t>(param_head);
                    if (pvt >= MODULE_BASE && pvt < MODULE_BASE + 0x10000000ULL)
                        fr.params = ReadUPropertyChain(param_head, 64);
                }
            }
            // Mark params
            for (auto& p : fr.params) p.is_param = true;

            result.push_back(std::move(fr));
        }
        return result;
    }

    // ── Dump a single UStruct/UClass to string ──────────────────────────────────
    std::string DumpStruct(const StructRecord& rec) {
        std::ostringstream oss;
        oss << "// " << (rec.is_class ? "Class" : "Struct") << " /Script/"
            << rec.package << "." << rec.name << "\n";
        oss << "// Address: 0x" << std::hex << rec.addr << "\n";
        oss << "// Size: 0x" << std::hex << rec.props_size
            << " (" << std::dec << rec.props_size << " bytes)\n";
        if (!rec.super_name.empty())
            oss << "// Inherits: " << rec.super_name << " (0x" << std::hex << rec.super_addr << ")\n";
        // Walk full inheritance chain
        if (rec.super_addr) {
            oss << "// Inheritance chain:\n";
            uint64_t cur = rec.super_addr;
            std::unordered_set<uint64_t> chain_seen;
            int depth = 0;
            while (cur && chain_seen.insert(cur).second && depth < 16) {
                std::string nm = m_fname.GetName(cur);
                if (nm.empty()) nm = "Unknown";
                uint32_t sz = Read<uint32_t>(cur + ArcDecrypt::Offsets::UStruct::PropertiesSize);
                oss << "//   " << std::string(depth * 2, ' ') << "→ " << nm
                    << " (0x" << std::hex << cur << ", size=" << std::dec << sz << ")\n";
                cur = Read<uint64_t>(cur + ArcDecrypt::Offsets::UStruct::SuperStruct);
                ++depth;
            }
        }
        oss << "namespace " << rec.name << " {\n";
        for (const auto& pr : rec.properties) {
            std::string type_decl;
            if (pr.array_dim > 1)
                type_decl = pr.type_name + "[" + std::to_string(pr.array_dim) + "]";
            else
                type_decl = pr.type_name;
            std::string name_padded = pr.name;
            if (name_padded.size() < 40)
                name_padded.append(40 - name_padded.size(), ' ');
            oss << "constexpr uint32_t " << name_padded << " = 0x" << std::hex << pr.offset << ";";
            oss << "  // " << type_decl;
            if (pr.is_bool && pr.bool_byte_mask) {
                oss << " // mask=0x" << std::hex << (unsigned)pr.bool_byte_mask;
                if (pr.bool_field_size == 4)
                    oss << " (native)";
            }
            if (pr.elem_size > 0)
                oss << " // size=0x" << std::hex << pr.elem_size;
            oss << "\n";
        }
        if (!rec.functions.empty()) {
            oss << "\n// === Functions (" << rec.functions.size() << ") ===\n";
            for (const auto& fn : rec.functions) {
                // Find return value (param marked as return) and inputs
                std::string ret_type = "void";
                std::vector<const PropertyRecord*> in_params;
                for (const auto& par : fn.params) {
                    // Convention: return value is usually the last param named "ReturnValue" or has flag
                    if (par.name == "ReturnValue") ret_type = par.type_name;
                    else in_params.push_back(&par);
                }
                oss << "// 0x" << std::hex << fn.fn_addr;
                if (fn.native_rva) oss << " (RVA: 0x" << std::hex << fn.native_rva << ")";
                oss << " flags=0x" << std::hex << fn.flags << "\n";
                oss << ret_type << " " << fn.name << "(";
                bool first = true;
                for (const auto* par : in_params) {
                    if (!first) oss << ", ";
                    first = false;
                    oss << par->type_name << " " << par->name;
                    if (par->array_dim > 1) oss << "[" << par->array_dim << "]";
                }
                oss << "); // " << in_params.size() << " params\n";
            }
        }
        oss << "} // namespace " << rec.name << "  // size=0x" << std::hex << rec.props_size << "\n\n";
        return oss.str();
    }

    // ── Dump a UEnum to string ────────────────────────────────────────────────────────
    std::string DumpEnum(const EnumRecord& rec) {
        std::ostringstream oss;
        oss << "// Enum /Script/" << rec.package << "." << rec.name << "\n";
        oss << "namespace " << rec.name << " {\n";
        for (const auto& e : rec.entries) {
            std::string padded = e.name;
            if (padded.size() < 40)
                padded.append(40 - padded.size(), ' ');
            oss << "    constexpr int64_t " << padded << " = " << std::dec << e.value << ";\n";
        }
        oss << "} // namespace " << rec.name << "\n\n";
        return oss.str();
    }

    // ── Build SDK for all GObjects UClass/UScriptStruct/UEnum ──────────────────
    // object_ptrs: pre-built ordered list of (index, obj_ptr) pairs
    // addr_to_fullname: obj ptr → GetName() result
    // addr_to_name   : obj ptr → last segment after '/'
    SDKResult BuildSDK(
            const std::vector<std::pair<int32_t, uint64_t>>& object_ptrs,
            const std::unordered_map<uint64_t, std::string>& addr_to_name,
            const std::unordered_map<uint64_t, std::string>& addr_to_fullname)
    {
        SDKResult result;
        result.structs.reserve(16000);
        result.enums.reserve(3000);
        std::unordered_set<uint64_t> seen;

        // ── Pass 0: build package map  (addr → short name, e.g. "Engine") ────
        // Package objects have names starting with "/" (e.g. "/Script/Engine").
        std::unordered_map<uint64_t, std::string> pkg_map;
        for (const auto& kv : addr_to_fullname) {
            const std::string& n = kv.second;
            if (n.empty() || n[0] != '/') continue;
            size_t last_slash = n.rfind('/');
            std::string short_pkg = n.substr(last_slash + 1);
            if (!short_pkg.empty())
                pkg_map[kv.first] = short_pkg;
        }
        std::printf("[sdk] Package map: %zu packages\n", pkg_map.size());

        // ── Pass 1: find metaclass addresses + collect vtables ────────────
        uint64_t classAddr = 0, ssAddr = 0, enumAddr = 0;
        std::unordered_set<uint64_t> validClassTypes;  // "class-of-class" types
        std::unordered_set<uint64_t> validEnumTypes;   // enum subtypes (UserDefinedEnum etc.)
        // Multiple objects can be named "Class"/"ScriptStruct"/"Enum" (CDOs).
        // The actual metaclass is the FIRST one (lowest InternalIndex).
        // Also collect ALL such addresses since any could be a valid metaclass.
        std::unordered_set<uint64_t> ssAddrs, enumAddrs;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const std::string& n = it->second;
            if (n == "Class")             { if (!classAddr) classAddr = obj_ptr; validClassTypes.insert(obj_ptr); }
            else if (n == "ScriptStruct") { if (!ssAddr) ssAddr = obj_ptr; ssAddrs.insert(obj_ptr); }
            else if (n == "Enum")         { if (!enumAddr) enumAddr = obj_ptr; enumAddrs.insert(obj_ptr); }
            else if (n == "UserDefinedEnum" || n == "UserDefinedStruct") {
                validEnumTypes.insert(obj_ptr);
                ssAddrs.insert(obj_ptr);
            }
            else if (n == "BlueprintGeneratedClass" ||
                     n == "WidgetBlueprintGeneratedClass" ||
                     n == "AnimBlueprintGeneratedClass" ||
                     n == "DynamicClass" ||
                     n == "LinkerPlaceholderClass")
                validClassTypes.insert(obj_ptr);
        }
        if (!classAddr) {
            std::printf("[sdk] FATAL: Could not find 'Class' UClass object\n");
            return result;
        }

        std::printf("[sdk] Class=0x%llX  ScriptStruct=0x%llX  Enum=0x%llX  metaclassTypes=%zu\n",
            (unsigned long long)classAddr, (unsigned long long)ssAddr,
            (unsigned long long)enumAddr, validClassTypes.size());

        // ── Build "all type addresses" set ──────────────────────────────
        // Every address used as a Class pointer by ANY object is a type object.
        // This catches UClass instances even if GetClassPrivate decryption fails.
        std::unordered_set<uint64_t> allTypeAddrs;
        // Include ALL addresses used as ClassPrivate (even unnamed ones — they're still types)
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
            // Validate: must be a heap pointer in valid range
            if (cls > 0x10000 && cls < 0x7FFFFFFFFFFFULL)
                allTypeAddrs.insert(cls);
        }
        std::printf("[sdk] allTypeAddrs (addresses used as Class ptrs): %zu\n", allTypeAddrs.size());

        // ── Pre-pass: identify UFunction vtable RVAs ──────────────────────
        // Walk Children of known UClass objects that have ChildProperties (= have functions).
        // The function metaclass (named "Function") should appear as ClassPrivate of children.
        // Find "Function" metaclass: must be a UClass (ClassPrivate = classAddr)
        std::unordered_set<uint64_t> funcMetaAddrs;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const auto& n = it->second;
            if (n == "Function" || n == "DelegateFunction" || n == "SparseDelegateFunction") {
                uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
                if (validClassTypes.count(cls))  // Must be a UClass object
                    funcMetaAddrs.insert(obj_ptr);
            }
        }
        std::printf("[sdk] Function metaclasses found: %zu\n", funcMetaAddrs.size());
        for (uint64_t fm : funcMetaAddrs) {
            auto it = addr_to_name.find(fm);
            std::printf("[sdk]   0x%llX = %s\n", (unsigned long long)fm,
                it != addr_to_name.end() ? it->second.c_str() : "?");
        }

        // ── Build owner→functions map from GObjects ──────────────────────
        // Four-pass discovery; each pass tightens or widens the signal so we
        // catch UFunctions that the previous pass missed:
        //   Pass 1: ClassPrivate decrypts to a known function metaclass (high confidence)
        //   Pass 2: vtable matches a pass-1 vtable AND Outer is a known type
        //   Pass 3: heuristic — FunctionFlags valid AND (known UFunc vtable OR known-type Outer)
        //           Also expands ufunc_vtbls so pass 4 can rescue siblings.
        //   Pass 4: vtable-only rescue for objects with sparse slot patterns
        //           (UFunctions whose ClassPrivate/Outer slots are empty/un-decryptable;
        //            real example: K2_AddActorWorldOffset has only one populated UObject slot).
        // Functions with no resolvable Outer get pushed under owner=0 so they appear in
        // the orphan section instead of being silently dropped.
        std::unordered_set<uint64_t> ufunc_vtbls;
        {
            int fn_found = 0;
            std::unordered_set<uint64_t> found_set;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
                if (!funcMetaAddrs.count(cls)) continue;
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                // Always push even if outer is 0 (orphan); allows the function
                // to appear in the orphan section instead of being lost.
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                uint64_t vt = Read<uint64_t>(obj_ptr);
                ufunc_vtbls.insert(vt);
                ++fn_found;
            }
            std::printf("[sdk] UFunction pass 1 (ClassPrivate): %d funcs, %zu vtables\n",
                fn_found, ufunc_vtbls.size());

            // Pass 2: find more by matching ANY known UFunction vtable + valid Outer
            int extra = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (found_set.count(obj_ptr)) continue;
                uint64_t vt = Read<uint64_t>(obj_ptr);
                if (!ufunc_vtbls.count(vt)) continue;
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                if (!outer || !addr_to_name.count(outer)) continue;
                m_owner_to_funcs[outer].push_back(obj_ptr);
                ++extra;
            }
            std::printf("[sdk] UFunction pass 2 (vtable+outer): %d extra funcs\n", extra);

            // Pass 3: heuristic — any named non-type object whose Outer is a known type
            // and has reasonable FunctionFlags at +0x128 is likely a UFunction.
            int pass3 = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (found_set.count(obj_ptr)) continue;
                auto nit = addr_to_name.find(obj_ptr);
                if (nit == addr_to_name.end()) continue;
                const auto& nm = nit->second;
                if (nm.empty() || nm[0] == '/') continue;
                // Skip CDOs and other non-function objects
                if (nm.rfind("Default__", 0) == 0) continue;
                // Skip if it's a known type itself
                if (allTypeAddrs.count(obj_ptr)) continue;
                if (validEnumTypes.count(obj_ptr)) continue;
                // FunctionFlags at +0x128 must be reasonable
                uint32_t flags = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                if (flags == 0 || flags > 0x10000000u) continue;
                // Accept if EITHER:
                //   (a) vtable is a known UFunction vtable, OR
                //   (b) Outer resolves to a known type (the original strict heuristic)
                uint64_t vt = Read<uint64_t>(obj_ptr);
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                bool vt_ok    = ufunc_vtbls.count(vt) > 0;
                bool outer_ok = outer && allTypeAddrs.count(outer) > 0;
                if (!vt_ok && !outer_ok) continue;
                // If accepted by vtable but outer isn't a known type, push to orphans
                if (!outer_ok) outer = 0;
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                ufunc_vtbls.insert(vt);  // expand vtable set so pass 4 can rescue siblings
                ++pass3;
            }
            std::printf("[sdk] UFunction pass 3 (heuristic): %d extra funcs\n", pass3);

            // Pass 4: catch UFunctions whose ClassPrivate/Outer slots are empty or
            // un-decryptable (sparse slot pattern — only one of the four UObject
            // name slots holds data, e.g. K2_AddActorWorldOffset). Identify by:
            //   - vtable in known UFunction vtable set (expanded by pass 3)
            //   - FunctionFlags at +0x128 looks valid
            //   - NextPtr at +0x98 either NULL or heap (matches UField layout)
            // Outer of 0 → orphan owner; the function still appears in the SDK's
            // orphan section.
            int pass4 = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (found_set.count(obj_ptr)) continue;
                uint64_t vt = Read<uint64_t>(obj_ptr);
                if (!ufunc_vtbls.count(vt)) continue;
                uint32_t flags = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                if (flags == 0 || flags > 0x10000000u) continue;
                uint64_t nxt = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::NextPtr);
                if (nxt != 0 && (nxt < 0x10000 || nxt >= 0x800000000000ULL)) continue;
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                ++pass4;
            }
            std::printf("[sdk] UFunction pass 4 (sparse-slot rescue): %d extra funcs (ufunc_vtbls=%zu)\n",
                pass4, ufunc_vtbls.size());
        }
        {
            int total_fn = 0;
            for (auto& [owner, fns] : m_owner_to_funcs) total_fn += fns.size();
            std::printf("[sdk] Total UFunction objects: %d, owners: %zu\n",
                total_fn, m_owner_to_funcs.size());
        }

        // ── Auto-discover vtable-to-type mappings (replaces bootstrap + sweep) ──
        AutoDiscoverVTables(object_ptrs, addr_to_name, allTypeAddrs, ssAddr);

        // ── Helper: resolve package name for any obj ptr ──────────────────────
        auto resolvePackage = [&](uint64_t obj_ptr) -> std::string {
            uint64_t pkg_ptr = m_fname.GetPackagePtr(obj_ptr);
            if (!pkg_ptr) return "Unknown";
            auto it = pkg_map.find(pkg_ptr);
            if (it != pkg_map.end()) return it->second;
            auto fn = addr_to_fullname.find(pkg_ptr);
            if (fn != addr_to_fullname.end()) {
                const std::string& s = fn->second;
                if (!s.empty() && s[0]=='/') {
                    size_t ls = s.rfind('/');
                    return s.substr(ls+1);
                }
                return s;
            }
            return "Unknown";
        };

        // ── Pass 2: iterate objects — include all type objects ──────────────────
        // An object is a type if: (a) it's in allTypeAddrs (used as class ptr by others),
        // OR (b) GetClassPrivate returns classAddr/ssAddr/enumAddr/validClassTypes.
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            if (!obj_ptr || seen.count(obj_ptr)) continue;
            seen.insert(obj_ptr);

            auto fn_it = addr_to_name.find(obj_ptr);
            std::string short_name = (fn_it != addr_to_name.end()) ? fn_it->second : std::string();
            // Skip packages (start with "/")
            if (!short_name.empty() && short_name[0] == '/') continue;
            // For unnamed objects, only proceed if they're referenced as a type
            if (short_name.empty()) {
                // Will check is_type_by_ref below; generate a placeholder name
                char buf[32]; std::snprintf(buf, sizeof(buf), "Class_0x%llX", (unsigned long long)obj_ptr);
                short_name = buf;
            }

            // Determine type via two paths:
            // Path A: GetClassPrivate gives a known metaclass/type indicator
            uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
            bool is_class_by_cls = validClassTypes.count(cls) > 0;
            bool is_scriptstruct = ssAddrs.count(cls) > 0;
            bool is_enum         = enumAddrs.count(cls) > 0 || validEnumTypes.count(cls) > 0;

            // Path C: heuristic — Names array at +0xA8 (UEnum::Names)
            // Only apply when not already classified as a type
            bool _is_type_by_ref_check = allTypeAddrs.count(obj_ptr) > 0;
            if (!is_class_by_cls && !is_scriptstruct && !is_enum && !_is_type_by_ref_check) {
                uint64_t names_ptr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names);
                uint32_t names_cnt = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 8);
                uint32_t names_max = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 12);
                if (names_ptr > 0x10000 && names_ptr < 0x7FFFFFFFFFFFULL &&
                    names_cnt > 0 && names_cnt < 4096 && names_cnt == names_max) {
                    int32_t first_ci = Read<int32_t>(names_ptr);
                    // CI range expanded: 29-bit pool indices can be up to ~536M
                    if (first_ci > 0 && (uint32_t)first_ci < 0x1FFFFFFFu) {
                        is_enum = true;
                    }
                }
                // Heuristic for structs: name starts with character (not /), has small props_size
                if (!is_enum && !short_name.empty() && short_name[0] != 'C' &&
                    (short_name[0] == 'F' || short_name.find("Struct") != std::string::npos ||
                     short_name.find("Vector") != std::string::npos ||
                     short_name.find("Rotator") != std::string::npos ||
                     short_name.find("Color") != std::string::npos ||
                     short_name.find("Quat") != std::string::npos ||
                     short_name.find("Transform") != std::string::npos ||
                     short_name.find("Box") != std::string::npos ||
                     short_name.find("Matrix") != std::string::npos)) {
                    uint32_t ps = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::PropertiesSize);
                    if (ps > 0 && ps < 4096) is_scriptstruct = true;
                }
            }

            // Path B: this address is used as a Class pointer by other objects → it's a type
            bool is_type_by_ref = allTypeAddrs.count(obj_ptr) > 0;

            // Skip objects that aren't types by either path
            if (!is_class_by_cls && !is_scriptstruct && !is_enum && !is_type_by_ref) continue;

            // Classify: if detected by reference but not by Class decrypt,
            // it's likely a UClass (most allTypeAddrs entries are UClass objects)
            bool is_class = is_class_by_cls || (is_type_by_ref && !is_scriptstruct && !is_enum);

            std::string pkg = resolvePackage(obj_ptr);

            // ─── UEnum ────────────────────────────────────────────────────────
            if (is_enum) {
                EnumRecord erec{};
                erec.addr    = obj_ptr;
                erec.name    = short_name;
                erec.package = pkg;

                uint64_t names_ptr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names);
                uint32_t names_cnt = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 8);

                if (names_ptr && names_cnt > 0 && names_cnt < 4096) {
                    for (uint32_t j = 0; j < names_cnt; ++j) {
                        uint64_t ep  = names_ptr + (uint64_t)j * 16;
                        int32_t  ci  = Read<int32_t>(ep + 0);
                        int64_t  val = Read<int64_t>(ep + 8);
                        std::string ev = m_fname.CompIndexToName(ci);
                        if (ev.empty()) continue;
                        size_t cc = ev.find("::");
                        if (cc != std::string::npos) ev = ev.substr(cc + 2);
                        erec.entries.push_back({ev, val});
                    }
                }
                if (!erec.entries.empty())
                    result.enums.push_back(std::move(erec));
                continue;
            }

            // ─── UClass / UScriptStruct ────────────────────────────────────────
            StructRecord rec{};
            rec.addr       = obj_ptr;
            rec.name       = short_name;
            rec.package    = pkg;
            rec.is_class   = is_class && !is_scriptstruct;
            rec.props_size = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::PropertiesSize);

            // SuperStruct
            rec.super_addr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::SuperStruct);
            if (rec.super_addr) {
                auto sit = addr_to_name.find(rec.super_addr);
                if (sit != addr_to_name.end())
                    rec.super_name = sit->second;
            }

            // Properties: scan ALL offsets 0x80-0x140 for FField chains and
            // dedup by FField address (unique per field). Previous version
            // keyed on p.offset, which collapsed everything to a single entry
            // on patch 20260421 where Offset_Internal is at an unknown RVA
            // (current read lands on zeros for most FProperties).
            std::unordered_map<uint64_t, PropertyRecord> best_at_ff;
            for (int co = 0x80; co <= 0x140; co += 8) {
                uint64_t chain_head = Read<uint64_t>(obj_ptr + co);
                if (chain_head <= 0x10000 || chain_head >= 0x7FFFFFFFFFFFULL) continue;
                uint64_t cpvt = Read<uint64_t>(chain_head);
                if (cpvt < MODULE_BASE || cpvt >= MODULE_BASE + 0x10000000ULL) continue;
                auto chain_props = ReadPropertyChain(chain_head);
                for (auto& p : chain_props) {
                    if (p.offset > 0x20000) continue;
                    auto it = best_at_ff.find(p.ff_addr);
                    if (it == best_at_ff.end()) {
                        best_at_ff[p.ff_addr] = std::move(p);
                    } else {
                        bool cur_unk = (it->second.name.rfind("UnknownProp_", 0) == 0 ||
                                        it->second.name.rfind("Prop_CI", 0) == 0);
                        bool new_unk = (p.name.rfind("UnknownProp_", 0) == 0 ||
                                        p.name.rfind("Prop_CI", 0) == 0);
                        bool cur_tk  = (it->second.type_name != "FProperty_Unknown");
                        bool new_tk  = (p.type_name != "FProperty_Unknown");
                        int cur_score = (cur_unk ? 0 : 2) + (cur_tk ? 1 : 0);
                        int new_score = (new_unk ? 0 : 2) + (new_tk ? 1 : 0);
                        if (new_score > cur_score) best_at_ff[p.ff_addr] = std::move(p);
                    }
                }
            }
            for (auto& [ff, p] : best_at_ff)
                rec.properties.push_back(std::move(p));
            // Legacy UProperty chain intentionally disabled — it corrupts output with
            // bogus entries (~3%) and the FField chain covers almost everything.

            // Functions: found from GObjects by ClassPrivate, grouped by Outer
            rec.functions = ReadFunctionsFromMap(obj_ptr);

            result.structs.push_back(std::move(rec));
        }

        // Sort alphabetically by package then name
        auto sort_by_pkg_name = [](const auto& a, const auto& b) {
            return a.package < b.package || (a.package == b.package && a.name < b.name);
        };
        std::sort(result.structs.begin(), result.structs.end(), sort_by_pkg_name);
        std::sort(result.enums.begin(),   result.enums.end(),   sort_by_pkg_name);

        return result;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: format SDK output
// ─────────────────────────────────────────────────────────────────────────────
inline std::string FormatSDK(Generator& gen, const SDKResult& sdk) {
    std::ostringstream oss;
    oss << "// ============================================================\n";
    oss << "// ARC Raiders SDK Dump\n";
    oss << "// Enums:   " << std::dec << sdk.enums.size()   << "\n";
    oss << "// Structs: " << std::dec << sdk.structs.size() << "\n";
    oss << "// ============================================================\n\n";
    oss << "#pragma once\n#include <cstdint>\n\nnamespace ARC {\n\n";
    if (!sdk.enums.empty()) {
        oss << "namespace Enums {\n\n";
        for (const auto& e : sdk.enums)   oss << gen.DumpEnum(e);
        oss << "} // namespace Enums\n\n";
    }
    if (!sdk.structs.empty()) {
        oss << "namespace Types {\n\n";
        for (const auto& s : sdk.structs) oss << gen.DumpStruct(s);
        oss << "} // namespace Types\n\n";
    }
    oss << "} // namespace ARC\n";
    return oss.str();
}

} // namespace SDKGen
