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

    std::unordered_map<int32_t, std::string> m_type_idx_to_name;
    std::unordered_set<std::string> m_canonical_property_type_names;
    bool m_dynamic_type_table_loaded = false;
    std::unordered_set<uint64_t> m_observed_fclass_ptrs;
    int32_t m_fclass_typeidx_offset = -1;
    // FFieldClass NamePrivate slot offset, calibrated at runtime. -1 = not yet
    // calibrated / no offset works. Probed via the same FField NamePrivate
    // decode pipeline (PSHUFLW(0x4B) → ROL32(3) → PSHUFLW(0x72) → XOR → ROL64(32))
    // — shape verified on 20260421 IDA in FProperty_GetNameCPP @ 0x3AFE70 reading
    // FFieldClass+0x20. The slot offset moves between patches; calibration tries
    // 16-byte-aligned offsets 0x10..0x80 and picks the one that resolves the most
    // FFieldClasses to canonical property-type names.
    int32_t m_fclass_nameslot_offset = -1;
    // Sets populated during property walk: every FStructProperty.Struct value is
    // a UScriptStruct address; every FEnumProperty.Enum value is a UEnum.
    // Used in classification to mark these UObjects as struct/enum even when
    // the slot-picker-based detection misses them.
    std::unordered_set<uint64_t> m_known_structs;
    std::unordered_set<uint64_t> m_known_enums;

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

    // ── ReadFFieldClassPtr ───────────────────────────────────────────────
    // Read an FField's ClassPrivate (FFieldClass*) with patch-aware probing.
    //   CL-1177146: ClassPrivate is at +0x90 (live-verified — see
    //   /tmp/probe_ff_classpriv probe results).
    //   Older patches: +0x88 was used.
    // Validates the result lies within the module .data section
    // (where all FFieldClass globals are statically allocated). Returns 0
    // when neither candidate falls in .data — that signals the FField
    // pointer itself is garbage (chain-walker overshoot into uninit heap).
    //
    // .data range (CL-1177146): MODULE_BASE + [0xDAF3000 .. 0xE25C000)
    uint64_t ReadFFieldClassPtr(uint64_t ff) {
        constexpr uint64_t kDataLo = 0xDAF3000ULL;
        constexpr uint64_t kDataHi = 0xE25C000ULL;
        uint64_t lo = MODULE_BASE + kDataLo;
        uint64_t hi = MODULE_BASE + kDataHi;
        uint64_t fc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
        if (fc >= lo && fc < hi) return fc;
        uint64_t fc2 = Read<uint64_t>(ff + 0x88);
        if (fc2 >= lo && fc2 < hi) return fc2;
        return 0;
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
                    if (kit != known.end() && IsCanonicalPropertyTypeName(kit->second)) {
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

    // ── Patch 20260430 / CL-1177146: dynamic FProperty-type-index → FName CI table ──
    // The game maintains a flat uint32_t[703] table inside the GNamePool struct.
    // On CL-1177146 the GNamePool base moved to module+0xDBB3F80 and the table
    // sits at struct-offset 0x2540 (= dword index 2384), so the absolute RVA is
    //   0xDBB3F80 + 0x2540 = 0xDBB64C0.
    //
    // Reader function `sub_231DA0(out, idx)` does:
    //   *out = *((_DWORD *)&unk_DBB3F80 + idx + 2384);
    // Caller `sub_46D480` compares the result directly against an int32 CompIndex
    // (`*((_DWORD *)a2 + 2)` from a property descriptor) — so entries are still
    // plain FName CompIndex values, no extra transform required.
    //
    // Length verified from the pool ctor (sub_2334A0):
    //   merge_out_clusters(a1 + 9536, 0, 2812)  → buffer size = 2812 bytes = 703 DWORDs
    // (9536 = 0x2540 — same struct offset as the reader)
    bool LoadDynamicPropertyTypeTable() {
        constexpr uint64_t TABLE_RVA = 0xDBB64C0;
        constexpr size_t   TABLE_LEN = 703;
        m_type_idx_to_name.clear();
        m_canonical_property_type_names.clear();
        std::vector<uint32_t> handles(TABLE_LEN, 0);
        if (!m_reader.Read(MODULE_BASE + TABLE_RVA, handles.data(), TABLE_LEN * sizeof(uint32_t))) {
            std::printf("[ptable] failed to read property-type table @ 0x%llX\n",
                (unsigned long long)(MODULE_BASE + TABLE_RVA));
            return false;
        }
        size_t Decoded = 0;
        size_t Nonzero = 0;
        for (size_t I = 0; I < TABLE_LEN; ++I) {
            uint32_t H = handles[I];
            if (!H) continue;
            ++Nonzero;
            int32_t Ci = static_cast<int32_t>(H);
            std::string Name = m_fname.CompIndexToNameLenient(Ci);
            if (Name.empty()) continue;
            bool NameOk = !Name.empty();
            for (char C : Name) {
                if (!((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
                      (C >= '0' && C <= '9') || C == '_')) {
                    NameOk = false; break;
                }
            }
            if (!NameOk) continue;
            m_type_idx_to_name[static_cast<int32_t>(I)] = Name;
            m_canonical_property_type_names.insert(Name);
            ++Decoded;
        }
        std::printf("[ptable] dynamic property-type table: %zu/%zu non-zero handles, %zu decoded names\n",
            Nonzero, TABLE_LEN, Decoded);
        m_dynamic_type_table_loaded = (Decoded >= 8);
        if (m_dynamic_type_table_loaded) {
            size_t Shown = 0;
            std::vector<std::pair<int32_t, std::string>> Sorted(
                m_type_idx_to_name.begin(), m_type_idx_to_name.end());
            std::sort(Sorted.begin(), Sorted.end());
            std::printf("[ptable] sample entries:");
            for (const auto& [Idx, Nm] : Sorted) {
                if (Shown++ >= 12) break;
                std::printf(" [%d]=%s", Idx, Nm.c_str());
            }
            std::printf("\n");
        }
        return m_dynamic_type_table_loaded;
    }

    bool IsCanonicalPropertyTypeName(const std::string& Name) const {
        if (!m_dynamic_type_table_loaded) return true;
        if (Name.empty()) return false;
        if (m_canonical_property_type_names.count(Name)) return true;
        if (Name.size() > 1 && Name[0] == 'F' &&
            m_canonical_property_type_names.count(Name.substr(1))) {
            return true;
        }
        return false;
    }

    const std::unordered_map<int32_t, std::string>& GetTypeIdxToName() const {
        return m_type_idx_to_name;
    }

    bool DynamicPropertyTypeTableLoaded() const { return m_dynamic_type_table_loaded; }

    // ── Patch 20260421: hardcoded FFieldClass* → type-name map ──────────
    // Obtained by scanning live .data for the FFieldClass signature
    //   10 19 22 2B 34 3D 46 4F  at +0x08  and decoding +0x20 via the
    // SIMD name-decrypt pipeline, then resolving CI→string via FNameDecryptor.
    // See SIGNATURES.md §FFieldClass for details. 36 singletons total (34
    // distinct property types; FObjectProperty has two singletons due to
    // a secondary helper class sharing the same FName).
    //
    // Applied BEFORE Tier 1/2/3 auto-discovery so it supersedes any
    // Tier-1 name-heuristic mistakes (e.g. NameProperty mislabeled as
    // ObjectProperty because a property named "Owner" pointed to it).
    void SeedHardcodedFClassMap_20260421() {
        // 20260428 type-global RVAs — extracted from IDA via xrefs to the type
        // registration function sub_3E3010(global_ptr, type_name_wstring, ...).
        // These are the values stored at FField+0x88 — the per-FProperty-subclass
        // global state pointer. Different from FField::ClassPrivate at +0x20
        // (which is often 0 for engine reflection-stripped FFields in 20260428).
        static const std::pair<uint64_t, const char*> kSeeds[] = {
            { 0xDE0CF70, "FEnumProperty" },
            { 0xDE0D050, "FField" },
            { 0xDE0D0C0, "FFieldPathProperty" },
            { 0xDE14C30, "FProperty" },
            { 0xDE14CA0, "FArrayProperty" },
            { 0xDE14D10, "FObjectPropertyBase" },
            { 0xDE14D80, "FBoolProperty" },
            { 0xDE14DF0, "FByteProperty" },
            { 0xDE14E60, "FClassProperty" },
            { 0xDE14ED0, "FClassPtrProperty" },
            { 0xDE14F40, "FDelegateProperty" },
            { 0xDE14FC0, "FInterfaceProperty" },
            { 0xDE15030, "FLazyObjectProperty" },
            { 0xDE150A0, "FMapProperty" },
            { 0xDE15120, "FMulticastDelegateProperty" },
            { 0xDE15190, "FMulticastInlineDelegateProperty" },
            { 0xDE15200, "FMulticastSparseDelegateProperty" },
            { 0xDE15270, "FNameProperty" },
            { 0xDE152E0, "FNumericProperty" },
            { 0xDE15350, "FInt8Property" },
            { 0xDE153C0, "FInt16Property" },
            { 0xDE15430, "FIntProperty" },
            { 0xDE154A0, "FInt64Property" },
            { 0xDE15510, "FUInt16Property" },
            { 0xDE15580, "FUInt32Property" },
            { 0xDE155F0, "FUInt64Property" },
            { 0xDE15660, "FFloatProperty" },
            { 0xDE156D0, "FDoubleProperty" },
            { 0xDE15740, "FObjectProperty" },
            { 0xDE157C0, "FObjectProperty" },
            { 0xDE15830, "FOptionalProperty" },
            { 0xDE15C40, "FSetProperty" },
            { 0xDE15CB0, "FSoftClassProperty" },
            { 0xDE15D20, "FSoftObjectProperty" },
            { 0xDE15DE0, "FStrProperty" },
            { 0xDE15E50, "FStructProperty" },
            { 0xDE15ED0, "FWeakObjectProperty" },
            { 0xDE17200, "FTextProperty" },
        };
        for (auto [rva, type] : kSeeds)
            m_fclass_to_type[MODULE_BASE + rva] = type;
        std::printf("[fcmap] seeded %zu hardcoded FFieldClass mappings (patch 20260428)\n",
            sizeof(kSeeds)/sizeof(kSeeds[0]));
    }

    int32_t CalibrateFClassTypeIdxOffset() {
        if (!m_dynamic_type_table_loaded || m_type_idx_to_name.empty()) return -1;
        if (m_fclass_to_type.empty()) return -1;
        std::unordered_map<std::string, int32_t> NameToIdx;
        for (const auto& [Idx, Nm] : m_type_idx_to_name) {
            NameToIdx[Nm] = Idx;
            NameToIdx["F" + Nm] = Idx;
        }
        struct OffsetScore { int32_t Off; int32_t Hits; int32_t Total; };
        std::vector<OffsetScore> Scores;
        for (int32_t Off = 0x00; Off <= 0x6C; Off += 4) {
            int32_t Hits = 0;
            int32_t Total = 0;
            for (const auto& [FcPtr, TypeName] : m_fclass_to_type) {
                auto Nit = NameToIdx.find(TypeName);
                if (Nit == NameToIdx.end()) continue;
                ++Total;
                uint32_t StoredIdx = 0;
                if (!m_reader.Read(FcPtr + static_cast<uint64_t>(Off), &StoredIdx, 4)) continue;
                if (static_cast<int32_t>(StoredIdx) == Nit->second) ++Hits;
            }
            Scores.push_back({Off, Hits, Total});
        }
        std::sort(Scores.begin(), Scores.end(),
            [](const OffsetScore& A, const OffsetScore& B) { return A.Hits > B.Hits; });
        if (Scores.empty() || Scores[0].Hits == 0) {
            std::printf("[fcmap] typeidx offset calibration FAILED — no offset matched any seeded entry\n");
            return -1;
        }
        const OffsetScore& Best = Scores[0];
        int32_t Required = Best.Total / 2;
        if (Best.Hits < Required) {
            std::printf("[fcmap] typeidx offset calibration WEAK: best=+0x%X hits=%d/%d (need >=%d) — skipping\n",
                Best.Off, Best.Hits, Best.Total, Required);
            return -1;
        }
        std::printf("[fcmap] typeidx offset calibrated: +0x%X hits=%d/%d\n",
            Best.Off, Best.Hits, Best.Total);
        m_fclass_typeidx_offset = Best.Off;
        return Best.Off;
    }

    size_t SeedDynamicFClassMap() {
        if (m_fclass_typeidx_offset < 0) return 0;
        if (!m_dynamic_type_table_loaded) return 0;
        if (m_observed_fclass_ptrs.empty()) {
            std::printf("[fcmap-dyn] no observed FFieldClass pointers — pre-pass must run first\n");
            return 0;
        }
        size_t Added = 0;
        size_t Examined = 0;
        size_t IdxMissing = 0;
        size_t ReadFail = 0;
        size_t Already = 0;
        size_t TypeIdxBad = 0;
        std::unordered_map<std::string, size_t> AddedByType;
        for (uint64_t FcPtr : m_observed_fclass_ptrs) {
            ++Examined;
            if (m_fclass_to_type.count(FcPtr)) { ++Already; continue; }
            uint32_t StoredIdx = 0;
            if (!m_reader.Read(FcPtr + static_cast<uint64_t>(m_fclass_typeidx_offset), &StoredIdx, 4)) {
                ++ReadFail; continue;
            }
            int32_t TypeIdx = static_cast<int32_t>(StoredIdx);
            if (TypeIdx < 0 || TypeIdx >= 4096) { ++TypeIdxBad; continue; }
            auto Nit = m_type_idx_to_name.find(TypeIdx);
            if (Nit == m_type_idx_to_name.end()) { ++IdxMissing; continue; }
            std::string TypeName = "F" + Nit->second;
            m_fclass_to_type[FcPtr] = TypeName;
            ++Added;
            ++AddedByType[TypeName];
        }
        std::printf("[fcmap-dyn] examined=%zu already=%zu read_fail=%zu bad_idx=%zu unmapped_idx=%zu added=%zu\n",
            Examined, Already, ReadFail, TypeIdxBad, IdxMissing, Added);
        if (Added > 0) {
            std::vector<std::pair<std::string, size_t>> Sorted(AddedByType.begin(), AddedByType.end());
            std::sort(Sorted.begin(), Sorted.end(),
                [](const auto& A, const auto& B) { return A.second > B.second; });
            std::printf("[fcmap-dyn] new mappings by type:");
            size_t Shown = 0;
            for (const auto& [Tn, Cnt] : Sorted) {
                if (Shown++ >= 12) break;
                std::printf(" %s=%zu", Tn.c_str(), Cnt);
            }
            std::printf("\n");
        }
        return Added;
    }

    // ── FFieldClass NamePrivate-slot calibration & seeding ──────────────
    // Parallel path to the typeidx-based seeding above. Reasoning: on UE5
    // builds where FFieldClass has an FName slot (verified 20260421 IDA in
    // FProperty_GetNameCPP @ 0x3AFE70 reading FFieldClass+0x20), we can read
    // the type name DIRECTLY without needing a separate uint32 typeidx field
    // or the 703-entry property-type table.
    //
    // Strategy: probe each 16-byte-aligned offset 0x10..0x80 on observed
    // FFieldClasses, decrypt 16 bytes via the FField NamePrivate pipeline
    // (already auto-discovered + working on this build), resolve the result
    // CompIndex to a name string. Pick the offset that produces the most
    // canonical property-type names (BoolProperty, IntProperty, ...). The
    // threshold gates against false positives at noise offsets.
    int32_t CalibrateFClassNameSlotOffset() {
        if (m_observed_fclass_ptrs.empty()) {
            std::printf("[fcname-cal] no observed FFieldClass pointers — pre-pass must run first\n");
            return -1;
        }
        if (m_canonical_property_type_names.empty()) {
            std::printf("[fcname-cal] no canonical property-type names — ptable must be loaded\n");
            return -1;
        }

        // Sample up to 200 FFieldClasses to keep calibration fast.
        std::vector<uint64_t> Sample(m_observed_fclass_ptrs.begin(), m_observed_fclass_ptrs.end());
        if (Sample.size() > 200) Sample.resize(200);

        struct Score { int32_t Off; int32_t Hits; std::string Best; };
        std::vector<Score> Scores;

        for (int32_t Off = 0x10; Off <= 0x80; Off += 8) {
            int32_t Hits = 0;
            std::string FirstHitName;
            for (uint64_t Fc : Sample) {
                alignas(16) uint8_t Enc[16] = {};
                if (!m_reader.Read(Fc + static_cast<uint64_t>(Off), Enc, 16)) continue;
                // All-zero slot is uninitialized — skip.
                bool NonZero = false;
                for (int B = 0; B < 16; ++B) if (Enc[B]) { NonZero = true; break; }
                if (!NonZero) continue;
                uint64_t Dec = m_fname.DecryptFFieldNameSlot(Enc);
                uint32_t Lo = static_cast<uint32_t>(Dec);
                if (Lo < 2 || Lo > 0x2000000u) continue;
                std::string Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo));
                if (Name.empty()) continue;
                // Match against canonical type names — try with and without
                // the leading 'F' prefix that some builds use ("BoolProperty"
                // vs "FBoolProperty").
                bool Match = m_canonical_property_type_names.count(Name) > 0;
                if (!Match && Name.size() > 1 && Name[0] == 'F')
                    Match = m_canonical_property_type_names.count(Name.substr(1)) > 0;
                if (!Match && !Name.empty())
                    Match = m_canonical_property_type_names.count("F" + Name) > 0;
                if (!Match) continue;
                ++Hits;
                if (FirstHitName.empty()) FirstHitName = Name;
            }
            Scores.push_back({Off, Hits, FirstHitName});
        }

        std::sort(Scores.begin(), Scores.end(),
            [](const Score& A, const Score& B) { return A.Hits > B.Hits; });

        if (Scores.empty() || Scores[0].Hits == 0) {
            std::printf("[fcname-cal] no offset produced any canonical type-name match — pipeline likely different on this build\n");
            return -1;
        }

        const Score& Best = Scores[0];
        // Threshold: require ≥30% of sampled FFieldClasses to resolve to a
        // canonical name. Below that, the offset is probably noise.
        const int32_t Required = static_cast<int32_t>(Sample.size()) * 30 / 100;
        if (Best.Hits < Required) {
            std::printf("[fcname-cal] best offset +0x%X hits=%d/%zu < %d (30%%) — too weak; skipping\n",
                Best.Off, Best.Hits, Sample.size(), Required);
            // Still log top 5 for debugging.
            for (size_t I = 0; I < Scores.size() && I < 5; ++I) {
                std::printf("[fcname-cal]   +0x%X hits=%d  example=%s\n",
                    Scores[I].Off, Scores[I].Hits, Scores[I].Best.c_str());
            }
            return -1;
        }

        m_fclass_nameslot_offset = Best.Off;
        std::printf("[fcname-cal] FFieldClass NamePrivate offset = +0x%X  hits=%d/%zu (example=%s)\n",
            Best.Off, Best.Hits, Sample.size(), Best.Best.c_str());
        return Best.Off;
    }

    size_t SeedFClassMapByNameSlot() {
        if (m_fclass_nameslot_offset < 0) return 0;
        if (m_observed_fclass_ptrs.empty()) return 0;

        size_t Examined = 0, Already = 0, ReadFail = 0, BadCi = 0, NoName = 0;
        size_t NotCanonical = 0, Added = 0;
        std::unordered_map<std::string, size_t> AddedByType;

        for (uint64_t Fc : m_observed_fclass_ptrs) {
            ++Examined;
            if (m_fclass_to_type.count(Fc)) { ++Already; continue; }
            alignas(16) uint8_t Enc[16] = {};
            if (!m_reader.Read(Fc + static_cast<uint64_t>(m_fclass_nameslot_offset), Enc, 16)) {
                ++ReadFail; continue;
            }
            bool NonZero = false;
            for (int B = 0; B < 16; ++B) if (Enc[B]) { NonZero = true; break; }
            if (!NonZero) { ++BadCi; continue; }
            uint64_t Dec = m_fname.DecryptFFieldNameSlot(Enc);
            uint32_t Lo = static_cast<uint32_t>(Dec);
            if (Lo < 2 || Lo > 0x2000000u) { ++BadCi; continue; }
            std::string Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo));
            if (Name.empty()) { ++NoName; continue; }
            // Prefer the canonical "F"-prefixed form.
            std::string Canonical;
            if (m_canonical_property_type_names.count(Name)) {
                Canonical = "F" + Name;
            } else if (Name.size() > 1 && Name[0] == 'F' &&
                       m_canonical_property_type_names.count(Name.substr(1))) {
                Canonical = Name;
            } else if (m_canonical_property_type_names.count("F" + Name)) {
                Canonical = "F" + Name;
            } else {
                ++NotCanonical; continue;
            }
            m_fclass_to_type[Fc] = Canonical;
            ++Added;
            ++AddedByType[Canonical];
        }

        std::printf("[fcname-seed] examined=%zu already=%zu read_fail=%zu bad_ci=%zu "
                    "no_name=%zu non_canonical=%zu added=%zu\n",
            Examined, Already, ReadFail, BadCi, NoName, NotCanonical, Added);
        if (Added > 0) {
            std::vector<std::pair<std::string, size_t>> Sorted(AddedByType.begin(), AddedByType.end());
            std::sort(Sorted.begin(), Sorted.end(),
                [](const auto& A, const auto& B) { return A.second > B.second; });
            std::printf("[fcname-seed] new mappings by type:");
            size_t Shown = 0;
            for (const auto& [Tn, Cnt] : Sorted) {
                if (Shown++ >= 15) break;
                std::printf(" %s=%zu", Tn.c_str(), Cnt);
            }
            std::printf("\n");
        }
        return Added;
    }

    // ── Phase 8 seeder: directly map static FFieldClass globals → name ─
    // Phase 8 (DiscoverFFieldClassGlobals) extracted (target_rva, type_name)
    // pairs by scanning callers of the FFieldClass constructor. Critically:
    // the target_rva IS the FFieldClass STRUCT itself (a .data static
    // allocation), NOT a pointer-holding slot. The constructor writes the
    // FFieldClass fields into that .data slot in-place, so at runtime
    // m_observed_fclass_ptrs sees `module_base + target_rva` directly when
    // walking FProperty.ClassPrivate — no extra dereference.
    size_t SeedFClassMapFromGlobals() {
        const auto& Globals = AutoDiscovery::g_DiscoveredFClassGlobals;
        if (Globals.empty()) return 0;

        size_t Examined = 0, AlreadyMapped = 0, Conflict = 0, Added = 0;
        std::unordered_map<std::string, size_t> AddedByType;

        for (const auto& G : Globals) {
            ++Examined;
            uint64_t StaticAddr = MODULE_BASE + G.TargetRva;
            auto It = m_fclass_to_type.find(StaticAddr);
            if (It != m_fclass_to_type.end()) {
                if (It->second != G.TypeName) ++Conflict;
                else                            ++AlreadyMapped;
                continue;
            }
            m_fclass_to_type[StaticAddr] = G.TypeName;
            ++Added;
            ++AddedByType[G.TypeName];
        }

        std::printf("[fcglob-seed] examined=%zu already=%zu conflict=%zu added=%zu\n",
            Examined, AlreadyMapped, Conflict, Added);
        if (Added > 0) {
            std::vector<std::pair<std::string, size_t>> Sorted(
                AddedByType.begin(), AddedByType.end());
            std::sort(Sorted.begin(), Sorted.end(),
                [](const auto& A, const auto& B) { return A.second > B.second; });
            std::printf("[fcglob-seed] new mappings by type:");
            size_t Shown = 0;
            for (const auto& [Tn, Cnt] : Sorted) {
                if (Shown++ >= 15) break;
                std::printf(" %s=%zu", Tn.c_str(), Cnt);
            }
            std::printf("\n");
        }
        return Added;
    }

    // ── CastFlags-based seeder: resolve FFieldClass by CastFlags bitmask ─
    // FFieldClass+0x10 holds a 64-bit CastFlags bitmask, unique per property
    // type (FBoolProperty=0x28001, etc.). Verified via:
    //   - constructor sub_3E80E0: stores arg4 (e.g. 0x28001 for FBoolProperty)
    //     at FFieldClass+0x10
    //   - chain walker: `*(QWORD)(FField+144 [ClassPrivate] + 16) & MASK`
    //
    // Every FFieldClass type has unique CastFlags. The 55 vtable-Tier-1
    // mappings give us 55 known (FFieldClass*, name) pairs. Read CastFlags
    // for each → build (CastFlags → name) map → resolve all unmapped
    // FFieldClasses by their CastFlags. No SIMD pipeline, no FName decode,
    // no XOR keys needed.
    size_t SeedFClassMapByCastFlags() {
        if (m_observed_fclass_ptrs.empty()) return 0;
        if (m_fclass_to_type.empty())       return 0;

        // Build (CastFlags → name) from already-mapped FFieldClasses.
        std::unordered_map<uint64_t, std::string> CastFlagsToName;
        std::unordered_map<uint64_t, int>         CastFlagsConflicts;
        for (const auto& [Fc, Name] : m_fclass_to_type) {
            uint64_t CastFlags = 0;
            if (!m_reader.Read(Fc + 0x10, &CastFlags, 8)) continue;
            if (CastFlags == 0) continue;
            auto It = CastFlagsToName.find(CastFlags);
            if (It == CastFlagsToName.end()) {
                CastFlagsToName[CastFlags] = Name;
            } else if (It->second != Name) {
                ++CastFlagsConflicts[CastFlags];
            }
        }
        std::printf("[fcflags] built %zu unique CastFlags from %zu mapped FFieldClasses (%zu conflicts)\n",
            CastFlagsToName.size(), m_fclass_to_type.size(), CastFlagsConflicts.size());

        if (CastFlagsToName.empty()) return 0;

        // Resolve unmapped FFieldClasses by CastFlags.
        size_t Examined = 0, Already = 0, NoCastFlags = 0;
        size_t Conflict = 0, NoMatch = 0, Added = 0;
        std::unordered_map<std::string, size_t> AddedByType;

        for (uint64_t Fc : m_observed_fclass_ptrs) {
            ++Examined;
            if (m_fclass_to_type.count(Fc)) { ++Already; continue; }
            uint64_t CastFlags = 0;
            if (!m_reader.Read(Fc + 0x10, &CastFlags, 8)) { ++NoCastFlags; continue; }
            if (CastFlags == 0) { ++NoCastFlags; continue; }
            // Skip ambiguous CastFlags (multiple names mapped to same value).
            auto Cf = CastFlagsConflicts.find(CastFlags);
            if (Cf != CastFlagsConflicts.end()) { ++Conflict; continue; }
            auto It = CastFlagsToName.find(CastFlags);
            if (It == CastFlagsToName.end()) { ++NoMatch; continue; }
            m_fclass_to_type[Fc] = It->second;
            ++Added;
            ++AddedByType[It->second];
        }

        std::printf("[fcflags] examined=%zu already=%zu no_castflags=%zu conflict=%zu no_match=%zu added=%zu\n",
            Examined, Already, NoCastFlags, Conflict, NoMatch, Added);
        if (Added > 0) {
            std::vector<std::pair<std::string, size_t>> Sorted(AddedByType.begin(), AddedByType.end());
            std::sort(Sorted.begin(), Sorted.end(),
                [](const auto& A, const auto& B) { return A.second > B.second; });
            std::printf("[fcflags] new mappings by type:");
            size_t Shown = 0;
            for (const auto& [Tn, Cnt] : Sorted) {
                if (Shown++ >= 15) break;
                std::printf(" %s=%zu", Tn.c_str(), Cnt);
            }
            std::printf("\n");
        }
        return Added;
    }

    // ── Phase 7 seeder: use auto-discovered FFieldClass NamePrivate decoder ─
    // The Phase 7 sig-scan extracts the FULL pipeline (XOR const, name slot
    // offset, shift/shuffle imms) from the inlined FFieldClass NamePrivate
    // decode in the live binary. This recovers the FName HANDLE (not CI) —
    // we then run it through the existing DecryptByHandle path to get a
    // type name string directly.
    size_t SeedFClassMapViaPhase7() {
        if (!AutoDiscovery::g_DiscoveredFFieldClassName.Valid) return 0;
        if (m_observed_fclass_ptrs.empty()) return 0;

        size_t Examined = 0, Already = 0, NoHandle = 0, NoName = 0;
        size_t NotCanonical = 0, Added = 0;
        std::unordered_map<std::string, size_t> AddedByType;

        for (uint64_t Fc : m_observed_fclass_ptrs) {
            ++Examined;
            if (m_fclass_to_type.count(Fc)) { ++Already; continue; }
            // CL-1177146: post-PSHUFLW result has the CI in (lo64 >> 32),
            // i.e. the upper 32 bits of the lower 64. ROL64(32) moves it
            // into the low 32, where DecryptFFieldClassNameCI extracts it.
            // The "DecryptByHandle" path treats the same value as an
            // encrypted heap pointer, which fails because it's a small CI.
            // Use CompIndexToName instead — that's the correct lookup.
            int32_t Ci = m_fname.DecryptFFieldClassNameCI(Fc);
            if (Ci <= 0) { ++NoHandle; continue; }
            std::string Name = m_fname.CompIndexToNameLenient(Ci);
            if (Name.empty()) { ++NoName; continue; }
            // Sanity: type name should be a short identifier.
            if (Name.size() > 64) { ++NotCanonical; continue; }
            bool ok = true;
            for (char c : Name) {
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_')) { ok = false; break; }
            }
            if (!ok) { ++NotCanonical; continue; }
            // Prefer canonical "F"-prefixed form to match the rest of the SDK.
            std::string Canonical = Name;
            if (!Name.empty() && Name[0] != 'F' &&
                m_canonical_property_type_names.count(Name))
            {
                Canonical = "F" + Name;
            }
            m_fclass_to_type[Fc] = Canonical;
            ++Added;
            ++AddedByType[Canonical];
        }

        std::printf("[fcname-p7] examined=%zu already=%zu no_handle=%zu no_name=%zu non_canonical=%zu added=%zu\n",
            Examined, Already, NoHandle, NoName, NotCanonical, Added);
        if (Added > 0) {
            std::vector<std::pair<std::string, size_t>> Sorted(AddedByType.begin(), AddedByType.end());
            std::sort(Sorted.begin(), Sorted.end(),
                [](const auto& A, const auto& B) { return A.second > B.second; });
            std::printf("[fcname-p7] new mappings by type:");
            size_t Shown = 0;
            for (const auto& [Tn, Cnt] : Sorted) {
                if (Shown++ >= 15) break;
                std::printf(" %s=%zu", Tn.c_str(), Cnt);
            }
            std::printf("\n");
        }
        return Added;
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
            // 20260428: Struct field is at +0x108 (uniform +0x20 shift).
            uint64_t sp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FStructProperty::Struct);
            if (sp) {
                if (sp > 0x10000 && sp < 0x7FFFFFFFFFFFULL)
                    m_known_structs.insert(sp);
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
            if (ep) {
                if (ep > 0x10000 && ep < 0x7FFFFFFFFFFFULL)
                    m_known_enums.insert(ep);
                std::string en = m_fname.GetName(ep);
                if (!en.empty()) type_name = en;
            }
        }
        // FByteProperty: if it wraps a UEnum, emit the enum name; else fall
        // through to primitive lowering (uint8_t).
        if (type_name == "FByteProperty") {
            uint64_t en = Read<uint64_t>(ff + ArcDecrypt::Offsets::FEnumProperty::UnderlyingProp); // shares +0x108
            if (en > 0x10000 && en < 0x7FFFFFFFFFFFULL) {
                m_known_enums.insert(en);
                std::string n = m_fname.GetName(en);
                if (!n.empty()) { type_name = n; return; }
            }
        }
        // FDelegateProperty: SignatureFunction at +0x108 names the delegate.
        if (type_name == "FDelegateProperty" ||
            type_name == "FMulticastInlineDelegateProperty" ||
            type_name == "FMulticastSparseDelegateProperty" ||
            type_name == "FMulticastDelegateProperty") {
            uint64_t sig = Read<uint64_t>(ff + 0x108);
            if (sig > 0x10000 && sig < 0x7FFFFFFFFFFFULL) {
                std::string n = m_fname.GetName(sig);
                if (!n.empty()) { type_name = "TDelegate<" + n + ">"; return; }
            }
        }
        // FFieldPathProperty: PropertyClass-style pointer; the field-class
        // struct holds a reflection-stripped pointer. Lower to TFieldPath<FField>.
        if (type_name == "FFieldPathProperty") {
            type_name = "TFieldPath<FField>";
            return;
        }
        // ── Primitive type lowering ────────────────────────────────────────
        // Rewrite raw FXxxProperty type names to their C++ equivalents. Runs
        // last so enum/struct/object resolution above takes precedence. Closes
        // the ~30K placeholder-token leak in function param/return types.
        static const std::unordered_map<std::string, std::string> kPrim = {
            {"FBoolProperty",   "bool"},      {"FByteProperty",   "uint8_t"},
            {"FIntProperty",    "int32_t"},   {"FInt64Property",  "int64_t"},
            {"FInt16Property",  "int16_t"},   {"FInt8Property",   "int8_t"},
            {"FUInt32Property", "uint32_t"},  {"FUInt64Property", "uint64_t"},
            {"FUInt16Property", "uint16_t"},
            {"FFloatProperty",  "float"},     {"FDoubleProperty", "double"},
            {"FNameProperty",   "FName"},     {"FStrProperty",    "FString"},
            {"FStringProperty", "FString"},   {"FTextProperty",   "FText"},
        };
        auto it = kPrim.find(type_name);
        if (it != kPrim.end()) type_name = it->second;
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

            // Ghost-FField guard (patch CL-1177146):
            // - Vtable at +0x00 must be in module range — strongest single
            //   signal that this is a real FField.
            // - ClassPrivate at +0x20 is often 0 for engine reflection-stripped
            //   FFields (don't break on that — only break on garbage non-zero)
            // - Salt sentinel 0x893BCE4393840650 is GONE in CL-1177146 (no
            //   matches anywhere in the binary), so the +0x78 salt check is
            //   removed; structural validation via vtable + class ptr only.
            // - 20260428 zero-offset sentinel 0x145D6034 (=bswap of old XOR key)
            //   still tracked for empty-slot detection alongside new key.
            {
                uint64_t vtbl = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::VTable);
                if (vtbl < (MODULE_BASE + 0x1000) ||
                    vtbl >= (MODULE_BASE + 0xE9D0000ULL)) break;
                uint64_t cls_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                if (cls_ptr != 0 &&
                    (cls_ptr < 0x100000ULL || cls_ptr >= 0x800000000000ULL)) break;
                // Sample the +0xB0..+0xCB region for any of the two known
                // CL-1177146 offset-sentinel positions (+0xC4 and +0xC8 both
                // observed live for different FProperty subclasses).
                alignas(16) uint8_t name_enc[16] = {};
                m_reader.Read(ff + ArcDecrypt::Offsets::FField::NameEncrypted, name_enc, 16);
                bool name_zero = true;
                for (uint8_t b : name_enc) if (b) { name_zero = false; break; }
                uint32_t raw_off_c4 = Read<uint32_t>(ff + 0xC4);
                uint32_t raw_off_c8 = Read<uint32_t>(ff + 0xC8);
                bool any_offset_sentinel =
                    (raw_off_c4 == 0 || raw_off_c4 == 0x40277448u || raw_off_c4 == 0x145D6034u) &&
                    (raw_off_c8 == 0 || raw_off_c8 == 0x40277448u || raw_off_c8 == 0x145D6034u);
                if (name_zero && any_offset_sentinel) break;
            }

            PropertyRecord pr{};
            pr.ff_addr   = ff;
            pr.is_param  = is_param;

            // Name
            pr.name = ReadFFieldName(ff);
            if (pr.name.empty()) {
                int32_t fci = m_fname.DecryptFFieldNameCI(ff);
                // CI's chunk_offset = (ci >> 8) & 0xFFFF00. Anything past the
                // live FNamePool's allocated range (~0x6A0000 on 20260421) is
                // either runtime-only or a walk overshoot — drop the entry.
                uint64_t chunk_off = (static_cast<uint64_t>(fci) >> 8) & 0xFFFF00ULL;
                if (chunk_off > 0x6A0000ULL) break;
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

            // ClassPrivate (FFieldClass*) — patch-aware probe + .data-bounded
            // validation. Returns 0 when neither +0x90 nor +0x88 lies in the
            // module .data section (signals chain walker overshoot).
            pr.fclass_ptr = ReadFFieldClassPtr(ff);
            if (pr.fclass_ptr) {
                m_observed_fclass_ptrs.insert(pr.fclass_ptr);
            }

            auto fc_it = m_fclass_to_type.find(pr.fclass_ptr);
            if (fc_it != m_fclass_to_type.end()) {
                pr.type_name = fc_it->second;
            } else {
                std::string vt_type = IdentifyPropertyType(ff);
                pr.type_name = (vt_type.find("UNKNOWN") == std::string::npos)
                               ? vt_type : "FProperty_Unknown";
            }
            pr.is_bool = (pr.type_name == "FBoolProperty");
            if (pr.is_bool) {
                pr.bool_byte_mask  = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::ByteMask);
                pr.bool_field_size = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::FieldSize);
            }

            // Offset_Internal: encrypted u32 with subtype-dependent placement.
            // CL-1177146 XOR key = 0x40277448 (LE bytes `48 74 27 40`). Live-verified positions:
            //   FBoolProperty (PostProcessSettings bools) → +0xC4
            //   non-bool FFields (RigidBodyState fields)  → +0xC8
            //   BPGC FFields with offset > 0xFF           → byte 2 of stored differs from 0x27
            //
            // Encoding: stored = bswap32(real_offset) XOR 0x40277448. For
            // real=0: stored = 0x40277448 (bytes `48 74 27 40`). For real>0xFF
            // (most fields), bswap32 puts the offset's middle bytes into stored
            // bytes 2-3, so byte 2 ≠ 0x27 and byte 3 ≠ 0x40. The OLD scan
            // required all 3 of byte 0=0x48, 1=0x74, 2=0x27 — which excluded
            // every non-zero offset > 0xFF. Now match only bytes 0-1 (which
            // remain `48 74` for all offsets < 0x10000, the practical range
            // for UE5 property offsets) and validate via the decoded value.
            {
                pr.offset = 0;
                alignas(8) uint8_t probe[28] = {};
                m_reader.Read(ff + 0xB0, probe, 28);  // scan +0xB0..+0xCB
                bool found = false;
                for (int dx = 0; dx + 4 <= 28 && !found; ++dx) {
                    if (probe[dx]     != 0x48) continue;  // low byte of XOR key (stable for offset < 0x100000)
                    if (probe[dx + 1] != 0x74) continue;  // 2nd byte (stable for offset < 0x1000000 — beyond practical UE5 props)
                    uint32_t stored;
                    std::memcpy(&stored, probe + dx, 4);
                    uint32_t real = __builtin_bswap32(stored ^ 0x40277448u);
                    if (real <= 0x100000u) {
                        pr.offset = real;
                        found = true;
                    }
                }
                // Fallback to fixed primary offset.
                if (!found) {
                    uint32_t stored_off = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                    pr.offset = ArcDecrypt::Patch20260421::DecryptPropertyOffsetNew(stored_off);
                    if (pr.offset > 0x100000) pr.offset = 0;
                }
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

            // Resolve sub-property types (struct name, object class, enum,
            // FByteProperty.Enum, delegate signature, primitive lowering).
            // ResolveSubPropertyType always runs — it handles all subclass
            // rewrites + final primitive lowering pass.
            ResolveSubPropertyType(ff, pr.type_name);

            // FArrayProperty: enrich parent + add Inner sub-property
            if (is_array) {
                uint64_t inner_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FArrayProperty::Inner);
                if (inner_ptr) {
                    PropertyRecord ipr{};
                    ipr.ff_addr    = inner_ptr;
                    ipr.name       = pr.name + "__Item";
                    ipr.is_param   = is_param;
                    ipr.fclass_ptr = ReadFFieldClassPtr(inner_ptr);
                    if (ipr.fclass_ptr)
                        m_observed_fclass_ptrs.insert(ipr.fclass_ptr);
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
                    // ElementSize is now directly on FField at +0xA0 in 20260428
                    ipr.elem_size = Read<uint32_t>(inner_ptr + ArcDecrypt::Offsets::FProperty::ElementSize);
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
                    epr.fclass_ptr = ReadFFieldClassPtr(elem_ptr);
                    if (epr.fclass_ptr)
                        m_observed_fclass_ptrs.insert(epr.fclass_ptr);
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
                    epr.elem_size = Read<uint32_t>(elem_ptr + ArcDecrypt::Offsets::FProperty::ElementSize);
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
                    mpr.fclass_ptr = ReadFFieldClassPtr(mp);
                    if (mpr.fclass_ptr)
                        m_observed_fclass_ptrs.insert(mpr.fclass_ptr);
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

            // UFunction params: scan a wide range of FField chain head offsets.
            // 20260421: +0xC8. 20260428: +0xC8 / +0xD0 / +0xE8 / +0xF0 (mirrors).
            // The widened range catches all known layouts.
            std::unordered_set<std::string> seen;
            for (int co = 0x80; co <= 0x140; co += 8) {
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

    // ── Format a single FunctionRecord (same format used inside DumpStruct) ───
    std::string FormatFunction(const FunctionRecord& fn) {
        std::ostringstream oss;
        std::string ret_type = "void";
        std::vector<const PropertyRecord*> in_params;
        for (const auto& par : fn.params) {
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
        return oss.str();
    }

    // ── Dump a single UStruct/UClass to string ──────────────────────────────────
    std::string DumpStruct(const StructRecord& rec) {
        std::ostringstream oss;
        // rec.package now holds the FULL UE5 path ("/Script/Engine",
        // "/Game/Pioneer/Items/BP_X"). Legacy non-path names (basename or
        // "Unknown") fall through with a "/Script/" prefix for back-compat.
        const std::string& pkg = rec.package;
        oss << "// " << (rec.is_class ? "Class" : "Struct") << " "
            << (!pkg.empty() && pkg[0] == '/' ? pkg : "/Script/" + pkg)
            << "." << rec.name << "\n";
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
            for (const auto& fn : rec.functions)
                oss << FormatFunction(fn);
        }
        oss << "} // namespace " << rec.name << "  // size=0x" << std::hex << rec.props_size << "\n\n";
        return oss.str();
    }

    // ── Dump a UEnum to string ────────────────────────────────────────────────────────
    std::string DumpEnum(const EnumRecord& rec) {
        std::ostringstream oss;
        const std::string& pkg = rec.package;
        oss << "// Enum "
            << (!pkg.empty() && pkg[0] == '/' ? pkg : "/Script/" + pkg)
            << "." << rec.name << "\n";
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

        // ── Pass 0: build package map  (addr → full path, e.g. "/Script/Engine") ────
        // Package objects have names starting with "/" (e.g. "/Script/Engine"
        // or "/Game/Pioneer/Items/BP_X"). Store the FULL path so DumpStruct
        // can emit the correct prefix — was previously stripped to basename
        // and DumpStruct hardcoded "/Script/" before it, which mis-formatted
        // /Game/ packages as "/Script/BP_X.BP_X".
        std::unordered_map<uint64_t, std::string> pkg_map;
        for (const auto& kv : addr_to_fullname) {
            const std::string& n = kv.second;
            if (n.empty() || n[0] != '/') continue;
            pkg_map[kv.first] = n;
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

        // Expanded metaclass whitelists for patch 20260421.
        //   - Angelscript integration adds ASClass/ASStruct.
        //   - Additional placeholder & generated-class variants appear.
        //   - Core UE metaclasses (Interface, etc.) are UClass-kind even though
        //     the dumper didn't historically track them.
        // Names NOT covered here still fall through to the CDO detection below.
        static const std::unordered_set<std::string> kClassMetaNames = {
            "Class", "BlueprintGeneratedClass", "WidgetBlueprintGeneratedClass",
            "AnimBlueprintGeneratedClass", "DynamicClass",
            "LinkerPlaceholderClass", "LinkerPlaceholderExportObject",
            "ASClass", "VerseClass", "AngelscriptClass",
            "MaterialBlueprintGeneratedClass", "ControlRigBlueprintGeneratedClass"
        };
        static const std::unordered_set<std::string> kStructMetaNames = {
            "ScriptStruct", "UserDefinedStruct", "ASStruct",
            "VerseStruct", "AngelscriptStruct", "SparseClassDataStruct"
        };
        static const std::unordered_set<std::string> kEnumMetaNames = {
            "Enum", "UserDefinedEnum", "VerseEnum", "AngelscriptEnum"
        };

        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const std::string& n = it->second;
            if (n == "Class")             { if (!classAddr) classAddr = obj_ptr; }
            else if (n == "ScriptStruct") { if (!ssAddr) ssAddr = obj_ptr; }
            else if (n == "Enum")         { if (!enumAddr) enumAddr = obj_ptr; }

            if (kClassMetaNames.count(n))        validClassTypes.insert(obj_ptr);
            else if (kStructMetaNames.count(n))  ssAddrs.insert(obj_ptr);
            else if (kEnumMetaNames.count(n))   { enumAddrs.insert(obj_ptr); validEnumTypes.insert(obj_ptr); }
        }

        // CDO-based metaclass detection: many metaclass objects have broken FName
        // slots (their name can't decrypt), so the name-match above misses them.
        // But Default__X CDOs DO decrypt, so we can recover the metaclass address
        // from Default__X.ClassPrivate (= X, the class instance).
        // e.g. Default__BlueprintGeneratedClass -> X=BlueprintGeneratedClass
        //      (a UClass-kind metaclass whose own name slot failed).
        std::size_t added_cls = 0, added_ss = 0, added_en = 0;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const std::string& n = it->second;
            if (n.rfind("Default__", 0) != 0) continue;
            // Try ALL 4 slots' pointer candidates — the slot picker hash
            // is unstable so GetClassPrivate alone misses metaclasses.
            auto candidates = m_fname.GetAllClassCandidates(obj_ptr);
            std::string meta = n.substr(9);
            for (uint64_t cls : candidates) {
                if (!cls) continue;
                // Filter out the OUTER/package slot only. CDOs have both the
                // metaclass pointer and the package pointer (/Script/X) in their
                // slots; if we let the package address into the metaclass sets
                // it pollutes Path A. Reject anything whose name starts with '/'.
                // (Don't enforce cname == meta — many real metaclass candidates
                // have GetName() returning the empty string for chunk-pool
                // addresses, and that strict check rejected ~846 valid enums.)
                std::string cname = m_fname.GetName(cls);
                if (!cname.empty() && cname[0] == '/') continue;

                if (meta == "Class" && !classAddr)             classAddr = cls;
                else if (meta == "ScriptStruct" && !ssAddr)    ssAddr    = cls;
                else if (meta == "Enum" && !enumAddr)          enumAddr  = cls;

                if (kClassMetaNames.count(meta)) {
                    if (validClassTypes.insert(cls).second) ++added_cls;
                } else if (kStructMetaNames.count(meta)) {
                    if (ssAddrs.insert(cls).second) ++added_ss;
                } else if (kEnumMetaNames.count(meta)) {
                    if (enumAddrs.insert(cls).second) ++added_en;
                    validEnumTypes.insert(cls);
                }
            }
        }
        std::printf("[sdk] CDO-based metaclass detection: +%zu class, +%zu struct, +%zu enum (fallback; zero = Pass-1 covered all)\n",
            added_cls, added_ss, added_en);

        // ── Pass 3: probe every distinct ClassPrivate target by name ──
        // The metaclass singletons (Enum, Class, ScriptStruct) aren't enumerable
        // as named UObjects on 20260428 — addr_to_name doesn't have them. But
        // they're still valid heap addresses pointed to by every type-instance's
        // ClassPrivate. Query their names directly via the FName resolver.
        std::unordered_set<uint64_t> seen_cls_p3;
        std::size_t p3_cls = 0, p3_ss = 0, p3_en = 0;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            // Probe ALL pointer-shape candidates — slot picker hash is unstable.
            auto cands = m_fname.GetAllClassCandidates(obj_ptr);
            for (uint64_t cls : cands) {
                if (cls < 0x10000 || cls >= 0x7FFFFFFFFFFFULL) continue;
                if (!seen_cls_p3.insert(cls).second) continue;
                std::string mname = m_fname.GetName(cls);
                auto dot = mname.rfind('.');
                if (dot != std::string::npos) mname = mname.substr(dot + 1);
                if (kClassMetaNames.count(mname)) {
                    if (validClassTypes.insert(cls).second) ++p3_cls;
                    if (!classAddr) classAddr = cls;
                } else if (kStructMetaNames.count(mname)) {
                    if (ssAddrs.insert(cls).second) ++p3_ss;
                    if (!ssAddr) ssAddr = cls;
                } else if (kEnumMetaNames.count(mname)) {
                    if (enumAddrs.insert(cls).second) ++p3_en;
                    validEnumTypes.insert(cls);
                    if (!enumAddr) enumAddr = cls;
                }
            }
        }
        std::printf("[sdk] Pass-3 (live-name metaclass probe): +%zu class, +%zu struct, +%zu enum (fallback; zero = Pass-1 covered all)\n",
            p3_cls, p3_ss, p3_en);

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
        // Include ALL addresses used as a class pointer by ANY object.
        // Use GetAllClassCandidates (probes all 4 slots) to catch class pointers
        // that the slot picker hash misses — slot picker is unstable on 20260428.
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto cands = m_fname.GetAllClassCandidates(obj_ptr);
            for (uint64_t cls : cands) {
                if (cls > 0x10000 && cls < 0x7FFFFFFFFFFFULL)
                    allTypeAddrs.insert(cls);
            }
        }
        std::printf("[sdk] allTypeAddrs (addresses used as Class ptrs): %zu\n", allTypeAddrs.size());

        // ── Pre-pass: identify UFunction vtable RVAs ──────────────────────
        // Walk Children of known UClass objects that have ChildProperties (= have functions).
        // The function metaclass (named "Function") should appear as ClassPrivate of children.
        // Find "Function" metaclass: must be a UClass (ClassPrivate = classAddr)
        std::unordered_set<uint64_t> funcMetaAddrs;
        // Path A: scan named objects whose name = "Function"/"DelegateFunction"/etc.
        // Drop the validClassTypes gate — on CL-1177146 the FName slot picker is
        // unstable so GetClassPrivate may not yield the UClass metaclass; the
        // single Function-named UObject may still be the legitimate metaclass.
        // The strict gate caused "Function metaclasses found: 0" → Pass 1+2
        // returned zero functions.  Accept any heap-shaped match.
        auto is_func_meta_name = [](const std::string& n) {
            return n == "Function" || n == "DelegateFunction" ||
                   n == "SparseDelegateFunction" ||
                   n.rfind("ASFunction", 0) == 0;
        };
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const auto& n = it->second;
            if (!is_func_meta_name(n)) continue;
            // The Function metaclass UClass is itself a UObject; require a vtable
            // in module range as the only sanity check.
            uint64_t vt = Read<uint64_t>(obj_ptr);
            if (vt < MODULE_BASE || vt >= MODULE_BASE + 0x10000000ULL) continue;
            funcMetaAddrs.insert(obj_ptr);
        }
        // Path B: CDO-based recovery. Default__ASFunction* / Default__Function CDOs
        // decrypt their name reliably; their ClassPrivate (one of 4 slot candidates)
        // IS the function metaclass UClass we want. Catches metaclasses whose own
        // name slot failed to decrypt.
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const auto& n = it->second;
            if (n.rfind("Default__", 0) != 0) continue;
            std::string meta = n.substr(9);
            if (!is_func_meta_name(meta)) continue;
            auto cands = m_fname.GetAllClassCandidates(obj_ptr);
            for (uint64_t cls : cands) {
                if (!cls) continue;
                if (cls < 0x10000 || cls >= 0x800000000000ULL) continue;
                // Reject package slots (start with '/').
                std::string cname = m_fname.GetName(cls);
                if (!cname.empty() && cname[0] == '/') continue;
                // Vtable sanity.
                uint64_t vt = Read<uint64_t>(cls);
                if (vt < MODULE_BASE || vt >= MODULE_BASE + 0x10000000ULL) continue;
                funcMetaAddrs.insert(cls);
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

            // Structural sanity test for "could be a UFunction".  Audit
            // (tools/audit_pass3_pass4.py + audit_b0_pattern.py) showed that
            // 100% of class-discovered UFunctions satisfy:
            //
            //   qword @ +0xB0 has high 56 bits == 0  (NumParms is a u8 followed
            //                                         by 7 padding bytes; non-
            //                                         UFunction objects store
            //                                         floats / heap ptrs there)
            //   low byte (NumParms) <= 64            (very loose UE limit)
            //
            // Pass 3's outer_ok path used to admit any named subobject under a
            // known type whose +0x120 happened to look like flags — including
            // OverlaySlots, StaticMeshes, Textures, etc. (≈19K bogus passers).
            // Adding this u8-shape gate catches those.
            auto looks_like_ufunc_struct = [&](uint64_t obj_ptr) -> bool {
                uint64_t qB0 = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::NumParms);
                if ((qB0 >> 8) != 0) return false;       // high 56 bits must be zero
                if ((qB0 & 0xFF) > 64) return false;     // NumParms range
                return true;
            };

            // Vtable-destructor sanity: the first virtual slot of a real
            // UFunction vtable points to module text containing real code, NOT
            // to a 0xCC INT3-padded region (which is where a stripped /
            // VMP-protected destructor leaves a placeholder).  Cached because
            // there are only ~5 distinct UFunction-shaped vtables in practice.
            std::unordered_map<uint64_t, bool> vt_dtor_ok_cache;
            auto vt_dtor_looks_real = [&](uint64_t vt) -> bool {
                auto it = vt_dtor_ok_cache.find(vt);
                if (it != vt_dtor_ok_cache.end()) return it->second;
                bool ok = false;
                if (vt >= MODULE_BASE && vt < MODULE_BASE + 0x10000000ULL) {
                    uint64_t dtor = Read<uint64_t>(vt);
                    if (dtor >= MODULE_BASE && dtor < MODULE_BASE + 0x10000000ULL) {
                        // Reject 0xCCCC… INT3 pads (stripped destructors).
                        uint64_t first_qw = Read<uint64_t>(dtor);
                        ok = (first_qw != 0xCCCCCCCCCCCCCCCCULL);
                    }
                }
                vt_dtor_ok_cache[vt] = ok;
                return ok;
            };

            for (const auto& [idx, obj_ptr] : object_ptrs) {
                // Probe ALL 4 slot candidates — slot picker hash is unstable on
                // CL-1177146 so a single-slot GetClassPrivate misses UFunctions
                // whose metaclass landed in a non-default slot.
                auto cands = m_fname.GetAllClassCandidates(obj_ptr);
                bool is_ufunc = false;
                for (uint64_t cls : cands) {
                    if (funcMetaAddrs.count(cls)) { is_ufunc = true; break; }
                }
                if (!is_ufunc) continue;
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
                found_set.insert(obj_ptr);  // FIX: prevent Pass 3/4 from re-pushing
                ++extra;
            }
            std::printf("[sdk] UFunction pass 2 (vtable+outer): %d extra funcs\n", extra);

            // Pass 3: heuristic — any named non-type object whose Outer is a known type
            // and has reasonable FunctionFlags at +0x120 is likely a UFunction.
            int pass3 = 0;
            int pass3_rej_struct = 0;
            int pass3_rej_dtor   = 0;
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
                // FunctionFlags at +0x120 must be reasonable
                uint32_t flags = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                if (flags == 0 || flags > 0x10000000u) continue;
                // Structural shape gate (catches OverlaySlot/StaticMesh/Texture
                // false positives whose +0xB0 holds a float / heap ptr).
                if (!looks_like_ufunc_struct(obj_ptr)) { ++pass3_rej_struct; continue; }
                // Accept if EITHER:
                //   (a) vtable is a known UFunction vtable, OR
                //   (b) Outer resolves to a known type (the original strict heuristic)
                uint64_t vt = Read<uint64_t>(obj_ptr);
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                bool vt_ok    = ufunc_vtbls.count(vt) > 0;
                bool outer_ok = outer && allTypeAddrs.count(outer) > 0;
                if (!vt_ok && !outer_ok) continue;
                // If admission is via outer-only (vt not yet in known set), the
                // vtable destructor must look real — rejects vtables whose
                // first slot points into 0xCC-padded / VMP-stripped regions
                // (e.g. 0x14B8ADCD0 / 0x14B8AE100, ~10K UWidget subobjects).
                if (!vt_ok && !vt_dtor_looks_real(vt)) { ++pass3_rej_dtor; continue; }
                // If accepted by vtable but outer isn't a known type, push to orphans
                if (!outer_ok) outer = 0;
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                ufunc_vtbls.insert(vt);  // expand vtable set so pass 4 can rescue siblings
                ++pass3;
            }
            std::printf("[sdk] UFunction pass 3 (heuristic): %d extra funcs "
                "(rejected %d by struct shape, %d by vt dtor)\n",
                pass3, pass3_rej_struct, pass3_rej_dtor);

            // Pass 4: catch UFunctions whose ClassPrivate/Outer slots are empty or
            // un-decryptable (sparse slot pattern — only one of the four UObject
            // name slots holds data, e.g. K2_AddActorWorldOffset). Identify by:
            //   - vtable in known UFunction vtable set (expanded by pass 3)
            //   - FunctionFlags at +0x128 looks valid
            //   - NextPtr at +0x98 either NULL or heap (matches UField layout)
            // Outer of 0 → orphan owner; the function still appears in the SDK's
            // orphan section.
            int pass4 = 0;
            int pass4_rej_struct = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (found_set.count(obj_ptr)) continue;
                uint64_t vt = Read<uint64_t>(obj_ptr);
                if (!ufunc_vtbls.count(vt)) continue;
                uint32_t flags = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                if (flags == 0 || flags > 0x10000000u) continue;
                uint64_t nxt = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::NextPtr);
                if (nxt != 0 && (nxt < 0x10000 || nxt >= 0x800000000000ULL)) continue;
                // Structural shape gate — same rationale as Pass 3.  Necessary
                // because Pass 3 may expand ufunc_vtbls with a sibling vtable
                // that legitimately matches some UFunctions but also matches
                // unrelated UObjects on the same heap chunk.
                if (!looks_like_ufunc_struct(obj_ptr)) { ++pass4_rej_struct; continue; }
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                ++pass4;
            }
            std::printf("[sdk] UFunction pass 4 (sparse-slot rescue): %d extra funcs "
                "(rejected %d by struct shape, ufunc_vtbls=%zu)\n",
                pass4, pass4_rej_struct, ufunc_vtbls.size());

            // Pass 5: walk UClass FuncMap (TMap<FName, UFunction*> at UClass+0x268).
            // Each UClass has a TMap with up to ~40 functions per class; total ~11K
            // UFunctions across 4020 UClass-derived objects. This corrects ownership
            // for functions that earlier passes either missed or assigned to the
            // wrong owner via slot-decrypt heuristics.
            //
            // CRITICAL: only walk +0x268 on real UClass objects. Earlier versions of
            // this pass walked every UObject indiscriminately, which read random heap
            // data on non-UClass instances (UDataAsset, UNavCollisionBase, CDOs, ...)
            // — those random pointers passed the "looks like a UFunction" filter and
            // were attributed to the non-UClass owner, swelling the orphan section
            // with thousands of bogus entries (e.g. 347 fake fns on an
            // AssaultRifle DataAsset instance, 214 on a NiagaraDataInterface CDO).
            // A UClass test = its ClassPrivate is one of the meta-class addresses
            // (UClass, BlueprintGeneratedClass, ASClass, AnimBPGC, …) i.e. lives in
            // validClassTypes. allTypeAddrs is also accepted (anything used as a
            // ClassPrivate by some other object is provably a UClass).
            int pass5 = 0;
            int classes_walked = 0;
            int pass5_skipped_nonclass = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                // Skip if already known to be a non-class type (enum/struct/CDO).
                if (validEnumTypes.count(obj_ptr)) continue;

                // FIX: skip walking FuncMaps of UFunction-meta classes themselves
                // (Function, DelegateFunction, SparseDelegateFunction, ASFunction*).
                // Their FuncMap data is either invalid or holds a global registry
                // of UFunctions whose real owner is some other class — walking them
                // here causes the same UFunction to be assigned to TWO owners (the
                // meta-class AND the real class), producing 2K+ duplicate emissions.
                if (funcMetaAddrs.count(obj_ptr)) { ++pass5_skipped_nonclass; continue; }

                // Strict UClass gate: object must EITHER be referenced as a class
                // pointer by some other object (allTypeAddrs), OR have its own
                // ClassPrivate decode to a meta-class address (validClassTypes).
                bool is_class = allTypeAddrs.count(obj_ptr) > 0;
                if (!is_class) {
                    auto cands = m_fname.GetAllClassCandidates(obj_ptr);
                    for (uint64_t cc : cands) {
                        if (cc && validClassTypes.count(cc)) { is_class = true; break; }
                    }
                }
                if (!is_class) { ++pass5_skipped_nonclass; continue; }

                uint64_t pairs_data = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_PairsData);
                if (pairs_data <= 0x10000 || pairs_data >= 0x800000000000ULL) continue;
                uint32_t num = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_Num);
                if (num == 0 || num > 4096) continue;
                uint32_t maxN = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_Max);
                if (maxN < num || maxN > 16384) continue;

                ++classes_walked;
                for (uint32_t i = 0; i < num; ++i) {
                    uint64_t entry = pairs_data + (uint64_t)i * ArcDecrypt::Offsets::UClass::FuncMap_PairStride;
                    uint64_t ufunc = Read<uint64_t>(entry + ArcDecrypt::Offsets::UClass::FuncMapPair_UFunction);
                    if (ufunc <= 0x10000 || ufunc >= 0x800000000000ULL) continue;
                    if (found_set.count(ufunc)) {
                        // Already enumerated; reassign owner to this UClass if
                        // currently bucketed under owner=0 (orphan) or wrong owner.
                        bool any = false;
                        for (auto& [own, fns] : m_owner_to_funcs) {
                            auto it2 = std::find(fns.begin(), fns.end(), ufunc);
                            if (it2 != fns.end()) {
                                if (own != obj_ptr) {
                                    fns.erase(it2);
                                    m_owner_to_funcs[obj_ptr].push_back(ufunc);
                                }
                                any = true;
                                break;
                            }
                        }
                        (void)any;
                    } else {
                        // New discovery
                        m_owner_to_funcs[obj_ptr].push_back(ufunc);
                        found_set.insert(ufunc);
                        uint64_t vt = Read<uint64_t>(ufunc);
                        if (vt >= MODULE_BASE && vt < MODULE_BASE + 0x10000000ULL)
                            ufunc_vtbls.insert(vt);
                        ++pass5;
                    }
                }
            }
            std::printf("[sdk] UFunction pass 5 (UClass FuncMap): %d new funcs across %d classes (skipped %d non-class objs)\n",
                pass5, classes_walked, pass5_skipped_nonclass);
        }

        // ── Dedup: ensure each UFunction appears in exactly ONE owner bucket ──
        // Defensive cleanup against the pass-5 reassignment race (the inner
        // for-loop over m_owner_to_funcs uses `break` after the first hit, so
        // if the same ufunc somehow lands in two buckets it stays in one of
        // them after a "reassign"). Also catches any remaining intra-bucket
        // duplicates from earlier passes. Walk in iteration order; first
        // sighting wins.
        {
            std::unordered_set<uint64_t> globally_seen;
            int dropped_dup_inter = 0;
            int dropped_dup_intra = 0;
            for (auto& [owner, fns] : m_owner_to_funcs) {
                std::vector<uint64_t> kept;
                kept.reserve(fns.size());
                std::unordered_set<uint64_t> bucket_seen;
                for (uint64_t fn : fns) {
                    if (!bucket_seen.insert(fn).second) { ++dropped_dup_intra; continue; }
                    if (!globally_seen.insert(fn).second) { ++dropped_dup_inter; continue; }
                    kept.push_back(fn);
                }
                fns = std::move(kept);
            }
            std::printf("[sdk] UFunction dedup: %d intra-bucket + %d cross-bucket duplicates removed\n",
                dropped_dup_intra, dropped_dup_inter);
        }

        {
            int total_fn = 0;
            for (auto& [owner, fns] : m_owner_to_funcs) total_fn += fns.size();
            std::printf("[sdk] Total UFunction objects: %d, owners: %zu\n",
                total_fn, m_owner_to_funcs.size());
        }

        // ── Patch 20260430 / CL-1177146 PRIMARY: read property-type table at module+0xDBB64C0
        //    dynamically and decode each non-zero FName handle. Provides the
        //    canonical set of property type names (e.g. "BoolProperty",
        //    "DoubleProperty", "ArrayProperty") used to validate FFieldClass
        //    name reads downstream.
        bool DynamicOk = LoadDynamicPropertyTypeTable();
        if (!DynamicOk) {
            std::printf("[ptable] dynamic load failed — relying on hardcoded map only\n");
        }

        // ── Seed hardcoded FFieldClass→type map BEFORE auto-discovery so
        //    Tier-1 name-heuristic mistakes cannot overwrite authoritative
        //    data. Always run because the hardcoded map keys (FField+0x88
        //    type-global pointers) are not derivable from the dynamic table
        //    alone — the dynamic table indexes by EClassCastFlags-style ID,
        //    not by global pointer. Use it as fallback when the dynamic
        //    pipeline cannot resolve a particular fclass_ptr.
        SeedHardcodedFClassMap_20260421();

        // ── Auto-discover vtable-to-type mappings (replaces bootstrap + sweep) ──
        AutoDiscoverVTables(object_ptrs, addr_to_name, allTypeAddrs, ssAddr);

        // ── Helper: resolve package name for any obj ptr ──────────────────────
        // When the pkg_ptr isn't in our 70K objects (e.g., /Script/Engine
        // UPackages live in chunks not reached by structural scan), query
        // the name LIVE via the FName resolver and cache it.
        std::unordered_map<uint64_t, std::string> live_pkg_cache;
        auto resolvePackage = [&](uint64_t obj_ptr) -> std::string {
            uint64_t pkg_ptr = m_fname.GetPackagePtr(obj_ptr);
            if (!pkg_ptr) return "Unknown";
            auto it = pkg_map.find(pkg_ptr);
            if (it != pkg_map.end()) return it->second;
            auto fn = addr_to_fullname.find(pkg_ptr);
            if (fn != addr_to_fullname.end()) {
                const std::string& s = fn->second;
                if (!s.empty() && s[0]=='/') return s;  // full path
                return s;
            }
            // Live fallback — read the name directly. ONLY accept results
            // that look like real package paths (start with '/'). Otherwise
            // the chain walk terminated early at a non-UPackage and we'd
            // mislabel objects with non-package names like "Class" or "Instance".
            auto cached = live_pkg_cache.find(pkg_ptr);
            if (cached != live_pkg_cache.end()) return cached->second;
            std::string live_name = m_fname.GetName(pkg_ptr);
            if (!live_name.empty() && live_name[0] == '/') {
                live_pkg_cache[pkg_ptr] = live_name;  // full path
                return live_name;
            }
            live_pkg_cache[pkg_ptr] = "Unknown";
            return "Unknown";
        };

        // ── Pre-pass: walk ChildProperties chains of all type-shaped objects
        // to populate m_known_structs / m_known_enums BEFORE classification.
        // Walks +0x80..+0x140 stride 8 (UClass at +0xC8/+0xD0, UScriptStruct
        // at +0xB0). For each FStructProperty.Struct / FEnumProperty.Enum found
        // we mark the target as a known struct/enum.
        std::printf("[sdk] Pre-pass: walking type-object chains for struct/enum discovery...\n");
        size_t pre_walked = 0;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            if (!obj_ptr) continue;
            // Only walk objects that look like UStructs (have a non-zero
            // ChildProperties chain head somewhere in +0x80..+0x140).
            for (int co = 0x80; co <= 0x140; co += 8) {
                uint64_t head = Read<uint64_t>(obj_ptr + co);
                if (head <= 0x10000 || head >= 0x800000000000ULL) continue;
                uint64_t hvt = Read<uint64_t>(head);
                if (hvt < MODULE_BASE || hvt >= MODULE_BASE + 0x10000000ULL) continue;
                // ReadPropertyChain calls ResolveSubPropertyType internally,
                // populating m_known_structs and m_known_enums.
                ReadPropertyChain(head, /*max_props=*/512, /*is_param=*/false);
                ++pre_walked;
                break;  // one chain per object is enough
            }
        }
        // Count how many known_structs are in our scanned object set vs extras.
        std::unordered_set<uint64_t> obj_set;
        for (const auto& [idx, op] : object_ptrs) obj_set.insert(op);
        size_t ks_in = 0, ks_out = 0;
        for (uint64_t a : m_known_structs) (obj_set.count(a) ? ks_in : ks_out)++;
        std::printf("[sdk] Pre-pass walked %zu chains; m_known_structs=%zu (in_set=%zu, extras=%zu) m_known_enums=%zu\n",
            pre_walked, m_known_structs.size(), ks_in, ks_out, m_known_enums.size());
        std::printf("[fcmap-dyn] observed %zu unique FFieldClass pointers during pre-pass\n",
            m_observed_fclass_ptrs.size());

        if (m_dynamic_type_table_loaded) {
            CalibrateFClassTypeIdxOffset();
            size_t DynAdded = SeedDynamicFClassMap();
            std::printf("[fcmap-dyn] dynamic seeding produced %zu new FFieldClass mappings (total=%zu)\n",
                DynAdded, m_fclass_to_type.size());

            // Parallel path: probe FFieldClass NamePrivate slot directly. On
            // builds where FFieldClass has an FName at a discoverable offset
            // (verified 20260421), this resolves the type name without a
            // typeidx lookup table — works even when the typeidx calibration
            // fails (which happens when FFieldClass has no uint32 typeidx
            // field, e.g. CL-1177146).
            CalibrateFClassNameSlotOffset();
            size_t NameAdded = SeedFClassMapByNameSlot();
            if (NameAdded > 0) {
                std::printf("[fcname-seed] FName-slot seeding produced %zu new FFieldClass mappings (total=%zu)\n",
                    NameAdded, m_fclass_to_type.size());
            }

            // Phase 8 path: dereference each (target_rva, type_name) tuple
            // extracted from FFieldClass init callers — direct map of static
            // .data globals to type names. Bypasses FName decryption entirely.
            // Runs FIRST so its mappings feed the CastFlags seeder below.
            size_t Phase8Added = SeedFClassMapFromGlobals();
            if (Phase8Added > 0) {
                std::printf("[fcglob-seed] Phase 8 globals produced %zu new FFieldClass mappings (total=%zu)\n",
                    Phase8Added, m_fclass_to_type.size());
            }

            // Phase 7 path: if FFieldClass NamePrivate decode auto-discovered
            // its full pipeline (PSHUFLW + ROL32 + PSHUFLW + XOR + ROL64),
            // use m_fname.DecryptFFieldClassNameCI directly on every observed
            // FFieldClass pointer. This bypasses the offset-only calibration
            // above (which assumes the FField NamePrivate pipeline shape;
            // FFieldClass uses a different shape).
            if (AutoDiscovery::g_DiscoveredFFieldClassName.Valid) {
                size_t Phase7Added = SeedFClassMapViaPhase7();
                if (Phase7Added > 0) {
                    std::printf("[fcname-p7] Phase 7 decoder seeded %zu new FFieldClass mappings (total=%zu)\n",
                        Phase7Added, m_fclass_to_type.size());
                }
            }

            // CastFlags path: read FFieldClass+0x10 (uint64 CastFlags bitmask),
            // build a (CastFlags → name) map from the now ~30-50 mapped
            // FFieldClasses (after Phase 8), then resolve every unmapped
            // observed FFieldClass by its CastFlags. Closes the bulk of the
            // FFieldClass mapping gap on CL-1177146 (~700+ unmapped objs).
            size_t CfAdded = SeedFClassMapByCastFlags();
            if (CfAdded > 0) {
                std::printf("[fcflags] CastFlags seeding produced %zu new FFieldClass mappings (total=%zu)\n",
                    CfAdded, m_fclass_to_type.size());
            }
        }

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
            // Skip CDOs — Default__X objects are class default *instances*,
            // not class definitions. They're already used in pass-1 to recover
            // metaclass addresses; emitting them again as their own type
            // produces 200+ bogus "Default__X" class entries with junk
            // inheritance chains (FNamePool keys decrypt as float / utf16 noise).
            if (short_name.rfind("Default__", 0) == 0) continue;
            // For unnamed objects, only proceed if they're referenced as a type
            if (short_name.empty()) {
                // Will check is_type_by_ref below; generate a placeholder name
                char buf[32]; std::snprintf(buf, sizeof(buf), "Class_0x%llX", (unsigned long long)obj_ptr);
                short_name = buf;
            }

            // Determine type via two paths:
            // Path A: probe ALL pointer-shaped slot decryptions and check
            // against known metaclass sets. GetClassPrivate alone is
            // unstable across calls (different objects encode their class
            // in different slots; the slot picker hash is wrong on 20260428).
            auto cls_cands = m_fname.GetAllClassCandidates(obj_ptr);
            uint64_t cls = 0;
            bool is_class_by_cls = false, is_scriptstruct = false, is_enum = false;
            // Path B': obj is in known-struct/enum sets (from FStructProperty.Struct
            // / FEnumProperty.Enum field reads during property walks). Strongest signal.
            if (m_known_structs.count(obj_ptr)) is_scriptstruct = true;
            if (m_known_enums.count(obj_ptr))   is_enum = true;
            // Path A: probe ALL pointer-shape candidates against metaclass sets.
            // Prefer enum > scriptstruct > class — even if the CDO pass leaks
            // package addresses into the metaclass sets (it shouldn't after the
            // recent fix, but defense in depth), enum/struct hits are smaller
            // sets and more authoritative than class hits, so we'd rather pick
            // an enum if any candidate is an enum metaclass.
            uint64_t enum_cls = 0, ss_cls = 0, class_cls = 0;
            for (uint64_t cc : cls_cands) {
                if (!cc) continue;
                if (!enum_cls  && enumAddrs.count(cc))       enum_cls  = cc;
                if (!ss_cls    && ssAddrs.count(cc))         ss_cls    = cc;
                if (!class_cls && validClassTypes.count(cc)) class_cls = cc;
            }
            if      (enum_cls)  { is_enum         = true; cls = enum_cls;  }
            else if (ss_cls)    { is_scriptstruct = true; cls = ss_cls;    }
            else if (class_cls) { is_class_by_cls = true; cls = class_cls; }
            if (!cls) cls = m_fname.GetClassPrivate(obj_ptr);  // fallback for legacy paths

            // Path C: heuristic — Names array at +0xA8 (UEnum::Names)
            // Only apply when not already classified as a type
            bool _is_type_by_ref_check = allTypeAddrs.count(obj_ptr) > 0;
            if (!is_class_by_cls && !is_scriptstruct && !is_enum && !_is_type_by_ref_check) {
                uint64_t names_ptr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names);
                uint32_t names_cnt = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 8);
                uint32_t names_max = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 12);
                // CDOs (Default__X) are never enums — skip the heuristic
                // for them to keep struct/class CDOs from being misdetected.
                bool is_cdo = short_name.rfind("Default__", 0) == 0;
                if (!is_cdo &&
                    names_ptr > 0x10000 && names_ptr < 0x7FFFFFFFFFFFULL &&
                    names_cnt > 0 && names_cnt < 4096 &&
                    names_max >= names_cnt && names_max < 4096) {
                    // Patch 20260421: entries are {uint32 CI, uint32 Num,
                    // int64 value} stride 16 (per IDA UEnum_GetValueByName
                    // at 0x3E44E0). The CI is obfuscated but always non-zero
                    // for a live enum; Num is almost always 0; values fit in
                    // a sane range. Random heap pages rarely satisfy all three.
                    int32_t  first_ci  = Read<int32_t>(names_ptr + 0);
                    uint32_t first_num = Read<uint32_t>(names_ptr + 4);
                    int64_t  first_val = Read<int64_t>(names_ptr + 8);
                    if (first_ci > 0 && (uint32_t)first_ci < 0x1FFFFFFFu &&
                        first_num < 0x1000 &&
                        first_val > -0x100000 && first_val < 0x100000) {
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
                    // Patch 20260428: entries are TPair<FName, int64> stride 16:
                    //   +0  uint32  FName.lo32 = direct FNamePool index (no obfuscation)
                    //   +4  uint32  FName.Number (typically 0 for enum entries)
                    //   +8  int64   enum value
                    // CompIndexToNameLenient does the FNamePool walk and is the
                    // correct path. DecryptCIByEmu was a 20260421 workaround that
                    // produces garbage on this patch.
                    for (uint32_t j = 0; j < names_cnt; ++j) {
                        uint64_t ep  = names_ptr + (uint64_t)j * 16;
                        int32_t  ci  = Read<int32_t>(ep + 0);
                        int64_t  val = Read<int64_t>(ep + 8);
                        std::string ev = m_fname.CompIndexToNameLenient(ci);
                        if (ev.empty()) continue;
                        if (ev.find('?') != std::string::npos) continue;
                        size_t cc = ev.find("::");
                        if (cc != std::string::npos) ev = ev.substr(cc + 2);
                        erec.entries.push_back({ev, val});
                    }
                }
                // Emit the enum even with no entries — a typed UEnum is still
                // useful for SDK consumers; missing entries are a decode issue,
                // not a "this isn't an enum" signal.
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

            // Properties: read OWN-ONLY chain via UStruct::ChildProperties at
            // the verified offset (+0xD0 on 20260428). The previous broad-scan
            // [0x80..0x140] also picked up PropertyLink/RefLink/DestructorLink/
            // PostConstructLink heads (the FULL inherited chains UE builds at
            // CDO time), and walking those via FField::Next leaked PARENT-class
            // properties into every derived class's namespace — inflating
            // emitted prop count by ~106K (51%). Reference dumpers emit each
            // field exactly once at its owning class, so we now mirror that.
            //
            // We still dedup by FField address to be safe in case ChildProperties
            // is mirrored across +0xE8/+0xF0 (same head pointer); identical heads
            // produce identical chains and are collapsed to one entry per FField.
            std::unordered_map<uint64_t, PropertyRecord> best_at_ff;
            // Try ChildProperties at +0x100 first (UStruct/UScriptStruct/native-UClass).
            // If that's null, fall back to candidate offsets where BPGCs and
            // engine-generated UClass subclasses store their PropertyLink:
            //   +0xB8  observed on BPGC (e.g. BP_CinCam_HandHeldShake_Jitter_C)
            //   +0x118 observed live as another chain head
            // Each candidate must point to a heap object whose +0x00 vtable
            // is in module range (= a real FField). Walking PropertyLink may
            // include inherited fields from parent classes, but ff_addr dedup
            // collapses identical FFields and the per-class emit (own-by-walk)
            // is preserved per call site. Matches reference dumpers for game
            // BPGCs that otherwise emit empty bodies.
            static constexpr uint64_t kChainOffs[] = { 0x100, 0xB8, 0x118 };
            auto walk_chain = [&](uint64_t chain_head) {
                if (chain_head <= 0x10000 || chain_head >= 0x7FFFFFFFFFFFULL) return;
                uint64_t cpvt = Read<uint64_t>(chain_head);
                if (cpvt < MODULE_BASE || cpvt >= MODULE_BASE + 0x10000000ULL) return;
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
            };
            for (uint64_t off : kChainOffs) {
                uint64_t head = Read<uint64_t>(obj_ptr + off);
                walk_chain(head);
                if (!best_at_ff.empty()) break;  // first non-empty chain wins
            }
            for (auto& [ff, p] : best_at_ff)
                rec.properties.push_back(std::move(p));
            // Legacy UProperty chain intentionally disabled — it corrupts output with
            // bogus entries (~3%) and the FField chain covers almost everything.

            // Functions: found from GObjects by ClassPrivate, grouped by Outer
            rec.functions = ReadFunctionsFromMap(obj_ptr);

            result.structs.push_back(std::move(rec));
        }

        // ── Pass 3: emit "extra" structs/enums discovered via property walks
        // that are NOT in our 70K object set (engine UScriptStructs / UEnums
        // that live in chunks the structural scan doesn't reach). For each,
        // resolve name live and emit a minimal record.
        size_t extra_structs_added = 0, extra_enums_added = 0;
        for (uint64_t sp : m_known_structs) {
            if (seen.count(sp)) continue;
            if (sp <= 0x10000 || sp >= 0x800000000000ULL) continue;
            seen.insert(sp);
            std::string name = m_fname.GetName(sp);
            if (name.empty() || name[0] == '/') continue;
            size_t dot = name.rfind('.');
            if (dot != std::string::npos) name = name.substr(dot + 1);
            StructRecord rec{};
            rec.addr = sp;
            rec.name = name;
            rec.package = resolvePackage(sp);
            rec.props_size = Read<uint32_t>(sp + ArcDecrypt::Offsets::UStruct::PropertiesSize);
            rec.is_class = false;
            rec.super_addr = Read<uint64_t>(sp + ArcDecrypt::Offsets::UStruct::SuperStruct);
            // Properties chain walk — own-only via ChildProperties.
            // (See main pass above for why broad-scan was removed.)
            {
                uint64_t head = Read<uint64_t>(sp + ArcDecrypt::Offsets::UStruct::ChildProperties);
                if (head > 0x10000 && head < 0x7FFFFFFFFFFFULL) {
                    uint64_t cpvt = Read<uint64_t>(head);
                    if (cpvt >= MODULE_BASE && cpvt < MODULE_BASE + 0x10000000ULL) {
                        auto chain = ReadPropertyChain(head);
                        for (auto& p : chain) rec.properties.push_back(std::move(p));
                    }
                }
            }
            result.structs.push_back(std::move(rec));
            ++extra_structs_added;
        }
        for (uint64_t ep : m_known_enums) {
            if (seen.count(ep)) continue;
            if (ep <= 0x10000 || ep >= 0x800000000000ULL) continue;
            seen.insert(ep);
            std::string name = m_fname.GetName(ep);
            if (name.empty() || name[0] == '/') continue;
            size_t dot = name.rfind('.');
            if (dot != std::string::npos) name = name.substr(dot + 1);
            EnumRecord erec{};
            erec.addr = ep;
            erec.name = name;
            erec.package = resolvePackage(ep);
            result.enums.push_back(std::move(erec));
            ++extra_enums_added;
        }
        std::printf("[sdk] Pass-3 emit extras: +%zu structs, +%zu enums\n",
            extra_structs_added, extra_enums_added);

        // Sort alphabetically by package then name (used for final emit order)
        auto sort_by_pkg_name = [](const auto& a, const auto& b) {
            return a.package < b.package || (a.package == b.package && a.name < b.name);
        };

        // ── Quality-first dedup ────────────────────────────────────────────────
        // Multiple records can share a short name (Object, Function,
        // HorizontalBoxSlot, …). We must rename collisions to *_N so C++
        // namespaces don't collide, but we want the *highest-quality*
        // record to keep the bare name. Quality factors (highest first):
        //   • package looks like a real engine/game package ("/Script/X" or "/Game/X")
        //     vs a misresolved outer (e.g. package="Class" or "Unknown" produced
        //     when GetPackagePtr's outer chain terminates at a UClass instead of
        //     a UPackage).
        //   • record has functions (UClass with reflected methods)
        //   • record has properties
        //   • is_class > is_struct (rare-name UClasses outweigh BP UScriptStructs)
        //   • larger props_size (more complete reflection)
        // Tie-break: shorter package name (prefers /Script/Engine over a deep
        // BP path), then lexical package, then addr (deterministic).
        auto pkg_quality = [](const std::string& p) -> int {
            // Real engine/game packages start with a script/game prefix or are
            // recognized as canonical UE module paths. Misresolved outers like
            // "Class", "Unknown", or a bare object name get score 0.
            if (p.empty() || p == "Unknown" || p == "Class" ||
                p == "ScriptStruct" || p == "Enum" || p == "Package")
                return 0;
            // Heuristic: a real package short-name typically contains no dot
            // and is one of /Script/X or /Game/Y/Z. Since we already strip to
            // the last segment, accept any non-blacklisted name as tier 1.
            return 1;
        };
        auto better_for_bare_name = [&](const auto& a, const auto& b) {
            int qa = pkg_quality(a.package), qb = pkg_quality(b.package);
            if (qa != qb) return qa > qb;
            bool fa = !a.functions.empty(), fb = !b.functions.empty();
            if (fa != fb) return fa;
            bool pa = !a.properties.empty(), pb = !b.properties.empty();
            if (pa != pb) return pa;
            if (a.is_class != b.is_class) return a.is_class;
            if (a.props_size != b.props_size) return a.props_size > b.props_size;
            if (a.package.size() != b.package.size()) return a.package.size() < b.package.size();
            if (a.package != b.package) return a.package < b.package;
            return a.addr < b.addr;
        };
        // Enums don't have functions/properties/is_class/props_size — fall
        // back to package-quality + lexical.
        auto better_for_bare_name_enum = [&](const auto& a, const auto& b) {
            int qa = pkg_quality(a.package), qb = pkg_quality(b.package);
            if (qa != qb) return qa > qb;
            if (a.package.size() != b.package.size()) return a.package.size() < b.package.size();
            if (a.package != b.package) return a.package < b.package;
            return a.addr < b.addr;
        };

        // Group by short name, pick the "best" record per group. Runner-ups
        // that are *empty* (size=0, no props, no funcs) get DROPPED — these
        // are stale UClass instances / hot-reload remnants / per-AngelScript
        // shadow copies that share a name with the real type but have no
        // reflection content. Runner-ups with content are renamed to *_N
        // (preserves legitimate cross-package collisions, e.g. "Object" in
        // Engine vs Game).
        //
        // Why drop instead of _N rename: pre-fix, /Script/Niagara had 2571
        // _N classes, /Script/UMG had 2237, /Script/Angelscript had 2K+. All
        // had size=0, no properties, no super_addr — i.e. zero reflection
        // content. They inflated the output 1.8x with no information value.
        auto struct_is_empty = [](const StructRecord& r) -> bool {
            if (r.props_size != 0) return false;
            if (!r.functions.empty()) return false;
            if (r.super_addr != 0) return false;
            for (const auto& p : r.properties) {
                if (p.name.rfind("UnknownProp_", 0) != 0 &&
                    p.name.rfind("Prop_CI", 0)      != 0) return false;
            }
            return true;
        };
        // Enums are never treated as "empty junk" — a typed but entry-less
        // UEnum is still useful, and there's no over-emit phenomenon for them.
        auto enum_is_empty = [](const EnumRecord&) -> bool { return false; };
        auto dedupe_by_quality = [&](auto& vec, auto&& cmp, auto&& is_empty) {
            std::unordered_map<std::string, std::vector<size_t>> by_name;
            for (size_t i = 0; i < vec.size(); ++i)
                by_name[vec[i].name].push_back(i);
            std::unordered_set<std::string> taken;
            std::vector<bool> drop(vec.size(), false);
            size_t dropped_empty = 0;
            // First pass: claim bare names for the best record in each group.
            for (auto& [name, idxs] : by_name) {
                std::sort(idxs.begin(), idxs.end(), [&](size_t x, size_t y) {
                    return cmp(vec[x], vec[y]);
                });
                taken.insert(vec[idxs.front()].name);  // best keeps bare name
            }
            // Second pass: drop empty runner-ups; rename non-empty runner-ups _N.
            for (auto& [name, idxs] : by_name) {
                if (idxs.size() <= 1) continue;
                bool best_has_content = !is_empty(vec[idxs.front()]);
                int n = 1;
                for (size_t k = 1; k < idxs.size(); ++k) {
                    auto& r = vec[idxs[k]];
                    if (best_has_content && is_empty(r)) {
                        drop[idxs[k]] = true;
                        ++dropped_empty;
                        continue;
                    }
                    std::string candidate;
                    for (;; ++n) {
                        candidate = name + "_" + std::to_string(n);
                        if (taken.insert(candidate).second) break;
                    }
                    r.name = std::move(candidate);
                    ++n;
                }
            }
            // Compact: erase dropped entries.
            if (dropped_empty) {
                size_t w = 0;
                for (size_t r = 0; r < vec.size(); ++r) {
                    if (!drop[r]) {
                        if (w != r) vec[w] = std::move(vec[r]);
                        ++w;
                    }
                }
                vec.resize(w);
                std::printf("[sdk] Dedup dropped %zu empty duplicate records\n",
                            dropped_empty);
            }
        };
        dedupe_by_quality(result.structs, better_for_bare_name,      struct_is_empty);
        dedupe_by_quality(result.enums,   better_for_bare_name_enum, enum_is_empty);

        // Final emit-order sort (after dedup so renamed entries stay grouped).
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
