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
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <cstdio>
#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

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
    std::unordered_set<uint64_t> m_known_enums_hi;

    // Owner (UClass/UStruct addr) → list of UFunction addresses
    std::unordered_map<uint64_t, std::vector<uint64_t>> m_owner_to_funcs;

    const std::unordered_map<uint64_t, std::string>* m_addr_to_name = nullptr;

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
        uint64_t lo, hi;
        if (AutoDiscovery::g_DiscoveredBounds.Valid) {
            lo = MODULE_BASE + AutoDiscovery::g_DiscoveredBounds.RDataRva;
            hi = MODULE_BASE + AutoDiscovery::g_DiscoveredBounds.DataRva
                             + AutoDiscovery::g_DiscoveredBounds.DataSize;
        } else {
            lo = MODULE_BASE + 0x1000ULL;
            hi = MODULE_BASE + 0xF0F5000ULL;
        }
        uint64_t fc0 = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
        if (fc0 >= lo && fc0 < hi) return fc0;
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

        return "UNKNOWN";
    }

    std::string ProbePropertyTypeStructural(uint64_t ff) {
        uint32_t ElemSize = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);

        uint64_t Ptr130 = Read<uint64_t>(ff + ArcDecrypt::Offsets::FStructProperty::Struct);
        uint64_t Ptr138 = Read<uint64_t>(ff + ArcDecrypt::Offsets::FEnumProperty::Enum);
        uint64_t Ptr140 = Read<uint64_t>(ff + ArcDecrypt::Offsets::FArrayProperty::Inner);

        auto IsHeapPtr = [](uint64_t P) {
            return P >= 0x10000ULL && P < 0x7FFFFFFFFFFFULL;
        };
        auto HasModuleVtable = [&](uint64_t P) -> bool {
            if (!IsHeapPtr(P)) return false;
            uint64_t Vt = Read<uint64_t>(P);
            uint64_t Rva = Vt - MODULE_BASE;
            return Rva >= 0x1000 && Rva < 0xE9D0000ULL;
        };
        auto IsFFieldLike = [&](uint64_t P) -> bool {
            if (!HasModuleVtable(P)) return false;
            uint64_t Nx = Read<uint64_t>(P + ArcDecrypt::Offsets::FField::Next);
            return Nx == 0 || IsHeapPtr(Nx);
        };
        auto IsUObjectOfVtable = [&](uint64_t P, uint64_t ExpectedRva) -> bool {
            if (!IsHeapPtr(P)) return false;
            uint64_t Vt = Read<uint64_t>(P);
            return (Vt - MODULE_BASE) == ExpectedRva;
        };

        uint64_t AsClassRva  = AutoDiscovery::g_DiscoveredVTables.ASClassRVA;
        uint64_t AsStructRva = AutoDiscovery::g_DiscoveredVTables.ASStructRVA;
        uint64_t AsEnumRva   = AutoDiscovery::g_DiscoveredVTables.EnumRVA;

        if (ElemSize == 80) {
            if (IsFFieldLike(Ptr130) && IsFFieldLike(Ptr138))
                return "FMapProperty";
            if (IsFFieldLike(Ptr130))
                return "FSetProperty";
            return "FMapProperty";
        }

        if (IsFFieldLike(Ptr140)) {
            uint32_t InnerElem = Read<uint32_t>(Ptr140 + ArcDecrypt::Offsets::FProperty::ElementSize);
            if (InnerElem > 0 && InnerElem < 0x10000)
                return "FArrayProperty";
        }

        if (ElemSize == 40) {
            if (AsClassRva && IsUObjectOfVtable(Ptr130, AsClassRva))
                return "FSoftClassProperty";
            return "FSoftObjectProperty";
        }

        uint8_t BoolFieldSize = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::FieldSize);
        uint8_t BoolByteMask  = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::ByteMask);
        uint8_t BoolFieldMask = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::FieldMask);
        bool LooksBool = (BoolFieldSize >= 1 && BoolFieldSize <= 8) &&
                         (BoolFieldSize == 1 || BoolFieldSize == 2 || BoolFieldSize == 4 || BoolFieldSize == 8) &&
                         (BoolByteMask != 0) &&
                         ((BoolByteMask & (BoolByteMask - 1)) == 0 || BoolByteMask == 0xFF) &&
                         (BoolFieldMask != 0) &&
                         (ElemSize == 0 || ElemSize == BoolFieldSize);

        if (HasModuleVtable(Ptr130) && HasModuleVtable(Ptr138)) {
            if (IsFFieldLike(Ptr130))
                return "FEnumProperty";
            if (AsClassRva && IsUObjectOfVtable(Ptr130, AsClassRva) &&
                IsUObjectOfVtable(Ptr138, AsClassRva))
                return "FClassProperty";
            return "FEnumProperty";
        }

        if (HasModuleVtable(Ptr130) && !LooksBool) {
            if (AsStructRva && IsUObjectOfVtable(Ptr130, AsStructRva))
                return "FStructProperty";
            if (AsClassRva && IsUObjectOfVtable(Ptr130, AsClassRva))
                return "FObjectProperty";
            if (AsEnumRva && IsUObjectOfVtable(Ptr130, AsEnumRva))
                return "FEnumProperty";
            if (ElemSize == 8)
                return "FObjectProperty";
            return "FStructProperty";
        }

        if (HasModuleVtable(Ptr138) && !LooksBool) {
            if (AsEnumRva && IsUObjectOfVtable(Ptr138, AsEnumRva))
                return "FEnumProperty";
        }

        if (LooksBool)
            return "FBoolProperty";

        if (ElemSize == 16) {
            if (HasModuleVtable(Ptr130))
                return "FInterfaceProperty";
            return "FStrProperty";
        }

        if (ElemSize == 0) {
            uint64_t PropFlags = Read<uint64_t>(ff + ArcDecrypt::Offsets::FProperty::PropertyFlags);
            if (PropFlags & 0x0000000000000002ULL)
                return "FBoolProperty";
            if (HasModuleVtable(Ptr130))
                return "FStructProperty";
            return "FBoolProperty";
        }

        switch (ElemSize) {
            case 1:  return "FByteProperty";
            case 2:  return "FUInt16Property";
            case 4:  return "FIntProperty";
            case 8:  return "FDoubleProperty";
            case 24: return "FTextProperty";
            case 32: return "FDelegateProperty";
            case 48: return "FMulticastInlineDelegateProperty";
            default:
                if (ElemSize > 8 && ElemSize < 0x10000)
                    return "FStructProperty";
                return "FProperty_Unknown";
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

                // Skip only if this specific FFieldClass* is already resolved.
                // Use ReadFFieldClassPtr (live .rdata/.data sweep) since our
                // hardcoded ClassPrivate offset is wrong on CL-1195482.
                uint64_t fc_early = ReadFFieldClassPtr(ff);
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
                        uint64_t fc = ReadFFieldClassPtr(ff);
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
                uint64_t fc_ptr = ReadFFieldClassPtr(ff);
                if (fc_ptr) elem = Read<uint32_t>(fc_ptr + ArcDecrypt::Offsets::FFieldClass::ElementSize);
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
    // Seed the canonical set with hardcoded UE5 property type names so the
    // FFieldClass NamePrivate calibration has something to match even when
    // the dynamic table read fails (CL-1195482 has the table at a different
    // RVA than 0xDBB64C0). Idempotent — safe to call multiple times.
    void SeedCanonicalPropertyTypeNamesFromBuiltin() {
        static const char* kBuiltin[] = {
            "BoolProperty", "Int8Property", "ByteProperty", "Int16Property",
            "UInt16Property", "IntProperty", "UInt32Property", "Int64Property",
            "UInt64Property", "FloatProperty", "DoubleProperty",
            "NameProperty", "StrProperty", "TextProperty",
            "EnumProperty", "StructProperty", "ArrayProperty",
            "MapProperty", "SetProperty", "ClassProperty",
            "ObjectProperty", "WeakObjectProperty", "LazyObjectProperty",
            "SoftObjectProperty", "SoftClassProperty", "InterfaceProperty",
            "DelegateProperty", "MulticastDelegateProperty",
            "MulticastInlineDelegateProperty", "MulticastSparseDelegateProperty",
            "FieldPathProperty", "OptionalProperty", "VerseStringProperty",
            "Property",
        };
        for (const char* n : kBuiltin) m_canonical_property_type_names.insert(n);
    }

    bool TryDecodePropertyTypeTable(uint64_t TableAddr, size_t TableLen, const char* Tag) {
        std::vector<uint32_t> Handles(TableLen, 0);
        if (!m_reader.Read(TableAddr, Handles.data(), TableLen * sizeof(uint32_t))) {
            std::printf("[ptable] failed to read %s @ 0x%llX\n",
                Tag, (unsigned long long)TableAddr);
            return false;
        }
        size_t Decoded = 0;
        size_t Nonzero = 0;
        size_t DiagShown = 0;
        for (size_t I = 0; I < TableLen; ++I) {
            uint32_t H = Handles[I];
            if (!H) continue;
            ++Nonzero;
            if (DiagShown < 5) {
                int32_t DiagCi = static_cast<int32_t>(H);
                std::string DiagName = m_fname.CompIndexToNameLenient(DiagCi);
                std::printf("[ptable-diag] %s [%zu] raw=0x%08X ci=%d name='%s'\n",
                    Tag, I, H, DiagCi, DiagName.c_str());
                ++DiagShown;
            }
            int32_t Ci = static_cast<int32_t>(H);
            std::string Name = m_fname.CompIndexToNameLenient(Ci);
            if (Name.empty()) continue;
            bool NameOk = true;
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
        std::printf("[ptable] %s: %zu/%zu non-zero handles, %zu decoded names\n",
            Tag, Nonzero, TableLen, Decoded);
        return (Decoded >= 8);
    }

    bool LoadDynamicPropertyTypeTable() {
        constexpr size_t   TABLE_LEN = 703;
        constexpr uint64_t TABLE_STRUCT_OFF = 0x2540;

        m_type_idx_to_name.clear();
        m_canonical_property_type_names.clear();
        SeedCanonicalPropertyTypeNamesFromBuiltin();

        uint64_t GNamePoolRva = ArcDecrypt::RVA_GNAMES_BASE ? ArcDecrypt::RVA_GNAMES_BASE : ArcDecrypt::v20260519::RVA_GNAMEPOOL;
        uint64_t PrimaryTableAddr = MODULE_BASE + GNamePoolRva + TABLE_STRUCT_OFF;

        constexpr uint64_t LEGACY_TABLE_RVA = 0xDBB64C0;
        uint64_t LegacyTableAddr = MODULE_BASE + LEGACY_TABLE_RVA;

        std::printf("[ptable] trying primary (GNamePool+0x%llX) @ RVA 0x%llX\n",
            (unsigned long long)TABLE_STRUCT_OFF,
            (unsigned long long)(GNamePoolRva + TABLE_STRUCT_OFF));

        bool Ok = TryDecodePropertyTypeTable(PrimaryTableAddr, TABLE_LEN, "primary");

        if (!Ok && PrimaryTableAddr != LegacyTableAddr) {
            std::printf("[ptable] primary failed, trying legacy @ RVA 0x%llX\n",
                (unsigned long long)LEGACY_TABLE_RVA);
            m_type_idx_to_name.clear();
            Ok = TryDecodePropertyTypeTable(LegacyTableAddr, TABLE_LEN, "legacy");
        }

        m_dynamic_type_table_loaded = Ok;
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
        // CL-1201801 (2026-05-21) FFieldClass RVAs — live-extracted via
        // fcname-rva pass (FFieldClass::NamePrivate decode at +0x40).
        // All in .data section (0xE034000..0xE7A7000).
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
        for (auto [rva, type] : kSeeds)
            m_fclass_to_type[MODULE_BASE + rva] = type;
        std::printf("[fcmap] seeded %zu hardcoded FFieldClass mappings (CL-1201801)\n",
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
        // Diagnostic: dump the first FEW observed FFieldClass instances'
        // bytes so we can see the actual struct layout on this build.
        {
            int dumped = 0;
            for (uint64_t Fc : m_observed_fclass_ptrs) {
                if (dumped++ >= 3) break;
                std::printf("[fcname-cal] sample FFieldClass @ 0x%llX:\n", (unsigned long long)Fc);
                for (int off = 0; off < 0xC0; off += 0x10) {
                    uint64_t a = 0, b = 0;
                    if (!m_reader.Read(Fc + off, &a, 8)) break;
                    m_reader.Read(Fc + off + 8, &b, 8);
                    std::printf("[fcname-cal]   +0x%02X: %016llX %016llX\n",
                                off, (unsigned long long)a, (unsigned long long)b);
                }
            }
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
                bool NonZero = false;
                for (int B = 0; B < 16; ++B) if (Enc[B]) { NonZero = true; break; }
                if (!NonZero) continue;
                // Try BOTH decoders: the (CL-1177146) FFieldClass-specific
                // pipeline + the FField NamePrivate decoder. On CL-1195482 the
                // FFieldClass-specific auto-disc sig is stale, so the FField
                // pipeline (PSHUFLW(0x4B) → ROL32(1) → PSHUFB → XOR → ROL64(32))
                // is used as the working fallback.
                uint64_t Dec1 = m_fname.DecryptFFieldClassNameSlotFromBytes(Enc);
                uint64_t Dec2 = m_fname.DecryptFFieldNameSlot(Enc);
                uint32_t Lo1 = static_cast<uint32_t>(Dec1);
                uint32_t Lo2 = static_cast<uint32_t>(Dec2);
                std::string Name;
                if (Lo1 >= 2 && Lo1 <= 0x2000000u) {
                    Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo1));
                }
                if (Name.empty() && Lo2 >= 2 && Lo2 <= 0x2000000u) {
                    Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo2));
                }
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
        // Threshold: require ≥15% of sampled FFieldClasses to resolve to a
        // canonical name AND a clean separation from the runner-up (best ≥
        // 5× runner-up). The observed FFieldClass set includes non-property
        // types (FField, FFieldPathProperty parent, etc.) that legitimately
        // won't match canonical-property-type names; the previous 30% bar
        // rejected real offsets when the property:non-property ratio was low.
        // The runner-up gate replaces the absolute threshold as the noise
        // filter — a real offset produces sharp clustering, noise offsets
        // are flat.
        const int32_t Required = static_cast<int32_t>(Sample.size()) * 15 / 100;
        const int32_t RunnerUp = (Scores.size() > 1) ? Scores[1].Hits : 0;
        const bool ClearWinner = Best.Hits >= 5 * std::max(1, RunnerUp);
        if (Best.Hits < Required || !ClearWinner) {
            std::printf("[fcname-cal] best offset +0x%X hits=%d/%zu (need >=%d, runner-up=%d) — too weak; skipping\n",
                Best.Off, Best.Hits, Sample.size(), Required, RunnerUp);
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
            // Dual decoder: FFieldClass-specific pipeline (CL-1177146) + FField
            // NamePrivate pipeline (CL-1195482 working fallback).
            uint64_t Dec1 = m_fname.DecryptFFieldClassNameSlotFromBytes(Enc);
            uint64_t Dec2 = m_fname.DecryptFFieldNameSlot(Enc);
            uint32_t Lo1 = static_cast<uint32_t>(Dec1);
            uint32_t Lo2 = static_cast<uint32_t>(Dec2);
            std::string Name;
            if (Lo1 >= 2 && Lo1 <= 0x2000000u) {
                Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo1));
            }
            if (Name.empty() && Lo2 >= 2 && Lo2 <= 0x2000000u) {
                Name = m_fname.CompIndexToName(static_cast<int32_t>(Lo2));
            }
            if (Name.empty()) { ++NoName; continue; }
            // Prefer the canonical "F"-prefixed form.
            // Normalise to F-prefixed canonical form if possible, otherwise use raw name.
            std::string Canonical;
            if (m_canonical_property_type_names.count(Name)) {
                Canonical = "F" + Name;
            } else if (Name.size() > 1 && Name[0] == 'F' &&
                       m_canonical_property_type_names.count(Name.substr(1))) {
                Canonical = Name;
            } else if (m_canonical_property_type_names.count("F" + Name)) {
                Canonical = "F" + Name;
            } else {
                Canonical = Name;  // non-canonical but valid — keep it
                ++NotCanonical;
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
    std::string GetNameTheia(uint64_t obj_ptr) {
        if (!obj_ptr || obj_ptr < 0x10000 || obj_ptr >= 0x7FFFFFFFFFFFULL) return {};
        std::string n = m_fname.GetName(obj_ptr);
        if (!n.empty()) return n;
        if (m_addr_to_name) {
            auto it = m_addr_to_name->find(obj_ptr);
            if (it != m_addr_to_name->end()) return it->second;
        }
        return {};
    }
    // ── Resolve sub-property type for Struct/Object/Enum/Class/Interface ────
    uint32_t m_resolveStructOk = 0, m_resolveStructFail = 0;
    uint32_t m_resolveObjOk = 0, m_resolveObjFail = 0;
    std::unordered_set<uint64_t> m_unresolvedShadowSample;

    void PrintResolveStats() {
        std::printf("[resolve] Struct: resolved=%u unresolved=%u  Object: resolved=%u unresolved=%u\n",
            m_resolveStructOk, m_resolveStructFail, m_resolveObjOk, m_resolveObjFail);
    }

    void DiagnoseShadowResolution() {
        std::printf("[shadow-diag] unique unresolved shadow targets: %zu (sampling up to 10)\n",
            m_unresolvedShadowSample.size());
        int Count = 0;
        for (uint64_t Sp : m_unresolvedShadowSample) {
            if (Count >= 10) break;
            uint64_t Vt = Read<uint64_t>(Sp);
            uint64_t VtRva = (Vt > MODULE_BASE) ? (Vt - MODULE_BASE) : 0;
            int32_t Ci = m_fname.GetCompIndex(Sp);
            std::string EmuName;
            if (Ci > 0) EmuName = m_fname.GetName(Sp);
            if (EmuName.empty()) EmuName = "(ci=" + std::to_string(Ci) + ")";
            uint64_t Super = Read<uint64_t>(Sp + 0xB0);
            uint32_t PSize = Read<uint32_t>(Sp + 0xE0);
            uint64_t ChildP = Read<uint64_t>(Sp + 0x118);
            std::printf("[shadow-diag]   0x%lX: vt_rva=0x%lX ci=%d name='%s' super=0x%lX psize=%u childp=0x%lX\n",
                Sp, VtRva, Ci, EmuName.c_str(), Super, PSize, ChildP);
            Count++;
        }
    }

    void ResolveSubPropertyType(uint64_t ff, std::string& type_name) {
        if (type_name == "FStructProperty") {
            uint64_t sp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FStructProperty::Struct);
            if (sp && sp > 0x10000 && sp < 0x7FFFFFFFFFFFULL) {
                m_known_structs.insert(sp);
                std::string sn = GetNameTheia(sp);
                if (!sn.empty()) { type_name = sn; m_resolveStructOk++; }
                else { m_resolveStructFail++; if (m_unresolvedShadowSample.size() < 200) m_unresolvedShadowSample.insert(sp); }
            }
            if (type_name == "FStructProperty") {
                uint32_t ElemSize = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);
                if (ElemSize > 0 && ElemSize < 0x10000) {
                    char Buf[32];
                    snprintf(Buf, sizeof(Buf), "struct_%Xh", ElemSize);
                    type_name = Buf;
                }
            }
        }
        if (type_name == "FObjectProperty" || type_name == "FWeakObjectProperty" ||
            type_name == "FSoftObjectProperty" || type_name == "FLazyObjectProperty") {
            uint64_t cp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (cp) {
                std::string cn = GetNameTheia(cp);
                if (!cn.empty()) { type_name = cn + "*"; m_resolveObjOk++; }
                else { m_resolveObjFail++; if (m_unresolvedShadowSample.size() < 200) m_unresolvedShadowSample.insert(cp); }
            }
        }
        if (type_name == "FClassProperty" || type_name == "FSoftClassProperty") {
            uint64_t mc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass + 8);
            if (mc) {
                std::string cn = GetNameTheia(mc);
                if (!cn.empty()) { type_name = "TSubclassOf<" + cn + ">"; return; }
            }
            uint64_t cp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (cp) { std::string cn = GetNameTheia(cp); if (!cn.empty()) type_name = "TSubclassOf<" + cn + ">"; }
        }
        if (type_name == "FInterfaceProperty") {
            uint64_t ic = Read<uint64_t>(ff + ArcDecrypt::Offsets::FObjectProperty::PropertyClass);
            if (ic) { std::string cn = GetNameTheia(ic); if (!cn.empty()) type_name = "TScriptInterface<" + cn + ">"; }
        }
        if (type_name == "FEnumProperty") {
            uint64_t ep = Read<uint64_t>(ff + ArcDecrypt::Offsets::FEnumProperty::Enum);
            if (ep) {
                if (ep > 0x10000 && ep < 0x7FFFFFFFFFFFULL) {
                    m_known_enums.insert(ep);
                    m_known_enums_hi.insert(ep);
                }
                std::string en = GetNameTheia(ep);
                if (!en.empty()) type_name = en;
            }
        }
        // FByteProperty: if it wraps a UEnum, emit the enum name; else fall
        // through to primitive lowering (uint8_t).
        if (type_name == "FByteProperty") {
            uint64_t en = Read<uint64_t>(ff + ArcDecrypt::Offsets::FEnumProperty::UnderlyingProp); // shares +0x108
            if (en > 0x10000 && en < 0x7FFFFFFFFFFFULL) {
                m_known_enums.insert(en);
                std::string n = GetNameTheia(en);
                if (!n.empty()) { type_name = n; return; }
            }
        }
        if (type_name == "FDelegateProperty" ||
            type_name == "FMulticastInlineDelegateProperty" ||
            type_name == "FMulticastSparseDelegateProperty" ||
            type_name == "FMulticastDelegateProperty") {
            uint64_t sig = Read<uint64_t>(ff + 0x108);
            if (sig > 0x10000 && sig < 0x7FFFFFFFFFFFULL) {
                std::string n = GetNameTheia(sig);
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
                                                   bool is_param = false,
                                                   uint64_t expected_owner = 0) {
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
                // CL-1195482: FField.ClassPrivate offset hasn't been verified —
                // the hardcoded 0x70 reads garbage for many FFields and used to
                // break the chain early. Relaxed: skip the cls_ptr range check.
                // Real chain-end detection still works via vtable + slot checks.
                // uint64_t cls_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                // if (cls_ptr != 0 &&
                //     (cls_ptr < 0x100000ULL || cls_ptr >= 0x800000000000ULL)) break;
                // Ghost-FField guard. CL-1177678 native UClass stores its
                // UField chain (UFunction list) at offsets like +0xC8/+0xD8,
                // and BPGC SuperStruct lands at +0xB8 — both can pass the
                // module-range vtable check but are NOT FFields. Real FFields
                // always have a populated NamePrivate slot (the FName
                // obfuscation pipeline produces non-zero bytes even for
                // CI=0 / FName::None). All-zero NamePrivate at BOTH the
                // auto-discovered offset AND the hardcoded +0x30 means the
                // candidate is either uninitialized memory or a UField/
                // UObject masquerading as an FField — break.
                // Two-offset check: auto-disc may drift NamePrivate to a
                // wrong offset; +0x30 is the verified CL-1177678 slot, so
                // we OR the two probes — break only if BOTH are zero.
                auto AnyNonZero = [&](uint64_t off) {
                    alignas(16) uint8_t enc[16] = {};
                    m_reader.Read(ff + off, enc, 16);
                    for (uint8_t b : enc) if (b) return true;
                    return false;
                };
                bool slot_present =
                    AnyNonZero(ArcDecrypt::Offsets::FField::NameEncrypted) ||
                    AnyNonZero(0x30);
                if (!slot_present) break;

                uint64_t ff_owner = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Owner);
                uint64_t ff_owner_clean = ff_owner & ~1ULL;
                if (ff_owner_clean != 0 && (ff_owner_clean < 0x10000ULL || ff_owner_clean >= 0x800000000000ULL))
                    break;
                if (ff_owner_clean == 0) break;
                if (expected_owner && ff_owner_clean != expected_owner) break;
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

            pr.fclass_ptr = ReadFFieldClassPtr(ff);
            if (pr.fclass_ptr)
                m_observed_fclass_ptrs.insert(pr.fclass_ptr);

            auto fc_it = m_fclass_to_type.find(pr.fclass_ptr);
            if (fc_it != m_fclass_to_type.end()) {
                pr.type_name = fc_it->second;
            } else {
                pr.type_name = ProbePropertyTypeStructural(ff);
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
                // CL-1195482: Offset_Internal is at FField+0x64. Use the
                // patch-aware DecryptPropertyOffsetNew helper (bswap(stored) ^
                // XOR) instead of the legacy inline (bswap(stored ^ XOR))
                // which only works when XOR is its own bswap.
                {
                    uint32_t stored_off = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                    uint32_t real = ArcDecrypt::Patch20260421::DecryptPropertyOffsetNew(stored_off);
                    if (real <= 0x100000u) pr.offset = real;
                }
                // Optional fallback: broad-scan +0x60..+0xA0 for the sentinel
                // byte signature of the live XOR key, in case Offset_Internal
                // drifts in a future patch. Sentinel value = bswap32(XOR_KEY)
                // so its LE memory bytes equal the LE bytes of bswap32(XOR_KEY).
                if (pr.offset == 0) {
                    const uint32_t live_xor = ArcDecrypt::Patch20260421::g_PropertyOffsetXor;
                    const uint32_t sentinel = __builtin_bswap32(live_xor);
                    const uint8_t k0 = static_cast<uint8_t>(sentinel & 0xFF);
                    const uint8_t k1 = static_cast<uint8_t>((sentinel >> 8) & 0xFF);
                    alignas(8) uint8_t probe[64] = {};
                    if (m_reader.Read(ff + 0x60, probe, 64)) {
                        for (int dx = 0; dx + 4 <= 64; ++dx) {
                            if (probe[dx]     != k0) continue;
                            if (probe[dx + 1] != k1) continue;
                            uint32_t stored;
                            std::memcpy(&stored, probe + dx, 4);
                            uint32_t real = ArcDecrypt::Patch20260421::DecryptPropertyOffsetNew(stored);
                            if (real > 0 && real <= 0x100000u) {
                                pr.offset = real;
                                break;
                            }
                        }
                    }
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
                uint32_t inner_elem_check = inner_ptr ? Read<uint32_t>(inner_ptr + ArcDecrypt::Offsets::FProperty::ElementSize) : 0;
                if (inner_ptr && inner_elem_check > 0 && inner_elem_check < 0x10000) {
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
                            ipr.type_name = ProbePropertyTypeStructural(inner_ptr);
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
                            epr.type_name = ProbePropertyTypeStructural(elem_ptr);
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
                            mpr.type_name = ProbePropertyTypeStructural(mp);
                        }
                    }
                    mpr.offset    = pr.offset;
                    mpr.elem_size = Read<uint32_t>(mp + ArcDecrypt::Offsets::FProperty::ElementSize);
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
            // CL-1195482: FField::Next offset isn't fully verified. Try the
            // configured offset first, then sweep a fixed set of candidates —
            // accept the first one whose value lands in heap AND whose +0x0
            // qword (vtable) lies in module range (FField shape).
            uint64_t next = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
            auto IsValidFFieldNext = [&](uint64_t cand) -> bool {
                if (cand == 0) return true;   // legitimate chain end
                if (cand < 0x10000ULL || cand >= 0x7FFFFFFFFFFFULL) return false;
                if (cand == ff) return false;
                uint64_t vt = 0;
                if (!m_reader.Read(cand, &vt, 8)) return false;
                if (vt < MODULE_BASE + 0x1000ULL ||
                    vt >= MODULE_BASE + 0xE9D0000ULL) return false;
                // Additional gate: candidate must have a non-zero NamePrivate slot
                uint8_t enc[16] = {};
                if (!m_reader.Read(cand + ArcDecrypt::Offsets::FField::NameEncrypted, enc, 16)) return false;
                for (uint8_t b : enc) if (b) return true;
                return false;
            };
            if (!IsValidFFieldNext(next)) {
                static constexpr uint64_t kSweepOffs[] = {
                    0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40,
                    0x48, 0x60, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8,
                    0xB0, 0xB8, 0xC0, 0xC8, 0xD0, 0xD8, 0xE0, 0xE8,
                };
                for (uint64_t off : kSweepOffs) {
                    if (off == ArcDecrypt::Offsets::FField::Next) continue;
                    uint64_t cand = Read<uint64_t>(ff + off);
                    if (IsValidFFieldNext(cand)) { next = cand; break; }
                }
            }
            ff = next;
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

            fr.name = GetNameTheia(fn_addr);
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
                auto chain = ReadPropertyChain(head, 64, /*is_param=*/true, /*expected_owner=*/fn_addr);
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
        std::vector<const PropertyRecord*> InParams;
        for (const auto& par : fn.params) {
            if (par.name == "ReturnValue") { ret_type = par.type_name; continue; }
            const bool IsContextGarbage = par.type_name == "FProperty_Unknown" &&
                                          par.name.rfind("Prop_CI", 0) == 0;
            if (!IsContextGarbage)
                InParams.push_back(&par);
        }
        oss << "// 0x" << std::hex << fn.fn_addr;
        if (fn.native_rva) oss << " (RVA: 0x" << std::hex << fn.native_rva << ")";
        oss << " flags=0x" << std::hex << fn.flags << "\n";
        oss << ret_type << " " << fn.name << "(";
        bool First = true;
        for (const auto* par : InParams) {
            if (!First) oss << ", ";
            First = false;
            oss << par->type_name << " " << par->name;
            if (par->array_dim > 1) oss << "[" << par->array_dim << "]";
        }
        oss << "); // " << InParams.size() << " params\n";
        return oss.str();
    }

    // ── True when a record is an actor/component INSTANCE misclassified as
    //    a class (CL-1195482 vtable detection picks up many UClass vtables
    //    shared by BPGC instances; their UAID/instance-suffix name + empty
    //    body + size=0 give them away). Skipping them de-noises the SDK
    //    output without losing any real classes.
    static bool IsJunkClassRecord(const StructRecord& rec) {
        if (!rec.is_class) return false;
        const bool no_body = rec.properties.empty() && rec.functions.empty();
        if (!no_body) return false;
        if (rec.props_size != 0) return false;
        // Name markers: UE5 emits `_UAID_XXXX_NN` for actor instances spawned
        // from level placements; `_C_NN` for blueprint-generated instances;
        // bare hex-tail names also occur. Drop the obvious ones.
        const std::string& n = rec.name;
        if (n.find("_UAID_") != std::string::npos) return true;
        // Any of the per-instance hash-suffixed BPGC names: 32+ hex chars
        // following an underscore (e.g. _D288F928443963046556AF8A9441662D)
        size_t und = n.rfind('_');
        if (und != std::string::npos && n.size() - und - 1 >= 16) {
            bool all_hex = true;
            for (size_t i = und + 1; i < n.size() && all_hex; ++i) {
                char c = n[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
                    all_hex = false;
            }
            if (all_hex) return true;
        }
        return false;
    }

    // A function is junk when every non-ReturnValue parameter has FProperty_Unknown type.
    // Functions with zero non-return parameters are NOT junk — they may be real events.
    static bool IsJunkFunction(const FunctionRecord& fn) {
        int NonRet = 0, UnkCnt = 0;
        for (const auto& Par : fn.params) {
            if (Par.name == "ReturnValue") continue;
            ++NonRet;
            if (Par.type_name == "FProperty_Unknown") ++UnkCnt;
        }
        return NonRet > 0 && NonRet == UnkCnt;
    }

    // ── Dump a single UStruct/UClass to string ──────────────────────────────────
    std::string DumpStruct(const StructRecord& rec) {
        if (rec.name.rfind("Class_0x", 0) == 0) return "";
        if (IsJunkClassRecord(rec)) return "";

        // Build filtered function list — drop functions whose only parameters
        // are CI=0 unknowns (Blueprint CDO synthetic events, static mesh events).
        std::vector<const FunctionRecord*> GoodFns;
        GoodFns.reserve(rec.functions.size());
        for (const auto& fn : rec.functions)
            if (!IsJunkFunction(fn))
                GoodFns.push_back(&fn);

        std::vector<const PropertyRecord*> GoodProps;
        GoodProps.reserve(rec.properties.size());
        for (const auto& pr : rec.properties) {
            const bool IsGarbage = pr.name.rfind("Prop_CI", 0) == 0 &&
                                   pr.type_name == "FProperty_Unknown";
            if (!IsGarbage)
                GoodProps.push_back(&pr);
        }

        // Skip namespaces that have nothing useful after filtering.
        if (GoodProps.empty() && GoodFns.empty()) return "";

        std::ostringstream oss;
        const std::string& pkg = rec.package;
        oss << "// " << (rec.is_class ? "Class" : "Struct") << " "
            << (!pkg.empty() && pkg[0] == '/' ? pkg : "/Script/" + pkg)
            << "." << rec.name << "\n";
        oss << "// Address: 0x" << std::hex << rec.addr << "\n";
        oss << "// Size: 0x" << std::hex << rec.props_size
            << " (" << std::dec << rec.props_size << " bytes)\n";
        if (!rec.super_name.empty())
            oss << "// Inherits: " << rec.super_name << " (0x" << std::hex << rec.super_addr << ")\n";
        if (rec.super_addr) {
            oss << "// Inheritance chain:\n";
            uint64_t cur = rec.super_addr;
            std::unordered_set<uint64_t> chain_seen;
            int depth = 0;
            while (cur && chain_seen.insert(cur).second && depth < 16) {
                std::string nm = GetNameTheia(cur);
                if (nm.empty()) nm = "Unknown";
                uint32_t sz = Read<uint32_t>(cur + ArcDecrypt::Offsets::UStruct::PropertiesSize);
                oss << "//   " << std::string(depth * 2, ' ') << "→ " << nm
                    << " (0x" << std::hex << cur << ", size=" << std::dec << sz << ")\n";
                cur = Read<uint64_t>(cur + ArcDecrypt::Offsets::UStruct::SuperStruct);
                ++depth;
            }
        }
        oss << "namespace " << rec.name << " {\n";
        std::unordered_map<std::string, int> NameCount;
        for (const auto* prp : GoodProps) {
            const auto& pr = *prp;
            std::string type_decl;
            if (pr.array_dim > 1)
                type_decl = pr.type_name + "[" + std::to_string(pr.array_dim) + "]";
            else
                type_decl = pr.type_name;
            std::string out_name = pr.name;
            auto& cnt = NameCount[out_name];
            if (cnt > 0) {
                out_name += "_" + std::to_string(cnt);
            }
            ++cnt;
            std::string name_padded = out_name;
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
        if (!GoodFns.empty()) {
            oss << "\n// === Functions (" << GoodFns.size() << ") ===\n";
            for (const auto* fn : GoodFns)
                oss << FormatFunction(*fn);
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
        m_addr_to_name = &addr_to_name;
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
                std::string cname = GetNameTheia(cls);
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

        std::unordered_set<uint64_t> funcMetaAddrs;
        auto is_func_meta_name = [](const std::string& n) {
            return n == "Function" || n == "DelegateFunction" ||
                   n == "SparseDelegateFunction" ||
                   n.rfind("ASFunction", 0) == 0;
        };

        // ── Pass 3: probe every distinct ClassPrivate target by name ──
        // The metaclass singletons (Enum, Class, ScriptStruct) aren't enumerable
        // as named UObjects on 20260428 — addr_to_name doesn't have them. But
        // they're still valid heap addresses pointed to by every type-instance's
        // ClassPrivate. Query their names directly via the FName resolver.
        // Also detects "Function" metaclass (Theia merges UScriptStruct+UFunction
        // under a single "Function" metaclass) → populates funcMetaAddrs AND ssAddrs.
        std::unordered_set<uint64_t> seen_cls_p3;
        std::size_t p3_cls = 0, p3_ss = 0, p3_en = 0, p3_fn = 0;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto cands = m_fname.GetAllClassCandidates(obj_ptr);
            for (uint64_t cls : cands) {
                if (cls < 0x10000 || cls >= 0x7FFFFFFFFFFFULL) continue;
                if (!seen_cls_p3.insert(cls).second) continue;
                std::string mname = GetNameTheia(cls);
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
                } else if (is_func_meta_name(mname)) {
                    funcMetaAddrs.insert(cls);
                    ssAddrs.insert(cls);
                    ++p3_fn;
                }
            }
        }
        std::printf("[sdk] Pass-3 (live-name metaclass probe): +%zu class, +%zu struct, +%zu enum, +%zu func-meta (fallback; zero = Pass-1 covered all)\n",
            p3_cls, p3_ss, p3_en, p3_fn);

        if (!classAddr) {
            std::printf("[sdk] FATAL: Could not find 'Class' UClass object\n");
            return result;
        }

        // ── Pass 4: vtable-based metaclass + UEnum::Names auto-probe ────
        // EnumRVA vtable scan disabled: auto_discovery's EnumRVA is unreliable
        // on Theia builds (was UCameraShakePattern on CL-1233465 instead of
        // UEnum). Wrong vtable calibrates Names offset on wrong objects and
        // pollutes enumAddr. UEnum detection relies on Path C heuristic instead.
        {
            const auto& VT = AutoDiscovery::g_DiscoveredVTables;
            (void)VT;

            if (!ssAddr) {
                for (const auto& [idx, obj_ptr] : object_ptrs) {
                    auto it = addr_to_name.find(obj_ptr);
                    if (it == addr_to_name.end()) continue;
                    if (kStructMetaNames.count(it->second)) {
                        uint64_t vt = Read<uint64_t>(obj_ptr);
                        if (vt >= MODULE_BASE && vt < MODULE_BASE + 0x10000000ULL) {
                            if (!ssAddr && it->second == "ScriptStruct") ssAddr = obj_ptr;
                            ssAddrs.insert(obj_ptr);
                        }
                    }
                }
                if (ssAddr)
                    std::printf("[sdk] Pass-4: ScriptStruct metaclass at 0x%llX, ssAddrs=%zu\n",
                        (unsigned long long)ssAddr, ssAddrs.size());
            }
        }

        // ── Build "all type addresses" via broad slot probing ─────────
        std::unordered_set<uint64_t> allTypeAddrs;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto Cands = m_fname.GetAllClassCandidates(obj_ptr);
            for (uint64_t Cls : Cands) {
                if (Cls > 0x10000 && Cls < 0x7FFFFFFFFFFFULL)
                    allTypeAddrs.insert(Cls);
            }
        }
        std::printf("[sdk] allTypeAddrs (broad slot probe): %zu\n", allTypeAddrs.size());

        std::unordered_map<uint64_t, uint32_t> ClassPrivateFreq;
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            uint64_t Cp = m_fname.GetClassPrivate(obj_ptr);
            if (Cp > 0x10000 && Cp < 0x7FFFFFFFFFFFULL)
                ClassPrivateFreq[Cp]++;
        }

        std::vector<std::pair<uint64_t, uint32_t>> FreqSorted(ClassPrivateFreq.begin(), ClassPrivateFreq.end());
        std::sort(FreqSorted.begin(), FreqSorted.end(), [](const auto& A, const auto& B) { return A.second > B.second; });
        std::printf("[sdk] ClassPrivate frequency (top 20):\n");
        for (size_t I = 0; I < std::min<size_t>(FreqSorted.size(), 20); ++I) {
            uint64_t Addr = FreqSorted[I].first;
            uint32_t Cnt = FreqSorted[I].second;
            std::string Name = GetNameTheia(Addr);
            if (Name.empty()) Name = "(unnamed)";
            std::printf("[sdk]   0x%llX: %u objects  name='%s'\n",
                (unsigned long long)Addr, Cnt, Name.c_str());
        }

        for (const auto& [Addr, Cnt] : ClassPrivateFreq) {
            std::string Name = GetNameTheia(Addr);
            if (Name.empty()) continue;
            if (Name == "Class" && !classAddr) classAddr = Addr;
            else if (Name == "ScriptStruct" && !ssAddr) { ssAddr = Addr; ssAddrs.insert(Addr); }
            else if (Name == "Enum" && !enumAddr) { enumAddr = Addr; validEnumTypes.insert(Addr); }
            else if (kClassMetaNames.count(Name)) validClassTypes.insert(Addr);
            else if (kStructMetaNames.count(Name)) ssAddrs.insert(Addr);
            else if (kEnumMetaNames.count(Name)) { enumAddrs.insert(Addr); validEnumTypes.insert(Addr); }
            else if (is_func_meta_name(Name)) funcMetaAddrs.insert(Addr);
        }
        std::printf("[sdk] After full freq scan: classAddr=0x%llX ssAddr=0x%llX enumAddr=0x%llX funcMetas=%zu\n",
            (unsigned long long)classAddr, (unsigned long long)ssAddr, (unsigned long long)enumAddr,
            funcMetaAddrs.size());
        if (!classAddr && !FreqSorted.empty()) {
            classAddr = FreqSorted[0].first;
            std::printf("[sdk] ClassPrivate frequency fallback: assigning top address 0x%llX as 'Class' metaclass (%u objects)\n",
                (unsigned long long)classAddr, FreqSorted[0].second);
            validClassTypes.insert(classAddr);
        }
        if (!ssAddr && FreqSorted.size() > 1) {
            for (size_t I = 1; I < std::min<size_t>(FreqSorted.size(), 20); ++I) {
                std::string Name = GetNameTheia(FreqSorted[I].first);
                if (Name.empty() && FreqSorted[I].second >= 100 && FreqSorted[I].second < FreqSorted[0].second / 2) {
                    ssAddr = FreqSorted[I].first;
                    ssAddrs.insert(ssAddr);
                    std::printf("[sdk] ClassPrivate frequency fallback: assigning 0x%llX as 'ScriptStruct' metaclass (%u objects, unnamed)\n",
                        (unsigned long long)ssAddr, FreqSorted[I].second);
                    break;
                }
            }
        }

        std::printf("[sdk] Class=0x%llX  ScriptStruct=0x%llX  Enum=0x%llX  metaclassTypes=%zu\n",
            (unsigned long long)classAddr, (unsigned long long)ssAddr,
            (unsigned long long)enumAddr, validClassTypes.size());

        // ── Pre-pass: identify UFunction vtable RVAs ──────────────────────
        // funcMetaAddrs + is_func_meta_name declared before Pass-3 (populated there via
        // live ClassPrivate target name probe). Path A/B below add any remaining
        // matches from addr_to_name and CDOs.
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
                std::string cname = GetNameTheia(cls);
                if (!cname.empty() && cname[0] == '/') continue;
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
                if ((qB0 >> 8) != 0) return false;
                if ((qB0 & 0xFF) > 64) return false;
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
                if (!looks_like_ufunc_struct(obj_ptr)) continue;
                uint64_t outer = m_fname.GetOuterPtr(obj_ptr);
                m_owner_to_funcs[outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                uint64_t vt = Read<uint64_t>(obj_ptr);
                ufunc_vtbls.insert(vt);
                ++fn_found;
            }
            std::printf("[sdk] UFunction pass 1 (ClassPrivate+struct-gate): %d funcs, %zu vtables\n",
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

            int Pass5 = 0;
            int ClassesWalked = 0;
            int Pass5SkippedNonclass = 0;
            int Pass5AllocSkipped = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (validEnumTypes.count(obj_ptr)) continue;
                if (funcMetaAddrs.count(obj_ptr)) { ++Pass5SkippedNonclass; continue; }

                bool IsClassObj = allTypeAddrs.count(obj_ptr) > 0;
                if (!IsClassObj) {
                    auto Cands = m_fname.GetAllClassCandidates(obj_ptr);
                    for (uint64_t Cc : Cands) {
                        if (Cc && validClassTypes.count(Cc)) { IsClassObj = true; break; }
                    }
                }
                if (!IsClassObj) { ++Pass5SkippedNonclass; continue; }

                uint64_t PairsData = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_PairsData);
                if (PairsData <= 0x10000 || PairsData >= 0x800000000000ULL) continue;
                uint32_t TotalSlots = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_Num);
                if (TotalSlots == 0 || TotalSlots > 4096) continue;
                uint32_t MaxSlots = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_Max);
                if (MaxSlots < TotalSlots || MaxSlots > 16384) continue;

                uint64_t AllocFlagsPtr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_AllocFlags);
                uint32_t NumFreeIndices = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UClass::FuncMap_NumFreeIndices);
                if (NumFreeIndices > TotalSlots) NumFreeIndices = 0;

                uint32_t AllocFlagsWords = (TotalSlots + 31) / 32;
                std::vector<uint32_t> AllocBits(AllocFlagsWords, 0xFFFFFFFFu);
                bool HasAllocFlags = false;
                if (AllocFlagsPtr > 0x10000 && AllocFlagsPtr < 0x800000000000ULL && AllocFlagsWords > 0) {
                    HasAllocFlags = m_reader.Read(AllocFlagsPtr, AllocBits.data(), AllocFlagsWords * 4);
                }

                ++ClassesWalked;
                for (uint32_t I = 0; I < TotalSlots; ++I) {
                    if (HasAllocFlags) {
                        uint32_t Word = AllocBits[I / 32];
                        if (!(Word & (1u << (I % 32)))) {
                            ++Pass5AllocSkipped;
                            continue;
                        }
                    }

                    uint64_t Entry = PairsData + (uint64_t)I * ArcDecrypt::Offsets::UClass::FuncMap_PairStride;
                    uint64_t Ufunc = Read<uint64_t>(Entry + ArcDecrypt::Offsets::UClass::FuncMapPair_UFunction);
                    if (Ufunc <= 0x10000 || Ufunc >= 0x800000000000ULL) continue;

                    uint64_t UfuncVt = Read<uint64_t>(Ufunc);
                    if (UfuncVt < MODULE_BASE || UfuncVt >= MODULE_BASE + 0x10000000ULL) continue;
                    if (!looks_like_ufunc_struct(Ufunc)) continue;
                    uint32_t UfuncFlags = Read<uint32_t>(Ufunc + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                    if (UfuncFlags == 0 || UfuncFlags > 0x10000000u) continue;

                    uint64_t NativeFunc = Read<uint64_t>(Ufunc + ArcDecrypt::Offsets::UFunction::NativeFunc);
                    bool HasNative = (NativeFunc >= MODULE_BASE && NativeFunc < MODULE_BASE + 0x10000000ULL);
                    bool KnownVt = ufunc_vtbls.count(UfuncVt) > 0;
                    if (!KnownVt && !HasNative) continue;

                    if (found_set.count(Ufunc)) {
                        bool Any = false;
                        for (auto& [Own, Fns] : m_owner_to_funcs) {
                            auto It2 = std::find(Fns.begin(), Fns.end(), Ufunc);
                            if (It2 != Fns.end()) {
                                if (Own == 0 && Own != obj_ptr) {
                                    Fns.erase(It2);
                                    m_owner_to_funcs[obj_ptr].push_back(Ufunc);
                                }
                                Any = true;
                                break;
                            }
                        }
                        (void)Any;
                    } else {
                        m_owner_to_funcs[obj_ptr].push_back(Ufunc);
                        found_set.insert(Ufunc);
                        ufunc_vtbls.insert(UfuncVt);
                        ++Pass5;
                    }
                }
            }
            std::printf("[sdk] UFunction pass 5 (UClass FuncMap w/ AllocFlags): %d new funcs across %d classes "
                "(skipped %d non-class, %d free-slots)\n",
                Pass5, ClassesWalked, Pass5SkippedNonclass, Pass5AllocSkipped);

            // Pass 6: NativeFunc-based structural detection.
            // Any object with a valid .text NativeFunc at +0x178, valid
            // FunctionFlags, and the NumParms u8-shape is almost certainly
            // a UFunction — regardless of vtable or ClassPrivate.
            // This catches UFunctions missed by all previous passes when
            // vtable is shared (CL-1233465: UClass/UScriptStruct/UFunction
            // all have vtable 0xB447980).
            int Pass6 = 0;
            int Pass6RejShape = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (found_set.count(obj_ptr)) continue;
                if (allTypeAddrs.count(obj_ptr)) continue;
                if (validEnumTypes.count(obj_ptr)) continue;
                if (funcMetaAddrs.count(obj_ptr)) continue;

                uint64_t NativeFunc = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::NativeFunc);
                if (NativeFunc < MODULE_BASE || NativeFunc >= MODULE_BASE + 0x10000000ULL) continue;

                uint32_t Flags = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UFunction::FunctionFlags);
                if (Flags == 0 || Flags > 0x10000000u) continue;

                if (!looks_like_ufunc_struct(obj_ptr)) { ++Pass6RejShape; continue; }

                uint64_t Vt = Read<uint64_t>(obj_ptr);
                if (Vt < MODULE_BASE || Vt >= MODULE_BASE + 0x10000000ULL) continue;

                uint64_t FirstQw = Read<uint64_t>(NativeFunc);
                if (FirstQw == 0xCCCCCCCCCCCCCCCCULL) continue;
                if (FirstQw == 0) continue;

                uint64_t Outer = m_fname.GetOuterPtr(obj_ptr);
                if (!Outer || !allTypeAddrs.count(Outer)) Outer = 0;
                m_owner_to_funcs[Outer].push_back(obj_ptr);
                found_set.insert(obj_ptr);
                ufunc_vtbls.insert(Vt);
                ++Pass6;
            }
            std::printf("[sdk] UFunction pass 6 (NativeFunc structural): %d extra funcs "
                "(rejected %d by shape)\n", Pass6, Pass6RejShape);
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

        std::unordered_set<uint64_t> func_obj_addrs;
        {
            int total_fn = 0;
            for (auto& [owner, fns] : m_owner_to_funcs) {
                total_fn += fns.size();
                for (uint64_t fn : fns) func_obj_addrs.insert(fn);
            }
            std::printf("[sdk] Total UFunction objects: %d, owners: %zu\n",
                total_fn, m_owner_to_funcs.size());
        }

        // ── Read property-type table (GNamePool+0x2540) dynamically and decode
        //    each non-zero FName handle. Provides the canonical set of property
        //    type names (e.g. "BoolProperty", "DoubleProperty", "ArrayProperty")
        //    used to validate FFieldClass name reads downstream. RVA computed
        //    from v20260519::RVA_GNAMEPOOL; falls back to legacy 0xDBB64C0.
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
        // SeedHardcodedFClassMap_20260421(); // CL-1201801 addresses wrong for CL-1233465

        // ── Auto-discover vtable-to-type mappings (replaces bootstrap + sweep) ──
        AutoDiscoverVTables(object_ptrs, addr_to_name, allTypeAddrs, ssAddr);

        // ── Brute-force FField::ClassPrivate offset calibration ─────────
        // For each plausible FField head, scan offsets 0x00..0xC0 for a ptr
        // into .rdata/.data WHOSE pointed-to struct has CastFlags-shape at
        // +0x10 (single-or-few-bit u64 < 0xFFFFFFFF). The offset that hits
        // most often across samples is FField::ClassPrivate.
        {
            uint64_t lo, hi;
            if (AutoDiscovery::g_DiscoveredBounds.Valid) {
                lo = MODULE_BASE + AutoDiscovery::g_DiscoveredBounds.RDataRva;
                hi = MODULE_BASE + AutoDiscovery::g_DiscoveredBounds.DataRva
                                 + AutoDiscovery::g_DiscoveredBounds.DataSize;
            } else { lo = MODULE_BASE + 0x1000ULL; hi = MODULE_BASE + 0xF0F5000ULL; }
            auto IsCastFlagsLike = [](uint64_t v) {
                if (v == 0 || v >= 0x100000000ULL) return false;
                // CastFlags has at most a few bits set among the low 32.
                int bits = __builtin_popcountll(v);
                return bits >= 1 && bits <= 6;
            };
            std::vector<uint64_t> ffSamples;
            for (const auto& [idx, ptr] : object_ptrs) {
                if (ffSamples.size() >= 200) break;
                uint64_t vt = 0;
                if (!m_reader.Read(ptr, &vt, 8)) continue;
                if (vt < MODULE_BASE + 0x1000ULL ||
                    vt >= MODULE_BASE + 0xE9D0000ULL) continue;
                uint64_t head = Read<uint64_t>(ptr + ArcDecrypt::Offsets::UStruct::ChildProperties);
                if (head < 0x10000ULL || head >= 0x7FFFFFFFFFFFULL) continue;
                ffSamples.push_back(head);
                // Walk a few hops via newly-discovered Next to collect more FFields.
                uint64_t cur = head; int hops = 0;
                std::unordered_set<uint64_t> seen;
                while (cur && hops < 8 && ffSamples.size() < 200) {
                    if (!seen.insert(cur).second) break;
                    uint64_t nx = Read<uint64_t>(cur + ArcDecrypt::Offsets::FField::Next);
                    if (!nx || nx < 0x10000ULL || nx >= 0x7FFFFFFFFFFFULL) break;
                    ffSamples.push_back(nx);
                    cur = nx; ++hops;
                }
            }
            std::unordered_map<uint64_t, int> cpScore;
            for (uint64_t ff : ffSamples) {
                for (uint64_t off = 0x00; off <= 0xC0; off += 0x08) {
                    uint64_t fc = Read<uint64_t>(ff + off);
                    if (fc < lo || fc >= hi) continue;
                    uint64_t castflags = Read<uint64_t>(fc + 0x10);
                    if (!IsCastFlagsLike(castflags)) continue;
                    cpScore[off]++;
                }
            }
            std::vector<std::pair<uint64_t,int>> ranked(cpScore.begin(), cpScore.end());
            std::sort(ranked.begin(), ranked.end(),
                      [](const auto& a, const auto& b){ return a.second > b.second; });
            std::printf("[autocal-cp] FField::ClassPrivate brute-force across %zu FField samples (top 6):\n",
                        ffSamples.size());
            for (size_t I = 0; I < std::min<size_t>(ranked.size(), 6); ++I) {
                std::printf("[autocal-cp]   off=+0x%llX hits=%d\n",
                            (unsigned long long)ranked[I].first, ranked[I].second);
            }
            if (!ranked.empty() && ranked[0].second >= 20) {
                std::printf("[autocal-cp] FField::ClassPrivate drift: 0x%llX -> 0x%llX (auto-fixed)\n",
                            (unsigned long long)ArcDecrypt::Offsets::FField::ClassPrivate,
                            (unsigned long long)ranked[0].first);
                ArcDecrypt::Offsets::FField::ClassPrivate = ranked[0].first;
            }
        }

        // ── Brute-force FField::Next offset calibration ──────────────────
        // Sample a handful of UClass objects, try every 8-aligned offset in
        // FField in 0x00..0xE8, walk the chain, count valid FField hops.
        // Whichever offset yields the longest aggregate chain across samples
        // is the real Next pointer offset on this patch.
        {
            std::vector<uint64_t> classSamples;
            // Sample objects that LOOK like UStructs: heap address, vtable in
            // module range, ChildProperties at our configured offset pointing
            // to a heap ptr. Doesn't depend on the m_vtable_to_type map being
            // populated (it may be empty or sparse at this point).
            for (const auto& [idx, ptr] : object_ptrs) {
                if (classSamples.size() >= 48) break;
                uint64_t vt = 0;
                if (!m_reader.Read(ptr, &vt, 8)) continue;
                if (vt < MODULE_BASE + 0x1000ULL ||
                    vt >= MODULE_BASE + 0xE9D0000ULL) continue;
                uint64_t head = Read<uint64_t>(ptr + ArcDecrypt::Offsets::UStruct::ChildProperties);
                if (head < 0x10000ULL || head >= 0x7FFFFFFFFFFFULL) continue;
                uint64_t headVt = 0;
                if (!m_reader.Read(head, &headVt, 8)) continue;
                if (headVt < MODULE_BASE + 0x1000ULL ||
                    headVt >= MODULE_BASE + 0xE9D0000ULL) continue;
                classSamples.push_back(ptr);
            }
            std::printf("[autocal-next] picked %zu UClass-shaped samples for FField::Next sweep\n",
                        classSamples.size());
            if (!classSamples.empty()) {
                // Get the head's vtable so we can require Next-pointed FFields
                // to share the SAME vtable family (a chain of FProperties shares
                // one vtable per concrete subclass — same vtable across the link
                // is a robust signal that the link is a real chain pointer).
                auto IsRealFField = [&](uint64_t ff) -> bool {
                    if (ff < 0x10000ULL || ff >= 0x7FFFFFFFFFFFULL) return false;
                    uint64_t vt = 0;
                    if (!m_reader.Read(ff, &vt, 8)) return false;
                    if (vt < MODULE_BASE + 0x1000ULL ||
                        vt >= MODULE_BASE + 0xE9D0000ULL) return false;
                    return true;
                };
                std::unordered_map<uint64_t, int> nextScore;
                for (uint64_t cls : classSamples) {
                    uint64_t head = Read<uint64_t>(cls + ArcDecrypt::Offsets::UStruct::ChildProperties);
                    if (!IsRealFField(head)) continue;
                    for (uint64_t nxo = 0x00; nxo <= 0x78; nxo += 0x08) {
                        uint64_t cur = head;
                        std::unordered_set<uint64_t> seen;
                        int hops = 0;
                        while (cur && hops < 256) {
                            if (!seen.insert(cur).second) break;
                            uint64_t nx = Read<uint64_t>(cur + nxo);
                            if (nx == 0) { ++hops; break; }
                            if (!IsRealFField(nx)) break;
                            ++hops; cur = nx;
                        }
                        if (hops > 1) nextScore[nxo] += hops;
                    }
                }
                if (!nextScore.empty()) {
                    std::vector<std::pair<uint64_t, int>> ranked(nextScore.begin(), nextScore.end());
                    std::sort(ranked.begin(), ranked.end(),
                              [](const auto& a, const auto& b){ return a.second > b.second; });
                    std::printf("[autocal-next] FField::Next brute-force across %zu UClass samples (top 6):\n",
                                classSamples.size());
                    for (size_t I = 0; I < std::min<size_t>(ranked.size(), 6); ++I) {
                        std::printf("[autocal-next]   next_off=+0x%llX total_hops=%d\n",
                                    (unsigned long long)ranked[I].first, ranked[I].second);
                    }
                    if (ranked[0].second >= 10) {
                        std::printf("[autocal-next] FField::Next drift: 0x%llX -> 0x%llX (auto-fixed)\n",
                                    (unsigned long long)ArcDecrypt::Offsets::FField::Next,
                                    (unsigned long long)ranked[0].first);
                        ArcDecrypt::Offsets::FField::Next = ranked[0].first;
                    }
                }
            }
        }

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
            std::string live_name = GetNameTheia(pkg_ptr);
            if (!live_name.empty() && live_name[0] == '/') {
                live_pkg_cache[pkg_ptr] = live_name;
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

        // CL-1195482: m_dynamic_type_table_loaded is false on this build (ptable
        // failed to decode), but we still want to RUN the FFieldClass.Name slot
        // calibration + seeding paths — they don't depend on the dynamic table,
        // only on m_observed_fclass_ptrs which IS populated.
        {
            if (m_dynamic_type_table_loaded) {
                CalibrateFClassTypeIdxOffset();
                size_t DynAdded = SeedDynamicFClassMap();
                std::printf("[fcmap-dyn] dynamic seeding produced %zu new FFieldClass mappings (total=%zu)\n",
                    DynAdded, m_fclass_to_type.size());
            }

            // Parallel path: probe FFieldClass NamePrivate slot directly. On
            // builds where FFieldClass has an FName at a discoverable offset
            // (verified 20260421), this resolves the type name without a
            // typeidx lookup table — works even when the typeidx calibration
            // fails (which happens when FFieldClass has no uint32 typeidx
            // field, e.g. CL-1177146).
            CalibrateFClassNameSlotOffset();
            if (m_fclass_nameslot_offset < 0) {
                m_fclass_nameslot_offset = static_cast<int32_t>(ArcDecrypt::v20260519::FFIELD_CLASS_NAME_OFF);
                std::printf("[fcname-cal] calibration below threshold — pinning FFieldClass NamePrivate offset to compile-time 0x%X\n",
                    m_fclass_nameslot_offset);
            }
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

        // ── Second pre-pass: re-walk property chains with full FFieldClass mappings.
        // The first pre-pass ran before fcname-seed, so FStructProperty/FEnumProperty
        // weren't identified. Now that fcname-seed has populated all 49 type mappings,
        // re-walk to populate m_known_structs and m_known_enums.
        {
            size_t Pre2Walked = 0;
            for (const auto& [idx, obj_ptr] : object_ptrs) {
                if (!obj_ptr) continue;
                for (int co = 0x80; co <= 0x140; co += 8) {
                    uint64_t head = Read<uint64_t>(obj_ptr + co);
                    if (head <= 0x10000 || head >= 0x800000000000ULL) continue;
                    uint64_t hvt = Read<uint64_t>(head);
                    if (hvt < MODULE_BASE || hvt >= MODULE_BASE + 0x10000000ULL) continue;
                    ReadPropertyChain(head, 512, false);
                    ++Pre2Walked;
                    break;
                }
            }
            std::printf("[sdk] Pre-pass 2 (post-fcname): walked %zu chains; m_known_structs=%zu m_known_enums=%zu\n",
                Pre2Walked, m_known_structs.size(), m_known_enums.size());
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
            if (func_obj_addrs.count(obj_ptr)) continue;
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

            // Path A: probe ALL pointer-shaped slot decryptions and check
            // against known metaclass sets. GetClassPrivate alone is
            // unstable across calls (different objects encode their class
            // in different slots; the slot picker hash is wrong on 20260428).
            // NOTE: Path V2 below may override these results based on vtable.
            auto cls_cands = m_fname.GetAllClassCandidates(obj_ptr);
            uint64_t cls = 0;
            bool is_class_by_cls = false, is_scriptstruct = false, is_enum = false;
            if (m_known_structs.count(obj_ptr)) is_scriptstruct = true;
            if (m_known_enums.count(obj_ptr))   is_enum = true;
            uint64_t enum_cls = 0, ss_cls = 0, class_cls = 0;
            for (uint64_t cc : cls_cands) {
                if (!cc) continue;
                if (!enum_cls  && enumAddrs.count(cc))       enum_cls  = cc;
                if (!ss_cls    && ssAddrs.count(cc))         ss_cls    = cc;
                if (!class_cls && validClassTypes.count(cc)) class_cls = cc;
            }
            bool RefAsClass = allTypeAddrs.count(obj_ptr) > 0;
            if (RefAsClass && class_cls) {
                is_class_by_cls = true; cls = class_cls;
            } else if (enum_cls && !RefAsClass) {
                is_enum = true; cls = enum_cls;
            } else if (ss_cls) {
                is_scriptstruct = true; cls = ss_cls;
            } else if (class_cls) {
                is_class_by_cls = true; cls = class_cls;
            } else if (enum_cls) {
                is_enum = true; cls = enum_cls;
            }
            if (!cls) cls = m_fname.GetClassPrivate(obj_ptr);  // fallback for legacy paths

            // Path V2: vtable-based classification (more reliable than ClassPrivate slots)
            // Reads the vtable pointer directly from obj_ptr+0x0, computes RVA,
            // and matches against auto-discovered engine vtable RVAs.
            // This OVERRIDES Path A because ClassPrivate slot matching is unreliable
            // on Theia (slot picker hash drifts across patches; different objects
            // encode their class in different slots, and ssAddrs is often empty).
            // ScriptStructRVA is validated by Phase 1.6 oracle cross-check.
            // EnumRVA may be wrong (was UCameraShakePattern on CL-1233465), so
            // Path C below will still validate — false positives get filtered.
            // Path V2: ONLY use vtable for UEnum (0xB462010 is unique).
            // Class/ScriptStruct/Function share vtable 0xB447980 — can't distinguish.
            // BPGC variants have unique vtables but are already handled by Path A.
            {
                static uint32_t V2EnumCount = 0;
                uint64_t obj_vt = Read<uint64_t>(obj_ptr);
                if (obj_vt >= MODULE_BASE && obj_vt < MODULE_BASE + 0x10000000ULL) {
                    uint64_t obj_vt_rva = obj_vt - MODULE_BASE;
                    const auto& Disc = AutoDiscovery::g_DiscoveredVTables;
                    if (Disc.EnumRVA && obj_vt_rva == Disc.EnumRVA) {
                        is_enum = true; is_class_by_cls = false; is_scriptstruct = false;
                        V2EnumCount++;
                    }
                }
            }

            // Path C: structural heuristic for enums/structs.
            bool is_type_by_ref_early = allTypeAddrs.count(obj_ptr) > 0;
            if (!is_enum && !is_scriptstruct && !m_known_structs.count(obj_ptr)) {
                uint64_t names_ptr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names);
                uint32_t names_cnt = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 8);
                uint32_t names_max = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 12);
                bool is_cdo = short_name.rfind("Default__", 0) == 0;
                if (!is_cdo &&
                    names_ptr > 0x10000 && names_ptr < 0x7FFFFFFFFFFFULL &&
                    names_cnt > 0 && names_cnt < 256 &&
                    names_max >= names_cnt && names_max < 256) {
                    bool plausible = true;
                    uint32_t probe_n = names_cnt < 16 ? names_cnt : 16;
                    for (uint32_t j = 0; j < probe_n; ++j) {
                        uint64_t ep   = names_ptr + (uint64_t)j * 16;
                        int32_t  ci   = Read<int32_t>(ep + 0);
                        uint32_t num  = Read<uint32_t>(ep + 4);
                        int64_t  val  = Read<int64_t>(ep + 8);
                        if (!(ci > 0 && (uint32_t)ci < 0x1FFFFFFFu) ||
                            num >= 0x100 ||
                            !(val > -0x10000 && val < 0x10000)) {
                            plausible = false;
                            break;
                        }
                    }
                    if (plausible && names_cnt == 1 &&
                        Read<int64_t>(names_ptr + 8) != 0) {
                        plausible = false;
                    }
                    if (plausible) {
                        is_enum = true;
                        is_class_by_cls = false;
                        is_scriptstruct = false;
                    }
                }
            }
            bool is_type_by_ref = is_type_by_ref_early;

            // Skip objects that aren't types by either path
            if (!is_class_by_cls && !is_scriptstruct && !is_enum && !is_type_by_ref) continue;

            // Classify: if detected by reference but not by Class decrypt,
            // it's likely a UClass (most allTypeAddrs entries are UClass objects)
            bool is_class = is_class_by_cls || (is_type_by_ref && !is_scriptstruct && !is_enum);

            std::string pkg = resolvePackage(obj_ptr);

            // ─── UEnum ────────────────────────────────────────────────────────
            if (is_enum) {
                uint64_t names_ptr = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names);
                uint32_t names_cnt = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 8);
                uint32_t names_max = Read<uint32_t>(obj_ptr + ArcDecrypt::Offsets::UEnum::Names + 12);

                // Even objects classified as enum by Path A (class candidate
                // matches enumAddrs) can be misclassified — GetAllClassCandidates
                // probes 4 slots and one may collide with an enum metaclass for
                // unrelated objects (e.g. /Script/Angelscript.AnimNotifyState_*).
                // Apply the same shape gate as Path C: validate entries' value
                // ranges and reject single-entry pseudo-enums with non-zero vals.
                bool shape_ok = false;
                if (names_ptr > 0x10000 && names_ptr < 0x7FFFFFFFFFFFULL &&
                    names_cnt > 0 && names_cnt < 256 &&
                    names_max >= names_cnt && names_max < 256) {
                    shape_ok = true;
                    uint32_t probe_n = names_cnt < 16 ? names_cnt : 16;
                    uint32_t resolved = 0;
                    for (uint32_t j = 0; j < probe_n; ++j) {
                        uint64_t ep   = names_ptr + (uint64_t)j * 16;
                        int32_t  ci   = Read<int32_t>(ep + 0);
                        uint32_t num  = Read<uint32_t>(ep + 4);
                        int64_t  val  = Read<int64_t>(ep + 8);
                        if (!(ci > 0 && (uint32_t)ci < 0x1FFFFFFFu) ||
                            num >= 0x100 ||
                            !(val > -0x10000 && val < 0x10000)) {
                            shape_ok = false;
                            break;
                        }
                        // Real enum entries' CIs all resolve via the name pool.
                        // Misclassified data assets (UClass +0xB0 = SuperStruct
                        // ptr; AnimNotifyState_SetGameplayTags has 5 slots with
                        // only one valid CI) typically have most entries fail.
                        std::string ev = m_fname.CompIndexToNameLenient(ci);
                        if (!ev.empty() && ev.find('?') == std::string::npos) {
                            ++resolved;
                        }
                    }
                    if (shape_ok) {
                        // Require ALL probed entries to resolve via the FName
                        // pool. Real enums hit 100% (CL-1177146 FName lookup is
                        // reliable); pseudo-enums (UClass/UAngelscriptClass +0xB0
                        // = SuperStruct ptr; CDA76AC0 had cnt=2 with one slot
                        // resolving "Camera.State" and another with garbage CI)
                        // fail. The 50% threshold tried earlier let CDA76AC0
                        // through because need=(2+1)/2=1 was satisfied by the
                        // single chance hit.
                        if (resolved < probe_n) shape_ok = false;
                    }
                    // Reject single-entry "enums" — real enums almost always
                    // have ≥ 2 entries (Type::None / EXyz_MAX pair etc.).
                    // 1-entry pseudo-enums are nearly all misclassifications
                    // (UClass +0xB0 = SuperStruct ptr happens to point at a
                    // heap region with one resolvable FName slot by chance).
                    if (shape_ok && names_cnt < 2) {
                        shape_ok = false;
                    }
                }
                // vtable-confirmed enums pass even without valid Names (Theia strips them)
                bool VtConfirmedEnum = false;
                {
                    uint64_t Vt = Read<uint64_t>(obj_ptr);
                    if (Vt >= MODULE_BASE) {
                        uint64_t VtRva = Vt - MODULE_BASE;
                        const auto& Disc = AutoDiscovery::g_DiscoveredVTables;
                        if (Disc.EnumRVA && VtRva == Disc.EnumRVA) VtConfirmedEnum = true;
                    }
                }
                if (!shape_ok && !VtConfirmedEnum) continue;

                EnumRecord erec{};
                erec.addr    = obj_ptr;
                erec.name    = short_name;
                erec.package = pkg;

                if (shape_ok) {
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
            // Live-probed offsets where FField chain heads land on CL-1177146.
            // Beyond the documented +0x100/+0xB8/+0x118/+0x190 set, native UClass
            // also stores heap-shaped FField pointers at +0xC8/+0xD8/+0x108/+0x138
            // (verified by reading 512 bytes at /Script/Engine.Pawn — +0x100 was
            // empty, but +0xB8/+0xC8/+0xD8/+0x108/+0x138 all held FField heads).
            // walk_chain validates each via ReadPropertyChain's ghost-FField guard,
            // so bogus offsets walk an empty chain harmlessly. ff_addr dedup
            // collapses identical fields walked via multiple heads.
            // CL-1177678: ChildProperties (FField head) moved to +0xB0
            // (verified live: Actor@0x2A5A9700+0xB0 = 0xBEECD000 → FField with
            // Owner=Actor|1, Pawn@0x75B71600+0xB0 = 0xC1165B00 → FField with
            // Owner=Pawn|1, ARFilter@0x8B9F4DE0+0xB0 = 0xA1B36600 → FField).
            // +0xB8 stays for UScriptStruct alt-heads / CL-1177146 fallback.
            // Other offsets retained as broad-scan fallbacks; the tightened
            // ghost-FField guard (NamePrivate at +0x30 must be non-zero)
            // rejects UField/UFunction lists that get caught at +0xB8 on
            // native UClass.
            // CL-1195482: exhaustive sweep — try every 8-byte-aligned offset
            // from 0x60 to 0x200. walk_chain validates each candidate via the
            // Ghost-FField guard (module-range vtable + non-zero NamePrivate
            // slot at +0x50/+0x30), so bogus offsets fail fast and only real
            // FField chain heads contribute properties.
            static constexpr uint64_t kChainOffs[] = {
                0xB0, 0xB8, 0xC8, 0xD0, 0xE8, 0xF0, 0xF8,
                0x100, 0x108, 0x110, 0x118, 0x120,
            };
            // +0xC0 is a UScriptStruct-only FField chain head on newer patches
            // (full chain, vs +0xB0's subset). On UClass it overlaps with
            // UField/UFunction list pointers and pollutes UFunction detection
            // downstream (pass-3 vt-dtor rejections explode). Gate it.
            static constexpr uint64_t kScriptStructOnlyChainOffs[] = { 0xC0 };
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
            // Walk ALL chain heads (was: first-non-empty-wins). Native UClass
            // has own properties at +0x100; BPGCs and engine-generated classes
            // store own+inherited at +0xB8 (PropertyLink); +0x118 (RefLink) and
            // +0x190 (DestructorLink) are alternative chain heads. ff_addr dedup
            // keeps duplicates out — each unique FField contributes once. The
            // previous "first wins" gate left native UClass walks blind to
            // PropertyLink, which carries inherited fields the reference SDK
            // counts per-class.
            for (uint64_t off : kChainOffs) {
                uint64_t head = Read<uint64_t>(obj_ptr + off);
                walk_chain(head);
            }
            if (is_scriptstruct && !is_class) {
                for (uint64_t off : kScriptStructOnlyChainOffs) {
                    uint64_t head = Read<uint64_t>(obj_ptr + off);
                    walk_chain(head);
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

        std::printf("[sdk] After main loop: m_known_structs=%zu m_known_enums=%zu\n",
            m_known_structs.size(), m_known_enums.size());
        PrintResolveStats();
        DiagnoseShadowResolution();

        {
            std::unordered_set<uint64_t> ConfirmedUScriptStruct;

            for (uint64_t Sp : m_known_structs)
                ConfirmedUScriptStruct.insert(Sp);

            for (const auto& Rec : result.structs) {
                if (!Rec.is_class) continue;
                if (ConfirmedUScriptStruct.count(Rec.addr)) continue;

                uint64_t PairsData = Read<uint64_t>(Rec.addr + ArcDecrypt::Offsets::UClass::FuncMap_PairsData);
                uint32_t FmNum     = Read<uint32_t>(Rec.addr + ArcDecrypt::Offsets::UClass::FuncMap_Num);
                uint32_t FmMax     = Read<uint32_t>(Rec.addr + ArcDecrypt::Offsets::UClass::FuncMap_Max);

                bool LooksLikeEmptyTMap = (PairsData == 0 && FmNum == 0 && FmMax == 0);
                bool LooksLikeValidTMap = (PairsData > 0x10000 && PairsData < 0x7FFFFFFFFFFFULL &&
                                           FmNum <= 4096 && FmMax >= FmNum && FmMax <= 16384);
                bool HasFuncMapShape = LooksLikeEmptyTMap || LooksLikeValidTMap;

                if (!HasFuncMapShape) {
                    ConfirmedUScriptStruct.insert(Rec.addr);
                }
            }

            std::unordered_map<uint64_t, std::vector<uint64_t>> ChildMap;
            for (const auto& Rec : result.structs) {
                if (Rec.super_addr)
                    ChildMap[Rec.super_addr].push_back(Rec.addr);
            }

            std::function<void(uint64_t)> PropagateDown = [&](uint64_t Addr) {
                auto Cit = ChildMap.find(Addr);
                if (Cit == ChildMap.end()) return;
                for (uint64_t Child : Cit->second) {
                    if (ConfirmedUScriptStruct.insert(Child).second)
                        PropagateDown(Child);
                }
            };
            for (uint64_t Ss : std::vector<uint64_t>(ConfirmedUScriptStruct.begin(), ConfirmedUScriptStruct.end()))
                PropagateDown(Ss);

            size_t Reclassified = 0;
            for (auto& Rec : result.structs) {
                if (!Rec.is_class) continue;
                if (!ConfirmedUScriptStruct.count(Rec.addr)) continue;
                Rec.is_class = false;
                ++Reclassified;
            }

            size_t FinalClasses = 0, FinalStructs = 0;
            for (const auto& Rec : result.structs) {
                if (Rec.is_class) ++FinalClasses;
                else ++FinalStructs;
            }
            std::printf("[sdk] Struct/Class reclassification: confirmed_ss=%zu reclassified=%zu "
                "(final: %zu classes, %zu structs)\n",
                ConfirmedUScriptStruct.size(), Reclassified, FinalClasses, FinalStructs);
        }

        // ── Pass 3: emit "extra" structs/enums discovered via property walks
        // that are NOT in our 70K object set (engine UScriptStructs / UEnums
        // that live in chunks the structural scan doesn't reach). For each,
        // resolve name live and emit a minimal record.
        size_t extra_structs_added = 0, extra_enums_added = 0;
        size_t diag_s_seen = 0, diag_s_range = 0, diag_s_noname = 0, diag_s_slash = 0;
        for (uint64_t sp : m_known_structs) {
            if (seen.count(sp)) { ++diag_s_seen; continue; }
            if (sp <= 0x10000 || sp >= 0x800000000000ULL) { ++diag_s_range; continue; }
            seen.insert(sp);
            std::string name = m_fname.GetName(sp);
            if (name.empty()) {
                int32_t Ci = m_fname.DecryptFFieldNameCI(sp);
                if (Ci > 1) name = m_fname.CompIndexToNameLenient(Ci);
            }
            if (name.empty()) {
                int32_t Ci = m_fname.DecryptFFieldNameCI(sp - 8);
                if (Ci > 1) name = m_fname.CompIndexToNameLenient(Ci);
            }
            if (name.empty()) { ++diag_s_noname; continue; }
            if (name[0] == '/') { ++diag_s_slash; continue; }
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
        size_t EnumSkippedShadow = 0;
        for (uint64_t ep : m_known_enums_hi) {
            if (seen.count(ep)) continue;
            if (ep <= 0x10000 || ep >= 0x800000000000ULL) continue;
            if (m_known_structs.count(ep)) continue;
            uint64_t Vt = Read<uint64_t>(ep);
            uint64_t VtRva = (Vt >= MODULE_BASE) ? (Vt - MODULE_BASE) : 0;
            bool IsShadowVt = (VtRva >= 0xB400000 && VtRva < 0xB500000);
            if (!IsShadowVt) {
                uint8_t SlotCheck[8];
                m_reader.Read(ep + 0x08, SlotCheck, 8);
                bool AllZero = true;
                for (int i = 0; i < 8; ++i) if (SlotCheck[i]) { AllZero = false; break; }
                if (AllZero) IsShadowVt = true;
            }
            if (IsShadowVt) { ++EnumSkippedShadow; continue; }
            seen.insert(ep);
            std::string name = m_fname.GetName(ep);
            if (name.empty()) {
                int32_t Ci = m_fname.DecryptFFieldNameCI(ep);
                if (Ci > 1) name = m_fname.CompIndexToNameLenient(Ci);
            }
            if (name.empty()) {
                int32_t Ci = m_fname.DecryptFFieldNameCI(ep - 8);
                if (Ci > 1) name = m_fname.CompIndexToNameLenient(Ci);
            }
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
        std::printf("[sdk] struct extras skip: seen=%zu range=%zu noname=%zu slash=%zu\n",
            diag_s_seen, diag_s_range, diag_s_noname, diag_s_slash);
        std::printf("[sdk] Pass-3 emit extras: +%zu structs, +%zu enums (shadow-skipped=%zu)\n",
            extra_structs_added, extra_enums_added, EnumSkippedShadow);

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

    // ─────────────────────────────────────────────────────────────────────────
    // Dumper-7 style per-package SDK emit
    // ─────────────────────────────────────────────────────────────────────────
    // Opt-in. When true, EmitDumper7() writes a directory tree similar to the
    // Dumper-7 layout that downstream menus / internal cheats / ESP expect:
    //     <base>/SDK.hpp
    //     <base>/SDK/Basic.hpp
    //     <base>/SDK/<Package>_classes.hpp
    //     <base>/SDK/<Package>_structs.hpp
    //     <base>/SDK/<Package>_enums.hpp
    //     <base>/SDK/<Package>_functions.hpp     (stubs only — no native call wiring)
    // SDK_Output.txt flat dump is still emitted regardless.
    static constexpr bool kEmitDumper7 = true;

    // ── Extract last segment of a UE5 path like "/Script/Engine" → "Engine"
    static std::string D7_ShortPackage(const std::string& pkg) {
        if (pkg.empty()) return "Unknown";
        size_t slash = pkg.find_last_of('/');
        std::string s = (slash == std::string::npos) ? pkg : pkg.substr(slash + 1);
        if (s.empty()) s = "Unknown";
        // Sanitize: replace any non-identifier char with '_'
        for (char& c : s) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                c = '_';
        }
        if (s[0] >= '0' && s[0] <= '9') s = "_" + s;
        return s;
    }

    // ── Sanitize an arbitrary identifier (field / class / enum) for C++ output
    static std::string D7_SanIdent(const std::string& name) {
        if (name.empty()) return "_unnamed";
        std::string s = name;
        for (char& c : s) {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_'))
                c = '_';
        }
        if (s[0] >= '0' && s[0] <= '9') s = "_" + s;
        return s;
    }

    // ── Map an FProperty type-name string to a Dumper-7 style C++ type token.
    // PropertyRecord only carries the FProperty subclass name (e.g.
    // "FArrayProperty") and not the resolved inner type, so containers fall
    // back to opaque inner ("uint8_t" / "void*"). Downstream consumers that
    // need full inner types can post-process via refSDK overlay.
    static std::string D7_PropertyType(const PropertyRecord& pr) {
        const std::string& t = pr.type_name;
        if (t == "FBoolProperty")               return pr.bool_field_size == 4 ? "bool" : "uint8_t";
        if (t == "FByteProperty")               return "uint8_t";
        if (t == "FInt8Property")               return "int8_t";
        if (t == "FInt16Property")              return "int16_t";
        if (t == "FIntProperty")                return "int32_t";
        if (t == "FInt64Property")              return "int64_t";
        if (t == "FUInt16Property")             return "uint16_t";
        if (t == "FUInt32Property")             return "uint32_t";
        if (t == "FUInt64Property")             return "uint64_t";
        if (t == "FFloatProperty")              return "float";
        if (t == "FDoubleProperty")             return "double";
        if (t == "FNameProperty")               return "FName";
        if (t == "FStrProperty")                return "FString";
        if (t == "FTextProperty")               return "FText";
        if (t == "FEnumProperty")               return "uint8_t";
        if (t == "FStructProperty")             return "FStructOpaque";
        if (t == "FObjectProperty")             return "class UObject*";
        if (t == "FObjectPropertyBase")         return "class UObject*";
        if (t == "FClassProperty")              return "class UClass*";
        if (t == "FClassPtrProperty")           return "class UClass*";
        if (t == "FWeakObjectProperty")         return "TWeakObjectPtr<class UObject>";
        if (t == "FLazyObjectProperty")         return "TLazyObjectPtr<class UObject>";
        if (t == "FSoftObjectProperty")         return "TSoftObjectPtr<class UObject>";
        if (t == "FSoftClassProperty")          return "TSoftClassPtr<class UObject>";
        if (t == "FInterfaceProperty")          return "TScriptInterface<class IInterface>";
        if (t == "FArrayProperty")              return "TArray<uint8_t>";
        if (t == "FSetProperty")                return "TSet<uint8_t>";
        if (t == "FMapProperty")                return "TMap<uint8_t, uint8_t>";
        if (t == "FOptionalProperty")           return "TOptional<uint8_t>";
        if (t == "FFieldPathProperty")          return "TFieldPath<void>";
        if (t == "FDelegateProperty")           return "FScriptDelegate";
        if (t == "FMulticastDelegateProperty")  return "FMulticastScriptDelegate";
        if (t == "FMulticastInlineDelegateProperty") return "FMulticastScriptDelegate";
        if (t == "FMulticastSparseDelegateProperty") return "FSparseDelegate";
        return "uint8_t";
    }

    // ── Type byte size, used to fill the holes between offsets.
    static uint32_t D7_PropertyTypeSize(const PropertyRecord& pr) {
        if (pr.elem_size > 0) return pr.elem_size;
        const std::string& t = pr.type_name;
        if (t == "FBoolProperty" || t == "FByteProperty" || t == "FInt8Property") return 1;
        if (t == "FInt16Property" || t == "FUInt16Property") return 2;
        if (t == "FIntProperty"  || t == "FUInt32Property" || t == "FFloatProperty" ||
            t == "FEnumProperty") return 4;
        if (t == "FInt64Property" || t == "FUInt64Property" || t == "FDoubleProperty" ||
            t == "FObjectProperty" || t == "FObjectPropertyBase" || t == "FClassProperty" ||
            t == "FClassPtrProperty")
            return 8;
        if (t == "FNameProperty") return 8;
        if (t == "FStrProperty" || t == "FTextProperty") return 16;
        if (t == "FArrayProperty" || t == "FSetProperty") return 16;
        if (t == "FMapProperty") return 80;
        if (t == "FStructProperty") return 0;
        return 0;
    }

    // ── Convert a parameter property type to a Dumper-7 style parameter token.
    static std::string D7_ParamType(const PropertyRecord& pr) {
        return D7_PropertyType(pr);
    }

    static void D7_Mkdir(const std::string& path) {
#ifdef _WIN32
        ::_mkdir(path.c_str());
#else
        ::mkdir(path.c_str(), 0755);
#endif
    }

    // ── Emit a Dumper-7 style SDK tree under <base_dir>/.
    // Creates <base_dir>/SDK/ and a master <base_dir>/SDK.hpp.
    void EmitDumper7(const SDKResult& sdk, const std::string& base_dir) {
        if (!kEmitDumper7) return;

        D7_Mkdir(base_dir);
        std::string sdk_dir = base_dir + "/SDK";
        D7_Mkdir(sdk_dir);
        // Per-package subdirectory layout requested by downstream consumers:
        //   SDK/<Package>/<Package>_classes.hpp etc.
        // The per-package directory is created lazily before each file write.

        // Bucket records by short package name. Use std::map for stable
        // alphabetical order of generated includes.
        std::map<std::string, std::vector<const StructRecord*>> pkg_classes;
        std::map<std::string, std::vector<const StructRecord*>> pkg_structs;
        std::map<std::string, std::vector<const EnumRecord*>>   pkg_enums;
        for (const auto& s : sdk.structs) {
            std::string p = D7_ShortPackage(s.package);
            if (s.is_class) pkg_classes[p].push_back(&s);
            else            pkg_structs[p].push_back(&s);
        }
        for (const auto& e : sdk.enums)
            pkg_enums[D7_ShortPackage(e.package)].push_back(&e);

        // Build name → short-package map so DumpStruct's #include chain can
        // forward-declare super classes living in another package.
        std::unordered_map<std::string, std::string> name_to_pkg;
        for (const auto& s : sdk.structs)
            name_to_pkg[s.name] = D7_ShortPackage(s.package);

        // ── 1. Basic.hpp — alias the UE primitives Dumper-7 expects ───────
        {
            std::ofstream f(sdk_dir + "/Basic.hpp");
            f << "#pragma once\n\n";
            f << "// FrostDumper — Basic.hpp (Dumper-7 style aliases)\n";
            f << "// Generated alongside SDK_Output.txt — opaque shells only,\n";
            f << "// downstream consumers must define real layouts as needed.\n\n";
            f << "#include <cstdint>\n#include <cstddef>\n\n";
            f << "#ifdef _MSC_VER\n#pragma pack(push, 0x8)\n#endif\n\n";
            f << "namespace SDK\n{\n\n";
            f << "struct FName        { uint8_t Pad[0x8]; };\n";
            f << "struct FString      { uint8_t Pad[0x10]; };\n";
            f << "struct FText        { uint8_t Pad[0x18]; };\n";
            f << "struct FScriptDelegate          { uint8_t Pad[0x14]; };\n";
            f << "struct FMulticastScriptDelegate { uint8_t Pad[0x10]; };\n";
            f << "struct FSparseDelegate          { uint8_t Pad[0x1]; };\n";
            f << "struct FStructOpaque            { uint8_t Pad[0x1]; };\n";
            f << "\ntemplate<typename T> struct TArray              { T* Data; int32_t Count; int32_t Max; };\n";
            f << "template<typename T> struct TSet                { uint8_t Pad[0x50]; };\n";
            f << "template<typename K, typename V> struct TMap    { uint8_t Pad[0x50]; };\n";
            f << "template<typename T> struct TOptional           { uint8_t Pad[0x10]; };\n";
            f << "template<typename T> struct TWeakObjectPtr      { int32_t Index; int32_t Serial; };\n";
            f << "template<typename T> struct TLazyObjectPtr      { uint8_t Pad[0x1C]; };\n";
            f << "template<typename T> struct TSoftObjectPtr      { uint8_t Pad[0x28]; };\n";
            f << "template<typename T> struct TSoftClassPtr       { uint8_t Pad[0x28]; };\n";
            f << "template<typename T> struct TSubclassOf         { class UClass* Class; };\n";
            f << "template<typename T> struct TScriptInterface    { class UObject* Object; void* Interface; };\n";
            f << "template<typename T> struct TFieldPath          { uint8_t Pad[0x20]; };\n";
            f << "\n";
            f << "class UObject;\n";
            f << "class UClass;\n";
            f << "class IInterface { };\n";
            f << "\n} // namespace SDK\n\n";
            f << "#ifdef _MSC_VER\n#pragma pack(pop)\n#endif\n";
        }

        // ── 2. Per-package files ──────────────────────────────────────────
        auto write_header = [](std::ofstream& f, const std::string& pkg, const std::string& kind) {
            f << "#pragma once\n\n";
            f << "// FrostDumper — " << pkg << "_" << kind << ".hpp\n";
            f << "// Auto-generated. Do not edit.\n\n";
            f << "#ifdef _MSC_VER\n#pragma pack(push, 0x8)\n#endif\n\n";
            f << "namespace SDK\n{\n\n";
        };
        auto write_footer = [](std::ofstream& f) {
            f << "\n} // namespace SDK\n\n";
            f << "#ifdef _MSC_VER\n#pragma pack(pop)\n#endif\n";
        };

        // Emit one StructRecord (class or struct) in Dumper-7 form.
        auto emit_record = [&](std::ofstream& f, const StructRecord& rec) {
            std::string clean_name = D7_SanIdent(rec.name);
            // Prefix with U/A/F? The dumper already strips prefixes (see
            // reference_sdk_naming memory), so we emit the bare name and let
            // downstream consumers re-prefix if needed. Inheritance uses the
            // bare super name too.
            f << "// 0x" << std::hex << rec.props_size
              << " (0x" << rec.props_size << " - 0x0)\n";
            f << "// " << (rec.is_class ? "Class " : "ScriptStruct ")
              << (rec.package.empty() ? "" : (rec.package[0] == '/' ? rec.package : "/Script/" + rec.package))
              << "." << rec.name << "\n";
            if (rec.is_class)
                f << "class " << clean_name;
            else
                f << "struct " << clean_name;
            if (!rec.super_name.empty())
                f << " : public " << D7_SanIdent(rec.super_name);
            f << "\n{\npublic:\n";

            // Sort properties by offset so the layout reads top-down. Bool
            // bitfields collapse into a single uint8_t per byte mask group;
            // we emit each entry verbatim with a comment indicating the mask.
            std::vector<const PropertyRecord*> sorted_props;
            sorted_props.reserve(rec.properties.size());
            for (const auto& p : rec.properties) sorted_props.push_back(&p);
            std::sort(sorted_props.begin(), sorted_props.end(),
                [](const PropertyRecord* a, const PropertyRecord* b) {
                    if (a->offset != b->offset) return a->offset < b->offset;
                    return a->name < b->name;
                });

            // Dedupe by (offset, name) — chain walks can pull the same field
            // through multiple PropertyLink heads.
            std::unordered_set<uint64_t> seen_key;
            for (const auto* p : sorted_props) {
                uint64_t key = (uint64_t)p->offset << 32;
                for (char c : p->name) key = key * 131 + (uint8_t)c;
                if (!seen_key.insert(key).second) continue;
                std::string ty = D7_PropertyType(*p);
                std::string nm = D7_SanIdent(p->name);
                uint32_t sz = D7_PropertyTypeSize(*p);
                if (p->array_dim > 1) {
                    f << "    " << ty << " " << nm << "[0x" << std::hex << p->array_dim << "];";
                } else {
                    f << "    " << ty << " " << nm << ";";
                }
                f << " // 0x" << std::hex << p->offset
                  << "(0x" << sz << ")";
                if (p->is_bool && p->bool_byte_mask)
                    f << " mask=0x" << std::hex << (unsigned)p->bool_byte_mask;
                f << " (" << p->type_name << ")\n";
            }

            // Functions — emit as stubs (no native-call wiring; downstream
            // consumers must hook ProcessEvent themselves).
            if (!rec.functions.empty()) {
                f << "\npublic:\n";
                std::unordered_set<std::string> seen_fn;
                for (const auto& fn : rec.functions) {
                    std::string ret = "void";
                    std::vector<const PropertyRecord*> ins;
                    for (const auto& par : fn.params) {
                        if (par.name == "ReturnValue") ret = D7_ParamType(par);
                        else ins.push_back(&par);
                    }
                    std::string fname = D7_SanIdent(fn.name);
                    // Disambiguate overloads — Dumper-7 normally uses
                    // suffixed names; we postfix with a counter when needed.
                    std::string base = fname;
                    int dup = 0;
                    while (!seen_fn.insert(fname).second)
                        fname = base + "_" + std::to_string(++dup);
                    f << "    " << ret << " " << fname << "(";
                    bool first = true;
                    for (const auto* par : ins) {
                        if (!first) f << ", ";
                        first = false;
                        f << D7_ParamType(*par) << " " << D7_SanIdent(par->name);
                        if (par->array_dim > 1) f << "[0x" << std::hex << par->array_dim << "]";
                    }
                    f << ");"
                      << " // 0x" << std::hex << fn.fn_addr
                      << " flags=0x" << fn.flags << "\n";
                }
            }
            f << "};\n\n";
        };

        // Emit one EnumRecord in Dumper-7 form.
        auto emit_enum = [&](std::ofstream& f, const EnumRecord& rec) {
            std::string clean = D7_SanIdent(rec.name);
            f << "// " << (rec.package.empty() ? "" : (rec.package[0] == '/' ? rec.package : "/Script/" + rec.package))
              << "." << rec.name << "\n";
            f << "enum class " << clean << " : uint8_t\n{\n";
            std::unordered_set<std::string> seen_e;
            for (const auto& ent : rec.entries) {
                std::string nm = D7_SanIdent(ent.name);
                // Strip Enum:: scope if present (UE often serializes as Foo::Bar)
                size_t cc = nm.find("__");
                if (cc != std::string::npos) nm = nm.substr(cc + 2);
                std::string base = nm;
                int dup = 0;
                while (!seen_e.insert(nm).second)
                    nm = base + "_" + std::to_string(++dup);
                f << "    " << nm << " = " << std::dec << ent.value << ",\n";
            }
            f << "};\n\n";
        };

        // Build a topologically sorted package list per kind. For simplicity
        // we use alphabetical order — Dumper-7's strict dep-graph requires
        // the parser to resolve inherits-from cross-package, which we
        // approximate by emitting all classes after all structs after all
        // enums in master SDK.hpp.
        std::vector<std::string> all_pkgs;
        {
            std::unordered_set<std::string> seen_pkg;
            auto add = [&](const std::string& p) {
                if (seen_pkg.insert(p).second) all_pkgs.push_back(p);
            };
            for (auto& kv : pkg_enums)   add(kv.first);
            for (auto& kv : pkg_structs) add(kv.first);
            for (auto& kv : pkg_classes) add(kv.first);
            std::sort(all_pkgs.begin(), all_pkgs.end());
        }

        size_t f_enums = 0, f_structs = 0, f_classes = 0, f_funcs = 0;
        for (const auto& pkg : all_pkgs) {
            std::string pkg_dir = sdk_dir + "/" + pkg;
            D7_Mkdir(pkg_dir);
            // Enums
            auto eit = pkg_enums.find(pkg);
            if (eit != pkg_enums.end() && !eit->second.empty()) {
                std::ofstream f(pkg_dir + "/" + pkg + "_enums.hpp");
                write_header(f, pkg, "enums");
                for (const auto* e : eit->second) emit_enum(f, *e);
                write_footer(f);
                ++f_enums;
            }
            // Structs
            auto sit = pkg_structs.find(pkg);
            if (sit != pkg_structs.end() && !sit->second.empty()) {
                std::ofstream f(pkg_dir + "/" + pkg + "_structs.hpp");
                write_header(f, pkg, "structs");
                for (const auto* s : sit->second) emit_record(f, *s);
                write_footer(f);
                ++f_structs;
            }
            // Classes
            auto cit = pkg_classes.find(pkg);
            if (cit != pkg_classes.end() && !cit->second.empty()) {
                std::ofstream f(pkg_dir + "/" + pkg + "_classes.hpp");
                write_header(f, pkg, "classes");
                for (const auto* c : cit->second) emit_record(f, *c);
                write_footer(f);
                ++f_classes;
            }
            // Functions — emit a small per-package stub file listing every
            // UFunction discovered for this package, so consumers can grep
            // RVAs out without parsing the class bodies.
            bool has_funcs = false;
            if (cit != pkg_classes.end())
                for (const auto* c : cit->second) if (!c->functions.empty()) { has_funcs = true; break; }
            if (!has_funcs && sit != pkg_structs.end())
                for (const auto* s : sit->second) if (!s->functions.empty()) { has_funcs = true; break; }
            if (has_funcs) {
                std::ofstream f(pkg_dir + "/" + pkg + "_functions.hpp");
                write_header(f, pkg, "functions");
                auto emit_fn_table = [&](const StructRecord& rec) {
                    if (rec.functions.empty()) return;
                    f << "// " << rec.name << " — " << rec.functions.size() << " functions\n";
                    for (const auto& fn : rec.functions) {
                        f << "//   0x" << std::hex << fn.fn_addr
                          << "  flags=0x" << fn.flags
                          << "  " << rec.name << "::" << fn.name
                          << "  params=" << std::dec << fn.params.size() << "\n";
                    }
                };
                if (cit != pkg_classes.end())
                    for (const auto* c : cit->second) emit_fn_table(*c);
                if (sit != pkg_structs.end())
                    for (const auto* s : sit->second) emit_fn_table(*s);
                write_footer(f);
                ++f_funcs;
            }
        }

        // ── 3. Master SDK.hpp ─────────────────────────────────────────────
        {
            std::ofstream m(base_dir + "/SDK.hpp");
            m << "#pragma once\n\n";
            m << "// FrostDumper — master SDK.hpp\n";
            m << "// Packages: " << std::dec << all_pkgs.size() << "\n\n";
            m << "#include \"SDK/Basic.hpp\"\n\n";
            m << "// Enums (no cross-package deps)\n";
            for (const auto& pkg : all_pkgs)
                if (pkg_enums.count(pkg))   m << "#include \"SDK/" << pkg << "/" << pkg << "_enums.hpp\"\n";
            m << "\n// Structs (may depend on enums)\n";
            for (const auto& pkg : all_pkgs)
                if (pkg_structs.count(pkg)) m << "#include \"SDK/" << pkg << "/" << pkg << "_structs.hpp\"\n";
            m << "\n// Classes (may depend on structs + enums)\n";
            for (const auto& pkg : all_pkgs)
                if (pkg_classes.count(pkg)) m << "#include \"SDK/" << pkg << "/" << pkg << "_classes.hpp\"\n";
            m << "\n// Function stub tables (optional)\n";
            for (const auto& pkg : all_pkgs) {
                bool has = false;
                auto cit = pkg_classes.find(pkg);
                auto sit = pkg_structs.find(pkg);
                if (cit != pkg_classes.end())
                    for (const auto* c : cit->second) if (!c->functions.empty()) { has = true; break; }
                if (!has && sit != pkg_structs.end())
                    for (const auto* s : sit->second) if (!s->functions.empty()) { has = true; break; }
                if (has) m << "// #include \"SDK/" << pkg << "/" << pkg << "_functions.hpp\"\n";
            }
        }

        std::printf("[dumper7] Wrote SDK tree to %s/SDK/  (packages=%zu enums=%zu structs=%zu classes=%zu fnstubs=%zu)\n",
            base_dir.c_str(), all_pkgs.size(), f_enums, f_structs, f_classes, f_funcs);
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
