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
    std::unordered_map<uint64_t, std::string> m_vtable_to_type;

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

        // Fallback: use ElementSize — only for unambiguous sizes
        uint32_t elem_size = 0;
        m_reader.Read(ff_addr + ArcDecrypt::Offsets::FProperty::ElementSize, &elem_size, 4);
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

                if (m_vtable_to_type.count(vtbl_rva)) {
                    ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
                    continue;
                }

                // Tier 1: name-based identification
                std::string pname = m_fname.GetFFieldName(ff);
                if (!pname.empty()) {
                    auto kit = known.find(pname);
                    if (kit != known.end()) {
                        m_vtable_to_type[vtbl_rva] = "F" + kit->second;
                        uint64_t fc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                        if (fc) m_fclass_name_cache[fc] = kit->second;
                        ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
                        continue;
                    }
                }

                // Record for Tier 2/3
                uint64_t fc = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                uint32_t elem = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);
                if (!unresolved_vtbls.count(vtbl_rva))
                    unresolved_vtbls[vtbl_rva] = {fc, elem};

                ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
            }
        }

        size_t tier1_count = m_vtable_to_type.size();
        std::printf("[vtbl] Tier 1 (name-based): scanned %d types, resolved %zu vtables\n",
            scanned, tier1_count);

        // ── Tier 2: FFieldClass name resolution ─────────────────────────
        size_t tier2_resolved = 0;
        for (auto it = unresolved_vtbls.begin(); it != unresolved_vtbls.end(); ) {
            uint64_t rva = it->first;
            uint64_t fc  = it->second.fclass;
            if (m_vtable_to_type.count(rva)) { it = unresolved_vtbls.erase(it); continue; }

            if (fc) {
                auto fc_it = m_fclass_name_cache.find(fc);
                if (fc_it != m_fclass_name_cache.end()) {
                    m_vtable_to_type[rva] = "F" + fc_it->second;
                    ++tier2_resolved;
                    it = unresolved_vtbls.erase(it);
                    continue;
                }
                // Live decrypt (now with plain FName fallback in fname_decrypt.h)
                std::string fcn = m_fname.GetFFieldClassName(fc);
                if (!fcn.empty()) {
                    m_fclass_name_cache[fc] = fcn;
                    m_vtable_to_type[rva] = "F" + fcn;
                    ++tier2_resolved;
                    it = unresolved_vtbls.erase(it);
                    continue;
                }
            }
            ++it;
        }
        std::printf("[vtbl] Tier 2 (FFieldClass): resolved %zu more vtables\n", tier2_resolved);

        // ── Tier 3: Element-size heuristic ──────────────────────────────
        size_t tier3_resolved = 0;
        for (auto& [rva, obs] : unresolved_vtbls) {
            if (m_vtable_to_type.count(rva)) continue;
            switch (obs.elem) {
                case 1:  m_vtable_to_type[rva] = "FBoolProperty"; break;
                case 2:  m_vtable_to_type[rva] = "FUInt16Property"; break;
                case 16: m_vtable_to_type[rva] = "FStructProperty"; break;
                case 24: m_vtable_to_type[rva] = "FTextProperty"; break;
                case 32: m_vtable_to_type[rva] = "FDelegateProperty"; break;
                case 80: m_vtable_to_type[rva] = "FMapProperty"; break;
                default: continue;
            }
            ++tier3_resolved;
        }
        std::printf("[vtbl] Tier 3 (heuristic): resolved %zu more vtables\n", tier3_resolved);
        std::printf("[vtbl] Total vtable mappings: %zu\n", m_vtable_to_type.size());

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
    // ── Resolve sub-property type for Struct/Object/Enum/Class/Interface ────
    void ResolveSubPropertyType(uint64_t ff, std::string& type_name) {
        if (type_name == "FStructProperty") {
            uint64_t sp = Read<uint64_t>(ff + ArcDecrypt::Offsets::FStructProperty::Struct);
            if (sp) {
                std::string sn = m_fname.GetName(sp);
                if (!sn.empty()) type_name = sn;
            } else {
                // No Struct pointer — likely FTextProperty misidentified via elem_size heuristic
                uint32_t elem = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);
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
    std::vector<PropertyRecord> ReadPropertyChain(uint64_t ff_head, int max_props = 512,
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
                // Fallback: generate name from offset so it's counted as "named"
                uint32_t raw_off_tmp = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                char buf[32]; snprintf(buf, sizeof(buf), "UnknownProp_0x%04X", raw_off_tmp);
                pr.name = buf;
            }

            // Type identification: vtable FIRST (always reliable), FFieldClass as fallback
            uint64_t vtbl     = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::VTable);
            uint64_t vtbl_rva = vtbl - MODULE_BASE;

            // Try vtable → type name (most reliable after bootstrap)
            auto vt_it = m_vtable_to_type.find(vtbl_rva);
            if (vt_it != m_vtable_to_type.end()) {
                pr.type_name = vt_it->second;
            } else {
                // Fallback: FFieldClass ptr → type name
                pr.fclass_ptr = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::ClassPrivate);
                pr.type_name  = FieldClassToTypeName(pr.fclass_ptr);
                // If still unknown, try IdentifyPropertyType (element-size heuristic)
                if (pr.type_name == "None" || pr.type_name == "FProperty_Unknown" ||
                    pr.type_name.find("UNKNOWN") != std::string::npos) {
                    std::string vt_type = IdentifyPropertyType(ff);
                    if (vt_type.find("UNKNOWN") == std::string::npos)
                        pr.type_name = vt_type;
                }
            }
            pr.is_bool = (pr.type_name == "FBoolProperty");
            if (pr.is_bool) {
                pr.bool_byte_mask  = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::ByteMask);
                pr.bool_field_size = Read<uint8_t>(ff + ArcDecrypt::Offsets::FBoolProperty::FieldSize);
            }

            // Encrypted offset: bswap32(raw ^ 0x46F1DEE5)
            {
                uint32_t raw_off = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::Offset_Internal);
                pr.offset = static_cast<uint32_t>(ArcDecrypt::DecryptPropertyOffset(raw_off));
            }

            pr.elem_size = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ElementSize);
            pr.array_dim = Read<uint32_t>(ff + ArcDecrypt::Offsets::FProperty::ArrayDim);

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
                    // Vtable-first type resolution for inner
                    uint64_t iv = Read<uint64_t>(inner_ptr) - MODULE_BASE;
                    auto iv_it = m_vtable_to_type.find(iv);
                    if (iv_it != m_vtable_to_type.end()) {
                        ipr.type_name = iv_it->second;
                    } else {
                        ipr.fclass_ptr = Read<uint64_t>(inner_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                        ipr.type_name  = FieldClassToTypeName(ipr.fclass_ptr);
                        if (ipr.type_name == "None" || ipr.type_name == "FProperty_Unknown" ||
                            ipr.type_name.find("UNKNOWN") != std::string::npos) {
                            std::string vt = IdentifyPropertyType(inner_ptr);
                            if (vt.find("UNKNOWN") == std::string::npos) ipr.type_name = vt;
                        }
                    }
                    ipr.offset     = pr.offset;
                    ipr.elem_size  = Read<uint32_t>(inner_ptr + ArcDecrypt::Offsets::FProperty::ElementSize);
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
                    uint64_t ev_rva = Read<uint64_t>(elem_ptr) - MODULE_BASE;
                    auto ev_it = m_vtable_to_type.find(ev_rva);
                    if (ev_it != m_vtable_to_type.end()) {
                        epr.type_name = ev_it->second;
                    } else {
                        epr.fclass_ptr = Read<uint64_t>(elem_ptr + ArcDecrypt::Offsets::FField::ClassPrivate);
                        epr.type_name  = FieldClassToTypeName(epr.fclass_ptr);
                        if (epr.type_name == "None" || epr.type_name == "FProperty_Unknown" ||
                            epr.type_name.find("UNKNOWN") != std::string::npos) {
                            std::string vt = IdentifyPropertyType(elem_ptr);
                            if (vt.find("UNKNOWN") == std::string::npos) epr.type_name = vt;
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
                    // Vtable-first type resolution
                    uint64_t mv_rva = Read<uint64_t>(mp) - MODULE_BASE;
                    auto mv_it = m_vtable_to_type.find(mv_rva);
                    if (mv_it != m_vtable_to_type.end()) {
                        mpr.type_name = mv_it->second;
                    } else {
                        mpr.fclass_ptr = Read<uint64_t>(mp + ArcDecrypt::Offsets::FField::ClassPrivate);
                        mpr.type_name  = FieldClassToTypeName(mpr.fclass_ptr);
                        if (mpr.type_name == "None" || mpr.type_name == "FProperty_Unknown" ||
                            mpr.type_name.find("UNKNOWN") != std::string::npos) {
                            std::string vt = IdentifyPropertyType(mp);
                            if (vt.find("UNKNOWN") == std::string::npos) mpr.type_name = vt;
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
            ff = Read<uint64_t>(ff + ArcDecrypt::Offsets::FField::Next);
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


    // ── Read UFunction linked list from a UStruct's Children pointer ───────
    // UStruct::Children (+0x110) → first UFunction/UDelegateFunction/etc.
    // UField::Next (+0x0B0) links each node to the next.
    // Accepts ALL UField-derived vtables (UFunction, UDelegateFunction, UInterfaceFunction)
    // by checking that the vtable RVA is within the module's code range.
    std::vector<FunctionRecord> ReadFunctions(uint64_t ustruct_addr, int max_funcs = 4096) {
        std::vector<FunctionRecord> result;
        std::unordered_set<uint64_t> visited;

        // Accept any vtable in the plausible UField-subclass vtable range.
        // UFunction=0xAB74190, UDelegateFunction/UInterfaceFunction are nearby.
        // Broad module range check: vtable RVA in [0x1000, 0xF000000] covers all code.
        auto IsUFieldVtbl = [&](uint64_t vtbl) -> bool {
            if (vtbl < MODULE_BASE) return false;
            uint64_t rva = vtbl - MODULE_BASE;
            return rva >= 0x1000ULL && rva < 0xF000000ULL;
        };

        uint64_t child = Read<uint64_t>(ustruct_addr + ArcDecrypt::Offsets::UStruct::Children);
        int count = 0;
        while (child && count < max_funcs) {
            if (visited.count(child)) break;
            visited.insert(child);

            uint64_t vtbl = Read<uint64_t>(child + ArcDecrypt::Offsets::UFunction::VTable);
            if (!IsUFieldVtbl(vtbl)) {
                // Corrupt/null vtable — stop (don't blindly walk corrupt Next)
                break;
            }

            // Accept function regardless of FunctionFlags value (BP funcs can have flags=0)
            FunctionRecord fr{};
            fr.fn_addr    = child;
            fr.flags      = Read<uint64_t>(child + ArcDecrypt::Offsets::UFunction::FunctionFlags);
            fr.native_rva = 0;

            uint64_t native = Read<uint64_t>(child + ArcDecrypt::Offsets::UFunction::NativeFunc);
            if (native >= MODULE_BASE && native < MODULE_BASE + 0x10000000ULL)
                fr.native_rva = native - MODULE_BASE;

            fr.name = m_fname.GetName(child);
            if (fr.name.empty()) fr.name = "<unnamed_func>";

            // Read UFunction ChildProperties (parameter list)
            uint64_t param_head = Read<uint64_t>(child + ArcDecrypt::Offsets::UStruct::ChildProperties);
            if (param_head)
                fr.params = ReadPropertyChain(param_head, 64, /*is_param=*/true);

            result.push_back(std::move(fr));

            child = Read<uint64_t>(child + ArcDecrypt::Offsets::UFunction::NextPtr);
            ++count;
        }

        return result;
    }

    // ── Dump a single UStruct/UClass to string ──────────────────────────────────
    std::string DumpStruct(const StructRecord& rec) {
        std::ostringstream oss;
        oss << "// " << (rec.is_class ? "Class" : "Struct") << " /Script/"
            << rec.package << "." << rec.name << "\n";
        oss << "// Size: 0x" << std::hex << rec.props_size
            << " (0x" << rec.props_size << " bytes)\n";
        if (!rec.super_name.empty())
            oss << "// Inherits: " << rec.super_name << "\n";
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
            oss << "\n// === Functions ===\n";
            for (const auto& fn : rec.functions) {
                oss << "// " << fn.name;
                if (fn.native_rva)
                    oss << "  (RVA: 0x" << std::hex << fn.native_rva << ")";
                if (!fn.params.empty()) {
                    oss << "\n//   Params:";
                    for (const auto& par : fn.params)
                        oss << " " << par.type_name << " " << par.name << ";";
                }
                oss << "\n";
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
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            auto it = addr_to_name.find(obj_ptr);
            if (it == addr_to_name.end()) continue;
            const std::string& n = it->second;
            if (n == "Class")             { classAddr = obj_ptr; validClassTypes.insert(obj_ptr); }
            else if (n == "ScriptStruct") { ssAddr = obj_ptr; }
            else if (n == "Enum")         { enumAddr = obj_ptr; }
            else if (n == "UserDefinedEnum") { validEnumTypes.insert(obj_ptr); }
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
        for (const auto& [idx, obj_ptr] : object_ptrs) {
            uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
            if (cls && addr_to_name.count(cls))
                allTypeAddrs.insert(cls);
        }
        std::printf("[sdk] allTypeAddrs (addresses used as Class ptrs): %zu\n", allTypeAddrs.size());

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
            if (fn_it == addr_to_name.end()) continue;
            const std::string& short_name = fn_it->second;
            if (short_name.empty() || short_name[0] == '/') continue;

            // Determine type via two paths:
            // Path A: GetClassPrivate gives a known metaclass/type indicator
            uint64_t cls = m_fname.GetClassPrivate(obj_ptr);
            bool is_class_by_cls = validClassTypes.count(cls) > 0;
            bool is_scriptstruct = (cls == ssAddr);
            bool is_enum         = (cls == enumAddr) || validEnumTypes.count(cls) > 0;

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

            // Properties
            uint64_t child_props = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::ChildProperties);
            if (child_props)
                rec.properties = ReadProperties(obj_ptr, 1024);

            // Functions
            uint64_t children = Read<uint64_t>(obj_ptr + ArcDecrypt::Offsets::UStruct::Children);
            if (children)
                rec.functions = ReadFunctions(obj_ptr, 1024);

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
