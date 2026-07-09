// =============================================================================
// auto_export.h
//
// Snapshots every runtime-discovered decryption constant, offset, and anchor
// the dumper has resolved during Init() and writes them to a JSON file next
// to SDK_Output.txt. Output is consumable by external tooling and serves as
// a forensic trail when a future patch breaks one of the probes.
//
// What gets exported:
//   • Module bounds & PE section RVAs (AutoDiscovery::g_DiscoveredBounds)
//   • Static anchors: RVA_GWORLD / RVA_GNAMES_BASE / RVA_FNAME_KEY_TABLE /
//     RVA_GOBJECT_ARRAY_BASE / SIMD-table RVAs (post-sig-scan / probe values)
//   • Engine type-pool vtable RVAs (UScriptStruct/UClass/UFunction/UEnum/UPackage)
//   • Full ArcDecrypt::Offsets::* layout (FField/FProperty/UStruct/UFunction/UClass)
//   • All Patch20260421/20260428 mutable constants
//     (ENTRY_HANDLE_XOR, g_PropertyOffsetXor, UObjSlot XOR scalar, etc.)
//   • AutoDiscovery probe results (every g_Discovered*.Valid=true struct)
//   • FName resolver constants (function start, imm64 / pshuflw / rol imm /
//     rdata-LEA targets walked from the FName fn body)
//
// All values are point-in-time snapshots — call WriteAll() AFTER Init()
// completes so probes have had a chance to commit drift fixes.
// =============================================================================
#pragma once

#include <cstdio>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

#include "arc_decrypt.h"
#include "auto_discovery.h"

namespace AutoExport {

inline std::string Hex64(uint64_t V) {
    char Buf[32];
    std::snprintf(Buf, sizeof(Buf), "0x%llX", (unsigned long long)V);
    return Buf;
}

inline std::string IsoTimestamp() {
    std::time_t T = std::time(nullptr);
    std::tm* Tm = std::gmtime(&T);
    char Buf[32];
    std::strftime(Buf, sizeof(Buf), "%Y-%m-%dT%H:%M:%SZ", Tm);
    return Buf;
}

class JsonWriter {
public:
    JsonWriter(std::ofstream& Os) : m_Os(Os), m_Depth(0) {}

    void OpenObj(const char* Key = nullptr) {
        if (Key) Comma();
        Indent();
        if (Key) m_Os << "\"" << Key << "\": ";
        m_Os << "{\n";
        m_Depth++;
        m_NeedsComma.push_back(false);
    }
    void CloseObj() {
        m_Depth--;
        m_Os << "\n";
        Indent();
        m_Os << "}";
        m_NeedsComma.pop_back();
        if (!m_NeedsComma.empty()) m_NeedsComma.back() = true;
    }
    void OpenArr(const char* Key) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": [\n";
        m_Depth++;
        m_NeedsComma.push_back(false);
    }
    void CloseArr() {
        m_Depth--;
        m_Os << "\n";
        Indent();
        m_Os << "]";
        m_NeedsComma.pop_back();
        if (!m_NeedsComma.empty()) m_NeedsComma.back() = true;
    }

    void KStr(const char* Key, const std::string& Val) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": \"" << EscapeStr(Val) << "\"";
        Mark();
    }
    void KU64(const char* Key, uint64_t Val) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": \"" << Hex64(Val) << "\"";
        Mark();
    }
    void KI64(const char* Key, int64_t Val) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": " << Val;
        Mark();
    }
    void KBool(const char* Key, bool Val) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": " << (Val ? "true" : "false");
        Mark();
    }
    void KArrU64(const char* Key, const std::vector<uint64_t>& Vals) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": [";
        for (size_t I = 0; I < Vals.size(); ++I) {
            if (I) m_Os << ", ";
            m_Os << "\"" << Hex64(Vals[I]) << "\"";
        }
        m_Os << "]";
        Mark();
    }
    void KArrU8Hex(const char* Key, const std::vector<uint8_t>& Vals) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": [";
        for (size_t I = 0; I < Vals.size(); ++I) {
            if (I) m_Os << ", ";
            char B[8];
            std::snprintf(B, sizeof(B), "\"0x%02X\"", Vals[I]);
            m_Os << B;
        }
        m_Os << "]";
        Mark();
    }
    void KArrU8HexFixed(const char* Key, const uint8_t* Vals, size_t N) {
        Comma();
        Indent();
        m_Os << "\"" << Key << "\": [";
        for (size_t I = 0; I < N; ++I) {
            if (I) m_Os << ", ";
            char B[8];
            std::snprintf(B, sizeof(B), "\"0x%02X\"", Vals[I]);
            m_Os << B;
        }
        m_Os << "]";
        Mark();
    }

    void StartItemObj() {
        Comma();
        Indent();
        m_Os << "{\n";
        m_Depth++;
        m_NeedsComma.push_back(false);
    }
    void EndItemObj() {
        m_Depth--;
        m_Os << "\n";
        Indent();
        m_Os << "}";
        m_NeedsComma.pop_back();
        Mark();
    }

private:
    void Indent() {
        for (int I = 0; I < m_Depth; ++I) m_Os << "  ";
    }
    void Comma() {
        if (!m_NeedsComma.empty() && m_NeedsComma.back()) m_Os << ",\n";
    }
    void Mark() {
        if (!m_NeedsComma.empty()) m_NeedsComma.back() = true;
    }
    static std::string EscapeStr(const std::string& S) {
        std::string Out;
        Out.reserve(S.size());
        for (char C : S) {
            switch (C) {
                case '"':  Out += "\\\""; break;
                case '\\': Out += "\\\\"; break;
                case '\n': Out += "\\n";  break;
                case '\t': Out += "\\t";  break;
                default:   Out += C;
            }
        }
        return Out;
    }

    std::ofstream& m_Os;
    int m_Depth;
    std::vector<bool> m_NeedsComma;
};

inline void EmitModuleBlock(JsonWriter& W, uint64_t ModuleBase) {
    W.OpenObj("module");
    W.KU64("base", ModuleBase);
    const auto& B = AutoDiscovery::g_DiscoveredBounds;
    W.KBool("bounds_valid", B.Valid);
    if (B.Valid) {
        W.KU64("image_size", B.ImageSize);
        W.KU64("text_rva", B.TextRva);
        W.KU64("text_size", B.TextSize);
        W.KU64("rdata_rva", B.RDataRva);
        W.KU64("rdata_size", B.RDataSize);
        W.KU64("data_rva", B.DataRva);
        W.KU64("data_size", B.DataSize);
    }
    W.CloseObj();
}

inline void EmitAnchors(JsonWriter& W) {
    W.OpenObj("anchors");
    W.KU64("rva_gworld",              ArcDecrypt::RVA_GWORLD);
    W.KU64("rva_gnames_base",         ArcDecrypt::RVA_GNAMES_BASE);
    W.KU64("rva_fname_key_table",     ArcDecrypt::RVA_FNAME_KEY_TABLE);
    W.KU64("rva_gobject_array_base",  ArcDecrypt::RVA_GOBJECT_ARRAY_BASE);
    W.KU64("rva_simd_objarray_xor",   ArcDecrypt::RVA_SIMD_OBJARRAY_XOR);
    W.KU64("rva_elem_mask_a",         ArcDecrypt::RVA_ELEM_MASK_A);
    W.KU64("rva_elem_mask_b",         ArcDecrypt::RVA_ELEM_MASK_B);
    W.KU64("rva_elem_xor_key",        ArcDecrypt::RVA_ELEM_XOR_KEY);
    W.KU64("rva_cidx_xor1",           ArcDecrypt::RVA_CIDX_XOR1);
    W.CloseObj();
}

inline void EmitOffsets(JsonWriter& W) {
    using namespace ArcDecrypt::Offsets;
    W.OpenObj("offsets");

    W.OpenObj("ustruct");
    W.KU64("super_struct",     UStruct::SuperStruct);
    W.KU64("children",         UStruct::Children);
    W.KU64("child_properties", UStruct::ChildProperties);
    W.KU64("properties_size",  UStruct::PropertiesSize);
    W.KU64("min_alignment",    UStruct::MinAlignment);
    W.CloseObj();

    W.OpenObj("uenum");
    W.KU64("names", UEnum::Names);
    W.CloseObj();

    W.OpenObj("ufunction");
    W.KU64("vtable",         UFunction::VTable);
    W.KU64("next_ptr",       UFunction::NextPtr);
    W.KU64("function_flags", UFunction::FunctionFlags);
    W.KU64("native_func",    UFunction::NativeFunc);
    W.KU64("num_parms",      UFunction::NumParms);
    W.CloseObj();

    W.OpenObj("uclass");
    W.KU64("func_map_pairs_data",  UClass::FuncMap_PairsData);
    W.KU64("func_map_num",         UClass::FuncMap_Num);
    W.KU64("func_map_max",         UClass::FuncMap_Max);
    W.KU64("func_map_pair_stride", UClass::FuncMap_PairStride);
    W.CloseObj();

    W.OpenObj("ffield");
    W.KU64("vtable",          FField::VTable);
    W.KU64("class_private",   FField::ClassPrivate);
    W.KU64("next",            FField::Next);
    W.KU64("owner",           FField::Owner);
    W.KU64("name_private",    FField::NamePrivate);
    W.KU64("name_encrypted",  FField::NameEncrypted);
    W.KU64("salt_sentinel",   FField::SaltSentinel);
    W.CloseObj();

    W.OpenObj("ffield_class");
    W.KU64("element_size", FFieldClass::ElementSize);
    W.CloseObj();

    W.OpenObj("fproperty");
    W.KU64("array_dim",        FProperty::ArrayDim);
    W.KU64("element_size",     FProperty::ElementSize);
    W.KU64("offset_internal",  FProperty::Offset_Internal);
    W.KU64("offset_xor",       (uint64_t)FProperty::Offset_XOR);
    W.KU64("property_flags",   FProperty::PropertyFlags);
    W.CloseObj();

    W.OpenObj("fbool_property");
    W.KU64("field_size",  FBoolProperty::FieldSize);
    W.KU64("byte_offset", FBoolProperty::ByteOffset);
    W.KU64("byte_mask",   FBoolProperty::ByteMask);
    W.KU64("field_mask",  FBoolProperty::FieldMask);
    W.CloseObj();

    W.OpenObj("fproperty_subclass");
    W.KU64("fstruct_property__struct",          FStructProperty::Struct);
    W.KU64("fobject_property__property_class",  FObjectProperty::PropertyClass);
    W.KU64("fenum_property__underlying_prop",   FEnumProperty::UnderlyingProp);
    W.KU64("fenum_property__enum",              FEnumProperty::Enum);
    W.KU64("farray_property__inner",            FArrayProperty::Inner);
    W.KU64("fset_property__element_prop",       FSetProperty::ElementProp);
    W.KU64("fsoftobject_property__property_class", FSoftObjectProperty::PropertyClass);
    W.KU64("fmap_property__key_prop",           FMapProperty::KeyProp);
    W.KU64("fmap_property__value_prop",         FMapProperty::ValueProp);
    W.CloseObj();

    W.OpenObj("uworld");
    W.KU64("persistent_level", UWorld::PersistentLevel);
    W.KU64("levels",           UWorld::Levels);
    W.CloseObj();

    W.OpenObj("uscene_component");
    W.KU64("component_to_world", USceneComponent::ComponentToWorld);
    W.CloseObj();

    W.CloseObj();
}

inline void EmitPatchConstants(JsonWriter& W) {
    W.OpenObj("patch_constants");

    W.OpenObj("fname_block");
    W.KU64("fnv_prime",         ArcDecrypt::FNAME_FNV_PRIME);
    W.KU64("fnv_offset",        ArcDecrypt::FNAME_FNV_OFFSET);
    W.KI64("fnv_rol1",          ArcDecrypt::FNAME_FNV_ROL1);
    W.KI64("fnv_rol2",          ArcDecrypt::FNAME_FNV_ROL2);
    W.KI64("block_pshuflw",     ArcDecrypt::FNAME_BLOCK_PSHUFLW);
    W.KI64("block_rol16",       ArcDecrypt::FNAME_BLOCK_ROL16);
    W.KU64("ptr_xor1",          ArcDecrypt::FNAME_PTR_XOR1);
    W.KU64("ptr_xor2",          ArcDecrypt::FNAME_PTR_XOR2);
    W.KU64("ptr_xor3",          ArcDecrypt::FNAME_PTR_XOR3);
    W.KU64("bhash_add",         ArcDecrypt::FNAME_BHASH_ADD);
    W.KI64("chunk_block_ptr_off", ArcDecrypt::FNAME_CHUNK_BLOCK_PTR_OFF);
    W.KI64("ansi_key_base",     ArcDecrypt::FNAME_ANSI_KEY_BASE);
    W.KI64("wide_key_base",     ArcDecrypt::FNAME_WIDE_KEY_BASE);
    W.CloseObj();

    W.OpenObj("fnv32_slot");
    W.KU64("prime",    ArcDecrypt::FNV32_SLOT_PRIME);
    W.KU64("k",        ArcDecrypt::FNV32_SLOT_K);
    W.KU64("hash_off", ArcDecrypt::FNV32_HASH_OFF);
    W.KU64("slot_off", ArcDecrypt::FNV32_SLOT_OFF);
    W.CloseObj();

    W.OpenObj("uobj_slot");
    W.KU64("sentinel",     ArcDecrypt::UOBJ_SLOT_SENTINEL);
    W.KI64("rol64",        ArcDecrypt::UOBJ_SLOT_ROL64);
    W.KI64("pshuflw_imm",  ArcDecrypt::UOBJ_SLOT_PSHUFLW_IMM);
    W.KI64("fname_rol",    ArcDecrypt::UOBJ_SLOT_FNAME_ROL);
    W.CloseObj();

    W.OpenObj("objarray");
    W.KI64("rol32", ArcDecrypt::OBJARRAY_ROL32);
    W.KI64("rol16", ArcDecrypt::OBJARRAY_ROL16);
    W.CloseObj();

    W.OpenObj("cidx");
    W.KI64("rol16",       ArcDecrypt::CIDX_ROL16);
    W.KI64("pshuflw_imm", ArcDecrypt::CIDX_PSHUFLW_IMM);
    W.KU64("hdr_xor",     ArcDecrypt::CIDX_HDR_XOR);
    W.KI64("hdr_rol",     ArcDecrypt::CIDX_HDR_ROL);
    W.CloseObj();

    W.OpenObj("uprop");
    W.KU64("fname_offset",   ArcDecrypt::UPROP_FNAME_OFFSET);
    W.KU64("fname_xor_key",  ArcDecrypt::UPROP_FNAME_XOR_KEY);
    W.CloseObj();

    W.OpenObj("patch20260421");
    W.KU64("entry_handle_xor",        ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR);
    W.KU64("entry_field_xor",         ArcDecrypt::Patch20260421::ENTRY_FIELD_XOR);
    W.KU64("rva_gnames_base_new",     ArcDecrypt::Patch20260421::RVA_GNAMES_BASE_NEW);
    W.KU64("g_property_offset_xor",   (uint64_t)ArcDecrypt::Patch20260421::g_PropertyOffsetXor);

    using namespace ArcDecrypt::Patch20260421::UObjSlot20260428;
    W.OpenObj("uobj_slot_20260428");
    W.KU64("xor_scalar", XOR_SCALAR);
    W.CloseObj();
    W.CloseObj();

    W.CloseObj();
}

inline void EmitAutoDiscovery(JsonWriter& W) {
    W.OpenObj("autodiscovery");

    W.OpenObj("vtables");
    {
        const auto& V = AutoDiscovery::g_DiscoveredVTables;
        W.KBool("valid",            V.Valid());
        W.KU64("script_struct_rva", V.ScriptStructRVA);
        W.KU64("class_native_rva",  V.ClassNativeRVA);
        W.KU64("function_rva",      V.FunctionRVA);
        W.KU64("enum_rva",          V.EnumRVA);
        W.KU64("package_rva",       V.PackageRVA);
        W.KU64("bpgc_rva",          V.BPGCRVA);
        W.KU64("wbpgc_rva",         V.WBPGCRVA);
        W.KU64("smbpgc_rva",        V.SMBPGCRVA);
        W.KU64("anim_bpgc_rva",     V.AnimBPGCRVA);
        W.KU64("asclass_rva",       V.ASClassRVA);
        W.KU64("asstruct_rva",      V.ASStructRVA);
        W.KArrU64("asfunction_rvas", V.ASFunctionRVAs);
    }
    W.CloseObj();

    W.OpenObj("world");
    {
        const auto& Wd = AutoDiscovery::g_DiscoveredWorld;
        W.KBool("valid", Wd.Valid);
        W.KU64("gworld_rva",              Wd.GWorldRva);
        W.KU64("gworld_abs",               Wd.GWorldAbs);
        W.KU64("persistent_level_abs",     Wd.PersistentLevelAbs);
        W.KU64("persistent_level_offset",  Wd.PersistentLevelOffset);
        W.KU64("actors_data_offset",       Wd.ActorsDataOffset);
        W.KU64("actors_count_offset",      Wd.ActorsCountOffset);
        W.KI64("actors_count",             Wd.ActorsCount);
        W.KBool("double_deref",            Wd.DoubleDeref);
    }
    W.CloseObj();

    W.OpenObj("ffield_name_decrypt");
    {
        const auto& F = AutoDiscovery::g_DiscoveredFFieldName;
        W.KBool("valid",        F.Valid);
        W.KU64("xor_const",     F.XorConst);
        W.KI64("rol32_amount",  F.Rol32Amount);
        W.KI64("rol64_amount",  F.Rol64Amount);
    }
    W.CloseObj();

    W.OpenObj("fproperty_offset_xor");
    {
        const auto& F = AutoDiscovery::g_DiscoveredFProperty;
        W.KBool("valid",            F.Valid);
        W.KU64("offset_reader_rva", F.OffsetReaderRva);
        W.KU64("offset_internal",   F.OffsetInternal);
        W.KU64("xor_key",           F.XorKey);
        W.KI64("validated_hits",    F.ValidatedHits);
    }
    W.CloseObj();

    W.OpenObj("uobj_slot_decrypt");
    {
        const auto& U = AutoDiscovery::g_DiscoveredUObjSlot;
        W.KBool("valid",          U.Valid);
        W.KU64("shuf_mask_rva",   U.ShufMaskRVA);
        W.KU64("xor_const_rva",   U.XorConstRVA);
        W.KU64("xor_scalar",      U.XorScalar);
        W.KI64("rol64_amount",    U.Rol64Amount);
        W.KArrU8HexFixed("shuf_mask_bytes", U.ShufMaskBytes, 8);
    }
    W.CloseObj();

    W.OpenObj("ffield_class_name");
    {
        const auto& F = AutoDiscovery::g_DiscoveredFFieldClassName;
        W.KBool("valid",                  F.Valid);
        W.KU64("xor_const_rva",           F.XorConstRva);
        W.KU64("xor_lo64",                F.XorLo64);
        W.KU64("ffield_class_offset",     F.FFieldClassOffset);
        W.KU64("name_private_offset",     F.NamePrivateOffset);
        W.KI64("pshuflw_imm",             F.PshuflwImm);
        W.KI64("rol32_amount",            F.Rol32Amount);
        W.KI64("rol64_amount",            F.Rol64Amount);
        W.KI64("consensus_site_count",    F.ConsensusSiteCount);
    }
    W.CloseObj();

    W.OpenObj("gnames");
    {
        const auto& G = AutoDiscovery::g_DiscoveredGNames;
        W.KBool("valid",           G.Valid);
        W.KU64("gnames_rva",       G.GNamesRva);
        W.KI64("ref_count",        G.RefCount);
        W.KU64("simd_block_rva",   G.SimdBlockRva);
        W.KI64("simd_block_refs",  G.SimdBlockRefs);
    }
    W.CloseObj();

    W.OpenObj("fname_keystream");
    {
        const auto& K = AutoDiscovery::g_DiscoveredFNameKey;
        W.KBool("valid",          K.Valid);
        W.KU64("keystream_rva",   K.KeystreamRva);
        W.KU64("cluster_base",    K.ClusterBase);
        W.KI64("window_hits",     K.WindowHits);
    }
    W.CloseObj();

    W.OpenObj("guobjarray_layout");
    {
        const auto& L = AutoDiscovery::g_DiscoveredGObjLayout;
        W.KBool("valid",                L.Valid);
        W.KU64("struct_abs",            L.StructAbs);
        W.KU64("num_elements_off",      L.NumElementsOff);
        W.KU64("num_elements",          (uint64_t)L.NumElements);
        W.KU64("chunks_array_ptr",      L.ChunksArrayPtr);
        W.KI64("num_chunks",            L.NumChunks);
        W.KI64("valid_chunks_probed",   L.ValidChunksProbed);
        W.KI64("indirection_depth",     L.IndirectionDepth);
        std::vector<uint64_t> P(L.PathOffsets.begin(), L.PathOffsets.end());
        W.KArrU64("path_offsets", P);
    }
    W.CloseObj();

    W.OpenObj("fname_resolver_consts");
    {
        const auto& F = AutoDiscovery::g_DiscoveredFName;
        W.KBool("valid",                 F.Valid);
        W.KU64("function_start_rva",     F.FunctionStartRva);
        W.KArrU64("all_imm64",           F.AllImm64);
        std::vector<uint8_t> Pi(F.AllPshuflwImm.begin(), F.AllPshuflwImm.end());
        std::vector<uint8_t> Ri(F.AllRolImm.begin(),     F.AllRolImm.end());
        W.KArrU8Hex("all_pshuflw_imm",   Pi);
        W.KArrU8Hex("all_rol_imm",       Ri);
        W.KArrU64("all_rdata_leas",      F.AllRDataLeas);
    }
    W.CloseObj();

    W.OpenArr("ffield_class_globals");
    {
        for (const auto& G : AutoDiscovery::g_DiscoveredFClassGlobals) {
            W.StartItemObj();
            W.KU64("target_rva",  G.TargetRva);
            W.KStr("type_name",   G.TypeName);
            W.KU64("flags",       (uint64_t)G.Flags);
            W.KU64("cast_flags",  (uint64_t)G.CastFlags);
            W.EndItemObj();
        }
    }
    W.CloseArr();

    W.CloseObj();
}

inline bool WriteAll(const char* Path, uint64_t ModuleBase) {
    std::ofstream Os(Path);
    if (!Os) {
        std::printf("[autoexport] failed to open %s for writing\n", Path);
        return false;
    }

    JsonWriter W(Os);
    W.OpenObj();
    W.KStr("schema",     "frostsdk.decrypt-export/v1");
    W.KStr("timestamp",  IsoTimestamp());
    W.KStr("patch",      "CL-1177678");

    EmitModuleBlock(W, ModuleBase);
    EmitAnchors(W);
    EmitOffsets(W);
    EmitPatchConstants(W);
    EmitAutoDiscovery(W);

    W.CloseObj();
    Os << "\n";
    Os.close();

    std::printf("[autoexport] wrote decryption snapshot → %s\n", Path);
    return true;
}

}  // namespace AutoExport
