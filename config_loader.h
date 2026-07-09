#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>

#include "arc_decrypt.h"
#include "auto_discovery.h"

namespace ConfigLoader {

struct JsonValue {
    enum Type { T_NULL, T_BOOL, T_INT, T_STR, T_OBJ, T_ARR };
    Type Typ = T_NULL;
    bool BoolVal = false;
    int64_t IntVal = 0;
    std::string StrVal;
    std::unordered_map<std::string, JsonValue> ObjVal;
    std::vector<JsonValue> ArrVal;

    bool IsNull() const { return Typ == T_NULL; }
    bool IsBool() const { return Typ == T_BOOL; }
    bool IsInt() const { return Typ == T_INT; }
    bool IsStr() const { return Typ == T_STR; }
    bool IsObj() const { return Typ == T_OBJ; }
    bool IsArr() const { return Typ == T_ARR; }

    const JsonValue& operator[](const char* Key) const {
        static JsonValue Null;
        if (Typ != T_OBJ) return Null;
        auto It = ObjVal.find(Key);
        return It != ObjVal.end() ? It->second : Null;
    }

    const JsonValue& operator[](size_t Idx) const {
        static JsonValue Null;
        if (Typ != T_ARR || Idx >= ArrVal.size()) return Null;
        return ArrVal[Idx];
    }

    uint64_t Hex64() const {
        if (Typ == T_STR && StrVal.size() > 2 && StrVal[0] == '0' && (StrVal[1] == 'x' || StrVal[1] == 'X'))
            return std::strtoull(StrVal.c_str(), nullptr, 16);
        if (Typ == T_INT)
            return static_cast<uint64_t>(IntVal);
        return 0;
    }

    uint32_t Hex32() const { return static_cast<uint32_t>(Hex64()); }

    int64_t Int() const {
        if (Typ == T_INT) return IntVal;
        if (Typ == T_STR) {
            if (StrVal.size() > 2 && StrVal[0] == '0' && (StrVal[1] == 'x' || StrVal[1] == 'X'))
                return static_cast<int64_t>(std::strtoull(StrVal.c_str(), nullptr, 16));
            return std::strtoll(StrVal.c_str(), nullptr, 10);
        }
        return 0;
    }

    bool Bool() const {
        if (Typ == T_BOOL) return BoolVal;
        return false;
    }

    size_t Size() const {
        if (Typ == T_ARR) return ArrVal.size();
        if (Typ == T_OBJ) return ObjVal.size();
        return 0;
    }
};

inline void SkipWs(const char*& P) {
    while (*P == ' ' || *P == '\t' || *P == '\n' || *P == '\r') ++P;
}

inline std::string ParseString(const char*& P) {
    std::string Out;
    if (*P != '"') return Out;
    ++P;
    while (*P && *P != '"') {
        if (*P == '\\' && *(P + 1)) {
            ++P;
            switch (*P) {
                case '"':  Out += '"';  break;
                case '\\': Out += '\\'; break;
                case 'n':  Out += '\n'; break;
                case 't':  Out += '\t'; break;
                case '/':  Out += '/';  break;
                default:   Out += *P;   break;
            }
        } else {
            Out += *P;
        }
        ++P;
    }
    if (*P == '"') ++P;
    return Out;
}

inline JsonValue ParseValue(const char*& P);

inline JsonValue ParseObject(const char*& P) {
    JsonValue V;
    V.Typ = JsonValue::T_OBJ;
    if (*P != '{') return V;
    ++P;
    SkipWs(P);
    while (*P && *P != '}') {
        SkipWs(P);
        if (*P == '}') break;
        std::string Key = ParseString(P);
        SkipWs(P);
        if (*P == ':') ++P;
        SkipWs(P);
        V.ObjVal[Key] = ParseValue(P);
        SkipWs(P);
        if (*P == ',') ++P;
    }
    if (*P == '}') ++P;
    return V;
}

inline JsonValue ParseArray(const char*& P) {
    JsonValue V;
    V.Typ = JsonValue::T_ARR;
    if (*P != '[') return V;
    ++P;
    SkipWs(P);
    while (*P && *P != ']') {
        SkipWs(P);
        if (*P == ']') break;
        V.ArrVal.push_back(ParseValue(P));
        SkipWs(P);
        if (*P == ',') ++P;
    }
    if (*P == ']') ++P;
    return V;
}

inline JsonValue ParseValue(const char*& P) {
    SkipWs(P);
    if (*P == '{') return ParseObject(P);
    if (*P == '[') return ParseArray(P);
    if (*P == '"') {
        JsonValue V;
        V.Typ = JsonValue::T_STR;
        V.StrVal = ParseString(P);
        return V;
    }
    if (*P == 't' && std::strncmp(P, "true", 4) == 0) {
        P += 4;
        JsonValue V;
        V.Typ = JsonValue::T_BOOL;
        V.BoolVal = true;
        return V;
    }
    if (*P == 'f' && std::strncmp(P, "false", 5) == 0) {
        P += 5;
        JsonValue V;
        V.Typ = JsonValue::T_BOOL;
        V.BoolVal = false;
        return V;
    }
    if (*P == 'n' && std::strncmp(P, "null", 4) == 0) {
        P += 4;
        return JsonValue{};
    }
    {
        JsonValue V;
        V.Typ = JsonValue::T_INT;
        bool Neg = false;
        if (*P == '-') { Neg = true; ++P; }
        int64_t N = 0;
        bool IsFloat = false;
        while (*P >= '0' && *P <= '9') {
            N = N * 10 + (*P - '0');
            ++P;
        }
        if (*P == '.') {
            IsFloat = true;
            ++P;
            while (*P >= '0' && *P <= '9') ++P;
        }
        if (*P == 'e' || *P == 'E') {
            IsFloat = true;
            ++P;
            if (*P == '+' || *P == '-') ++P;
            while (*P >= '0' && *P <= '9') ++P;
        }
        V.IntVal = Neg ? -N : N;
        return V;
    }
}

inline JsonValue ParseJson(const std::string& Text) {
    const char* P = Text.c_str();
    SkipWs(P);
    return ParseValue(P);
}

inline void LoadAnchors(const JsonValue& Root) {
    const auto& A = Root["anchors"];
    if (A.IsNull()) return;

    auto Set = [](uint64_t& Dst, const JsonValue& V) {
        if (!V.IsNull()) Dst = V.Hex64();
    };

    Set(ArcDecrypt::RVA_GWORLD,             A["rva_gworld"]);
    Set(ArcDecrypt::RVA_GNAMES_BASE,        A["rva_gnames_base"]);
    Set(ArcDecrypt::RVA_FNAME_KEY_TABLE,    A["rva_fname_key_table"]);
    Set(ArcDecrypt::RVA_GOBJECT_ARRAY_BASE, A["rva_gobject_array_base"]);
    Set(ArcDecrypt::RVA_SIMD_OBJARRAY_XOR,  A["rva_simd_objarray_xor"]);
    Set(ArcDecrypt::RVA_ELEM_MASK_A,        A["rva_elem_mask_a"]);
    Set(ArcDecrypt::RVA_ELEM_MASK_B,        A["rva_elem_mask_b"]);
    Set(ArcDecrypt::RVA_ELEM_XOR_KEY,       A["rva_elem_xor_key"]);
    Set(ArcDecrypt::RVA_CIDX_XOR1,          A["rva_cidx_xor1"]);

    std::printf("[config] loaded anchors: GWorld=0x%llX GNames=0x%llX GObj=0x%llX\n",
        (unsigned long long)ArcDecrypt::RVA_GWORLD,
        (unsigned long long)ArcDecrypt::RVA_GNAMES_BASE,
        (unsigned long long)ArcDecrypt::RVA_GOBJECT_ARRAY_BASE);
}

inline void LoadOffsets(const JsonValue& Root) {
    const auto& O = Root["offsets"];
    if (O.IsNull()) return;

    using namespace ArcDecrypt::Offsets;

    auto Set64 = [](uint64_t& Dst, const JsonValue& V) {
        if (!V.IsNull()) Dst = V.Hex64();
    };
    auto Set32 = [](uint32_t& Dst, const JsonValue& V) {
        if (!V.IsNull()) Dst = V.Hex32();
    };

    {
        const auto& S = O["ustruct"];
        Set64(UStruct::SuperStruct,     S["super_struct"]);
        Set64(UStruct::Children,        S["children"]);
        Set64(UStruct::ChildProperties, S["child_properties"]);
        Set64(UStruct::PropertiesSize,  S["properties_size"]);
        Set64(UStruct::MinAlignment,    S["min_alignment"]);
    }
    {
        const auto& S = O["uenum"];
        Set64(UEnum::Names, S["names"]);
    }
    {
        const auto& S = O["ufunction"];
        Set64(UFunction::VTable,        S["vtable"]);
        Set64(UFunction::NextPtr,       S["next_ptr"]);
        Set64(UFunction::FunctionFlags, S["function_flags"]);
        Set64(UFunction::NativeFunc,    S["native_func"]);
        Set64(UFunction::NumParms,      S["num_parms"]);
    }
    {
        const auto& S = O["uclass"];
        Set64(UClass::FuncMap_PairsData,  S["func_map_pairs_data"]);
        Set64(UClass::FuncMap_Num,        S["func_map_num"]);
        Set64(UClass::FuncMap_Max,        S["func_map_max"]);
        Set64(UClass::FuncMap_PairStride, S["func_map_pair_stride"]);
    }
    {
        const auto& S = O["ffield"];
        Set64(FField::VTable,        S["vtable"]);
        Set64(FField::ClassPrivate,  S["class_private"]);
        Set64(FField::Next,          S["next"]);
        Set64(FField::Owner,         S["owner"]);
        Set64(FField::NamePrivate,   S["name_private"]);
        Set64(FField::NameEncrypted, S["name_encrypted"]);
        Set64(FField::SaltSentinel,  S["salt_sentinel"]);
    }
    {
        const auto& S = O["ffield_class"];
        Set64(FFieldClass::ElementSize, S["element_size"]);
    }
    {
        const auto& S = O["fproperty"];
        Set64(FProperty::ArrayDim,        S["array_dim"]);
        Set64(FProperty::ElementSize,     S["element_size"]);
        Set64(FProperty::Offset_Internal, S["offset_internal"]);
        if (!S["offset_xor"].IsNull())
            FProperty::Offset_XOR = S["offset_xor"].Hex32();
        Set64(FProperty::PropertyFlags,   S["property_flags"]);
    }
    {
        const auto& S = O["fbool_property"];
        Set64(FBoolProperty::FieldSize,  S["field_size"]);
        Set64(FBoolProperty::ByteOffset, S["byte_offset"]);
        Set64(FBoolProperty::ByteMask,   S["byte_mask"]);
        Set64(FBoolProperty::FieldMask,  S["field_mask"]);
    }
    {
        const auto& S = O["fproperty_subclass"];
        Set64(FStructProperty::Struct,            S["fstruct_property__struct"]);
        Set64(FObjectProperty::PropertyClass,     S["fobject_property__property_class"]);
        Set64(FEnumProperty::UnderlyingProp,      S["fenum_property__underlying_prop"]);
        Set64(FEnumProperty::Enum,                S["fenum_property__enum"]);
        Set64(FArrayProperty::Inner,              S["farray_property__inner"]);
        Set64(FSetProperty::ElementProp,          S["fset_property__element_prop"]);
        Set64(FSoftObjectProperty::PropertyClass, S["fsoftobject_property__property_class"]);
        Set64(FMapProperty::KeyProp,              S["fmap_property__key_prop"]);
        Set64(FMapProperty::ValueProp,            S["fmap_property__value_prop"]);
    }
    {
        const auto& S = O["uworld"];
        Set64(UWorld::PersistentLevel, S["persistent_level"]);
        Set64(UWorld::Levels,          S["levels"]);
    }
    {
        const auto& S = O["uscene_component"];
        Set64(USceneComponent::ComponentToWorld, S["component_to_world"]);
    }

    std::printf("[config] loaded all ArcDecrypt::Offsets from config\n");
}

inline void LoadPatchConstants(const JsonValue& Root) {
    const auto& Pc = Root["patch_constants"];
    if (Pc.IsNull()) return;

    {
        const auto& S = Pc["patch20260421"];
        if (!S.IsNull()) {
            if (!S["entry_handle_xor"].IsNull())
                ArcDecrypt::Patch20260421::ENTRY_HANDLE_XOR = S["entry_handle_xor"].Hex64();
            if (!S["g_property_offset_xor"].IsNull())
                ArcDecrypt::Patch20260421::g_PropertyOffsetXor = S["g_property_offset_xor"].Hex32();
        }
    }

    std::printf("[config] loaded patch constants\n");
}

inline void LoadAutoDiscoveryVTables(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& V = Ad["vtables"];
    if (V.IsNull() || !V["valid"].Bool()) return;

    auto& Vt = AutoDiscovery::g_DiscoveredVTables;
    Vt.ScriptStructRVA = V["script_struct_rva"].Hex64();
    Vt.ClassNativeRVA  = V["class_native_rva"].Hex64();
    Vt.FunctionRVA     = V["function_rva"].Hex64();
    Vt.EnumRVA         = V["enum_rva"].Hex64();
    Vt.PackageRVA      = V["package_rva"].Hex64();
    Vt.BPGCRVA         = V["bpgc_rva"].Hex64();
    Vt.WBPGCRVA        = V["wbpgc_rva"].Hex64();
    Vt.SMBPGCRVA       = V["smbpgc_rva"].Hex64();
    Vt.AnimBPGCRVA     = V["anim_bpgc_rva"].Hex64();
    Vt.ASClassRVA      = V["asclass_rva"].Hex64();
    Vt.ASStructRVA     = V["asstruct_rva"].Hex64();

    const auto& AsF = V["asfunction_rvas"];
    if (AsF.IsArr()) {
        Vt.ASFunctionRVAs.clear();
        for (size_t I = 0; I < AsF.Size(); ++I)
            Vt.ASFunctionRVAs.push_back(AsF[I].Hex64());
    }

    std::printf("[config] loaded vtables: func=0x%llX enum=0x%llX pkg=0x%llX bpgc=0x%llX\n",
        (unsigned long long)Vt.FunctionRVA, (unsigned long long)Vt.EnumRVA,
        (unsigned long long)Vt.PackageRVA, (unsigned long long)Vt.BPGCRVA);
}

inline void LoadAutoDiscoveryUObjSlot(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& U = Ad["uobj_slot_decrypt"];
    if (U.IsNull() || !U["valid"].Bool()) return;

    auto& Slot = AutoDiscovery::g_DiscoveredUObjSlot;
    Slot.ShufMaskRVA = U["shuf_mask_rva"].Hex64();
    Slot.XorConstRVA = U["xor_const_rva"].Hex64();
    Slot.XorScalar   = U["xor_scalar"].Hex64();
    Slot.Rol64Amount = static_cast<int>(U["rol64_amount"].Int());

    const auto& Mb = U["shuf_mask_bytes"];
    if (Mb.IsArr()) {
        for (size_t I = 0; I < 8 && I < Mb.Size(); ++I)
            Slot.ShufMaskBytes[I] = static_cast<uint8_t>(Mb[I].Hex64());
    }

    Slot.Valid = true;

    std::printf("[config] loaded UObj slot decrypt: xor=0x%016llX rol=%d mask_rva=0x%llX\n",
        (unsigned long long)Slot.XorScalar, Slot.Rol64Amount,
        (unsigned long long)Slot.ShufMaskRVA);
}

inline void LoadAutoDiscoveryFProperty(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& F = Ad["fproperty_offset_xor"];
    if (F.IsNull() || !F["valid"].Bool()) return;

    auto& Fp = AutoDiscovery::g_DiscoveredFProperty;
    Fp.OffsetReaderRva = F["offset_reader_rva"].Hex64();
    Fp.OffsetInternal  = F["offset_internal"].Hex32();
    Fp.XorKey          = F["xor_key"].Hex32();
    Fp.ValidatedHits   = static_cast<int>(F["validated_hits"].Int());
    Fp.Valid           = true;

    ArcDecrypt::Patch20260421::g_PropertyOffsetXor = Fp.XorKey;

    std::printf("[config] loaded FProperty offset XOR: 0x%08X (%d sites)\n",
        Fp.XorKey, Fp.ValidatedHits);
}

inline void LoadAutoDiscoveryFFieldClassName(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& F = Ad["ffield_class_name"];
    if (F.IsNull() || !F["valid"].Bool()) return;

    auto& Fc = AutoDiscovery::g_DiscoveredFFieldClassName;
    Fc.XorConstRva       = F["xor_const_rva"].Hex64();
    Fc.XorLo64           = F["xor_lo64"].Hex64();
    Fc.FFieldClassOffset = F["ffield_class_offset"].Hex32();
    Fc.NamePrivateOffset = F["name_private_offset"].Hex32();
    Fc.PshuflwImm        = static_cast<uint8_t>(F["pshuflw_imm"].Int());
    Fc.Rol32Amount        = static_cast<uint8_t>(F["rol32_amount"].Int());
    Fc.Rol64Amount        = static_cast<uint8_t>(F["rol64_amount"].Int());
    Fc.ConsensusSiteCount = static_cast<int>(F["consensus_site_count"].Int());
    Fc.Valid              = true;

    std::printf("[config] loaded FFieldClass name decrypt: xor_lo64=0x%016llX pshuflw=0x%02X rol32=%d (%d sites)\n",
        (unsigned long long)Fc.XorLo64, Fc.PshuflwImm, Fc.Rol32Amount, Fc.ConsensusSiteCount);
}

inline void LoadAutoDiscoveryGNames(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& G = Ad["gnames"];
    if (G.IsNull() || !G["valid"].Bool()) return;

    auto& Gn = AutoDiscovery::g_DiscoveredGNames;
    Gn.GNamesRva     = G["gnames_rva"].Hex64();
    Gn.RefCount       = static_cast<int>(G["ref_count"].Int());
    Gn.SimdBlockRva   = G["simd_block_rva"].Hex64();
    Gn.SimdBlockRefs  = static_cast<int>(G["simd_block_refs"].Int());
    Gn.Valid           = true;

    std::printf("[config] loaded GNames: rva=0x%llX simd_block=0x%llX\n",
        (unsigned long long)Gn.GNamesRva, (unsigned long long)Gn.SimdBlockRva);
}

inline void LoadAutoDiscoveryFNameResolver(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& F = Ad["fname_resolver_consts"];
    if (F.IsNull() || !F["valid"].Bool()) return;

    auto& Fn = AutoDiscovery::g_DiscoveredFName;
    Fn.FunctionStartRva = F["function_start_rva"].Hex64();

    const auto& Imm64 = F["all_imm64"];
    if (Imm64.IsArr()) {
        Fn.AllImm64.clear();
        for (size_t I = 0; I < Imm64.Size(); ++I)
            Fn.AllImm64.push_back(Imm64[I].Hex64());
    }

    const auto& PsIm = F["all_pshuflw_imm"];
    if (PsIm.IsArr()) {
        Fn.AllPshuflwImm.clear();
        for (size_t I = 0; I < PsIm.Size(); ++I)
            Fn.AllPshuflwImm.push_back(static_cast<uint8_t>(PsIm[I].Hex64()));
    }

    const auto& RolIm = F["all_rol_imm"];
    if (RolIm.IsArr()) {
        Fn.AllRolImm.clear();
        for (size_t I = 0; I < RolIm.Size(); ++I)
            Fn.AllRolImm.push_back(static_cast<uint8_t>(RolIm[I].Hex64()));
    }

    const auto& Leas = F["all_rdata_leas"];
    if (Leas.IsArr()) {
        Fn.AllRDataLeas.clear();
        for (size_t I = 0; I < Leas.Size(); ++I)
            Fn.AllRDataLeas.push_back(Leas[I].Hex64());
    }

    Fn.Valid = true;

    std::printf("[config] loaded FName resolver consts: fn=0x%llX imm64s=%zu leas=%zu\n",
        (unsigned long long)Fn.FunctionStartRva, Fn.AllImm64.size(), Fn.AllRDataLeas.size());
}

inline void LoadAutoDiscoveryFFieldNameDecrypt(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& F = Ad["ffield_name_decrypt"];
    if (F.IsNull() || !F["valid"].Bool()) return;

    auto& Ff = AutoDiscovery::g_DiscoveredFFieldName;
    Ff.XorConst    = F["xor_const"].Hex64();
    Ff.Rol32Amount = static_cast<int>(F["rol32_amount"].Int());
    Ff.Rol64Amount = static_cast<int>(F["rol64_amount"].Int());
    Ff.Valid        = true;

    std::printf("[config] loaded FField name decrypt: xor=0x%016llX rol32=%d rol64=%d\n",
        (unsigned long long)Ff.XorConst, Ff.Rol32Amount, Ff.Rol64Amount);
}

inline void LoadAutoDiscoveryFNameKeystream(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& K = Ad["fname_keystream"];
    if (K.IsNull() || !K["valid"].Bool()) return;

    auto& Fk = AutoDiscovery::g_DiscoveredFNameKey;
    Fk.KeystreamRva = K["keystream_rva"].Hex64();
    Fk.ClusterBase  = K["cluster_base"].Hex64();
    Fk.WindowHits   = static_cast<int>(K["window_hits"].Int());
    Fk.Valid         = true;

    std::printf("[config] loaded FName keystream: rva=0x%llX cluster=0x%llX hits=%d\n",
        (unsigned long long)Fk.KeystreamRva, (unsigned long long)Fk.ClusterBase, Fk.WindowHits);
}

inline void LoadAutoDiscoveryGObjLayout(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& L = Ad["guobjarray_layout"];
    if (L.IsNull() || !L["valid"].Bool()) return;

    auto& Gl = AutoDiscovery::g_DiscoveredGObjLayout;
    Gl.StructAbs         = L["struct_abs"].Hex64();
    Gl.NumElementsOff    = L["num_elements_off"].Hex32();
    Gl.NumElements       = L["num_elements"].Hex32();
    Gl.ChunksArrayPtr    = L["chunks_array_ptr"].Hex64();
    Gl.NumChunks         = static_cast<int>(L["num_chunks"].Int());
    Gl.ValidChunksProbed = static_cast<int>(L["valid_chunks_probed"].Int());
    Gl.IndirectionDepth  = static_cast<int>(L["indirection_depth"].Int());

    const auto& Po = L["path_offsets"];
    if (Po.IsArr()) {
        Gl.PathOffsets.clear();
        for (size_t I = 0; I < Po.Size(); ++I)
            Gl.PathOffsets.push_back(Po[I].Hex32());
    }

    Gl.Valid = true;

    std::printf("[config] loaded GUObjectArray layout: num_elements=%u off=0x%X chunks=%d\n",
        Gl.NumElements, Gl.NumElementsOff, Gl.NumChunks);
}

inline void LoadAutoDiscoveryFClassGlobals(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& Arr = Ad["ffield_class_globals"];
    if (!Arr.IsArr() || Arr.Size() == 0) return;

    auto& Globals = AutoDiscovery::g_DiscoveredFClassGlobals;
    Globals.clear();
    for (size_t I = 0; I < Arr.Size(); ++I) {
        const auto& Item = Arr[I];
        AutoDiscovery::FFieldClassGlobal G;
        G.TargetRva = Item["target_rva"].Hex64();
        G.TypeName  = Item["type_name"].StrVal;
        G.Flags     = Item["flags"].Hex32();
        G.CastFlags = Item["cast_flags"].Hex32();
        Globals.push_back(std::move(G));
    }

    std::printf("[config] loaded %zu FFieldClass globals\n", Globals.size());
}

inline void LoadAutoDiscoveryWorld(const JsonValue& Root) {
    const auto& Ad = Root["autodiscovery"];
    if (Ad.IsNull()) return;

    const auto& W = Ad["world"];
    if (W.IsNull() || !W["valid"].Bool()) return;

    auto& Wd = AutoDiscovery::g_DiscoveredWorld;
    Wd.GWorldRva             = W["gworld_rva"].Hex64();
    Wd.GWorldAbs             = W["gworld_abs"].Hex64();
    Wd.PersistentLevelAbs    = W["persistent_level_abs"].Hex64();
    Wd.PersistentLevelOffset = W["persistent_level_offset"].Hex32();
    Wd.ActorsDataOffset      = W["actors_data_offset"].Hex32();
    Wd.ActorsCountOffset     = W["actors_count_offset"].Hex32();
    Wd.ActorsCount           = static_cast<uint32_t>(W["actors_count"].Int());
    Wd.DoubleDeref           = W["double_deref"].Bool();
    Wd.Valid                 = true;

    std::printf("[config] loaded world discovery: gworld_rva=0x%llX pl_off=0x%X actors=%u\n",
        (unsigned long long)Wd.GWorldRva, Wd.PersistentLevelOffset, Wd.ActorsCount);
}

struct LoadResult {
    bool Loaded = false;
    std::string Patch;
    int SectionsLoaded = 0;
};

inline LoadResult LoadDiscoveryConfig(const char* Path) {
    LoadResult Result;

    std::ifstream Ifs(Path);
    if (!Ifs) {
        std::printf("[config] %s not found — running full auto-discovery\n", Path);
        return Result;
    }

    std::string Content((std::istreambuf_iterator<char>(Ifs)),
                         std::istreambuf_iterator<char>());
    Ifs.close();

    if (Content.empty()) {
        std::printf("[config] %s is empty — running full auto-discovery\n", Path);
        return Result;
    }

    JsonValue Root = ParseJson(Content);
    if (!Root.IsObj()) {
        std::printf("[config] %s parse failed — running full auto-discovery\n", Path);
        return Result;
    }

    const auto& Schema = Root["schema"];
    if (!Schema.IsStr() || Schema.StrVal != "frostsdk.decrypt-export/v1") {
        std::printf("[config] %s has unknown schema '%s' — skipping\n",
            Path, Schema.IsStr() ? Schema.StrVal.c_str() : "(null)");
        return Result;
    }

    Result.Patch = Root["patch"].IsStr() ? Root["patch"].StrVal : "unknown";
    std::printf("[config] loading %s (patch %s, ts %s)\n",
        Path, Result.Patch.c_str(),
        Root["timestamp"].IsStr() ? Root["timestamp"].StrVal.c_str() : "?");

    LoadAnchors(Root);            Result.SectionsLoaded++;
    Result.SectionsLoaded++;
    LoadPatchConstants(Root);     Result.SectionsLoaded++;

    LoadAutoDiscoveryVTables(Root);          Result.SectionsLoaded++;
    LoadAutoDiscoveryUObjSlot(Root);         Result.SectionsLoaded++;
    LoadAutoDiscoveryFProperty(Root);        Result.SectionsLoaded++;
    LoadAutoDiscoveryFFieldClassName(Root);  Result.SectionsLoaded++;
    LoadAutoDiscoveryGNames(Root);           Result.SectionsLoaded++;
    LoadAutoDiscoveryFNameResolver(Root);    Result.SectionsLoaded++;
    LoadAutoDiscoveryFFieldNameDecrypt(Root); Result.SectionsLoaded++;
    LoadAutoDiscoveryFNameKeystream(Root);   Result.SectionsLoaded++;
    LoadAutoDiscoveryGObjLayout(Root);       Result.SectionsLoaded++;
    LoadAutoDiscoveryFClassGlobals(Root);    Result.SectionsLoaded++;
    LoadAutoDiscoveryWorld(Root);            Result.SectionsLoaded++;

    Result.Loaded = true;
    std::printf("[config] loaded %d sections from %s — auto-discovery will skip phases with valid cached data\n",
        Result.SectionsLoaded, Path);
    return Result;
}

}  // namespace ConfigLoader
