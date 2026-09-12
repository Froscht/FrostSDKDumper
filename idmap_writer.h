#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>

#include "sdk_generator.h"
#include "auto_discovery.h"
#include "arc_decrypt.h"

namespace IdmapWriter {

struct IdmapStats {
    size_t VTableEntries = 0;
    size_t ExecFunctionEntries = 0;
    size_t GlobalEntries = 0;
    size_t TotalEntries = 0;
    size_t BytesWritten = 0;
};

static bool IdmapAppendEntry(std::vector<uint8_t>& Buf, uint32_t Rva, const std::string& Name) {
    if (Name.empty()) return false;
    if (Name.size() > 0xFFFF) return false;
    if (Rva == 0) return false;
    uint16_t Len = (uint16_t)Name.size();
    size_t Off = Buf.size();
    Buf.resize(Off + 4 + 2 + Len);
    std::memcpy(Buf.data() + Off,     &Rva, 4);
    std::memcpy(Buf.data() + Off + 4, &Len, 2);
    std::memcpy(Buf.data() + Off + 6, Name.data(), Len);
    return true;
}

static std::string SanitizeIdent(const std::string& S) {
    std::string Out;
    Out.reserve(S.size());
    for (char C : S) {
        if ((C >= 'A' && C <= 'Z') || (C >= 'a' && C <= 'z') ||
            (C >= '0' && C <= '9') || C == '_')
            Out.push_back(C);
        else
            Out.push_back('_');
    }
    if (!Out.empty() && Out[0] >= '0' && Out[0] <= '9')
        Out.insert(Out.begin(), '_');
    return Out;
}

static bool IsActorDescendant(const std::string& Name,
                              const std::unordered_map<std::string, std::string>& SuperMap) {
    std::string Cur = Name;
    std::unordered_set<std::string> Seen;
    for (int I = 0; I < 64; ++I) {
        if (Cur.empty()) return false;
        if (Cur == "Actor") return true;
        if (!Seen.insert(Cur).second) return false;
        auto It = SuperMap.find(Cur);
        if (It == SuperMap.end()) return false;
        Cur = It->second;
    }
    return false;
}

static std::string PrefixedTypeName(const SDKGen::StructRecord& Rec,
                                    const std::unordered_map<std::string, std::string>& SuperMap) {
    if (!Rec.is_class) return "F" + Rec.name;
    if (Rec.name == "Actor" || IsActorDescendant(Rec.name, SuperMap)) return "A" + Rec.name;
    if (Rec.name == "Interface" || Rec.name.rfind("I", 0) == 0) {
        // Some engine interfaces already carry an I-prefix in the bare name;
        // fall back to U-prefix for everything not clearly an Actor. Consumers
        // can adjust in the plugin if a specific class needs I/A instead.
    }
    return "U" + Rec.name;
}

// Write .idmap V1 file (packed {u32 RVA, u16 NameLen, char Name[]} records).
// No header, no length prefix — the plugin reads until EOF.
//
//   Sdk                — SDKResult from Generator::BuildSDK (structs w/ functions).
//   FPropertyVTableMap — Generator::m_vtable_to_type (RVA -> "FIntProperty" etc.).
//   EngineVTables      — AutoDiscovery::g_DiscoveredVTables (UClass/UStruct/... vtables).
//   Sheet              — ArcDecrypt::g_Sheet (GNamePool + chunks_manager RVAs).
//   OutPath            — target file (e.g. "SDK_Output.idmap").
static IdmapStats WriteIdmap(
    const SDKGen::SDKResult& Sdk,
    const std::unordered_map<uint64_t, std::string>& FPropertyVTableMap,
    const AutoDiscovery::VTableMap& EngineVTables,
    const ArcDecrypt::LiveSheet& Sheet,
    const std::string& OutPath)
{
    IdmapStats Stats{};
    std::vector<uint8_t> Buf;
    std::unordered_set<uint64_t> UsedRvas;   // dedupe: last-writer wins per RVA

    auto Emit = [&](uint64_t Rva, const std::string& Name) -> bool {
        if (Rva == 0 || Rva > 0xFFFFFFFFULL) return false;
        if (!UsedRvas.insert(Rva).second) return false;
        return IdmapAppendEntry(Buf, (uint32_t)Rva, Name);
    };

    // 1) VTables — engine base types. These name the .rdata vtable slots that
    //    every UClass / UScriptStruct / UFunction / etc. instance points at,
    //    so any (obj + 0) load in the disassembly types the object.
    struct EngineVt { uint64_t Rva; const char* Name; };
    const EngineVt EngineList[] = {
        { EngineVTables.ClassNativeRVA, "UClass_VFT" },
        { EngineVTables.ScriptStructRVA,"UScriptStruct_VFT" },
        { EngineVTables.FunctionRVA,    "UFunction_VFT" },
        { EngineVTables.EnumRVA,        "UEnum_VFT" },
        { EngineVTables.PackageRVA,     "UPackage_VFT" },
        { EngineVTables.BPGCRVA,        "UBlueprintGeneratedClass_VFT" },
        { EngineVTables.WBPGCRVA,       "UWidgetBlueprintGeneratedClass_VFT" },
        { EngineVTables.SMBPGCRVA,      "UStaticMeshBlueprintGeneratedClass_VFT" },
        { EngineVTables.AnimBPGCRVA,    "UAnimBlueprintGeneratedClass_VFT" },
        { EngineVTables.ASClassRVA,     "UASClass_VFT" },
        { EngineVTables.ASStructRVA,    "UASStruct_VFT" },
    };
    for (const auto& E : EngineList) {
        if (Emit(E.Rva, E.Name)) Stats.VTableEntries++;
    }
    // AngelScript function vtable pool: ~1 per script signature.
    for (size_t I = 0; I < EngineVTables.ASFunctionRVAs.size(); ++I) {
        char NameBuf[64];
        std::snprintf(NameBuf, sizeof(NameBuf), "UASFunction_%zu_VFT", I);
        if (Emit(EngineVTables.ASFunctionRVAs[I], NameBuf)) Stats.VTableEntries++;
    }

    // 2) FProperty subclass vtables — one per FProperty subtype (FIntProperty,
    //    FStructProperty, ...). Extracted at runtime by Generator::AutoDiscoverVTables
    //    and dumped to vtable_map.md. On patches where every FProperty shares
    //    a single vtable the map has one entry, which is still valuable.
    for (const auto& Kv : FPropertyVTableMap) {
        std::string TypeName = Kv.second;
        if (TypeName.empty()) continue;
        std::string Sanitized = SanitizeIdent(TypeName);
        if (Sanitized.empty()) continue;
        std::string EntryName = Sanitized + "_VFT";
        if (Emit(Kv.first, EntryName)) Stats.VTableEntries++;
    }

    // 3) Native (exec) UFunction implementations. UE compiles every
    //    `UFUNCTION(BlueprintCallable)` with a native impl into an
    //    exec<FunctionName> thunk whose address lives in the UFunction's
    //    NativeFunc pointer. FUNC_Native = 0x400.
    std::unordered_map<std::string, std::string> SuperMap;
    SuperMap.reserve(Sdk.structs.size());
    for (const auto& Rec : Sdk.structs) {
        if (!Rec.super_name.empty())
            SuperMap.emplace(Rec.name, Rec.super_name);
    }

    for (const auto& Rec : Sdk.structs) {
        if (Rec.drop) continue;
        if (Rec.functions.empty()) continue;
        std::string ClassPrefixed = PrefixedTypeName(Rec, SuperMap);
        std::string ClassSanitized = SanitizeIdent(ClassPrefixed);
        if (ClassSanitized.empty()) continue;
        for (const auto& Fn : Rec.functions) {
            if ((Fn.flags & 0x400ULL) == 0) continue;   // FUNC_Native
            if (Fn.native_rva == 0) continue;
            if (Fn.name.empty()) continue;
            std::string FnSanitized = SanitizeIdent(Fn.name);
            if (FnSanitized.empty()) continue;
            std::string EntryName = ClassSanitized + "__exec" + FnSanitized;
            if (Emit(Fn.native_rva, EntryName)) Stats.ExecFunctionEntries++;
        }
    }

    // 4) Global symbols. Only what the dumper has actually resolved is emitted;
    //    a zero RVA (e.g. UObject::ProcessEvent on v908 until dynamically
    //    resolved) is skipped by Emit() so the plugin does not stamp a wrong
    //    name on address 0.
    if (Emit(Sheet.Pool908Rva,                 "GNames"))                             Stats.GlobalEntries++;
    if (Emit(Sheet.ChunkMgr908Rva,             "GObjects"))                           Stats.GlobalEntries++;
    if (Emit(Sheet.FNameToString908Rva,        "FName__ToString"))                    Stats.GlobalEntries++;
    if (Emit(Sheet.FNameAppendString908Rva,    "FName__AppendString"))                Stats.GlobalEntries++;
    if (Emit(Sheet.UObjProcessEvent908Rva,     "UObject__ProcessEvent"))              Stats.GlobalEntries++;
    if (Emit(Sheet.UObjProcessInternal908Rva,  "UObject__ProcessInternal"))           Stats.GlobalEntries++;
    if (Emit(Sheet.FFrameStep908Rva,           "FFrame__Step"))                       Stats.GlobalEntries++;
    if (Emit(Sheet.FFramePrintCallstack908Rva, "FFrame__PrintScriptCallstack"))       Stats.GlobalEntries++;
    if (Emit(Sheet.BPThrowException908Rva,     "FBlueprintCoreDelegates__ThrowScriptException")) Stats.GlobalEntries++;
    if (Emit(Sheet.UFunctionInvoke908Rva,      "UFunction__Invoke"))                  Stats.GlobalEntries++;
    if (Emit(Sheet.ExBytecodeCallThunk908Rva,  "EX_Bytecode_CallThunk"))              Stats.GlobalEntries++;
    if (Emit(Sheet.ExBytecodeCallDecrypt908Rva,"EX_Bytecode_CallDecrypt"))            Stats.GlobalEntries++;

    Stats.TotalEntries = Stats.VTableEntries + Stats.ExecFunctionEntries + Stats.GlobalEntries;

    std::ofstream Out(OutPath, std::ios::binary | std::ios::trunc);
    if (!Out) return Stats;
    if (!Buf.empty())
        Out.write(reinterpret_cast<const char*>(Buf.data()), (std::streamsize)Buf.size());
    Out.close();
    Stats.BytesWritten = Buf.size();
    return Stats;
}

// Sibling ReadMe.txt describing the .idmap format and the consuming plugin.
// Written next to the .idmap so an end user opening the folder in IDA knows
// what to feed and where.
static bool WriteReadMe(const std::string& OutPath) {
    std::ofstream Rm(OutPath, std::ios::trunc);
    if (!Rm) return false;
    Rm << "/*\n"
          " * File generated by FrostSDKDumper (Dumper-7 compatible mapping)\n"
          " */\n\n"
          "Supported: IDA 7.7+ (incl. IDA 8.3, IDA 9.x)\n\n"
          "'.idmap' files import VFTable and Exec function names into IDA via:\n"
          "https://github.com/Fischsalat/IDAExecFunctionsImporter\n\n"
          "FileFormat:\n"
          "An '.idmap' file is a packed array of Identifier records (V1 legacy stream):\n"
          "struct Identifier {\n"
          "    uint32 Offset;            // RVA from image base\n"
          "    uint16 NameLength;\n"
          "    char   Name[NameLength];  // NOT null-terminated\n"
          "};\n\n"
          "Emitted entry categories:\n"
          "  * Engine vtables       (UClass_VFT, UScriptStruct_VFT, UFunction_VFT, ...)\n"
          "  * FProperty vtables    (FIntProperty_VFT, FStructProperty_VFT, ...)\n"
          "  * Native exec thunks   (<UClassName>__exec<FunctionName>) for every UFunction\n"
          "                          with FUNC_Native (0x400) set and a resolved NativeFunc\n"
          "  * Global symbols       (GNames, GObjects) — from the resolved LiveSheet\n";
    Rm.close();
    return true;
}

} // namespace IdmapWriter
