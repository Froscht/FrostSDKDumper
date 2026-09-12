#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <unordered_map>

#include "sdk_generator.h"

namespace UsmapWriter {

static int32_t UsmapAddName(std::vector<uint8_t>& NameTable,
                            std::unordered_map<std::string, int32_t>& NameLookup,
                            int32_t& NameCounter,
                            const std::string& Name) {
    auto It = NameLookup.find(Name);
    if (It != NameLookup.end()) return It->second;
    int32_t Idx = NameCounter++;
    NameLookup[Name] = Idx;
    uint8_t Len = (uint8_t)std::min<size_t>(Name.size(), 255);
    NameTable.push_back(Len);
    NameTable.insert(NameTable.end(), Name.begin(), Name.begin() + Len);
    return Idx;
}

template <typename T>
static void UsmapWrite(std::vector<uint8_t>& Buf, T V) {
    const uint8_t* P = reinterpret_cast<const uint8_t*>(&V);
    Buf.insert(Buf.end(), P, P + sizeof(T));
}

static uint8_t MappingTypeFromFieldClass(const std::string& Fc) {
    if (Fc == "ByteProperty")              return 0;
    if (Fc == "BoolProperty")              return 1;
    if (Fc == "IntProperty")               return 2;
    if (Fc == "FloatProperty")             return 3;
    if (Fc == "ObjectProperty")            return 4;
    if (Fc == "NameProperty")              return 5;
    if (Fc == "DelegateProperty")          return 6;
    if (Fc == "DoubleProperty")            return 7;
    if (Fc == "ArrayProperty")             return 8;
    if (Fc == "StructProperty")            return 9;
    if (Fc == "StrProperty")               return 10;
    if (Fc == "TextProperty")              return 11;
    if (Fc == "InterfaceProperty")         return 12;
    if (Fc == "MulticastDelegateProperty") return 13;
    if (Fc == "WeakObjectProperty")        return 14;
    if (Fc == "LazyObjectProperty")        return 15;
    if (Fc == "AssetObjectProperty")       return 16;
    if (Fc == "SoftObjectProperty")        return 17;
    if (Fc == "UInt64Property")            return 18;
    if (Fc == "UInt32Property")            return 19;
    if (Fc == "UInt16Property")            return 20;
    if (Fc == "Int64Property")             return 21;
    if (Fc == "Int16Property")             return 22;
    if (Fc == "Int8Property")              return 23;
    if (Fc == "MapProperty")               return 24;
    if (Fc == "SetProperty")               return 25;
    if (Fc == "EnumProperty")              return 26;
    if (Fc == "FieldPathProperty")         return 27;
    if (Fc == "OptionalProperty")          return 28;
    if (Fc == "Utf8StrProperty")           return 29;
    if (Fc == "AnsiStrProperty")           return 30;
    return 0xFF;
}

static bool StartsWith(const std::string& S, const char* Prefix) {
    size_t Pl = 0; while (Prefix[Pl]) ++Pl;
    if (S.size() < Pl) return false;
    for (size_t I = 0; I < Pl; ++I) if (S[I] != Prefix[I]) return false;
    return true;
}

static std::string PropertyTypeToFieldClass(const std::string& Tn,
                                            const std::unordered_map<std::string, bool>& KnownEnums) {
    if (Tn.empty()) return "";

    if (StartsWith(Tn, "TArray<"))          return "ArrayProperty";
    if (StartsWith(Tn, "TMap<"))            return "MapProperty";
    if (StartsWith(Tn, "TSet<"))            return "SetProperty";
    if (StartsWith(Tn, "TSubclassOf<"))     return "ClassProperty";
    if (StartsWith(Tn, "TSoftClassPtr<"))   return "SoftClassProperty";
    if (StartsWith(Tn, "TWeakObjectPtr<"))  return "WeakObjectProperty";
    if (StartsWith(Tn, "TLazyObjectPtr<"))  return "LazyObjectProperty";
    if (StartsWith(Tn, "TSoftObjectPtr<"))  return "SoftObjectProperty";
    if (StartsWith(Tn, "TScriptInterface<"))return "InterfaceProperty";
    if (StartsWith(Tn, "TDelegate<"))       return "DelegateProperty";
    if (StartsWith(Tn, "TFieldPath<"))      return "FieldPathProperty";
    if (StartsWith(Tn, "TOptional<"))       return "OptionalProperty";

    if (!Tn.empty() && Tn.back() == '*')    return "ObjectProperty";

    if (Tn == "bool")     return "BoolProperty";
    if (Tn == "uint8_t")  return "ByteProperty";
    if (Tn == "uint16_t") return "UInt16Property";
    if (Tn == "uint32_t") return "UInt32Property";
    if (Tn == "uint64_t") return "UInt64Property";
    if (Tn == "int8_t")   return "Int8Property";
    if (Tn == "int16_t")  return "Int16Property";
    if (Tn == "int32_t")  return "IntProperty";
    if (Tn == "int64_t")  return "Int64Property";
    if (Tn == "float")    return "FloatProperty";
    if (Tn == "double")   return "DoubleProperty";
    if (Tn == "FName")    return "NameProperty";
    if (Tn == "FString")  return "StrProperty";
    if (Tn == "FText")    return "TextProperty";

    if (Tn.size() > 1 && Tn[0] == 'F' && Tn.find("Property") != std::string::npos) {
        return Tn.substr(1);
    }

    if (KnownEnums.count(Tn)) return "EnumProperty";

    return "StructProperty";
}

static std::string StripTypePrefix(const std::string& S) {
    if (S.size() > 1 && (S[0] == 'U' || S[0] == 'A' || S[0] == 'F')) {
        bool Upper = S.size() > 1 && S[1] >= 'A' && S[1] <= 'Z';
        if (Upper) return S.substr(1);
    }
    return S;
}

static void WriteUsmap(const SDKGen::SDKResult& Sdk, const std::string& OutPath) {
    std::vector<uint8_t> NameTable;
    std::unordered_map<std::string, int32_t> NameLookup;
    int32_t NameCounter = 0;

    std::vector<uint8_t> EnumPayload;
    std::vector<uint8_t> StructPayload;
    uint32_t NumEnums = 0;
    uint32_t NumStructs = 0;

    std::unordered_map<std::string, bool> KnownEnums;
    for (const auto& E : Sdk.enums) KnownEnums[E.name] = true;

    for (const auto& E : Sdk.enums) {
        int32_t EnNameIdx = UsmapAddName(NameTable, NameLookup, NameCounter, E.name);
        UsmapWrite<int32_t>(EnumPayload, EnNameIdx);
        UsmapWrite<uint16_t>(EnumPayload, (uint16_t)std::min<size_t>(E.entries.size(), 65535));
        size_t Limit = std::min<size_t>(E.entries.size(), 65535);
        for (size_t I = 0; I < Limit; ++I) {
            const auto& En = E.entries[I];
            int32_t VnIdx = UsmapAddName(NameTable, NameLookup, NameCounter, En.name);
            UsmapWrite<uint64_t>(EnumPayload, (uint64_t)En.value);
            UsmapWrite<int32_t>(EnumPayload, VnIdx);
        }
        NumEnums++;
    }

    for (const auto& S : Sdk.structs) {
        if (S.drop) continue;
        int32_t StNameIdx = UsmapAddName(NameTable, NameLookup, NameCounter, S.name);
        int32_t SuperIdx = -1;
        if (!S.super_name.empty()) {
            std::string Sup = StripTypePrefix(S.super_name);
            SuperIdx = UsmapAddName(NameTable, NameLookup, NameCounter, Sup);
        }
        UsmapWrite<int32_t>(StructPayload, StNameIdx);
        UsmapWrite<int32_t>(StructPayload, SuperIdx);

        uint16_t PropCount = 0;
        uint16_t PropSerializable = (uint16_t)std::min<size_t>(S.properties.size(), 65535);
        for (const auto& P : S.properties) {
            uint32_t Ad = P.array_dim > 0 ? P.array_dim : 1;
            uint32_t Next = (uint32_t)PropCount + Ad;
            PropCount = (uint16_t)std::min<uint32_t>(Next, 65535);
        }
        UsmapWrite<uint16_t>(StructPayload, PropCount);
        UsmapWrite<uint16_t>(StructPayload, PropSerializable);

        int32_t SchemaIdx = 0;
        size_t PropLimit = std::min<size_t>(S.properties.size(), 65535);
        for (size_t I = 0; I < PropLimit; ++I) {
            const auto& P = S.properties[I];
            int32_t Ad = P.array_dim > 0 ? (int32_t)P.array_dim : 1;
            UsmapWrite<int32_t>(StructPayload, SchemaIdx);
            UsmapWrite<int32_t>(StructPayload, Ad);
            int32_t NIdx = UsmapAddName(NameTable, NameLookup, NameCounter, P.name);
            UsmapWrite<int32_t>(StructPayload, NIdx);
            std::string Fc = PropertyTypeToFieldClass(P.type_name, KnownEnums);
            UsmapWrite<uint8_t>(StructPayload, MappingTypeFromFieldClass(Fc));
            SchemaIdx += Ad;
        }
        NumStructs++;
    }

    std::vector<uint8_t> Data;
    UsmapWrite<uint32_t>(Data, (uint32_t)NameCounter);
    Data.insert(Data.end(), NameTable.begin(), NameTable.end());
    UsmapWrite<uint32_t>(Data, NumEnums);
    Data.insert(Data.end(), EnumPayload.begin(), EnumPayload.end());
    UsmapWrite<uint32_t>(Data, NumStructs);
    Data.insert(Data.end(), StructPayload.begin(), StructPayload.end());

    std::ofstream Usmap(OutPath, std::ios::binary);
    if (!Usmap) return;
    uint16_t Magic = 0x30C4;
    uint8_t  Version = 4;
    int32_t  HasVersioning = 0;
    uint8_t  CompMethod = 0;
    uint32_t UncSize = (uint32_t)Data.size();
    uint32_t CmpSize = UncSize;
    Usmap.write(reinterpret_cast<const char*>(&Magic), 2);
    Usmap.write(reinterpret_cast<const char*>(&Version), 1);
    Usmap.write(reinterpret_cast<const char*>(&HasVersioning), 4);
    Usmap.write(reinterpret_cast<const char*>(&CompMethod), 1);
    Usmap.write(reinterpret_cast<const char*>(&CmpSize), 4);
    Usmap.write(reinterpret_cast<const char*>(&UncSize), 4);
    if (!Data.empty())
        Usmap.write(reinterpret_cast<const char*>(Data.data()), Data.size());
    Usmap.close();
}

} // namespace UsmapWriter
