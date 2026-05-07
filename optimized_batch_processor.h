#pragma once
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <string>
#include <algorithm>

namespace FrostSDK {

struct BatchCIEntry {
    uint64_t SourceAddress;     // FField address
    uint32_t CompactIndex;      // Decrypted CI
    uint64_t PropertyOffset;    // Offset within struct
    std::string PropertyType;   // FBoolProperty, etc.
    std::string ResolvedName;   // Final resolved name
    bool IsResolved;
};

struct FunctionPointers {
    uint64_t FField_DecryptNamePrivate_CL1177678     = 0x353830;
    uint64_t FName_Index2Name_CL1177678              = 0x2311B0;
    uint64_t FName_ResolveCI_ToString_CL1177678      = 0x22EF40;
    uint64_t FNamePool_FindOrAdd_CL1177678           = 0x22D2E0;
    uint64_t UObject_FName_Equals_CL1177678          = 0x4CD5B0;
    uint64_t ChunksManager_Decrypt_CL1177678         = 0x4067A0;
    uint64_t FName_Constructor_FromString_CL1177678  = 0x22CB40;
};

class OptimizedBatchProcessor {
private:
    FunctionPointers Funcs;
    std::unordered_map<uint32_t, std::string> CIToNameCache;
    std::vector<BatchCIEntry> BatchEntries;
    uint64_t GameModuleBase;

public:
    OptimizedBatchProcessor(uint64_t module_base) : GameModuleBase(module_base) {
        AdjustFunctionPointers();
        InitializeCache();
    }

    void AdjustFunctionPointers() {
        Funcs.FField_DecryptNamePrivate_CL1177678    += GameModuleBase;
        Funcs.FName_Index2Name_CL1177678             += GameModuleBase;
        Funcs.FName_ResolveCI_ToString_CL1177678     += GameModuleBase;
        Funcs.FNamePool_FindOrAdd_CL1177678          += GameModuleBase;
        Funcs.UObject_FName_Equals_CL1177678         += GameModuleBase;
        Funcs.ChunksManager_Decrypt_CL1177678        += GameModuleBase;
        Funcs.FName_Constructor_FromString_CL1177678 += GameModuleBase;

        printf("[BatchProcessor] Function pointers adjusted to module base 0x%016llX\n", GameModuleBase);
    }

    void InitializeCache() {
        printf("[BatchProcessor] Initializing CI → name cache...\n");
        CIToNameCache.reserve(100000);

        std::vector<std::pair<uint32_t, std::string>> common_entries = {
            {1, "None"},
            {505, "Object"},
            {506, "Class"},
            {507, "ScriptStruct"},
            {508, "Function"},
            {509, "ByteProperty"},
            {510, "IntProperty"},
            {511, "BoolProperty"},
            {512, "FloatProperty"},
            {513, "ObjectProperty"},
            {514, "NameProperty"},
            {515, "StructProperty"},
            {516, "ArrayProperty"},
            {517, "StrProperty"},
            {518, "TextProperty"},
            {519, "DelegateProperty"},
            {520, "MulticastDelegateProperty"},
        };

        for (const auto& [ci, name] : common_entries) {
            CIToNameCache[ci] = name;
        }

        printf("[BatchProcessor] Cache initialized with %zu common entries\n", CIToNameCache.size());
    }

    void AddFFieldForProcessing(uint64_t ffield_addr, uint64_t property_offset, const std::string& property_type) {
        BatchCIEntry entry;
        entry.SourceAddress = ffield_addr;
        entry.PropertyOffset = property_offset;
        entry.PropertyType = property_type;
        entry.IsResolved = false;

        BatchEntries.push_back(entry);
    }

    int ProcessBatch() {
        printf("[BatchProcessor] Processing batch of %zu FField entries...\n", BatchEntries.size());

        int phase1_resolved = Phase1_DirectDecryption();
        int phase2_resolved = Phase2_CacheHits();
        int phase3_resolved = Phase3_LiveResolution();

        int total_resolved = phase1_resolved + phase2_resolved + phase3_resolved;

        printf("[BatchProcessor] Batch complete: %d/%zu resolved (%.1f%%)\n",
               total_resolved, BatchEntries.size(),
               (100.0 * total_resolved) / BatchEntries.size());

        printf("[BatchProcessor] Phase 1 (Direct): %d, Phase 2 (Cache): %d, Phase 3 (Live): %d\n",
               phase1_resolved, phase2_resolved, phase3_resolved);

        return total_resolved;
    }

    std::vector<BatchCIEntry> GetResolvedEntries() const {
        std::vector<BatchCIEntry> resolved;
        std::copy_if(BatchEntries.begin(), BatchEntries.end(), std::back_inserter(resolved),
                     [](const BatchCIEntry& entry) { return entry.IsResolved; });
        return resolved;
    }

    void ClearBatch() {
        BatchEntries.clear();
    }

    void OptimizeForLocality() {
        printf("[BatchProcessor] Optimizing batch for memory locality...\n");

        std::sort(BatchEntries.begin(), BatchEntries.end(),
                  [](const BatchCIEntry& a, const BatchCIEntry& b) {
                      return a.SourceAddress < b.SourceAddress;
                  });

        printf("[BatchProcessor] Batch sorted by address for optimal cache performance\n");
    }

private:
    int Phase1_DirectDecryption() {
        printf("[BatchProcessor] Phase 1: Direct FField NamePrivate decryption...\n");
        int resolved = 0;

        for (auto& entry : BatchEntries) {
            if (entry.IsResolved) continue;

            uint32_t ci = CallFFieldDecryptNamePrivate(entry.SourceAddress);
            if (ci != 0 && ci < 0x1000000) {  // Valid CI range
                entry.CompactIndex = ci;

                auto cache_it = CIToNameCache.find(ci);
                if (cache_it != CIToNameCache.end()) {
                    entry.ResolvedName = cache_it->second;
                    entry.IsResolved = true;
                    resolved++;
                }
            }
        }

        printf("[BatchProcessor] Phase 1 resolved: %d entries\n", resolved);
        return resolved;
    }

    int Phase2_CacheHits() {
        printf("[BatchProcessor] Phase 2: Cache lookup optimization...\n");
        int resolved = 0;

        std::vector<uint32_t> unique_cis;
        for (const auto& entry : BatchEntries) {
            if (!entry.IsResolved && entry.CompactIndex != 0) {
                if (std::find(unique_cis.begin(), unique_cis.end(), entry.CompactIndex) == unique_cis.end()) {
                    unique_cis.push_back(entry.CompactIndex);
                }
            }
        }

        printf("[BatchProcessor] Processing %zu unique CIs for cache expansion...\n", unique_cis.size());

        for (uint32_t ci : unique_cis) {
            if (CIToNameCache.find(ci) == CIToNameCache.end()) {
                std::string resolved_name = CallFNameIndex2Name(ci);
                if (!resolved_name.empty() && IsValidPropertyName(resolved_name)) {
                    CIToNameCache[ci] = resolved_name;
                }
            }
        }

        for (auto& entry : BatchEntries) {
            if (!entry.IsResolved && entry.CompactIndex != 0) {
                auto cache_it = CIToNameCache.find(entry.CompactIndex);
                if (cache_it != CIToNameCache.end()) {
                    entry.ResolvedName = cache_it->second;
                    entry.IsResolved = true;
                    resolved++;
                }
            }
        }

        printf("[BatchProcessor] Phase 2 resolved: %d entries\n", resolved);
        return resolved;
    }

    int Phase3_LiveResolution() {
        printf("[BatchProcessor] Phase 3: Live FName resolution...\n");
        int resolved = 0;

        for (auto& entry : BatchEntries) {
            if (!entry.IsResolved && entry.CompactIndex != 0) {
                std::string name = CallFNameResolveToString(entry.CompactIndex);
                if (!name.empty() && IsValidPropertyName(name)) {
                    entry.ResolvedName = name;
                    entry.IsResolved = true;
                    CIToNameCache[entry.CompactIndex] = name;
                    resolved++;
                }
            }
        }

        printf("[BatchProcessor] Phase 3 resolved: %d entries\n", resolved);
        return resolved;
    }

    uint32_t CallFFieldDecryptNamePrivate(uint64_t ffield_addr) {
        typedef uint64_t (*FFieldDecryptFunc)(uint64_t, void*, void*);
        auto func = reinterpret_cast<FFieldDecryptFunc>(Funcs.FField_DecryptNamePrivate_CL1177678);

        uint64_t fname_output = 0;

        try {
            func(0, &fname_output, reinterpret_cast<void*>(ffield_addr));
            return static_cast<uint32_t>(fname_output & 0xFFFFFFFF);
        } catch (...) {
            return 0;
        }
    }

    std::string CallFNameIndex2Name(uint32_t ci) {
        typedef uint32_t (*FNameIndex2NameFunc)(uint32_t*, char*);
        auto func = reinterpret_cast<FNameIndex2NameFunc>(Funcs.FName_Index2Name_CL1177678);

        char output_buffer[256] = {0};

        try {
            uint32_t length = func(&ci, output_buffer);
            if (length > 0 && length < 255) {
                return std::string(output_buffer, length);
            }
        } catch (...) {
            return "";
        }

        return "";
    }

    std::string CallFNameResolveToString(uint32_t ci) {
        typedef uint64_t (*FNameResolveFunc)(uint32_t*, char*);
        auto func = reinterpret_cast<FNameResolveFunc>(Funcs.FName_ResolveCI_ToString_CL1177678);

        char output_buffer[256] = {0};

        try {
            func(&ci, output_buffer);

            size_t len = strlen(output_buffer);
            if (len > 0 && len < 255) {
                return std::string(output_buffer, len);
            }
        } catch (...) {
            return "";
        }

        return "";
    }

    bool IsValidPropertyName(const std::string& name) {
        if (name.empty() || name.length() > 100) {
            return false;
        }

        if (name.find("Prop_CI") != std::string::npos) {
            return false;
        }

        int alpha_count = 0;
        for (char c : name) {
            if (c < 0x20 || c > 0x7E) {
                return false;
            }
            if (isalpha(c)) {
                alpha_count++;
            }
        }

        return alpha_count >= 2;
    }

public:
    void PrintCacheStatistics() const {
        printf("[BatchProcessor] Cache Statistics:\n");
        printf("[BatchProcessor]   Total entries: %zu\n", CIToNameCache.size());
        printf("[BatchProcessor]   Memory usage: ~%zu KB\n",
               (CIToNameCache.size() * 32) / 1024);

        std::unordered_map<char, int> prefix_counts;
        for (const auto& [ci, name] : CIToNameCache) {
            if (!name.empty()) {
                prefix_counts[name[0]]++;
            }
        }

        printf("[BatchProcessor]   Common prefixes: ");
        for (const auto& [prefix, count] : prefix_counts) {
            if (count >= 10) {
                printf("%c:%d ", prefix, count);
            }
        }
        printf("\n");
    }

    int GetCacheSize() const {
        return static_cast<int>(CIToNameCache.size());
    }

    int GetBatchSize() const {
        return static_cast<int>(BatchEntries.size());
    }
};

}

#include <iostream>
#include <iomanip>

namespace FrostSDK {

class BatchProcessorReporter {
public:
    static void PrintDetailedReport(const OptimizedBatchProcessor& processor) {
        auto resolved = processor.GetResolvedEntries();

        std::cout << "\n=== BATCH PROCESSING DETAILED REPORT ===\n";
        std::cout << std::setw(15) << "Address" << " | "
                  << std::setw(8) << "CI" << " | "
                  << std::setw(12) << "Offset" << " | "
                  << std::setw(20) << "Type" << " | "
                  << "Name\n";
        std::cout << std::string(80, '-') << "\n";

        int count = 0;
        for (const auto& entry : resolved) {
            if (count++ >= 50) {  // Limit output
                std::cout << "... and " << (resolved.size() - 50) << " more entries\n";
                break;
            }

            std::cout << std::hex << std::setw(15) << entry.SourceAddress << " | "
                      << std::dec << std::setw(8) << entry.CompactIndex << " | "
                      << std::hex << std::setw(12) << entry.PropertyOffset << " | "
                      << std::setw(20) << entry.PropertyType << " | "
                      << entry.ResolvedName << "\n";
        }

        std::cout << "=== END REPORT ===\n\n";
    }
};

}