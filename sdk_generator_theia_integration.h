#pragma once

// =============================================================================
// FrostSDKDumper - Theia Integration Layer
//
// Integrates the complete Theia resolution system into the existing SDK generator.
// This file should be included AFTER sdk_generator.h and provides enhanced
// property name resolution using all discovered techniques.
// =============================================================================

#include "theia_master_resolver.h"
#include <fstream>
#include <sstream>

namespace SDKGen {

class TheiaIntegratedGenerator : public Generator {
private:
    std::unique_ptr<FrostSDK::TheiaMasterResolver> TheiaResolver;
    ResolutionStatistics LastResolutionStats;

public:
    TheiaIntegratedGenerator() : Generator() {
        // Initialize Theia resolver with game module info
        uint64_t module_base = 0x140000000;  // Wine default base
        uint64_t module_size = 0x10000000;   // Estimate ~256MB

        TheiaResolver = std::make_unique<FrostSDK::TheiaMasterResolver>(module_base, module_size);

        printf("[TheiaIntegrated] Enhanced SDK generator initialized\n");
    }

    // Override the main BuildSDK function to include Theia resolution
    SDKResult BuildSDK() override {
        printf("\n=== FROST SDK DUMPER - THEIA INTEGRATED BUILD ===\n");

        // Step 1: Run standard SDK generation
        printf("[TheiaIntegrated] Step 1: Running standard SDK generation...\n");
        SDKResult standard_result = Generator::BuildSDK();

        // Step 2: Extract placeholders from the results
        printf("[TheiaIntegrated] Step 2: Extracting placeholders for resolution...\n");
        auto placeholders = ExtractPlaceholdersFromSDK(standard_result);

        printf("[TheiaIntegrated] Found %zu placeholders to resolve\n", placeholders.size());

        // Step 3: Execute Theia resolution
        printf("[TheiaIntegrated] Step 3: Executing advanced Theia resolution...\n");
        TheiaResolver->LoadPlaceholders(placeholders);
        LastResolutionStats = TheiaResolver->ExecuteFullResolution();

        // Step 4: Apply resolved names back to SDK
        printf("[TheiaIntegrated] Step 4: Applying resolved names to SDK...\n");
        ApplyResolvedNamesToSDK(standard_result, TheiaResolver->GetAllPlaceholders());

        // Step 5: Generate enhanced output
        printf("[TheiaIntegrated] Step 5: Generating enhanced output files...\n");
        GenerateEnhancedOutput(standard_result);

        PrintFinalSummary(standard_result);

        return standard_result;
    }

private:
    std::vector<PlaceholderEntry> ExtractPlaceholdersFromSDK(const SDKResult& result) {
        std::vector<PlaceholderEntry> placeholders;

        // Extract from struct properties
        for (const auto& struct_rec : result.structs) {
            for (const auto& prop : struct_rec.properties) {
                if (IsPlaceholderName(prop.name)) {
                    PlaceholderEntry placeholder;
                    placeholder.OriginalName = prop.name;
                    placeholder.PropertyOffset = prop.offset;
                    placeholder.CompactIndex = ExtractCIFromName(prop.name);
                    placeholders.push_back(placeholder);
                }
            }

            // Extract from function parameters
            for (const auto& func : struct_rec.functions) {
                for (const auto& param : func.params) {
                    if (IsPlaceholderName(param.name)) {
                        PlaceholderEntry placeholder;
                        placeholder.OriginalName = param.name;
                        placeholder.PropertyOffset = param.offset;
                        placeholder.CompactIndex = ExtractCIFromName(param.name);
                        placeholders.push_back(placeholder);
                    }
                }
            }
        }

        return placeholders;
    }

    bool IsPlaceholderName(const std::string& name) {
        return name.find("Prop_CI") != std::string::npos ||
               name.find("Param_CI") != std::string::npos ||
               name.find("Field_") != std::string::npos ||
               (name.length() > 10 && name.substr(0, 4) == "Unk_");
    }

    uint32_t ExtractCIFromName(const std::string& name) {
        size_t ci_pos = name.find("CI");
        if (ci_pos == std::string::npos) return 0;

        size_t num_start = ci_pos + 2;
        while (num_start < name.length() && !isdigit(name[num_start])) {
            num_start++;
        }

        if (num_start >= name.length()) return 0;

        size_t num_end = num_start;
        while (num_end < name.length() && isdigit(name[num_end])) {
            num_end++;
        }

        if (num_end <= num_start) return 0;

        try {
            return static_cast<uint32_t>(std::stoul(name.substr(num_start, num_end - num_start)));
        } catch (...) {
            return 0;
        }
    }

    void ApplyResolvedNamesToSDK(SDKResult& result, const std::vector<PlaceholderEntry>& resolved_placeholders) {
        // Create mapping from original name to resolved name
        std::unordered_map<std::string, std::string> name_map;
        std::unordered_map<uint32_t, std::string> ci_map;

        for (const auto& placeholder : resolved_placeholders) {
            if (!placeholder.ResolvedName.empty()) {
                name_map[placeholder.OriginalName] = placeholder.ResolvedName;
                if (placeholder.CompactIndex != 0) {
                    ci_map[placeholder.CompactIndex] = placeholder.ResolvedName;
                }
            }
        }

        printf("[TheiaIntegrated] Applying %zu resolved names to SDK structures...\n", name_map.size());

        int applied_count = 0;

        // Apply to struct properties
        for (auto& struct_rec : result.structs) {
            for (auto& prop : struct_rec.properties) {
                auto it = name_map.find(prop.name);
                if (it != name_map.end()) {
                    prop.name = it->second;
                    applied_count++;
                } else {
                    // Try CI-based mapping
                    uint32_t ci = ExtractCIFromName(prop.name);
                    if (ci != 0) {
                        auto ci_it = ci_map.find(ci);
                        if (ci_it != ci_map.end()) {
                            prop.name = ci_it->second;
                            applied_count++;
                        }
                    }
                }
            }

            // Apply to function parameters
            for (auto& func : struct_rec.functions) {
                for (auto& param : func.params) {
                    auto it = name_map.find(param.name);
                    if (it != name_map.end()) {
                        param.name = it->second;
                        applied_count++;
                    } else {
                        // Try CI-based mapping
                        uint32_t ci = ExtractCIFromName(param.name);
                        if (ci != 0) {
                            auto ci_it = ci_map.find(ci);
                            if (ci_it != ci_map.end()) {
                                param.name = ci_it->second;
                                applied_count++;
                            }
                        }
                    }
                }
            }
        }

        printf("[TheiaIntegrated] Applied %d resolved names to SDK structures\n", applied_count);
    }

    void GenerateEnhancedOutput(const SDKResult& result) {
        // Generate standard SDK output
        GenerateSDKFiles(result);

        // Generate Theia resolution report
        GenerateTheiaResolutionReport();

        // Generate detailed analysis report
        GenerateDetailedAnalysisReport(result);
    }

    void GenerateSDKFiles(const SDKResult& result) {
        // Enhanced SDK_Output.txt with resolution statistics
        std::ofstream sdk_file("SDK_Output.txt");
        if (!sdk_file) {
            printf("[TheiaIntegrated] ERROR: Could not create SDK_Output.txt\n");
            return;
        }

        sdk_file << "// FrostSDKDumper Enhanced Output\n";
        sdk_file << "// Generated with Theia Resolution System\n";
        sdk_file << "// Resolution Statistics:\n";
        sdk_file << "//   Total Properties: " << LastResolutionStats.TotalPlaceholders << "\n";
        sdk_file << "//   Success Rate: " << std::fixed << std::setprecision(1)
                 << LastResolutionStats.SuccessRate << "%\n";
        sdk_file << "//   Processing Time: " << std::fixed << std::setprecision(1)
                 << LastResolutionStats.ProcessingTimeMs << " ms\n";
        sdk_file << "\n";

        // Generate namespace-organized output
        std::unordered_map<std::string, std::vector<const StructRecord*>> package_map;

        for (const auto& struct_rec : result.structs) {
            package_map[struct_rec.package].push_back(&struct_rec);
        }

        for (const auto& [package, structs] : package_map) {
            sdk_file << "namespace " << SanitizeNamespaceName(package) << " {\n\n";

            for (const auto* struct_rec : structs) {
                GenerateStructOutput(sdk_file, *struct_rec);
            }

            sdk_file << "} // namespace " << SanitizeNamespaceName(package) << "\n\n";
        }

        printf("[TheiaIntegrated] Generated enhanced SDK_Output.txt\n");
    }

    void GenerateStructOutput(std::ofstream& file, const StructRecord& struct_rec) {
        file << "// " << (struct_rec.is_class ? "Class" : "Struct") << " " << struct_rec.name;
        if (!struct_rec.super_name.empty()) {
            file << " : " << struct_rec.super_name;
        }
        file << " (Size: 0x" << std::hex << std::uppercase << struct_rec.props_size << std::dec << ")\n";

        file << (struct_rec.is_class ? "class " : "struct ") << struct_rec.name;
        if (!struct_rec.super_name.empty()) {
            file << " : public " << struct_rec.super_name;
        }
        file << " {\npublic:\n";

        // Sort properties by offset for clean output
        auto sorted_props = struct_rec.properties;
        std::sort(sorted_props.begin(), sorted_props.end(),
                  [](const PropertyRecord& a, const PropertyRecord& b) {
                      return a.offset < b.offset;
                  });

        for (const auto& prop : sorted_props) {
            file << "    " << prop.type_name << " " << prop.name;

            if (prop.array_dim > 1) {
                file << "[" << prop.array_dim << "]";
            }

            file << "; // 0x" << std::hex << std::uppercase << prop.offset;
            if (prop.elem_size > 0) {
                file << " (Size: 0x" << prop.elem_size << ")";
            }
            file << std::dec << "\n";
        }

        // Add functions if any
        if (!struct_rec.functions.empty()) {
            file << "\n    // Functions:\n";
            for (const auto& func : struct_rec.functions) {
                file << "    // " << func.name << " (Flags: 0x"
                     << std::hex << func.flags << std::dec << ")\n";
            }
        }

        file << "};\n\n";
    }

    void GenerateTheiaResolutionReport() {
        std::ofstream report_file("Theia_Resolution_Report.txt");
        if (!report_file) {
            printf("[TheiaIntegrated] ERROR: Could not create Theia_Resolution_Report.txt\n");
            return;
        }

        auto unresolved = TheiaResolver->GetUnresolvedPlaceholders();

        report_file << "THEIA RESOLUTION DETAILED REPORT\n";
        report_file << "Generated: " << __DATE__ << " " << __TIME__ << "\n";
        report_file << "================================\n\n";

        report_file << "RESOLUTION STATISTICS:\n";
        report_file << "Total Placeholders:        " << LastResolutionStats.TotalPlaceholders << "\n";
        report_file << "Resolved by BLAKE3:        " << LastResolutionStats.ResolvedByBlake3 << "\n";
        report_file << "Resolved by Pattern Scan:  " << LastResolutionStats.ResolvedByPatternScan << "\n";
        report_file << "Resolved by Batch Proc:    " << LastResolutionStats.ResolvedByBatchProcessor << "\n";
        report_file << "Resolved by Epic Fallback: " << LastResolutionStats.ResolvedByEpicFallback << "\n";
        report_file << "Remaining Unresolved:      " << LastResolutionStats.RemainingUnresolved << "\n";
        report_file << "Success Rate:              " << std::fixed << std::setprecision(1)
                    << LastResolutionStats.SuccessRate << "%\n";
        report_file << "Processing Time:           " << std::fixed << std::setprecision(1)
                    << LastResolutionStats.ProcessingTimeMs << " ms\n\n";

        if (!unresolved.empty()) {
            report_file << "UNRESOLVED PLACEHOLDERS (" << unresolved.size() << "):\n";
            report_file << "----------------------------------------\n";

            for (size_t i = 0; i < std::min(unresolved.size(), size_t(100)); ++i) {
                const auto& placeholder = unresolved[i];
                report_file << std::setw(6) << (i + 1) << ". "
                           << std::setw(20) << placeholder.OriginalName
                           << " CI:" << std::setw(8) << placeholder.CompactIndex
                           << " Offset:0x" << std::hex << placeholder.PropertyOffset << std::dec << "\n";
            }

            if (unresolved.size() > 100) {
                report_file << "... and " << (unresolved.size() - 100) << " more entries\n";
            }
        }

        printf("[TheiaIntegrated] Generated Theia_Resolution_Report.txt\n");
    }

    void GenerateDetailedAnalysisReport(const SDKResult& result) {
        std::ofstream analysis_file("Detailed_Analysis_Report.txt");
        if (!analysis_file) {
            printf("[TheiaIntegrated] ERROR: Could not create Detailed_Analysis_Report.txt\n");
            return;
        }

        analysis_file << "FROSTSDKDUMPER DETAILED ANALYSIS REPORT\n";
        analysis_file << "Generated: " << __DATE__ << " " << __TIME__ << "\n";
        analysis_file << "=======================================\n\n";

        // SDK Statistics
        int total_properties = 0;
        int total_functions = 0;
        int named_properties = 0;

        for (const auto& struct_rec : result.structs) {
            total_properties += static_cast<int>(struct_rec.properties.size());
            total_functions += static_cast<int>(struct_rec.functions.size());

            for (const auto& prop : struct_rec.properties) {
                if (!IsPlaceholderName(prop.name)) {
                    named_properties++;
                }
            }
        }

        analysis_file << "SDK STATISTICS:\n";
        analysis_file << "Structures:        " << result.structs.size() << "\n";
        analysis_file << "Enumerations:      " << result.enums.size() << "\n";
        analysis_file << "Total Properties:  " << total_properties << "\n";
        analysis_file << "Named Properties:  " << named_properties << "\n";
        analysis_file << "Property Coverage: " << std::fixed << std::setprecision(1)
                      << (100.0 * named_properties / total_properties) << "%\n";
        analysis_file << "Total Functions:   " << total_functions << "\n\n";

        // Package distribution
        std::unordered_map<std::string, int> package_counts;
        for (const auto& struct_rec : result.structs) {
            package_counts[struct_rec.package]++;
        }

        analysis_file << "PACKAGE DISTRIBUTION:\n";
        for (const auto& [package, count] : package_counts) {
            analysis_file << std::setw(30) << package << ": " << count << " structures\n";
        }

        printf("[TheiaIntegrated] Generated Detailed_Analysis_Report.txt\n");
    }

    std::string SanitizeNamespaceName(const std::string& package) {
        std::string result = package;

        // Remove /Script/ prefix
        if (result.substr(0, 8) == "/Script/") {
            result = result.substr(8);
        }

        // Replace invalid characters
        std::replace(result.begin(), result.end(), '/', '_');
        std::replace(result.begin(), result.end(), '.', '_');
        std::replace(result.begin(), result.end(), '-', '_');

        // Ensure it starts with a letter
        if (!result.empty() && !std::isalpha(result[0])) {
            result = "Namespace_" + result;
        }

        return result.empty() ? "Default" : result;
    }

    void PrintFinalSummary(const SDKResult& result) {
        printf("\n");
        printf("================================================================\n");
        printf("          FROSTSDKDUMPER - THEIA INTEGRATED - COMPLETE         \n");
        printf("================================================================\n");
        printf("Structures Generated:      %8zu\n", result.structs.size());
        printf("Enumerations Generated:    %8zu\n", result.enums.size());
        printf("Property Resolution Rate:  %8.1f%%\n", LastResolutionStats.SuccessRate);
        printf("Total Processing Time:     %8.1f ms\n", LastResolutionStats.ProcessingTimeMs);

        if (LastResolutionStats.SuccessRate >= 99.0) {
            printf("\n🎉 DUMPER FUNCTIONALLY COMPLETE - 99%+ RESOLUTION ACHIEVED! 🎉\n");
        } else if (LastResolutionStats.SuccessRate >= 95.0) {
            printf("\n✅ DUMPER HIGHLY FUNCTIONAL - 95%+ RESOLUTION ACHIEVED!\n");
        } else {
            printf("\n⚠️  DUMPER FUNCTIONAL - OPTIMIZATION OPPORTUNITIES REMAIN\n");
        }

        printf("================================================================\n");
        printf("Output Files Generated:\n");
        printf("  • SDK_Output.txt - Enhanced SDK with resolved names\n");
        printf("  • Theia_Resolution_Report.txt - Detailed resolution analysis\n");
        printf("  • Detailed_Analysis_Report.txt - Comprehensive statistics\n");
        printf("================================================================\n");
    }

public:
    ResolutionStatistics GetLastResolutionStats() const {
        return LastResolutionStats;
    }

    // Utility function to test the Theia resolver independently
    void TestTheiaResolutionOnly() {
        printf("[TheiaIntegrated] Testing Theia resolution system independently...\n");

        // Create sample placeholders for testing
        std::vector<PlaceholderEntry> test_placeholders = {
            {"Prop_CI505_Off0x250", 505, 0x250, "", ""},
            {"Prop_CI1_Off0x0", 1, 0x0, "", ""},
            {"Prop_CI22529_0x1B8", 22529, 0x1B8, "", ""},
            {"Prop_CI36866_0x148", 36866, 0x148, "", ""},
        };

        for (auto& p : test_placeholders) {
            if (p.CompactIndex != 0) {
                // Mark as potential Theia opaque
            }
        }

        TheiaResolver->LoadPlaceholders(test_placeholders);
        ResolutionStatistics test_stats = TheiaResolver->ExecuteFullResolution();

        printf("[TheiaIntegrated] Test complete - resolved %d/%d placeholders\n",
               test_stats.TotalPlaceholders - test_stats.RemainingUnresolved,
               test_stats.TotalPlaceholders);
    }
};

} // namespace SDKGen