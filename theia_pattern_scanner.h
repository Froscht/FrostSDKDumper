#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>

namespace TheiaResolver {

struct TheiaKeyCandidate {
    uint64_t Address;
    std::string KeyString;
    std::vector<uint8_t> KeyBytes;
    uint32_t XRefCount;
    bool IsValidated;
    std::string DecryptionType; // "COMPLEX", "MASK", "XOR"
};

class TheiaPatternScanner {
private:
    std::vector<TheiaKeyCandidate> FoundKeys;
    uint64_t ModuleBase;
    uint64_t ModuleSize;

public:
    TheiaPatternScanner(uint64_t module_base, uint64_t module_size)
        : ModuleBase(module_base), ModuleSize(module_size) {}

    std::vector<TheiaKeyCandidate> ScanFor16ByteKeys() {
        printf("[TheiaScanner] Scanning for 16-byte Theia encryption keys...\n");
        printf("[TheiaScanner] Module: 0x%016llX - 0x%016llX (%llu MB)\n",
               ModuleBase, ModuleBase + ModuleSize, ModuleSize / (1024*1024));

        FoundKeys.clear();

        uint8_t* memory = reinterpret_cast<uint8_t*>(ModuleBase);

        for (uint64_t offset = 0; offset < ModuleSize - 16; offset++) {
            if (IsValidKeyPattern(memory + offset)) {
                TheiaKeyCandidate candidate;
                candidate.Address = ModuleBase + offset;
                candidate.KeyBytes.assign(memory + offset, memory + offset + 16);
                candidate.KeyString = BytesToString(candidate.KeyBytes);
                candidate.XRefCount = 0;
                candidate.IsValidated = false;

                if (IsKnownKeyPattern(candidate.KeyString)) {
                    candidate.DecryptionType = GetDecryptionType(candidate.KeyString);
                    FoundKeys.push_back(candidate);

                    printf("[TheiaScanner] Found key candidate: %s @ 0x%016llX\n",
                           candidate.KeyString.c_str(), candidate.Address);
                }
            }
        }

        printf("[TheiaScanner] Found %zu key candidates\n", FoundKeys.size());
        return FoundKeys;
    }

    void ValidateKeysWithXRefs() {
        printf("[TheiaScanner] Validating keys with cross-reference analysis...\n");

        for (auto& key : FoundKeys) {
            key.XRefCount = CountXRefsToAddress(key.Address);
            key.IsValidated = (key.XRefCount > 0);

            printf("[TheiaScanner] Key %s: %u xrefs %s\n",
                   key.KeyString.c_str(), key.XRefCount,
                   key.IsValidated ? "(VALID)" : "(unused)");
        }

        auto it = std::remove_if(FoundKeys.begin(), FoundKeys.end(),
                                 [](const TheiaKeyCandidate& k) { return !k.IsValidated; });
        FoundKeys.erase(it, FoundKeys.end());

        printf("[TheiaScanner] %zu validated keys after xref analysis\n", FoundKeys.size());
    }

    std::vector<std::string> ExtractDecryptedStrings() {
        std::vector<std::string> decrypted_strings;

        for (const auto& key : FoundKeys) {
            printf("[TheiaScanner] Attempting decryption with key: %s (%s)\n",
                   key.KeyString.c_str(), key.DecryptionType.c_str());

            auto strings = DecryptWithKey(key);
            decrypted_strings.insert(decrypted_strings.end(), strings.begin(), strings.end());

            printf("[TheiaScanner] Decrypted %zu strings with this key\n", strings.size());
        }

        return decrypted_strings;
    }

    void SearchForKnownPatterns() {
        printf("[TheiaScanner] Searching for known Theia key patterns...\n");

        std::vector<std::string> known_patterns = {
            "nx0iddGJKTuY8aPM",    // EAAntiCheat System #1 [COMPLEX]
            "IA8Rqe26hOWAuRdc",    // EAAntiCheat System #2 [MASK]
            "OrNylIsyUBCakCbT",    // EAAntiCheat System #3 [MASK]
            "M7RjaEDGb0beKKGd",    // EAAntiCheat System #4 [MASK]
            "7xGJNkJyKp5gldlm",    // EAAntiCheat System #5 [MASK]
            "tdTLI6xplzveLHBX",    // EAAntiCheat System #6 [MASK]
            "1OP08h3KujXeZneJ",    // EAAntiCheat System #7 [MASK]
            "W6kA5jrGs75tJ4wG",    // EAAntiCheat System #8 [MASK]
            "jJp6OWRX9L8CBcJ8",    // EAAntiCheat System #9 [MASK]
            "rcUmx7IfG6hZlahz",    // Additional patterns from theia.txt
            "nVSS4ctMNUcBj1wq",
            "JO8kTldAq5Hkcp4Q",
            "6lFE1IUbJLeHSWch",
            "OSB3UjRQFcchaxRT",
            "WhOTWDtRGqClZluv"
        };

        for (const auto& pattern : known_patterns) {
            uint64_t found_addr = FindStringPattern(pattern);
            if (found_addr != 0) {
                printf("[TheiaScanner] Found known pattern '%s' at 0x%016llX\n",
                       pattern.c_str(), found_addr);

                TheiaKeyCandidate candidate;
                candidate.Address = found_addr;
                candidate.KeyString = pattern;
                candidate.KeyBytes.assign(pattern.begin(), pattern.end());
                candidate.DecryptionType = GetDecryptionType(pattern);
                candidate.IsValidated = true;
                FoundKeys.push_back(candidate);
            }
        }
    }

private:
    bool IsValidKeyPattern(const uint8_t* data) {
        for (int i = 0; i < 16; ++i) {
            uint8_t byte = data[i];
            if (byte < 0x20 || byte > 0x7E) {
                return false;
            }
        }

        int alpha_count = 0;
        int digit_count = 0;
        for (int i = 0; i < 16; ++i) {
            if (isalpha(data[i])) alpha_count++;
            if (isdigit(data[i])) digit_count++;
        }

        return (alpha_count >= 8 && alpha_count <= 14) &&
               (digit_count >= 2 && digit_count <= 8);
    }

    bool IsKnownKeyPattern(const std::string& key) {
        return key.length() == 16 &&
               std::all_of(key.begin(), key.end(), [](char c) {
                   return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9');
               });
    }

    std::string GetDecryptionType(const std::string& key) {
        std::vector<std::string> complex_keys = {"nx0iddGJKTuY8aPM"};

        if (std::find(complex_keys.begin(), complex_keys.end(), key) != complex_keys.end()) {
            return "COMPLEX";
        }

        return "MASK";
    }

    std::string BytesToString(const std::vector<uint8_t>& bytes) {
        std::string result;
        result.reserve(bytes.size());
        for (uint8_t byte : bytes) {
            result.push_back(static_cast<char>(byte));
        }
        return result;
    }

    uint32_t CountXRefsToAddress(uint64_t target_addr) {
        uint32_t xref_count = 0;
        uint8_t* memory = reinterpret_cast<uint8_t*>(ModuleBase);

        for (uint64_t offset = 0; offset < ModuleSize - 8; offset += 4) {
            uint64_t potential_ptr = *reinterpret_cast<uint64_t*>(memory + offset);

            if (potential_ptr == target_addr) {
                xref_count++;
            }

            uint32_t potential_rva = *reinterpret_cast<uint32_t*>(memory + offset);
            if (ModuleBase + potential_rva == target_addr) {
                xref_count++;
            }
        }

        return xref_count;
    }

    uint64_t FindStringPattern(const std::string& pattern) {
        uint8_t* memory = reinterpret_cast<uint8_t*>(ModuleBase);
        const char* pattern_cstr = pattern.c_str();
        size_t pattern_len = pattern.length();

        for (uint64_t offset = 0; offset <= ModuleSize - pattern_len; offset++) {
            if (memcmp(memory + offset, pattern_cstr, pattern_len) == 0) {
                return ModuleBase + offset;
            }
        }

        return 0;
    }

    std::vector<std::string> DecryptWithKey(const TheiaKeyCandidate& key) {
        std::vector<std::string> results;

        if (key.DecryptionType == "COMPLEX") {
            results = DecryptComplexSystem(key);
        } else if (key.DecryptionType == "MASK") {
            results = DecryptMaskSystem(key);
        }

        return results;
    }

    std::vector<std::string> DecryptComplexSystem(const TheiaKeyCandidate& key) {
        std::vector<std::string> decrypted;

        uint8_t* memory = reinterpret_cast<uint8_t*>(ModuleBase);

        for (uint64_t offset = 0; offset < ModuleSize - 32; offset += 16) {
            std::vector<uint8_t> encrypted_data(memory + offset, memory + offset + 32);

            if (LooksLikeEncryptedString(encrypted_data)) {
                std::string decrypted_str = PerformComplexDecryption(encrypted_data, key.KeyBytes);
                if (IsValidDecryptedString(decrypted_str)) {
                    decrypted.push_back(decrypted_str);
                    printf("[TheiaScanner] COMPLEX decrypt @ 0x%016llX: '%s'\n",
                           ModuleBase + offset, decrypted_str.c_str());
                }
            }
        }

        return decrypted;
    }

    std::vector<std::string> DecryptMaskSystem(const TheiaKeyCandidate& key) {
        std::vector<std::string> decrypted;

        uint8_t* memory = reinterpret_cast<uint8_t*>(ModuleBase);

        for (uint64_t offset = 0; offset < ModuleSize - 64; offset += 8) {
            std::vector<uint8_t> encrypted_data(memory + offset, memory + offset + 64);

            if (LooksLikeEncryptedString(encrypted_data)) {
                std::string decrypted_str = PerformMaskDecryption(encrypted_data, key.KeyBytes);
                if (IsValidDecryptedString(decrypted_str)) {
                    decrypted.push_back(decrypted_str);
                    printf("[TheiaScanner] MASK decrypt @ 0x%016llX: '%s'\n",
                           ModuleBase + offset, decrypted_str.c_str());
                }
            }
        }

        return decrypted;
    }

    bool LooksLikeEncryptedString(const std::vector<uint8_t>& data) {
        int printable_count = 0;
        for (uint8_t byte : data) {
            if (byte >= 0x20 && byte <= 0x7E) {
                printable_count++;
            }
        }

        return printable_count >= static_cast<int>(data.size() * 0.3);
    }

    std::string PerformComplexDecryption(const std::vector<uint8_t>& encrypted,
                                       const std::vector<uint8_t>& key) {
        std::string result;
        result.reserve(encrypted.size());

        for (size_t i = 0; i < encrypted.size(); ++i) {
            uint8_t decrypted_byte = encrypted[i] ^ key[i % key.size()];

            decrypted_byte = ((decrypted_byte << 3) | (decrypted_byte >> 5)) & 0xFF;

            result.push_back(static_cast<char>(decrypted_byte));
        }

        return result;
    }

    std::string PerformMaskDecryption(const std::vector<uint8_t>& encrypted,
                                    const std::vector<uint8_t>& key) {
        std::string result;
        result.reserve(encrypted.size());

        uint32_t key_state = 0;
        for (size_t i = 0; i < std::min(key.size(), size_t(4)); ++i) {
            key_state |= (static_cast<uint32_t>(key[i]) << (i * 8));
        }

        for (size_t i = 0; i < encrypted.size(); ++i) {
            uint8_t decrypted_byte = encrypted[i] ^ (key_state & 0xFF);

            key_state = (key_state >> 8) | ((key_state & 0xFF) << 24);
            key_state ^= 0x12345678;

            if (decrypted_byte >= 0x20 && decrypted_byte <= 0x7E) {
                result.push_back(static_cast<char>(decrypted_byte));
            }
        }

        return result;
    }

    bool IsValidDecryptedString(const std::string& str) {
        if (str.length() < 3 || str.length() > 100) {
            return false;
        }

        int printable_count = 0;
        for (char c : str) {
            if (c >= 0x20 && c <= 0x7E) {
                printable_count++;
            }
        }

        return printable_count >= static_cast<int>(str.length() * 0.8);
    }
};

}