#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>

namespace TheiaResolver {

constexpr uint64_t THEIA_BLAKE3_MAGIC_IV = 0x666CC71CF1242CBA;
constexpr uint32_t THEIA_OPAQUE_HASH_SEED_DEFAULT = 4919; // 0x1337

struct Blake3Context {
    uint32_t state[8];
    uint64_t counter;
    uint8_t buffer[64];
    uint8_t buffer_len;
};

struct FNameEntryTheia {
    uint64_t HashLower;
    uint16_t Header;
    bool bIsOpaque;
    char Name[];
};

class TheiaBlake3Extractor {
private:
    Blake3Context Ctx;
    uint32_t CurrentSeed;
    std::unordered_map<uint64_t, std::string> HashToNameMap;
    std::vector<std::string> UE5StandardNames;

public:
    TheiaBlake3Extractor() : CurrentSeed(THEIA_OPAQUE_HASH_SEED_DEFAULT) {
        InitializeStandardNames();
        InitializeBlake3();
    }

    void InitializeBlake3() {
        static constexpr uint32_t BLAKE3_IV[8] = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
            0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
        };

        for (int i = 0; i < 8; ++i) {
            Ctx.state[i] = BLAKE3_IV[i];
        }

        Ctx.state[0] ^= (THEIA_BLAKE3_MAGIC_IV & 0xFFFFFFFF);
        Ctx.state[1] ^= ((THEIA_BLAKE3_MAGIC_IV >> 32) & 0xFFFFFFFF);

        Ctx.counter = 0;
        Ctx.buffer_len = 0;
    }

    void InitializeStandardNames() {
        UE5StandardNames = {
            "None", "ByteProperty", "IntProperty", "BoolProperty", "FloatProperty",
            "ObjectProperty", "NameProperty", "DelegateProperty", "DoubleProperty",
            "ArrayProperty", "StructProperty", "VectorProperty", "RotatorProperty",
            "StrProperty", "TextProperty", "InterfaceProperty", "MulticastDelegateProperty",
            "WeakObjectProperty", "LazyObjectProperty", "AssetObjectProperty",
            "SoftObjectProperty", "UInt64Property", "UInt32Property", "UInt16Property",
            "Int64Property", "Int16Property", "Int8Property", "MapProperty", "SetProperty",
            "EnumProperty", "FFieldPathProperty", "InlineMulticastDelegateProperty",

            "Actor", "Pawn", "Character", "PlayerController", "GameModeBase",
            "World", "Level", "Scene", "Component", "Transform", "Vector", "Rotator",
            "Location", "Rotation", "Scale", "Velocity", "Force", "Mass", "Friction",

            "BeginPlay", "Tick", "EndPlay", "Destroy", "Spawn", "GetWorld", "GetOwner",
            "SetOwner", "GetActorLocation", "SetActorLocation", "GetActorRotation",
            "SetActorRotation", "GetActorScale", "SetActorScale", "GetRootComponent",

            "Health", "MaxHealth", "Armor", "Damage", "Speed", "JumpHeight", "WalkSpeed",
            "RunSpeed", "CrouchSpeed", "SwimSpeed", "FlySpeed", "TeamID", "PlayerName",
            "Score", "Kills", "Deaths", "Level", "Experience", "Currency", "Inventory",

            "Input", "InputAxis", "InputAction", "Bind", "Unbind", "Execute", "Activate",
            "Deactivate", "Enable", "Disable", "Visible", "Hidden", "Collision", "Overlap",
            "Hit", "Touch", "Enter", "Exit", "Start", "Stop", "Pause", "Resume",

            "Material", "Texture", "Mesh", "Animation", "Sound", "Music", "Effect",
            "Particle", "Light", "Shadow", "Camera", "Viewport", "Canvas", "Widget",
            "Button", "Slider", "CheckBox", "TextBox", "Image", "Panel", "Menu",

            "Network", "Server", "Client", "Host", "Join", "Leave", "Connect", "Disconnect",
            "Send", "Receive", "Broadcast", "Multicast", "Replicate", "Authority", "Remote",
            "Local", "Session", "Match", "Lobby", "Room", "Channel", "Message", "Event"
        };
    }

    uint64_t ComputeCityHash64WithSeed(const std::string& name, uint32_t seed) {
        std::string lowercase_name = name;
        std::transform(lowercase_name.begin(), lowercase_name.end(), lowercase_name.begin(), ::tolower);

        return CityHash64WithSeed(lowercase_name.c_str(), lowercase_name.length(), seed);
    }

    uint64_t CityHash64WithSeed(const char* s, size_t len, uint32_t seed) {
        static constexpr uint64_t k0 = 0xc3a5c85c97cb3127ULL;
        static constexpr uint64_t k1 = 0xb492b66fbe98f273ULL;
        static constexpr uint64_t k2 = 0x9ae16a3b2f90404fULL;

        uint64_t a = seed;
        uint64_t b = seed * k1 + len;
        uint64_t c = 0;

        if (len >= 24) {
            uint64_t a0 = a, a1 = a, a2 = a, a3 = a, a4 = a;
            uint64_t b0 = b, b1 = b, b2 = b, b3 = b, b4 = b;

            do {
                a ^= Fetch64(s) * k1; a = Rotate(a, 23) * k2;
                a0 ^= Fetch64(s + 8) * k1; a0 = Rotate(a0, 23) * k2;
                a1 ^= Fetch64(s + 16) * k1; a1 = Rotate(a1, 23) * k2;
                s += 24; len -= 24;
            } while (len >= 24);

            a ^= a0 ^ a1;
            b ^= b0 ^ b1;
        }

        if (len >= 16) {
            a ^= Fetch64(s) * k1; a = Rotate(a, 23) * k2;
            b ^= Fetch64(s + 8) * k1; b = Rotate(b, 23) * k2;
            s += 16; len -= 16;
        }

        if (len >= 8) {
            a ^= Fetch64(s) * k1; a = Rotate(a, 23) * k2;
            s += 8; len -= 8;
        }

        if (len >= 4) {
            a ^= Fetch32(s) * k1; a = Rotate(a, 23) * k2;
            s += 4; len -= 4;
        }

        if (len > 0) {
            uint32_t tail = 0;
            for (size_t i = 0; i < len; ++i) {
                tail |= static_cast<uint32_t>(s[i]) << (i * 8);
            }
            a ^= tail * k1; a = Rotate(a, 23) * k2;
        }

        return HashLen16(a, b);
    }

    bool ExtractSeedFromMemory() {
        printf("[TheiaBlake3] Searching for Theia seed in game memory...\n");

        for (uint32_t test_seed = 1; test_seed <= 65535; ++test_seed) {
            uint64_t none_hash = ComputeCityHash64WithSeed("None", test_seed);

            if (IsHashPresentInFNamePool(none_hash)) {
                CurrentSeed = test_seed;
                printf("[TheiaBlake3] Found Theia seed: %u (0x%X)\n", test_seed, test_seed);
                printf("[TheiaBlake3] 'None' hash with this seed: 0x%016llX\n", none_hash);
                return true;
            }

            if (test_seed % 1000 == 0) {
                printf("[TheiaBlake3] Testing seed %u...\n", test_seed);
            }
        }

        printf("[TheiaBlake3] Seed extraction failed - using default seed %u\n", THEIA_OPAQUE_HASH_SEED_DEFAULT);
        return false;
    }

    void BuildHashDictionary() {
        printf("[TheiaBlake3] Building hash dictionary with %zu standard names...\n", UE5StandardNames.size());

        for (const auto& name : UE5StandardNames) {
            uint64_t hash = ComputeCityHash64WithSeed(name, CurrentSeed);
            HashToNameMap[hash] = name;

            std::string variations[] = {
                "b" + name,           // bVisible, bEnabled, etc.
                name + "Component",   // ActorComponent, etc.
                name + "Class",       // ActorClass, etc.
                name + "Property",    // ActorProperty, etc.
                "On" + name,          // OnBeginPlay, etc.
                name + "Event",       // BeginPlayEvent, etc.
                "Is" + name,          // IsValid, etc.
                "Get" + name,         // GetActor, etc.
                "Set" + name,         // SetActor, etc.
                name + "s",           // Actors, Components, etc.
                name + "ID",          // ActorID, etc.
                name + "Type",        // ActorType, etc.
                name + "State",       // ActorState, etc.
                name + "Data",        // ActorData, etc.
                name + "Info",        // ActorInfo, etc.
                name + "Config",      // ActorConfig, etc.
            };

            for (const auto& variation : variations) {
                uint64_t var_hash = ComputeCityHash64WithSeed(variation, CurrentSeed);
                HashToNameMap[var_hash] = variation;
            }
        }

        printf("[TheiaBlake3] Dictionary built: %zu hash entries\n", HashToNameMap.size());
    }

    std::string ResolveOpaqueHash(uint64_t hash_lower) {
        auto it = HashToNameMap.find(hash_lower);
        if (it != HashToNameMap.end()) {
            return it->second;
        }

        return "";
    }

    int ResolvePlaceholders(std::vector<PlaceholderEntry>& placeholders) {
        int resolved_count = 0;

        printf("[TheiaBlake3] Attempting to resolve %zu Theia placeholders...\n", placeholders.size());

        for (auto& placeholder : placeholders) {
            if (placeholder.IsTheiaOpaque()) {
                uint64_t truncated_hash = placeholder.GetTruncatedHash();

                for (const auto& [full_hash, name] : HashToNameMap) {
                    if ((full_hash & 0xFFFFFFFF) == truncated_hash) {
                        placeholder.ResolvedName = name;
                        placeholder.ResolutionMethod = "TheiaBlake3";
                        resolved_count++;

                        printf("[TheiaBlake3] Resolved: CI=%u -> '%s' (hash=0x%016llX)\n",
                               truncated_hash, name.c_str(), full_hash);
                        break;
                    }
                }
            }
        }

        printf("[TheiaBlake3] Resolved %d/%zu placeholders (%.1f%%)\n",
               resolved_count, placeholders.size(),
               (100.0 * resolved_count) / placeholders.size());

        return resolved_count;
    }

private:
    uint64_t Rotate(uint64_t val, int shift) {
        return (val >> shift) | (val << (64 - shift));
    }

    uint64_t Fetch64(const char* p) {
        uint64_t result;
        memcpy(&result, p, sizeof(result));
        return result;
    }

    uint32_t Fetch32(const char* p) {
        uint32_t result;
        memcpy(&result, p, sizeof(result));
        return result;
    }

    uint64_t HashLen16(uint64_t u, uint64_t v) {
        static constexpr uint64_t kMul = 0x9ddfea08eb382d69ULL;
        uint64_t a = (u ^ v) * kMul;
        a ^= (a >> 47);
        uint64_t b = (v ^ a) * kMul;
        b ^= (b >> 47);
        return b * kMul;
    }

    bool IsHashPresentInFNamePool(uint64_t hash) {
        return false;
    }
};

}

struct PlaceholderEntry {
    uint32_t CompactIndex;
    std::string OriginalName;
    std::string ResolvedName;
    std::string ResolutionMethod;
    uint64_t PropertyOffset;

    bool IsTheiaOpaque() const {
        return OriginalName.find("Prop_CI") != std::string::npos &&
               CompactIndex >= 9900000 && CompactIndex <= 17000000;
    }

    uint32_t GetTruncatedHash() const {
        return CompactIndex;
    }
};