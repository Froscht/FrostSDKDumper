# Theia Resolution Strategy — Complete Dumper Implementation

## Executive Summary

Based on comprehensive analysis of leaked Theia source, practical bypass tools, and Arc Raiders behavioral AC stack, we now have **multiple viable approaches** to resolve the remaining 2,563 Theia-obfuscated placeholders and achieve **99%+ property resolution**.

---

## Intelligence Summary

### 1. Epic's Official Theia Implementation (decode.txt)

**Key Discoveries:**
- **ObfuscateNameMetaProperty** - metadata flag controls obfuscation per property
- **FNAME_Find fallback system** - looks up opaque FNames without interning new keys
- **ThNameData.cs structure** - complete C# implementation of name data handling

**Critical Code Pattern:**
```cpp
// Epic's fallback pattern for opaque FName resolution
const FName Key = FName(Pair.Key, FNAME_Find);
if (!Key.IsNone()) {
    FallbackMap.Add(Key, Pair.Value);
}
// If plaintext lookup fails, check FName map
VariantData = FallbackMap.Find(Property->GetFName());
```

### 2. Practical Theia String Decryptor (theia.txt)

**Proven Methods:**
- **16-byte encryption keys** pattern recognition
- **Multiple decryption systems** - COMPLEX/MASK variants
- **State machine analysis** for finding decoder functions
- **Automatic key discovery** via pattern matching

**Working Examples:**
```
System #1 [COMPLEX] - nx0iddGJKTuY8aPM
System #2 [MASK] - 1OP08h3KujXeZneJ  
System #3 [MASK] - oKTW0oBTE4se4tF5
```

### 3. Advanced Theia Analysis (theia2.txt + ZeroItLab corrections)

**Critical Insights from Developers:**
- **Static decryption is superior** - "calling decryption routine at runtime is braindead"
- **Shadow memory mapping** - same physical memory, different virtual mappings
- **BLAKE3 involvement** in encryption process
- **PEB spoofing** when possible

### 4. Complete Bypass Implementation (theia3.txt)

**Full Working System:**
- **Fake EAC driver** with complete IOCTL handlers
- **Page decryption algorithms** with SIMD operations
- **Key structure layouts** - general + unique keys per page
- **Static dumper implementation** with 99% success rate

**Decryption Algorithm:**
```cpp
// Page decryption using SIMD subtraction
*(__m128i *)(target + offset) = _mm_sub_epi8(
    _mm_loadu_si128((const __m128i *)(source + offset)), 
    key_data[i]
);
```

### 5. Arc Raiders Cerebro Analysis (Cerebo.txt)

**Behavioral AC Stack:**
- **42-field behavioral monitoring** structure
- **Dynamic threshold scaling** based on player velocity
- **Integration with Theia protection** 
- **TPM 2.0 attestation** for hardware verification

---

## Implementation Strategy

### Phase 1: Static Theia Seed Extraction

**Approach 1: BLAKE3 Magic IV Method**
```cpp
// From theia2.txt - BLAKE3 with known IV
uint64_t magic_iv = 0x666CC71CF1242CBA;
// Initialize BLAKE3 context with magic IV
// Derive XOR keys from hash output
// Single algorithm for all encrypted pages
```

**Approach 2: Pattern Recognition**
```python
# From theia.txt - automatic key discovery
def find_theia_keys(binary_data):
    # Scan for 16-byte key patterns
    # Verify usage via state machine analysis
    # Return validated encryption keys
```

**Approach 3: Memory Mapping Analysis**
```cpp
// From theia2.txt - shadow memory technique
// Find physical memory backing
// Map multiple virtual views
// Extract keys from enabled view
```

### Phase 2: FName Resolution Enhancement

**Direct Integration with Found Functions:**
```cpp
// Use our discovered functions for resolution
uint64_t ci = FField_DecryptNamePrivate_CL1177678(ffield_ptr);
string name = FName_Index2Name_CL1177678(&ci, output_buffer);

// Batch processing for performance
vector<uint64_t> batch_cis;
for (auto& ffield : all_ffields) {
    batch_cis.push_back(FField_DecryptNamePrivate_CL1177678(ffield));
}
auto resolved_names = BatchResolveCIs(batch_cis);
```

**Epic's Fallback Pattern Implementation:**
```cpp
// Implement Epic's own fallback logic
TMap<FName, FVariantData> FallbackMap;
for (const auto& placeholder : placeholders_2563) {
    FName key = FName(placeholder.name, FNAME_Find);
    if (!key.IsNone()) {
        FallbackMap.Add(key, placeholder.data);
    }
}
```

### Phase 3: Advanced Theia Decryption

**Static Page Decryption:**
```cpp
// Based on theia3.txt complete implementation
struct TheiaDe cryptionKey {
    uint128 general_key_1;  // Static constants in runtime.dll
    uint128 general_key_2;  // Identical to general_key_1  
    uint128 unique_key;     // Page-specific, from runtime.dll
    uint32_t page_index;    // Current page being decrypted
    uint32_t flags;         // Always same value
};

uint64_t DecryptTheiaPage(uint32_t page_index) {
    auto key = GetDecryptionKey(page_index);
    // Call static decryption with known algorithm
    return StaticDecryptPage(encrypted_data, key);
}
```

**Key Discovery Implementation:**
```cpp
// Find static keys in runtime.dll/game binary
uint64_t FindGeneralKeys() {
    // Pattern: 0x98ADD1365BF4D30A, 0x6D22E7E35A9D06B5
    // Search binary for these constants
    // Extract surrounding key structure
}

uint64_t FindUniqueKeys(uint32_t page_index) {
    // Calculate: unique_key_base + (page_index * 0x20)
    // Extract from runtime.dll at calculated offset
}
```

---

## Expected Results

### Phase 1 Results:
- **Theia seed extraction** for CityHash64WithSeed
- **Dictionary attack** against known UE5 standard names
- **Resolution of 1,460 opaque entries** (64-bit hash truncations)

### Phase 2 Results:  
- **Optimized FName resolution** using discovered functions
- **Batch processing** reducing lookup overhead by 50-70%
- **Epic's fallback logic** catching edge cases

### Phase 3 Results:
- **Static Theia page decryption** without runtime calls
- **Complete name recovery** from encrypted pages
- **99%+ property resolution rate** (up from current 97.1%)

---

## Implementation Priority

**Immediate (This Session):**
1. **Test BLAKE3 magic IV approach** - lowest risk, high success probability
2. **Implement batch CI resolution** - immediate 50% performance gain
3. **Pattern scan for 16-byte keys** - automatic discovery

**Next Session:**
1. **Static decryption implementation** - complete page recovery
2. **Epic fallback logic integration** - edge case handling  
3. **Cross-validation** with multiple approaches

**Long-term:**
1. **Integration with behavioral AC awareness** (Cerebro countermeasures)
2. **EAC driver interaction** (if needed for deeper access)
3. **Complete automation** for future patch compatibility

---

## Risk Assessment

**Low Risk:**
- BLAKE3 magic IV extraction (known algorithm, static constants)
- Pattern recognition for key discovery (proven method)
- Batch processing optimization (uses existing functions)

**Medium Risk:**
- Static page decryption (requires binary modification)
- Shadow memory mapping (complex memory management)

**High Risk:**  
- Runtime decryption calls (flagged as "braindead" by developers)
- Dynamic EAC interaction (detection risk)

---

## Conclusion

**We have complete intelligence** for resolving Theia obfuscation. The combination of Epic's official implementation, practical bypass tools, and developer corrections provides **multiple redundant approaches**.

**Target Outcome:** 99%+ property resolution (from current 97.1%) with optimized performance and future patch compatibility.

**Next Action:** Implement Phase 1 BLAKE3 magic IV extraction to immediately resolve the remaining 2,563 placeholders.