#pragma once
// =============================================================================
// pe_reader.h — read code/data pages from a PioneerGame*.exe dump on disk,
// applying PE base relocations so embedded pointers line up with the live
// runtime base. Used as a fallback when the live kernel reader can't serve a
// page (VMProtect keeps cold functions encrypted until first call → reads
// return 0xCC). Extracted from FrostSDKDumper/emu_engine.h.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace SigScan {

class PEFileReader {
public:
    struct PESection {
        uint32_t virtualAddress;
        uint32_t virtualSize;
        uint32_t rawDataOffset;
        uint32_t rawDataSize;
        char     name[9];
    };

    bool Open(const char* path) {
        if (m_file) std::fclose(m_file);
        m_file = std::fopen(path, "rb");
        if (!m_file) { std::printf("[PE] fopen failed: %s\n", path); return false; }

        uint16_t dosSig = 0;
        std::fread(&dosSig, 2, 1, m_file);
        if (dosSig != 0x5A4D) { Close(); return false; }

        std::fseek(m_file, 0x3C, SEEK_SET);
        uint32_t peOffset = 0;
        std::fread(&peOffset, 4, 1, m_file);

        std::fseek(m_file, peOffset, SEEK_SET);
        uint32_t peSig = 0;
        std::fread(&peSig, 4, 1, m_file);
        if (peSig != 0x00004550) { Close(); return false; }

        uint16_t machine = 0, numSections = 0;
        std::fread(&machine, 2, 1, m_file);
        std::fread(&numSections, 2, 1, m_file);
        std::fseek(m_file, 12, SEEK_CUR);
        uint16_t optHeaderSize = 0;
        std::fread(&optHeaderSize, 2, 1, m_file);
        std::fseek(m_file, 2, SEEK_CUR);

        long optHeaderStart = std::ftell(m_file);
        uint16_t optMagic = 0;
        std::fread(&optMagic, 2, 1, m_file);
        if (optMagic != 0x20B) { Close(); return false; } // PE32+ only

        std::fseek(m_file, optHeaderStart + 24, SEEK_SET);
        std::fread(&m_imageBase, 8, 1, m_file);
        std::fseek(m_file, optHeaderStart + 56, SEEK_SET);
        std::fread(&m_sizeOfImage, 4, 1, m_file);

        std::fseek(m_file, optHeaderStart + optHeaderSize, SEEK_SET);
        m_sections.clear();
        for (uint16_t i = 0; i < numSections; ++i) {
            uint8_t hdr[40];
            std::fread(hdr, 40, 1, m_file);
            PESection sec = {};
            std::memcpy(sec.name, hdr, 8);
            sec.name[8] = 0;
            sec.virtualSize    = *(uint32_t*)(hdr + 8);
            sec.virtualAddress = *(uint32_t*)(hdr + 12);
            sec.rawDataSize    = *(uint32_t*)(hdr + 16);
            sec.rawDataOffset  = *(uint32_t*)(hdr + 20);
            m_sections.push_back(sec);
        }
        ParseRelocations();

        std::printf("[PE] Opened %s (%u sections, ImageBase=0x%llX, SizeOfImage=0x%X, reloc entries=%u)\n",
                    path, (unsigned)m_sections.size(),
                    (unsigned long long)m_imageBase, m_sizeOfImage, m_totalRelocEntries);
        return true;
    }

    void Close() {
        if (m_file) { std::fclose(m_file); m_file = nullptr; }
        m_sections.clear();
        m_relocs.clear();
    }

    ~PEFileReader() { Close(); }

    bool     IsOpen()        const { return m_file != nullptr; }
    uint64_t PreferredBase() const { return m_imageBase; }
    uint32_t SizeOfImage()   const { return m_sizeOfImage; }

    bool ReadAtRVA(uint32_t rva, void* buf, size_t size, int64_t relocDelta = 0) {
        if (!m_file) return false;
        for (auto& sec : m_sections) {
            if (rva >= sec.virtualAddress &&
                rva <  sec.virtualAddress + sec.rawDataSize) {
                uint32_t offsetInSection = rva - sec.virtualAddress;
                uint32_t fileOffset = sec.rawDataOffset + offsetInSection;
                size_t available = sec.rawDataSize - offsetInSection;
                size_t toRead = (size < available) ? size : available;
                std::fseek(m_file, fileOffset, SEEK_SET);
                size_t got = std::fread(buf, 1, toRead, m_file);
                if (got < size)
                    std::memset((uint8_t*)buf + got, 0, size - got);
                if (relocDelta != 0 && got > 0)
                    ApplyRelocations(rva, (uint8_t*)buf, size, relocDelta);
                return got > 0;
            }
        }
        return false;
    }

private:
    FILE* m_file = nullptr;
    std::vector<PESection> m_sections;
    uint64_t m_imageBase = 0;
    uint32_t m_sizeOfImage = 0;
    uint32_t m_totalRelocEntries = 0;

    struct RelocEntry { uint8_t type; uint16_t offset; };
    std::unordered_map<uint32_t, std::vector<RelocEntry>> m_relocs;

    void ParseRelocations() {
        PESection* relocSec = nullptr;
        for (auto& sec : m_sections) {
            if (std::strncmp(sec.name, ".reloc", 6) == 0) { relocSec = &sec; break; }
        }
        if (!relocSec) return;

        std::vector<uint8_t> relocData(relocSec->rawDataSize);
        std::fseek(m_file, relocSec->rawDataOffset, SEEK_SET);
        std::fread(relocData.data(), 1, relocSec->rawDataSize, m_file);

        size_t offset = 0;
        while (offset + 8 <= relocData.size()) {
            uint32_t pageRVA   = *(uint32_t*)(relocData.data() + offset);
            uint32_t blockSize = *(uint32_t*)(relocData.data() + offset + 4);
            if (blockSize < 8 || offset + blockSize > relocData.size()) break;

            uint32_t numEntries = (blockSize - 8) / 2;
            auto& entries = m_relocs[pageRVA];
            for (uint32_t i = 0; i < numEntries; ++i) {
                uint16_t raw = *(uint16_t*)(relocData.data() + offset + 8 + i * 2);
                uint8_t type = (raw >> 12) & 0xF;
                uint16_t off = raw & 0xFFF;
                if (type == 0) continue;
                entries.push_back({type, off});
                m_totalRelocEntries++;
            }
            offset += blockSize;
        }
    }

    void ApplyRelocations(uint32_t startRVA, uint8_t* buf, size_t bufSize, int64_t delta) {
        uint32_t pageStart = startRVA & ~0xFFFU;
        uint32_t endRVA = (uint32_t)(startRVA + bufSize);
        uint32_t pageEnd = (endRVA + 0xFFF) & ~0xFFFU;

        for (uint32_t pageRVA = pageStart; pageRVA < pageEnd; pageRVA += 0x1000) {
            auto it = m_relocs.find(pageRVA);
            if (it == m_relocs.end()) continue;
            for (auto& entry : it->second) {
                uint32_t relocRVA = pageRVA + entry.offset;
                if (entry.type == 10) { // IMAGE_REL_BASED_DIR64
                    if (relocRVA >= startRVA && relocRVA + 8 <= endRVA) {
                        size_t bufOff = relocRVA - startRVA;
                        uint64_t val;
                        std::memcpy(&val, buf + bufOff, 8);
                        val = (uint64_t)((int64_t)val + delta);
                        std::memcpy(buf + bufOff, &val, 8);
                    }
                } else if (entry.type == 3) { // IMAGE_REL_BASED_HIGHLOW
                    if (relocRVA >= startRVA && relocRVA + 4 <= endRVA) {
                        size_t bufOff = relocRVA - startRVA;
                        uint32_t val;
                        std::memcpy(&val, buf + bufOff, 4);
                        val = (uint32_t)((int32_t)val + (int32_t)delta);
                        std::memcpy(buf + bufOff, &val, 4);
                    }
                }
            }
        }
    }
};

} // namespace SigScan
