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
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "memreader_iface.h"

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

        // Single-item fread wrapper — bails the whole Open() on a short read.
        auto rd = [this](void* p, size_t sz) {
            return std::fread(p, sz, 1, m_file) == 1;
        };

        uint16_t dosSig = 0;
        if (!rd(&dosSig, 2) || dosSig != 0x5A4D) { Close(); return false; }

        std::fseek(m_file, 0x3C, SEEK_SET);
        uint32_t peOffset = 0;
        if (!rd(&peOffset, 4)) { Close(); return false; }

        std::fseek(m_file, peOffset, SEEK_SET);
        uint32_t peSig = 0;
        if (!rd(&peSig, 4) || peSig != 0x00004550) { Close(); return false; }

        uint16_t machine = 0, numSections = 0;
        if (!rd(&machine, 2) || !rd(&numSections, 2)) { Close(); return false; }
        std::fseek(m_file, 12, SEEK_CUR);
        uint16_t optHeaderSize = 0;
        if (!rd(&optHeaderSize, 2)) { Close(); return false; }
        std::fseek(m_file, 2, SEEK_CUR);

        long optHeaderStart = std::ftell(m_file);
        uint16_t optMagic = 0;
        if (!rd(&optMagic, 2) || optMagic != 0x20B) { Close(); return false; } // PE32+ only

        std::fseek(m_file, optHeaderStart + 24, SEEK_SET);
        if (!rd(&m_imageBase, 8)) { Close(); return false; }
        std::fseek(m_file, optHeaderStart + 56, SEEK_SET);
        if (!rd(&m_sizeOfImage, 4)) { Close(); return false; }

        // DataDirectory[5] = BASE_RELOC (offset +112 into opt header for PE32+)
        std::fseek(m_file, optHeaderStart + 24 + 112, SEEK_SET);
        if (!rd(&m_relocDirRVA, 4) || !rd(&m_relocDirSize, 4)) { Close(); return false; }

        std::fseek(m_file, optHeaderStart + optHeaderSize, SEEK_SET);
        m_sections.clear();
        for (uint16_t i = 0; i < numSections; ++i) {
            uint8_t hdr[40];
            if (!rd(hdr, 40)) { Close(); return false; }
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
    uint32_t m_relocDirRVA = 0;
    uint32_t m_relocDirSize = 0;

    struct RelocEntry { uint8_t type; uint16_t offset; };
    std::unordered_map<uint32_t, std::vector<RelocEntry>> m_relocs;

    // Reloc-free raw read by RVA — used while parsing relocations themselves
    // to avoid recursion (ApplyRelocations needs the table that ReadAtRVA
    // would apply). Copy of ReadAtRVA with relocDelta forced to 0.
    bool ReadAtRVARaw(uint32_t rva, void* buf, size_t size) {
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
                return got > 0;
            }
        }
        return false;
    }

    void ParseRelocations() {
        // Prefer the `.reloc` section — some dumpers (e.g. our Apr-21 dump)
        // leave the BASE_RELOC data-directory pointing into .rdata garbage
        // while the real reloc table lives in the named section. Fall back
        // to the data-dir RVA when no named section exists.
        uint32_t relocRVA = 0, relocSize = 0;
        for (auto& sec : m_sections) {
            if (std::strncmp(sec.name, ".reloc", 6) == 0) {
                relocRVA = sec.virtualAddress;
                relocSize = sec.rawDataSize;
                break;
            }
        }
        if ((!relocRVA || !relocSize) && m_relocDirRVA && m_relocDirSize) {
            relocRVA = m_relocDirRVA;
            relocSize = m_relocDirSize;
        }
        if (!relocRVA || !relocSize) return;

        std::vector<uint8_t> relocData(relocSize);
        if (!ReadAtRVARaw(relocRVA, relocData.data(), relocSize)) return;

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

// =============================================================================
// PEReaderFile — offline IMemoryReader backed by an mmap'd .exe on disk.
//
// Maps virtual addresses (using a synthetic UE5 image base of 0x140000000) back
// to file offsets through the section table. Sections are page-aligned in VM
// but unaligned on disk, so a single Read() that straddles a section boundary
// is serviced section-by-section. Bytes that land in zero-fill tail (VirtSize
// > RawSize) are returned as 0x00 — the live reader returns the page contents,
// but PE loaders zero-extend that tail so this matches the in-memory image for
// the only addresses callers will actually probe.
//
// Use for: CI sigscan validation, offline vtable extraction, patch-day triage
// without launching the game. Cannot satisfy reads that target heap/stack or
// otherwise-RVA-less addresses — those return false.
// =============================================================================
class PEReaderFile : public IMemoryReader {
public:
    static constexpr uint64_t kSyntheticBase = 0x140000000ULL;

    struct SectionView {
        uint32_t VirtualAddress;
        uint32_t VirtualSize;
        uint32_t RawDataOffset;
        uint32_t RawDataSize;
        char     Name[9];
    };

    PEReaderFile() = default;

    explicit PEReaderFile(const char* Path) { Open(Path); }
    explicit PEReaderFile(const std::string& Path) { Open(Path.c_str()); }

    ~PEReaderFile() override { Close(); }

    PEReaderFile(const PEReaderFile&)            = delete;
    PEReaderFile& operator=(const PEReaderFile&) = delete;

    bool Open(const char* Path) {
        Close();
        int Fd = ::open(Path, O_RDONLY | O_CLOEXEC);
        if (Fd < 0) {
            std::printf("[PEFile] open failed: %s\n", Path);
            return false;
        }
        struct stat St = {};
        if (::fstat(Fd, &St) != 0 || St.st_size < 0x200) {
            ::close(Fd);
            std::printf("[PEFile] fstat failed or file too small: %s\n", Path);
            return false;
        }
        size_t MapSize = static_cast<size_t>(St.st_size);
        void* Mapping = ::mmap(nullptr, MapSize, PROT_READ, MAP_PRIVATE, Fd, 0);
        ::close(Fd);
        if (Mapping == MAP_FAILED) {
            std::printf("[PEFile] mmap failed: %s\n", Path);
            return false;
        }

        m_Map     = static_cast<const uint8_t*>(Mapping);
        m_MapSize = MapSize;

        if (!ParseHeaders()) {
            std::printf("[PEFile] PE header parse failed: %s\n", Path);
            Close();
            return false;
        }

        std::printf("[PEFile] Opened %s (sections=%u, ImageBase=0x%llX→synth=0x%llX, "
                    ".text=0x%X+0x%X, .rdata=0x%X+0x%X, .data=0x%X+0x%X)\n",
                    Path, (unsigned)m_Sections.size(),
                    (unsigned long long)m_PreferredBase,
                    (unsigned long long)kSyntheticBase,
                    (unsigned)TextRva, (unsigned)TextSize,
                    (unsigned)RDataRva, (unsigned)RDataSize,
                    (unsigned)DataRva, (unsigned)DataSize);
        return true;
    }

    void Close() {
        if (m_Map) {
            ::munmap(const_cast<uint8_t*>(m_Map), m_MapSize);
            m_Map     = nullptr;
            m_MapSize = 0;
        }
        m_Sections.clear();
        m_PreferredBase = 0;
        m_SizeOfImage   = 0;
        TextRva = TextSize = 0;
        RDataRva = RDataSize = 0;
        DataRva = DataSize = 0;
    }

    bool IsOpen() const { return m_Map != nullptr && !m_Sections.empty(); }

    // ── ModuleBounds-style accessors (kept as raw fields to avoid a circular
    // include with auto_discovery.h, which itself pulls pe_reader.h).
    uint32_t TextRva   = 0;
    uint32_t TextSize  = 0;
    uint32_t RDataRva  = 0;
    uint32_t RDataSize = 0;
    uint32_t DataRva   = 0;
    uint32_t DataSize  = 0;

    uint64_t ModuleBase()    const { return kSyntheticBase; }
    uint64_t PreferredBase() const { return m_PreferredBase; }
    uint32_t SizeOfImage()   const { return m_SizeOfImage; }
    const std::vector<SectionView>& Sections() const { return m_Sections; }

    // IMemoryReader: addr is a runtime VA against kSyntheticBase. Splits the
    // request at section boundaries and zero-fills any tail that falls in
    // VirtSize-beyond-RawSize space or outside every section.
    bool Read(uint64_t Address, void* OutBuffer, size_t Size) override {
        if (!OutBuffer || !Size || !m_Map) return false;
        if (Address < kSyntheticBase) return false;
        uint64_t Rva = Address - kSyntheticBase;
        if (Rva >= m_SizeOfImage) return false;

        uint8_t* Dst       = static_cast<uint8_t*>(OutBuffer);
        size_t   Remaining = Size;
        uint64_t CurRva    = Rva;
        bool     AnyHit    = false;
        std::memset(Dst, 0, Size);

        while (Remaining > 0) {
            const SectionView* Sec = FindSection(static_cast<uint32_t>(CurRva));
            if (!Sec) {
                // Skip one byte at a time across an inter-section gap; in
                // practice PE loaders never leave true gaps so this just
                // bails on out-of-image addresses.
                CurRva++; Dst++; Remaining--;
                continue;
            }
            uint32_t OffInSection = static_cast<uint32_t>(CurRva) - Sec->VirtualAddress;
            uint32_t SectionEnd   = Sec->VirtualAddress + Sec->VirtualSize;
            size_t   Avail        = SectionEnd - static_cast<uint32_t>(CurRva);
            size_t   Chunk        = (Remaining < Avail) ? Remaining : Avail;

            if (OffInSection < Sec->RawDataSize) {
                size_t   RawAvail    = Sec->RawDataSize - OffInSection;
                size_t   RawChunk    = (Chunk < RawAvail) ? Chunk : RawAvail;
                uint64_t FileOff     = static_cast<uint64_t>(Sec->RawDataOffset) + OffInSection;
                if (FileOff + RawChunk <= m_MapSize) {
                    std::memcpy(Dst, m_Map + FileOff, RawChunk);
                    AnyHit = true;
                }
            }
            // Whatever falls beyond RawDataSize (BSS tail) stays zero from
            // the initial memset — matches PE loader zero-extension.

            Dst       += Chunk;
            CurRva    += Chunk;
            Remaining -= Chunk;
        }
        return AnyHit;
    }

private:
    const uint8_t*           m_Map           = nullptr;
    size_t                   m_MapSize       = 0;
    uint64_t                 m_PreferredBase = 0;
    uint32_t                 m_SizeOfImage   = 0;
    std::vector<SectionView> m_Sections;

    bool ParseHeaders() {
        if (m_MapSize < 0x40) return false;
        if (m_Map[0] != 'M' || m_Map[1] != 'Z') return false;
        uint32_t PeOff = *reinterpret_cast<const uint32_t*>(m_Map + 0x3C);
        if (PeOff + 0x18 > m_MapSize) return false;
        if (*reinterpret_cast<const uint32_t*>(m_Map + PeOff) != 0x00004550) return false;

        uint16_t NumSections   = *reinterpret_cast<const uint16_t*>(m_Map + PeOff + 6);
        uint16_t OptHeaderSize = *reinterpret_cast<const uint16_t*>(m_Map + PeOff + 0x14);
        uint32_t OptHdrOff     = PeOff + 0x18;
        if (OptHdrOff + OptHeaderSize > m_MapSize) return false;

        uint16_t OptMagic = *reinterpret_cast<const uint16_t*>(m_Map + OptHdrOff);
        if (OptMagic != 0x20B) return false; // PE32+ only

        m_PreferredBase = *reinterpret_cast<const uint64_t*>(m_Map + OptHdrOff + 24);
        m_SizeOfImage   = *reinterpret_cast<const uint32_t*>(m_Map + OptHdrOff + 56);

        uint32_t SectStart = OptHdrOff + OptHeaderSize;
        if (SectStart + uint32_t(NumSections) * 0x28 > m_MapSize) return false;

        m_Sections.clear();
        m_Sections.reserve(NumSections);
        for (uint16_t i = 0; i < NumSections; ++i) {
            const uint8_t* S = m_Map + SectStart + i * 0x28;
            SectionView Sec = {};
            std::memcpy(Sec.Name, S, 8);
            Sec.Name[8]        = 0;
            Sec.VirtualSize    = *reinterpret_cast<const uint32_t*>(S + 8);
            Sec.VirtualAddress = *reinterpret_cast<const uint32_t*>(S + 12);
            Sec.RawDataSize    = *reinterpret_cast<const uint32_t*>(S + 16);
            Sec.RawDataOffset  = *reinterpret_cast<const uint32_t*>(S + 20);
            m_Sections.push_back(Sec);

            if (std::strncmp(Sec.Name, ".text", 5) == 0) {
                TextRva  = Sec.VirtualAddress;
                TextSize = Sec.VirtualSize;
            } else if (std::strncmp(Sec.Name, ".rdata", 6) == 0) {
                RDataRva  = Sec.VirtualAddress;
                RDataSize = Sec.VirtualSize;
            } else if (std::strncmp(Sec.Name, ".data", 5) == 0 && DataRva == 0) {
                DataRva  = Sec.VirtualAddress;
                DataSize = Sec.VirtualSize;
            }
        }
        if (!TextRva || !RDataRva || !DataRva || !m_SizeOfImage) return false;
        return true;
    }

    // Section-virtual-to-file mapper. Sections are 0x1000-aligned in memory
    // but FileAlignment-aligned on disk (commonly 0x200), so a hit on Rva
    // must be located via VirtualAddress/VirtualSize, then translated to
    // RawDataOffset + (Rva - VirtualAddress).
    const SectionView* FindSection(uint32_t Rva) const {
        for (const auto& Sec : m_Sections) {
            if (Rva >= Sec.VirtualAddress &&
                Rva <  Sec.VirtualAddress + Sec.VirtualSize) {
                return &Sec;
            }
        }
        return nullptr;
    }
};

} // namespace SigScan
