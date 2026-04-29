#pragma once
// =============================================================================
// emu_engine.h — Unicorn-based emulation engine for ARC Raiders decrypt
//                functions, ported into FrostSDKDumper.
//
// Approach: read game memory pages on demand via the IMemoryReader (HyperV
// hypercall path), map them into Unicorn, then execute the game's own native
// decrypt code instead of reimplementing the SIMD pipelines by hand.
//
// When the live process can't supply a page (demand-paged .text/.rdata that
// the running game hasn't touched yet), we fall back to reading the same
// bytes from a dumped copy of PioneerGame*.exe on disk and applying base
// relocations so the dumped pointers match the live runtime base.
//
// For calls that leave the game module (CRT memmove etc.), the fault handler
// writes a minimal Unicorn-compatible memmove stub at the faulting address.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <unicorn/unicorn.h>

#include "memreader_iface.h"

namespace EmuEngineNS {

// ── Trivial pointer-validity check (replaces the reference tool's
//    ptr_utils::IsValidPtr — same canonical user-mode range). ───────────────
inline bool IsValidPtr(uint64_t p) {
    return p >= 0x00010000ULL && p < 0x00007FFF'FFFFFFFFULL;
}

// =============================================================================
// PEFileReader — reads static sections from a dumped PioneerGame.exe and
// applies base relocations so any embedded pointers line up with the live
// runtime base. Used as a fallback when the hypervisor can't read a page.
// =============================================================================
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
        if (!m_file) {
            std::printf("[PE] Failed to open: %s\n", path);
            return false;
        }

        // Single-item fread wrapper — bails the whole Open() on a short read.
        auto rd = [this](void* p, size_t sz) {
            return std::fread(p, sz, 1, m_file) == 1;
        };

        uint16_t dosSig = 0;
        if (!rd(&dosSig, 2) || dosSig != 0x5A4D) {
            std::printf("[PE] Invalid DOS signature\n");
            Close();
            return false;
        }

        std::fseek(m_file, 0x3C, SEEK_SET);
        uint32_t peOffset = 0;
        if (!rd(&peOffset, 4)) { Close(); return false; }

        std::fseek(m_file, peOffset, SEEK_SET);
        uint32_t peSig = 0;
        if (!rd(&peSig, 4) || peSig != 0x00004550) {
            std::printf("[PE] Invalid PE signature\n");
            Close();
            return false;
        }

        uint16_t machine = 0, numSections = 0;
        if (!rd(&machine, 2) || !rd(&numSections, 2)) { Close(); return false; }
        std::fseek(m_file, 12, SEEK_CUR);
        uint16_t optHeaderSize = 0;
        if (!rd(&optHeaderSize, 2)) { Close(); return false; }
        std::fseek(m_file, 2, SEEK_CUR);

        long optHeaderStart = std::ftell(m_file);
        uint16_t optMagic = 0;
        if (!rd(&optMagic, 2)) { Close(); return false; }

        if (optMagic == 0x20B) { // PE32+
            std::fseek(m_file, optHeaderStart + 24, SEEK_SET);
            if (!rd(&m_imageBase, 8)) { Close(); return false; }
            std::fseek(m_file, optHeaderStart + 56, SEEK_SET);
            if (!rd(&m_sizeOfImage, 4)) { Close(); return false; }
            // DataDirectory[5] = BASE_RELOC (offset +112 into opt header for PE32+)
            std::fseek(m_file, optHeaderStart + 24 + 112, SEEK_SET);
            if (!rd(&m_relocDirRVA, 4) || !rd(&m_relocDirSize, 4)) { Close(); return false; }
        }

        std::fseek(m_file, optHeaderStart + optHeaderSize, SEEK_SET);

        m_sections.clear();
        for (uint16_t i = 0; i < numSections; i++) {
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

        std::printf("[PE] Opened %s (%u sections, ImageBase=0x%llX, SizeOfImage=0x%X)\n",
                    path, (unsigned)m_sections.size(),
                    (unsigned long long)m_imageBase, m_sizeOfImage);
        for (auto& s : m_sections) {
            std::printf("[PE]   %-8s VA=0x%08X Size=0x%08X FileOff=0x%08X\n",
                        s.name, s.virtualAddress, s.virtualSize, s.rawDataOffset);
        }
        std::printf("[PE] Parsed %u relocation entries across %u pages\n",
                    m_totalRelocEntries, (unsigned)m_relocs.size());
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

    void ParseRelocations() {
        // Prefer `.reloc` section — some dumpers leave BASE_RELOC data-dir
        // pointing into .rdata garbage while real reloc table is in the
        // named section. Data-dir is the fallback.
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
        // Resolve RVA → file offset without going through ReadAtRVA (which
        // would try to apply relocations that we haven't parsed yet).
        for (auto& sec : m_sections) {
            if (relocRVA >= sec.virtualAddress &&
                relocRVA <  sec.virtualAddress + sec.rawDataSize) {
                uint32_t fileOff = sec.rawDataOffset + (relocRVA - sec.virtualAddress);
                std::fseek(m_file, fileOff, SEEK_SET);
                size_t got = std::fread(relocData.data(), 1, relocSize, m_file);
                if (got < relocSize) relocData.resize(got);  // walk only what we read
                break;
            }
        }

        size_t offset = 0;
        while (offset + 8 <= relocData.size()) {
            uint32_t pageRVA   = *(uint32_t*)(relocData.data() + offset);
            uint32_t blockSize = *(uint32_t*)(relocData.data() + offset + 4);
            if (blockSize < 8 || offset + blockSize > relocData.size()) break;

            uint32_t numEntries = (blockSize - 8) / 2;
            auto& entries = m_relocs[pageRVA];
            for (uint32_t i = 0; i < numEntries; i++) {
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
// EmuEngine — Unicorn wrapper with lazy page faulting + PE fallback +
// external-call interception. Driven by IMemoryReader.
// =============================================================================
class EmuEngine {
public:
    EmuEngine() = default;
    ~EmuEngine() { Shutdown(); }

    bool Initialize(IMemoryReader* reader,
                    uint64_t gameBase,
                    uint64_t gameSize,
                    const char* peFilePath = nullptr)
    {
        m_reader = reader;
        m_base   = gameBase;
        m_size   = gameSize;

        if (peFilePath && peFilePath[0]) {
            if (m_peFile.Open(peFilePath)) {
                if (m_size == 0 && m_peFile.SizeOfImage() > 0)
                    m_size = m_peFile.SizeOfImage();
            }
        }

        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
        if (err != UC_ERR_OK) {
            std::printf("[EMU] uc_open failed: %s\n", uc_strerror(err));
            return false;
        }

        if ((err = uc_mem_map(m_uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL)) != UC_ERR_OK) {
            std::printf("[EMU] stack map failed: %s\n", uc_strerror(err));
            return false;
        }
        for (uint64_t p = STACK_BASE; p < STACK_BASE + STACK_SIZE; p += 0x1000)
            m_mapped.insert(p);

        uc_mem_map(m_uc, INPUT_BASE,    0x1000, UC_PROT_ALL);
        uc_mem_map(m_uc, OUTPUT_BASE,   0x1000, UC_PROT_ALL);
        uc_mem_map(m_uc, SENTINEL_PAGE, 0x1000, UC_PROT_ALL);
        m_mapped.insert(INPUT_BASE);
        m_mapped.insert(OUTPUT_BASE);
        m_mapped.insert(SENTINEL_PAGE);

        uc_hook hk;
        err = uc_hook_add(m_uc, &hk, UC_HOOK_MEM_UNMAPPED,
                          (void*)HookMemFault, this, 1, 0);
        if (err != UC_ERR_OK) {
            std::printf("[EMU] hook_add failed: %s\n", uc_strerror(err));
            return false;
        }

        m_initialized = true;
        std::printf("[EMU] Engine initialized (base=0x%llX size=0x%llX pe=%s)\n",
                    (unsigned long long)m_base, (unsigned long long)m_size,
                    m_peFile.IsOpen() ? "yes" : "no");
        return true;
    }

    void Shutdown() {
        if (m_uc) { uc_close(m_uc); m_uc = nullptr; }
        m_mapped.clear();
        m_peFile.Close();
        m_initialized = false;
    }

    bool IsReady() const { return m_initialized && m_uc; }

    // ── Section-budget management ───────────────────────────────────────────
    // Unicorn (Qemu) hard-limits the phys-section table to TARGET_PAGE_SIZE
    // (4096) entries. Each `uc_mem_map` consumes one slot — `uc_mem_unmap`
    // does NOT reclaim it. Long batch sessions that lazily fault in
    // thousands of distinct game pages will trip the assertion:
    //   `phys_section_add: map->sections_nb < TARGET_PAGE_SIZE`
    //
    // Workaround: when the live-mapped page set grows past `kSectionsBudget`,
    // tear down the engine entirely and reopen — fresh slot counter, all
    // game pages forgotten. The fixed regions (stack, scratch, sentinel)
    // are remapped immediately; everything else re-faults on demand.
    //
    // Callers that pin per-call state on top of the engine (e.g. EmuFName's
    // fake TEB) can detect a reset by watching `Epoch()` — it ticks every
    // time the engine is rebuilt.
    static constexpr size_t kSectionsBudget = 3500;   // headroom under 4096
    uint32_t Epoch() const { return m_epoch; }
    size_t   MappedPages() const { return m_mapped.size(); }

    bool MaybeReset(size_t headroom_pages = 64) {
        if (!m_uc) return false;
        if (m_mapped.size() + headroom_pages <= kSectionsBudget) return false;
        return Reset();
    }

    // Full teardown + reinit. Restores fixed regions and last-set GS_BASE.
    // Returns false if reopen failed (engine then unusable).
    bool Reset() {
        if (m_uc) { uc_close(m_uc); m_uc = nullptr; }
        m_mapped.clear();
        m_initialized = false;

        uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);
        if (err != UC_ERR_OK) {
            std::printf("[EMU] reset uc_open failed: %s\n", uc_strerror(err));
            return false;
        }
        if ((err = uc_mem_map(m_uc, STACK_BASE, STACK_SIZE, UC_PROT_ALL)) != UC_ERR_OK) {
            std::printf("[EMU] reset stack map failed: %s\n", uc_strerror(err));
            return false;
        }
        for (uint64_t p = STACK_BASE; p < STACK_BASE + STACK_SIZE; p += 0x1000)
            m_mapped.insert(p);
        uc_mem_map(m_uc, INPUT_BASE,    0x1000, UC_PROT_ALL);
        uc_mem_map(m_uc, OUTPUT_BASE,   0x1000, UC_PROT_ALL);
        uc_mem_map(m_uc, SENTINEL_PAGE, 0x1000, UC_PROT_ALL);
        m_mapped.insert(INPUT_BASE);
        m_mapped.insert(OUTPUT_BASE);
        m_mapped.insert(SENTINEL_PAGE);

        uc_hook hk;
        err = uc_hook_add(m_uc, &hk, UC_HOOK_MEM_UNMAPPED,
                          (void*)HookMemFault, this, 1, 0);
        if (err != UC_ERR_OK) {
            std::printf("[EMU] reset hook_add failed: %s\n", uc_strerror(err));
            return false;
        }
        if (m_gsBase) {
            uc_reg_write(m_uc, UC_X86_REG_GS_BASE, &m_gsBase);
        }
        m_initialized = true;
        ++m_epoch;
        std::printf("[EMU] Reset (epoch=%u, mapped=%zu)\n", m_epoch, m_mapped.size());
        return true;
    }

    // Most recent unmapped-access details captured by HookMemFault, useful
    // for diagnostics. Reset on every Run() call by callers if needed.
    uint64_t LastFaultAddr() const { return m_lastFaultAddr; }
    int      LastFaultType() const { return m_lastFaultType; }

    bool SetGSBase(uint64_t gsBase) {
        if (!m_uc) return false;
        uc_err err = uc_reg_write(m_uc, UC_X86_REG_GS_BASE, &gsBase);
        if (err != UC_ERR_OK) {
            std::printf("[EMU] SetGSBase failed: %s\n", uc_strerror(err));
            return false;
        }
        m_gsBase = gsBase;   // remember for Reset() restore
        return true;
    }

    // Map a single 4 KB page from the live game (or PE fallback).
    bool MapGamePage(uint64_t addr) {
        const uint64_t page = addr & ~0xFFFULL;
        if (m_mapped.count(page)) return true;

        uint8_t buf[0x1000];
        std::memset(buf, 0, sizeof(buf));
        bool readOk = m_reader && m_reader->Read(page, buf, 0x1000);

        if (!readOk && m_peFile.IsOpen() && page >= m_base) {
            uint32_t rva = (uint32_t)(page - m_base);
            int64_t relocDelta = (int64_t)m_base - (int64_t)m_peFile.PreferredBase();
            readOk = m_peFile.ReadAtRVA(rva, buf, 0x1000, relocDelta);
            if (readOk) {
                static int peFallbackCount = 0;
                if (peFallbackCount < 5)
                    std::printf("[EMU] PE fallback OK for page 0x%llX (RVA=0x%X)\n",
                                (unsigned long long)page, rva);
                else if (peFallbackCount == 5)
                    std::printf("[EMU] PE fallback OK (further messages suppressed)\n");
                peFallbackCount++;
            }
        }

        if (!readOk) {
            static int unreadableCount = 0;
            if (unreadableCount < 5)
                std::printf("[EMU] WARNING: page 0x%llX unreadable, mapping zeros\n",
                            (unsigned long long)page);
            else if (unreadableCount == 5)
                std::printf("[EMU] WARNING: page unreadable (further messages suppressed)\n");
            unreadableCount++;
        }

        uc_err err = uc_mem_map(m_uc, page, 0x1000, UC_PROT_ALL);
        if (err == UC_ERR_MAP) {
            uc_mem_write(m_uc, page, buf, 0x1000);
            m_mapped.insert(page);
            return true;
        }
        if (err != UC_ERR_OK) {
            static int mapFailCount = 0;
            if (mapFailCount < 3)
                std::printf("[EMU] map 0x%llX failed: %s\n",
                            (unsigned long long)page, uc_strerror(err));
            else if (mapFailCount == 3)
                std::printf("[EMU] map failed (further messages suppressed)\n");
            mapFailCount++;
            return false;
        }
        uc_mem_write(m_uc, page, buf, 0x1000);
        m_mapped.insert(page);
        return true;
    }

    void PreMapRange(uint64_t start, uint64_t size) {
        uint64_t pageStart = start & ~0xFFFULL;
        uint64_t pageEnd   = (start + size + 0xFFF) & ~0xFFFULL;
        for (uint64_t p = pageStart; p < pageEnd; p += 0x1000)
            MapGamePage(p);
    }

    void ResetCPU() {
        if (!m_uc) return;
        uint64_t zero = 0;
        for (int reg : {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
                        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP,
                        UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
                        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15})
            uc_reg_write(m_uc, reg, &zero);

        uint64_t rsp = STACK_BASE + STACK_SIZE - 0x100;
        uc_reg_write(m_uc, UC_X86_REG_RSP, &rsp);

        uint8_t xmm_zero[16] = {};
        for (int i = UC_X86_REG_XMM0; i <= UC_X86_REG_XMM15; i++)
            uc_reg_write(m_uc, i, xmm_zero);
    }

    uc_err Run(uint64_t startAddr, uint64_t endAddr,
               uint64_t timeout_us = 0, size_t maxInsns = 0) {
        return uc_emu_start(m_uc, startAddr, endAddr, timeout_us, maxInsns);
    }

    uint64_t ReadReg(int regId) {
        uint64_t val = 0;
        uc_reg_read(m_uc, regId, &val);
        return val;
    }
    void WriteReg(int regId, uint64_t val) {
        uc_reg_write(m_uc, regId, &val);
    }

    bool EmuRead(uint64_t addr, void* buf, size_t size) {
        return uc_mem_read(m_uc, addr, buf, size) == UC_ERR_OK;
    }
    bool EmuWrite(uint64_t addr, const void* buf, size_t size) {
        return uc_mem_write(m_uc, addr, buf, size) == UC_ERR_OK;
    }

    uc_err AddHook(uc_hook* hk, int type, void* callback, void* userdata,
                   uint64_t begin = 1, uint64_t end = 0) {
        return uc_hook_add(m_uc, hk, type, callback, userdata, begin, end);
    }
    void DelHook(uc_hook hk) { uc_hook_del(m_uc, hk); }

    void WriteRetStub(uint64_t addr) {
        MapGamePage(addr);
        uint8_t ret = 0xC3;
        uc_mem_write(m_uc, addr, &ret, 1);
    }

    void WriteMemmoveStub(uint64_t addr) {
        MapGamePage(addr);
        // mov rax,rcx ; push rdi ; push rsi ; mov rdi,rcx ; mov rsi,rdx ;
        // mov rcx,r8 ; rep movsb ; pop rsi ; pop rdi ; ret
        static const uint8_t stub[] = {
            0x48, 0x89, 0xC8, 0x57, 0x56,
            0x48, 0x89, 0xCF, 0x48, 0x89, 0xD6, 0x4C, 0x89, 0xC1,
            0xF3, 0xA4, 0x5E, 0x5F, 0xC3
        };
        uc_mem_write(m_uc, addr, stub, sizeof(stub));
    }

    uc_engine* UC()              { return m_uc; }
    uint64_t   ModuleBase() const { return m_base; }
    uint64_t   ModuleSize() const { return m_size; }

    static constexpr uint64_t STACK_BASE     = 0x00000000'70000000ULL;
    static constexpr uint64_t STACK_SIZE     = 0x00020000ULL;        // 128 KB
    static constexpr uint64_t INPUT_BASE     = 0x00000000'00010000ULL;
    static constexpr uint64_t OUTPUT_BASE    = 0x00000000'00020000ULL;
    static constexpr uint64_t SENTINEL_PAGE  = 0x00000000'DEAD0000ULL;
    static constexpr uint64_t SENTINEL_RIP   = 0x00000000'DEAD0000ULL;

private:
    uc_engine*        m_uc          = nullptr;
    IMemoryReader*    m_reader      = nullptr;
    uint64_t          m_base        = 0;
    uint64_t          m_size        = 0;
    bool              m_initialized = false;
    std::set<uint64_t> m_mapped;
    PEFileReader      m_peFile;
    uint64_t          m_lastFaultAddr = 0;
    int               m_lastFaultType = 0;
    uint64_t          m_gsBase        = 0;   // last value passed to SetGSBase, restored on Reset()
    uint32_t          m_epoch         = 0;   // ticks every Reset() so dependent state can re-arm

    // Lazy page-fault handler — also intercepts external calls
    static bool HookMemFault(uc_engine* uc, uc_mem_type type,
                             uint64_t address, int size,
                             int64_t value, void* user_data)
    {
        (void)value;
        auto* self = static_cast<EmuEngine*>(user_data);
        // Always record the most recent fault details for diagnostics.
        self->m_lastFaultAddr = address;
        self->m_lastFaultType = (int)type;
        const uint64_t page = address & ~0xFFFULL;

        if (page == 0) {
            static int s_null_count = 0;
            if (s_null_count < 3) {
                std::printf("[EMU] NULL deref at 0x%llX (size=%d type=%d)\n",
                            (unsigned long long)address, size, (int)type);
                s_null_count++;
            }
            return false;
        }

        // Intercept code fetches that leave the game module: drop a tiny
        // memmove stub at the faulting address and let execution continue.
        uint64_t moduleEnd = self->m_base + self->m_size;
        if (moduleEnd <= self->m_base) moduleEnd = self->m_base + 0x10000000;

        if (type == UC_MEM_FETCH_UNMAPPED &&
            (address < self->m_base || address >= moduleEnd))
        {
            uc_err map_err = uc_mem_map(uc, page, 0x1000, UC_PROT_ALL);
            if (map_err != UC_ERR_OK && map_err != UC_ERR_MAP)
                return false;

            // Safe memmove stub: checks for NULL src/dst before copying.
            //   mov rax, rcx          ; return = dst
            //   test rdx, rdx         ; if (src == NULL)
            //   jz  .done
            //   test r8, r8           ; if (count == 0)
            //   jz  .done
            //   push rdi
            //   push rsi
            //   mov rdi, rcx
            //   mov rsi, rdx
            //   mov rcx, r8
            //   rep movsb
            //   pop rsi
            //   pop rdi
            // .done:
            //   ret
            static const uint8_t memmove_stub[] = {
                0x48, 0x89, 0xC8,                   // mov rax, rcx
                0x48, 0x85, 0xD2,                   // test rdx, rdx
                0x74, 0x10,                          // jz +16 (.done)
                0x4D, 0x85, 0xC0,                   // test r8, r8
                0x74, 0x0C,                          // jz +12 (.done)
                0x57,                                // push rdi
                0x56,                                // push rsi
                0x48, 0x89, 0xCF,                   // mov rdi, rcx
                0x48, 0x89, 0xD6,                   // mov rsi, rdx
                0x4C, 0x89, 0xC1,                   // mov rcx, r8
                0xF3, 0xA4,                          // rep movsb
                0x5E,                                // pop rsi
                0x5F,                                // pop rdi
                0xC3                                 // ret
            };
            uc_mem_write(uc, address, memmove_stub, sizeof(memmove_stub));
            self->m_mapped.insert(page);

            static int interceptCount = 0;
            if (interceptCount < 10) {
                std::printf("[EMU] Intercepted external call at 0x%llX\n",
                            (unsigned long long)address);
                interceptCount++;
            }
            return true;
        }

        return self->MapGamePage(address);
    }
};

} // namespace EmuEngineNS

// Convenience type alias so callers can write `EmuEngine` after one
// `using namespace EmuEngineNS;` or directly via the namespace.
using EmuEngine = EmuEngineNS::EmuEngine;
