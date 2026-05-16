#pragma once
// =============================================================================
// find_fname_func.h — locate the *outer* FName→string decrypt function in
// the live game by signature scanning .text. The signature is the canonical
// caller setup pattern from the reference tool:
//
//   48 8D 4C 24 28              LEA  RCX, [RSP+0x28]    ; output buffer
//   48 8D 94 24 30 08 00 00     LEA  RDX, [RSP+0x830]   ; (or similar)
//   E8 ?? ?? ?? ??              CALL Dec_GName_Index2Name
//
// We scan .text page-by-page (sliding window so straddling matches survive),
// resolve the E8 displacement to get the called function's RVA, and report
// the most-frequent target across all caller hits. That target is the FName
// decrypt function entry — the one we'll feed to Unicorn in Phase 2.
// =============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "memreader_iface.h"
#include "insn_decoder.h"

namespace FNameFuncFinder {

struct Hit {
    uint64_t caller_rva = 0;  // RVA of the LEA RCX,[RSP+0x28] instruction
    uint64_t target_rva = 0;  // RVA of the called function (E8 disp resolved)
};

struct Result {
    bool                  found = false;
    uint64_t              best_target_rva = 0;   // most-frequent target across hits
    uint32_t              best_target_count = 0;
    std::vector<Hit>      hits;
};

// Walk backwards from `hit_offset` looking for an MSVC-style function frame
// setup: a `SUB RSP, imm8/imm32` instruction (`48 83 EC ??` or `48 81 EC ?? ?? ?? ??`)
// optionally preceded by a sequence of PUSH instructions / `MOV [RSP+x], REG`
// stores. We walk back at most `max_back` bytes; if we don't find a frame
// setup we return 0 (caller treats this as "no function start found").
//
// This is much more reliable than the CC-padding heuristic, which falsely
// triggers on int3 alignment inside function bodies (after no-return calls
// or before hot-loop labels).
inline size_t WalkBackToFrameSetup(const uint8_t* buf, size_t hit_offset,
                                   size_t max_back = 0x400)
{
    if (hit_offset < 4) return 0;
    size_t lo = (hit_offset > max_back) ? (hit_offset - max_back) : 0;

    // Look for `48 83 EC ??` (SUB RSP, imm8) or `48 81 EC ?? ?? ?? ??` (SUB RSP, imm32).
    // The function start is the FIRST PUSH/MOV-store/REX-pushed-reg byte at
    // or before that SUB instruction. We walk back from hit looking for the
    // SUB, then walk forward over preceding pushes to find the entry.
    for (size_t i = hit_offset - 4; i >= lo; --i) {
        // SUB RSP, imm8: 48 83 EC ??
        bool sub_rsp_imm8 = (buf[i] == 0x48 && buf[i+1] == 0x83 && buf[i+2] == 0xEC);
        // SUB RSP, imm32: 48 81 EC ?? ?? ?? ??
        bool sub_rsp_imm32 = (buf[i] == 0x48 && buf[i+1] == 0x81 && buf[i+2] == 0xEC);
        if (sub_rsp_imm8 || sub_rsp_imm32) {
            // Walk back from `i` over PUSH variants and `MOV [RSP+x], REG` saves.
            // PUSH RBP/RBX/RSI/RDI/RAX/RCX/RDX = 0x50..0x57
            // PUSH R8..R15                     = 0x41 0x50..0x57
            // PUSH RBX with REX                = 0x40 0x53
            // MOV [RSP+x], REG (8/32 disp)     = 48 89 5C/6C/74/7C 24 disp
            size_t j = i;
            while (j > lo) {
                uint8_t b = buf[j - 1];
                // Single-byte PUSH r{ax..di}
                if (b >= 0x50 && b <= 0x57) { --j; continue; }
                // REX prefix + PUSH r{8..15}: check 41 50..57
                if (j >= 2 && buf[j - 2] == 0x41 && b >= 0x50 && b <= 0x57) { j -= 2; continue; }
                // 40 53 = PUSH RBX with redundant REX
                if (j >= 2 && buf[j - 2] == 0x40 && b == 0x53) { j -= 2; continue; }
                // MOV [RSP+disp8], REG: 48 89 5C/6C/74/7C 24 disp8 → 5 bytes
                if (j >= 5 && buf[j - 5] == 0x48 && buf[j - 4] == 0x89 &&
                    (buf[j - 3] == 0x5C || buf[j - 3] == 0x6C ||
                     buf[j - 3] == 0x74 || buf[j - 3] == 0x7C) &&
                    buf[j - 2] == 0x24)
                {
                    j -= 5; continue;
                }
                break;
            }
            return j;
        }
        if (i == lo) break;
    }
    return 0;
}

// Walk backwards from `hit_offset` inside `buf` to the previous RUN of
// `min_run` or more consecutive 0xCC padding bytes (real function alignment
// padding, not single `int3` instructions inside function bodies). Returns
// the offset of the first non-CC byte after that run (i.e. the function
// start). Returns 0 if no such run is found within the buffer.
//
// The default `min_run = 4` is high enough to skip past stray int3s emitted
// after no-return calls (which appear singly or in pairs) but still matches
// the typical 4–15 byte alignment fill MSVC inserts between functions.
inline size_t WalkBackToFuncStart(const uint8_t* buf, size_t hit_offset,
                                  int min_run = 4) {
    if (hit_offset == 0) return 0;
    int run = 0;
    for (size_t i = hit_offset; i > 0; --i) {
        if (buf[i - 1] == 0xCC) {
            ++run;
            if (run >= min_run) {
                // Walk forward over the rest of the CC run (if any) and
                // return the byte right after it.
                size_t start = i;
                while (start < hit_offset && buf[start] == 0xCC) ++start;
                return start;
            }
        } else {
            run = 0;
        }
    }
    return 0;
}

// Read PE .text bounds from the live module's image header.
// Returns true on success.
inline bool GetTextBoundsLive(IMemoryReader& reader, uint64_t module_base,
                              uint32_t& text_rva, uint32_t& text_size)
{
    uint8_t hdr[0x1000] = {};
    if (!reader.Read(module_base, hdr, sizeof(hdr))) return false;

    uint32_t e_lfanew = *(uint32_t*)(hdr + 0x3C);
    if (e_lfanew >= sizeof(hdr) - 0x100) return false;
    if (*(uint32_t*)(hdr + e_lfanew) != 0x00004550) return false; // "PE\0\0"

    uint16_t numSections   = *(uint16_t*)(hdr + e_lfanew + 6);
    uint16_t optHeaderSize = *(uint16_t*)(hdr + e_lfanew + 0x14);
    uint32_t sectStart     = e_lfanew + 0x18 + optHeaderSize;

    for (uint16_t i = 0; i < numSections && sectStart + (i+1)*0x28 <= sizeof(hdr); ++i) {
        const uint8_t* s = hdr + sectStart + i * 0x28;
        if (std::memcmp(s, ".text", 5) == 0) {
            text_size = *(uint32_t*)(s + 8);
            text_rva  = *(uint32_t*)(s + 12);
            return true;
        }
    }
    return false;
}

// Scan .text for the LEA RCX/LEA RDX/CALL prologue setup, resolve targets,
// and tally to find the most-likely FName decrypt function.
inline Result Find(IMemoryReader& reader, uint64_t module_base) {
    Result out;

    uint32_t text_rva = 0, text_size = 0;
    if (!GetTextBoundsLive(reader, module_base, text_rva, text_size)) {
        std::printf("[find-fname] PE header parse failed\n");
        return out;
    }
    if (text_size > 0x10000000u) text_size = 0x10000000u;
    std::printf("[find-fname] .text: rva=0x%X size=0x%X\n", text_rva, text_size);

    // Caller signature: 14 fixed bytes (the LEAs are fully literal because
    // the displacements are constant in this idiom). 5-byte tail = E8 + rel32.
    static const uint8_t pat[] = {
        0x48, 0x8D, 0x4C, 0x24, 0x28,                  // LEA RCX,[RSP+0x28]
        0x48, 0x8D, 0x94, 0x24, 0x30, 0x08, 0x00, 0x00,// LEA RDX,[RSP+0x830]
        0xE8                                            // CALL rel32
    };
    constexpr size_t PAT_LEN  = sizeof(pat);
    constexpr size_t TAIL_LEN = 4;                  // rel32 disp
    constexpr size_t TOTAL    = PAT_LEN + TAIL_LEN; // 18

    // Sliding-window page scanner — same shape as fname_autodetect's
    // GetTextBounds path so unmapped pages don't kill the scan.
    constexpr size_t PAGE = 0x1000;
    uint8_t window[PAGE * 2] = {};
    bool    page_valid[2] = { false, false };

    size_t good_pages = 0, bad_pages = 0;
    std::unordered_map<uint64_t, uint32_t> target_counts;

    for (uint32_t page_off = 0; page_off < text_size; page_off += PAGE) {
        std::memcpy(window, window + PAGE, PAGE);
        page_valid[0] = page_valid[1];
        page_valid[1] = false;

        size_t read_size = PAGE;
        if (page_off + read_size > text_size) read_size = text_size - page_off;
        if (reader.Read(module_base + text_rva + page_off, window + PAGE, read_size)) {
            if (read_size < PAGE) std::memset(window + PAGE + read_size, 0, PAGE - read_size);
            page_valid[1] = true;
            good_pages++;
        } else {
            std::memset(window + PAGE, 0, PAGE);
            bad_pages++;
        }

        if (!page_valid[0]) continue;

        size_t search_len = page_valid[1] ? (PAGE + TOTAL) : PAGE;
        if (search_len > sizeof(window)) search_len = sizeof(window);
        if (search_len < TOTAL) continue;

        // Linear scan for the literal prefix; small enough to be fine.
        const size_t last = search_len - TOTAL;
        for (size_t i = 0; i <= last; ++i) {
            if (window[i] != pat[0]) continue;
            if (std::memcmp(window + i, pat, PAT_LEN) != 0) continue;

            // RVA of the LEA RCX instruction = (page_off - PAGE) + i
            // RIP after the CALL instruction (5 bytes total: E8+rel32) is
            //   call_rva + 5, where call_rva = caller_rva + 13 (13 = LEA RCX(5)+LEA RDX(8))
            uint64_t caller_rva = (uint64_t)text_rva + (page_off - PAGE) + i;
            uint64_t call_rva   = caller_rva + 13;
            int32_t  rel        = *(const int32_t*)(window + i + PAT_LEN);
            uint64_t target_rva = call_rva + 5 + (int64_t)rel;

            Hit h{ caller_rva, target_rva };
            out.hits.push_back(h);
            target_counts[target_rva]++;
        }
    }

    std::printf("[find-fname] scanned %zu pages (%zu good, %zu bad), %zu hits\n",
                good_pages + bad_pages, good_pages, bad_pages, out.hits.size());

    // Pick the most-frequent target.
    for (auto& kv : target_counts) {
        if (kv.second > out.best_target_count) {
            out.best_target_count = kv.second;
            out.best_target_rva   = kv.first;
        }
    }
    out.found = (out.best_target_count > 0);

    if (out.found) {
        std::printf("[find-fname] best target: rva=0x%llX (%u callers)\n",
                    (unsigned long long)out.best_target_rva,
                    out.best_target_count);

        // Show all distinct targets so we can sanity-check (sometimes the
        // same idiom is used by multiple unrelated functions).
        if (target_counts.size() > 1) {
            std::printf("[find-fname] all distinct targets:\n");
            for (auto& kv : target_counts) {
                std::printf("[find-fname]   rva=0x%llX  callers=%u\n",
                            (unsigned long long)kv.first, kv.second);
            }
        }

        // Dump the first 32 bytes of the target so we can eyeball-verify
        // it looks like a real function prologue.
        uint8_t pro[32] = {};
        if (reader.Read(module_base + out.best_target_rva, pro, sizeof(pro))) {
            std::printf("[find-fname] target prologue bytes: ");
            for (int i = 0; i < 32; ++i) std::printf("%02X ", pro[i]);
            std::printf("\n");
        } else {
            std::printf("[find-fname] (could not read target page from live process)\n");
        }
    } else {
        std::printf("[find-fname] no caller signature matched in .text\n");
    }

    return out;
}

// =============================================================================
// Plan B — scan .text for every CALL E8 whose rel32 target equals
// `inner_func_rva`, back-walk each call site to its enclosing function start
// (via 0xCC padding), and report the deduplicated set of caller functions.
//
// `inner_func_rva` is typically the per-name decryptor we already found via
// fname_autodetect (e.g. 0x13B0045 in live 1.1137). The callers we find
// are one level up the call graph; the FName→string entry point should
// be either there directly or one more level up.
// =============================================================================
struct CallerHit {
    uint64_t call_site_rva = 0;  // address of the E8 byte
    uint64_t func_start_rva = 0; // back-walked function-start RVA
};

inline std::vector<CallerHit> FindCallersOf(IMemoryReader& reader,
                                            uint64_t module_base,
                                            uint64_t inner_func_rva)
{
    std::vector<CallerHit> out;

    uint32_t text_rva = 0, text_size = 0;
    if (!GetTextBoundsLive(reader, module_base, text_rva, text_size)) {
        std::printf("[find-callers] PE header parse failed\n");
        return out;
    }
    if (text_size > 0x10000000u) text_size = 0x10000000u;
    std::printf("[find-callers] .text: rva=0x%X size=0x%X  target=0x%llX\n",
                text_rva, text_size, (unsigned long long)inner_func_rva);

    // Sliding window: keep 0x400 bytes of history so the back-walk to a
    // function start can find the previous CC padding even if the call
    // site is near the start of the current page.
    constexpr size_t PAGE = 0x1000;
    constexpr size_t HIST = 0x1000;        // 4 KB of back-history for the func-start walk
    constexpr size_t WIN  = HIST + PAGE * 2;

    std::vector<uint8_t> window(WIN, 0);
    bool                 page_valid[2] = { false, false };
    size_t               good_pages = 0, bad_pages = 0;

    std::unordered_map<uint64_t, uint32_t> func_counts;

    for (uint32_t page_off = 0; page_off < text_size; page_off += PAGE) {
        // Slide: discard the oldest PAGE, shift everything down by PAGE,
        // pull in a new page at the back. The HIST prefix preserves
        // enough history for the function-start back-walk.
        std::memmove(window.data(), window.data() + PAGE, WIN - PAGE);
        page_valid[0] = page_valid[1];
        page_valid[1] = false;
        std::memset(window.data() + WIN - PAGE, 0, PAGE);

        size_t read_size = PAGE;
        if (page_off + read_size > text_size) read_size = text_size - page_off;
        if (reader.Read(module_base + text_rva + page_off, window.data() + WIN - PAGE, read_size)) {
            page_valid[1] = true;
            good_pages++;
        } else {
            bad_pages++;
        }

        if (!page_valid[0]) continue;

        // The "current" page being searched is the FIRST of the two
        // pages at the back of the window — i.e. window[HIST..HIST+PAGE].
        // Its absolute base RVA is (page_off - PAGE) + text_rva.
        size_t cur_base = HIST;
        size_t cur_end  = HIST + PAGE;
        // Need 5 trailing bytes for the rel32 to be readable inside window.
        if (cur_end + 4 > WIN) cur_end = WIN - 4;

        for (size_t i = cur_base; i + 4 < cur_end; ++i) {
            if (window[i] != 0xE8) continue;

            int32_t  rel        = *(const int32_t*)(window.data() + i + 1);
            // call site RVA = (page_off - PAGE) + (i - HIST) + text_rva
            uint64_t cs_rva     = (uint64_t)text_rva + (page_off - PAGE) + (i - HIST);
            uint64_t next_ip    = cs_rva + 5;
            uint64_t target_rva = next_ip + (int64_t)rel;

            if (target_rva != inner_func_rva) continue;

            // Try the MSVC frame-setup walker first (much more accurate
            // than CC padding); fall back to CC heuristic if that fails.
            size_t start_off = WalkBackToFrameSetup(window.data(), i, /*max_back=*/0xC00);
            if (start_off == 0) {
                start_off = WalkBackToFuncStart(window.data(), i);
            }
            uint64_t func_start_rva = (uint64_t)text_rva + (page_off - PAGE) + (start_off - HIST);

            // Best-effort: if the back-walk hit position 0 (no padding
            // found in window), fall back to recording the call site
            // address itself so the user has *something* to look at.
            if (start_off == 0) func_start_rva = cs_rva;

            CallerHit ch{ cs_rva, func_start_rva };
            out.push_back(ch);
            func_counts[func_start_rva]++;
        }
    }

    std::printf("[find-callers] scanned %zu pages (%zu good, %zu bad)  hits=%zu  unique funcs=%zu\n",
                good_pages + bad_pages, good_pages, bad_pages, out.size(), func_counts.size());

    // Print sorted summary by frequency.
    std::vector<std::pair<uint64_t, uint32_t>> sorted(func_counts.begin(), func_counts.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    for (size_t k = 0; k < sorted.size() && k < 16; ++k) {
        std::printf("[find-callers]   func rva=0x%llX  call_count=%u\n",
                    (unsigned long long)sorted[k].first, sorted[k].second);
        // Dump 32 bytes of prologue so we can eyeball it
        uint8_t pro[32] = {};
        if (reader.Read(module_base + sorted[k].first, pro, sizeof(pro))) {
            std::printf("[find-callers]     prologue: ");
            for (int j = 0; j < 32; ++j) std::printf("%02X ", pro[j]);
            std::printf("\n");
        }
    }

    return out;
}

// =============================================================================
// Plan C — find every instruction that takes a RIP-relative reference to a
// given absolute target RVA, back-walk each site to its enclosing function
// start, and tally. Use this to find functions that touch a known data
// global (e.g. the FName per-length key table at module+0xBD61C20).
//
// We scan every byte position in .text and reinterpret bytes [pos..pos+4) as
// a rel32 displacement. For each instruction encoding in our shortlist, the
// disp32 sits at a different offset from the start of the instruction, so we
// effectively check `(pos + insn_len) + disp32 == target` for several
// plausible values of `insn_len`. Any of {6,7,8,9} catches all the SSE /
// LEA / MOV rip-rel encodings we care about.
// =============================================================================
inline std::vector<CallerHit> FindRipRelRefs(IMemoryReader& reader,
                                             uint64_t module_base,
                                             uint64_t target_rva)
{
    std::vector<CallerHit> out;

    uint32_t text_rva = 0, text_size = 0;
    if (!GetTextBoundsLive(reader, module_base, text_rva, text_size)) {
        std::printf("[find-rip-ref] PE header parse failed\n");
        return out;
    }
    if (text_size > 0x10000000u) text_size = 0x10000000u;
    std::printf("[find-rip-ref] .text: rva=0x%X size=0x%X  target=0x%llX\n",
                text_rva, text_size, (unsigned long long)target_rva);

    constexpr size_t PAGE = 0x1000;
    constexpr size_t HIST = 0x1000;        // 4 KB of back-history for the func-start walk
    constexpr size_t WIN  = HIST + PAGE * 2;

    std::vector<uint8_t> window(WIN, 0);
    bool                 page_valid[2] = { false, false };
    size_t               good_pages = 0, bad_pages = 0;

    std::unordered_map<uint64_t, uint32_t> func_counts;

    // Plausible instruction lengths for rip-rel encodings whose disp32
    // is the LAST 4 bytes of the instruction. Each value tested means:
    // "the disp32 sits at offset (insn_len - 4) from the instruction start".
    static const int kInsnLens[] = { 6, 7, 8, 9 };

    for (uint32_t page_off = 0; page_off < text_size; page_off += PAGE) {
        std::memmove(window.data(), window.data() + PAGE, WIN - PAGE);
        page_valid[0] = page_valid[1];
        page_valid[1] = false;
        std::memset(window.data() + WIN - PAGE, 0, PAGE);

        size_t read_size = PAGE;
        if (page_off + read_size > text_size) read_size = text_size - page_off;
        if (reader.Read(module_base + text_rva + page_off, window.data() + WIN - PAGE, read_size)) {
            page_valid[1] = true;
            good_pages++;
        } else {
            bad_pages++;
        }

        if (!page_valid[0]) continue;

        size_t cur_base = HIST;
        size_t cur_end  = HIST + PAGE;
        if (cur_end + 4 > WIN) cur_end = WIN - 4;

        for (size_t i = cur_base; i + 4 < cur_end; ++i) {
            int32_t disp = *(const int32_t*)(window.data() + i);
            // Coarse range filter: real disp32 to .data section is positive
            // (data is after .text in the image) and within +/- 256 MB. The
            // bulk of random 4-byte windows fail this check immediately.
            if (disp <= 0 || disp > 0x10000000) continue;

            for (int len : kInsnLens) {
                // disp32 sits at offset (len - 4) from the instruction
                // start. So instruction starts at (i - (len - 4)), and the
                // RIP after the instruction is `instr_start + len`. The
                // disp is then resolved against that RIP.
                int disp_off  = len - 4;
                int insn_off  = (int)i - disp_off;
                if (insn_off < (int)cur_base) continue;
                int next_ip   = insn_off + len;
                uint64_t cur_page_rva = (uint64_t)text_rva + (page_off - PAGE);
                uint64_t next_ip_rva  = cur_page_rva + (next_ip - HIST);
                uint64_t resolved     = next_ip_rva + (int64_t)disp;
                if (resolved != target_rva) continue;

                // Got a hit. Try the frame-setup back-walk first; fall
                // back to CC padding if that turns up nothing.
                size_t start_off = WalkBackToFrameSetup(window.data(), (size_t)insn_off);
                if (start_off == 0) {
                    start_off = WalkBackToFuncStart(window.data(), (size_t)insn_off);
                }
                uint64_t insn_rva       = cur_page_rva + (insn_off - (int)HIST);
                uint64_t func_start_rva = cur_page_rva + (start_off - HIST);
                if (start_off == 0) func_start_rva = insn_rva;

                CallerHit ch{ insn_rva, func_start_rva };
                out.push_back(ch);
                func_counts[func_start_rva]++;
                break; // one hit per byte position is enough
            }
        }
    }

    std::printf("[find-rip-ref] scanned %zu pages (%zu good, %zu bad)  hits=%zu  unique funcs=%zu\n",
                good_pages + bad_pages, good_pages, bad_pages, out.size(), func_counts.size());

    std::vector<std::pair<uint64_t, uint32_t>> sorted(func_counts.begin(), func_counts.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });

    for (size_t k = 0; k < sorted.size() && k < 16; ++k) {
        std::printf("[find-rip-ref]   func rva=0x%llX  ref_count=%u\n",
                    (unsigned long long)sorted[k].first, sorted[k].second);

        // Dump 192 bytes BEFORE the candidate so we can see the real
        // enclosing function prologue / boundary instead of just the loop
        // alignment pad the back-walk landed on.
        const uint64_t pre_addr = module_base + sorted[k].first - 192;
        uint8_t pre[192] = {};
        if (sorted[k].first >= 192 && reader.Read(pre_addr, pre, sizeof(pre))) {
            std::printf("[find-rip-ref]     pre-context (192 B):\n     ");
            for (int j = 0; j < 192; ++j) {
                std::printf("%02X ", pre[j]);
                if ((j & 0x1F) == 0x1F && j != 191) std::printf("\n     ");
            }
            std::printf("\n");
        }

        uint8_t pro[64] = {};
        if (reader.Read(module_base + sorted[k].first, pro, sizeof(pro))) {
            std::printf("[find-rip-ref]     at-hit (64 B):     ");
            for (int j = 0; j < 64; ++j) std::printf("%02X ", pro[j]);
            std::printf("\n");
        }
    }

    return out;
}

// =============================================================================
// Plan D — find the FName decrypt function by its distinctive SIMD body
// instead of a caller-side stack-setup pattern.
//
// Patch 20260421's FName decrypt (sub_23D3E0) executes this fingerprint:
//
//   66 0F 38 00 05 ?? ?? ?? ??   pshufb xmm0, [rip+disp32]   ; FName_CI_PSHUFB_Mask
//   66 0F 6F C8                  movdqa xmm1, xmm0
//   66 0F 72 D1 1A               psrld  xmm1, 0x1A           ; ROR shift = 32-6
//   66 0F 72 F0 06               pslld  xmm0, 6              ; ROL shift = 6
//   66 0F EB C1                  por    xmm0, xmm1
//   F2 0F 70 C0 93               pshuflw xmm0, xmm0, 0x93
//
// The combination of PSRLD imm=0x1A + PSLLD imm=6 (a ROL32(6) implemented as
// shifts + OR) and PSHUFLW imm=0x93 doesn't occur naturally elsewhere in the
// binary — those three immediates are the FName algorithm's "shape". Even if
// the encryption KEYS change between patches, this *shape* tends to survive
// (the algorithm is the same, only the constants move).
//
// We scan .text for the fingerprint, then back-walk via WalkBackToFrameSetup
// to find the function entry. Returns the function-start RVA, or 0.
// =============================================================================
inline uint64_t FindBySimdFingerprint(IMemoryReader& reader, uint64_t module_base) {
    uint32_t text_rva = 0, text_size = 0;
    if (!GetTextBoundsLive(reader, module_base, text_rva, text_size)) return 0;
    if (text_size > 0x10000000u) text_size = 0x10000000u;

    // 36-byte signature with a single 4-byte wildcard for the PSHUFB rip-rel disp.
    // Each byte: lo nibble of `mask[i]` set means literal-match required.
    static const uint8_t sig[]  = {
        0x66, 0x0F, 0x38, 0x00, 0x05,   0x00, 0x00, 0x00, 0x00,  // pshufb xmm0,[rip+?]
        0x66, 0x0F, 0x6F, 0xC8,                                   // movdqa xmm1, xmm0
        0x66, 0x0F, 0x72, 0xD1, 0x1A,                             // psrld xmm1, 0x1A
        0x66, 0x0F, 0x72, 0xF0, 0x06,                             // pslld xmm0, 6
        0x66, 0x0F, 0xEB, 0xC1,                                   // por xmm0, xmm1
        0xF2, 0x0F, 0x70, 0xC0, 0x93                              // pshuflw xmm0,xmm0,0x93
    };
    static const uint8_t mask[] = {
        1,1,1,1,1, 0,0,0,0,        // pshufb (4 wildcards for disp32)
        1,1,1,1,
        1,1,1,1,1,
        1,1,1,1,1,
        1,1,1,1,
        1,1,1,1,1
    };
    constexpr size_t SIG_LEN = sizeof(sig);

    // Sliding-window page scanner mirroring Plan A.
    constexpr size_t PAGE = 0x1000;
    uint8_t window[PAGE * 2] = {};
    bool    page_valid[2] = { false, false };
    uint64_t hit_text_off = 0;
    bool     found_hit    = false;

    for (uint32_t page_off = 0; page_off < text_size && !found_hit; page_off += PAGE) {
        std::memcpy(window, window + PAGE, PAGE);
        page_valid[0] = page_valid[1];
        page_valid[1] = false;

        size_t read_size = PAGE;
        if (page_off + read_size > text_size) read_size = text_size - page_off;
        if (reader.Read(module_base + text_rva + page_off, window + PAGE, read_size)) {
            if (read_size < PAGE) std::memset(window + PAGE + read_size, 0, PAGE - read_size);
            page_valid[1] = true;
        } else {
            std::memset(window + PAGE, 0, PAGE);
        }

        if (!page_valid[0]) continue;
        size_t search_len = page_valid[1] ? (PAGE + SIG_LEN) : PAGE;
        if (search_len > sizeof(window)) search_len = sizeof(window);
        if (search_len < SIG_LEN) continue;

        const size_t last = search_len - SIG_LEN;
        for (size_t i = 0; i <= last; ++i) {
            bool ok = true;
            for (size_t j = 0; j < SIG_LEN; ++j) {
                if (mask[j] && window[i + j] != sig[j]) { ok = false; break; }
            }
            if (!ok) continue;
            // page_off-PAGE is the absolute base of window[0..PAGE]; the hit is at i.
            hit_text_off = (uint64_t)(page_off - PAGE) + i;
            // Back-walk from the SIMD body to the function start. The
            // body starts ~0x21 bytes into sub_23D3E0 (push x4 + sub rsp +
            // security cookie setup), so a 0x100-byte back-walk is plenty.
            // Note: WalkBackToFrameSetup expects the offset INSIDE `window`.
            size_t start_off = WalkBackToFrameSetup(window, i, /*max_back=*/0x200);
            uint64_t func_start_rva = 0;
            if (start_off > 0)
                func_start_rva = (uint64_t)text_rva + (page_off - PAGE) + start_off;
            else
                func_start_rva = (uint64_t)text_rva + hit_text_off; // fallback: SIMD-body addr
            std::printf("[find-fname-simd] fingerprint @ rva=0x%llX  func_start≈0x%llX\n",
                        (unsigned long long)((uint64_t)text_rva + hit_text_off),
                        (unsigned long long)func_start_rva);
            found_hit = true;
            return func_start_rva;
        }
    }
    std::printf("[find-fname-simd] SIMD fingerprint not found\n");
    return 0;
}

// =============================================================================
// Extract the ENTRY_HANDLE_XOR constant (`bswap64(handle ^ XOR)`) from the
// FName function body. Pattern in patch 20260421:
//
//   48 B? <imm64-LE>          mov r64, imm64        ; the XOR constant
//   48 33 ?? ?? ?? ?? ??      xor r64, [rsp+disp]   ; xor with the pipeline value
//   48 0F C?                  bswap r64
//
// We scan from `func_start_rva` for the first MOV r64,imm64 (REX prefix 0x48
// or 0x49, opcode 0xB8..0xBF) followed within ~32 bytes by a BSWAP r64.
// Returns the imm64 on success, 0 on failure.
// =============================================================================
inline uint64_t ExtractEntryHandleXor(IMemoryReader& reader,
                                      uint64_t module_base,
                                      uint64_t func_start_rva,
                                      size_t   max_scan = 0x200)
{
    if (!func_start_rva) return 0;
    std::vector<uint8_t> buf(max_scan);
    if (!reader.Read(module_base + func_start_rva, buf.data(), max_scan)) {
        std::printf("[xor-extract] couldn't read function body @ 0x%llX\n",
                    (unsigned long long)func_start_rva);
        return 0;
    }

    // Walk the buffer looking for the MOV r64,imm64 instruction.
    // 48 B8..BF = mov r{ax..di},imm64; 49 B8..BF = mov r{8..15},imm64.
    // The instruction is 10 bytes; imm64 is at +2.
    for (size_t i = 0; i + 16 < max_scan; ++i) {
        bool rex_w   = (buf[i] == 0x48 || buf[i] == 0x49);
        bool mov_imm = (buf[i + 1] >= 0xB8 && buf[i + 1] <= 0xBF);
        if (!rex_w || !mov_imm) continue;

        uint64_t imm64 = 0;
        std::memcpy(&imm64, buf.data() + i + 2, 8);

        // Look ahead up to 32 bytes for a BSWAP r64 (48/49 0F C8..CF).
        // Must also see a XOR (48/49 33 ...) between the MOV and the BSWAP.
        bool saw_xor = false, saw_bswap = false;
        for (size_t j = i + 10; j + 2 < std::min(max_scan, i + 10 + 32); ++j) {
            bool rex2 = (buf[j] == 0x48 || buf[j] == 0x49);
            if (!rex2) continue;
            if (buf[j + 1] == 0x33) { saw_xor = true; continue; }
            if (buf[j + 1] == 0x0F &&
                buf[j + 2] >= 0xC8 && buf[j + 2] <= 0xCF) {
                saw_bswap = true; break;
            }
        }
        if (saw_xor && saw_bswap) {
            std::printf("[xor-extract] found XOR=0x%016llX at func+0x%zX\n",
                        (unsigned long long)imm64, i);
            return imm64;
        }
    }
    std::printf("[xor-extract] MOV r64,imm64 + XOR + BSWAP triple not found\n");
    return 0;
}

// =============================================================================
// Keystream-offset rediscovery — extends the auto-disc heap-probe pipeline so
// it survives one more patch generation.
//
// Background: the existing path in auto_discovery.h::DiscoverFNameKeystream
// picks the densest SIMD-constants cluster, then assumes the keystream sits at
// a fixed +0xA0 inside that block. On CL-1177678 that's still true, but on
// later builds (current = ScriptStruct vtable moved from 0xAD9DC20 → 0xADF4820)
// the +0xA0 bias is the first thing that drifts when ARC reshuffles the SIMD
// constants table. The fix is to validate multiple offsets and pick by entropy
// — encrypted u16 keystream tables have ~7.7 bits/byte Shannon entropy, while
// the adjacent SIMD masks / XOR constants are full of repeating patterns
// (entropy ≤ 5.0) or runs of 0x00 / 0xFF padding (entropy → 0).
// =============================================================================

// Shannon entropy of `len` bytes, returned as bits-per-byte (max = 8.0).
inline double KeystreamEntropy(const uint8_t* buf, size_t len) {
    if (len == 0) return 0.0;
    int hist[256] = {};
    for (size_t i = 0; i < len; ++i) hist[buf[i]]++;
    double h = 0.0;
    const double inv = 1.0 / (double)len;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        double p = (double)hist[i] * inv;
        h -= p * std::log2(p);
    }
    return h;
}

// Reject anchors whose +0..256 window is all-zero, all-FF, or has < 32 distinct
// byte values. Real keystreams hit at least ~120 distinct bytes in 256.
inline bool KeystreamShapeOK(const uint8_t* buf, size_t len) {
    if (len < 64) return false;
    bool all_same = true;
    for (size_t i = 1; i < len; ++i) {
        if (buf[i] != buf[0]) { all_same = false; break; }
    }
    if (all_same) return false;
    int distinct = 0;
    int hist[256] = {};
    for (size_t i = 0; i < len; ++i) {
        if (!hist[buf[i]]) { hist[buf[i]] = 1; ++distinct; }
    }
    return distinct >= 32;
}

struct KeystreamCandidate {
    uint64_t offset_from_anchor = 0;
    uint64_t absolute_rva       = 0;
    double   entropy            = 0.0;
    bool     shape_ok           = false;
    bool     readable           = false;
};

struct KeystreamProbeResult {
    bool                            found        = false;
    uint64_t                        best_rva     = 0;
    uint64_t                        best_offset  = 0;
    double                          best_entropy = 0.0;
    std::vector<KeystreamCandidate> candidates;
};

// Try +0x80, +0xA0, +0xC0, +0xE0, +0x100 from `anchor_rva` (the SIMD-constants
// cluster base). For each, read 256 bytes via the live reader, gate on shape,
// score by Shannon entropy, and pick the highest-entropy survivor. Threshold:
// entropy ≥ 6.0 bits/byte (encrypted keystreams sit at ~7.5–7.9; structured
// SIMD masks rarely break 5.5).
inline KeystreamProbeResult ProbeKeystreamOffsets(IMemoryReader& reader,
                                                  uint64_t module_base,
                                                  uint64_t anchor_rva,
                                                  double   entropy_min = 6.0)
{
    KeystreamProbeResult out;
    if (!anchor_rva) {
        std::printf("[autodisc-fname] ProbeKeystreamOffsets: anchor=0 — skipped\n");
        return out;
    }

    static const uint64_t kOffsets[] = { 0x80, 0xA0, 0xC0, 0xE0, 0x100 };
    constexpr size_t SAMPLE = 256;
    uint8_t buf[SAMPLE] = {};

    std::printf("[autodisc-fname] probing keystream offsets from anchor 0x%llX:\n",
                (unsigned long long)anchor_rva);

    for (uint64_t off : kOffsets) {
        KeystreamCandidate c;
        c.offset_from_anchor = off;
        c.absolute_rva       = anchor_rva + off;

        std::memset(buf, 0, SAMPLE);
        c.readable = reader.Read(module_base + c.absolute_rva, buf, SAMPLE);
        if (!c.readable) {
            std::printf("[autodisc-fname]   +0x%03llX rva=0x%llX  unreadable\n",
                        (unsigned long long)off,
                        (unsigned long long)c.absolute_rva);
            out.candidates.push_back(c);
            continue;
        }
        c.shape_ok = KeystreamShapeOK(buf, SAMPLE);
        c.entropy  = KeystreamEntropy(buf, SAMPLE);

        std::printf("[autodisc-fname]   +0x%03llX rva=0x%llX  H=%.3f  shape=%s\n",
                    (unsigned long long)off,
                    (unsigned long long)c.absolute_rva,
                    c.entropy, c.shape_ok ? "ok" : "BAD");

        out.candidates.push_back(c);

        if (c.shape_ok && c.entropy >= entropy_min && c.entropy > out.best_entropy) {
            out.best_entropy = c.entropy;
            out.best_offset  = off;
            out.best_rva     = c.absolute_rva;
            out.found        = true;
        }
    }

    if (out.found) {
        std::printf("[autodisc-fname] pick: +0x%llX → rva=0x%llX  H=%.3f\n",
                    (unsigned long long)out.best_offset,
                    (unsigned long long)out.best_rva,
                    out.best_entropy);
    } else {
        std::printf("[autodisc-fname] no candidate passed entropy floor %.2f — probe failed\n",
                    entropy_min);
    }
    return out;
}

// =============================================================================
// Structural fallback — when the SIMD-anchor + offset probe fails entirely,
// walk the FName resolver function (plus its first-level direct callees) with
// Zydis and collect every rip-rel load whose target lands in .data/.rdata.
// The keystream cluster shows up as a dense window of distinct addresses
// (≥2 separate loads in a 0x100-byte band) — same fingerprint as the primary
// auto-disc, just centred on the resolver call-graph instead of the
// AppendNameToString chain.
//
// Returns the highest-entropy 256-byte window inside any such cluster, or 0
// if nothing qualifies. Cheap — decodes ≤ 0x800 bytes per function and only
// recurses one level deep (the keystream load is always within 2 frames of
// the resolver entry per the CL-1177678 reference: 0x2311B0 → 0x245AA0
// → 0x2458C0 has the MOVQ xmm, cs:keystream).
// =============================================================================
struct ResolverKeystreamScan {
    uint64_t keystream_rva = 0;     // best candidate RVA (cluster base)
    double   entropy       = 0.0;
    int      cluster_size  = 0;     // distinct rip-rel loads inside the cluster window
    bool     found         = false;
    std::vector<uint64_t> hot_targets; // top rip-rel targets, sorted by ref count
};

inline ResolverKeystreamScan ScanResolverForKeystream(IMemoryReader& reader,
                                                     uint64_t module_base,
                                                     uint64_t fname_fn_rva,
                                                     int max_depth = 2)
{
    ResolverKeystreamScan out;
    if (!fname_fn_rva) {
        std::printf("[autodisc-fname] ScanResolver: fname_rva=0 — skipped\n");
        return out;
    }

    InsnDecoder dec;

    // BFS over the call chain — bounded to `max_depth` frames so we don't
    // chase the entire transitive graph. CL-1177678's keystream load lives at
    // depth 2 (entry → sub_245AA0 → sub_2458C0), so 2 is the floor.
    std::unordered_set<uint64_t> visited;
    std::vector<uint64_t> frontier{ fname_fn_rva };

    std::unordered_map<uint64_t, int> data_hits;  // target_rva → ref count

    for (int depth = 0; depth <= max_depth && !frontier.empty(); ++depth) {
        std::vector<uint64_t> next;
        for (uint64_t fn_rva : frontier) {
            if (!visited.insert(fn_rva).second) continue;

            uint8_t code[0x800] = {};
            if (!reader.Read(module_base + fn_rva, code, sizeof(code))) continue;

            auto insns = dec.Decode(code, sizeof(code), fn_rva);
            for (const auto& ins : insns) {
                // Collect direct callees for next frontier layer.
                if (ins.type == INSN_CALL_RIP && ins.hasRipRel) {
                    uint64_t tgt = ins.ResolveRipRVA();
                    if (tgt && tgt != fn_rva) next.push_back(tgt);
                    continue;
                }
                // Skip control flow / non-data rip-rel.
                if (ins.type == INSN_JMP)  continue;
                if (ins.type == INSN_JCC)  continue;
                if (!ins.hasRipRel) continue;

                uint64_t t = ins.ResolveRipRVA();
                if (!t) continue;
                // Heuristic: .data/.rdata live well after .text. Reject
                // anything that looks like a back-ref into .text (resolver
                // itself, jump tables) by requiring t > fname_fn_rva + 0x100000.
                if (t < fname_fn_rva + 0x100000ULL) continue;
                data_hits[t]++;
            }
        }
        frontier.swap(next);
    }

    if (data_hits.empty()) {
        std::printf("[autodisc-fname] ScanResolver: no rip-rel data targets in call chain\n");
        return out;
    }

    // Cluster the targets exactly like DiscoverFNameKeystream does: a 0x100-
    // byte window with ≥2 distinct hits is the keystream signature (single-
    // shot PXOR/PAND constants give 1-distinct clusters).
    std::vector<uint64_t> targets;
    targets.reserve(data_hits.size());
    for (const auto& kv : data_hits) targets.push_back(kv.first);
    std::sort(targets.begin(), targets.end());

    uint64_t best_lo = 0;
    int      best_distinct = 0;
    for (size_t i = 0; i < targets.size(); ++i) {
        uint64_t lo = targets[i];
        uint64_t hi = lo + 0x100;
        int distinct = 0;
        for (size_t j = i; j < targets.size() && targets[j] < hi; ++j) ++distinct;
        if (distinct > best_distinct) {
            best_distinct = distinct;
            best_lo       = lo;
        }
    }

    // Surface the top-N rip-rel targets for the verbose log so a human can
    // sanity-check on patch-day.
    std::vector<std::pair<uint64_t, int>> sorted(data_hits.begin(), data_hits.end());
    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.second > b.second; });
    std::printf("[autodisc-fname] ScanResolver: %zu distinct rip-rel targets across "
                "call chain (depth≤%d); top loads:\n",
                data_hits.size(), max_depth);
    int shown = 0;
    for (const auto& [t, c] : sorted) {
        if (shown++ >= 8) break;
        std::printf("[autodisc-fname]   rva=0x%llX  refs=%d\n",
                    (unsigned long long)t, c);
        out.hot_targets.push_back(t);
    }

    if (best_distinct < 2) {
        std::printf("[autodisc-fname] ScanResolver: best cluster has %d distinct loads "
                    "(need ≥2) — fallback failed\n", best_distinct);
        return out;
    }

    // Score the cluster's 256-byte window by entropy; only accept if it
    // actually looks like a keystream (same gate as ProbeKeystreamOffsets).
    uint8_t buf[256] = {};
    if (!reader.Read(module_base + best_lo, buf, sizeof(buf))) {
        std::printf("[autodisc-fname] ScanResolver: cluster @ 0x%llX unreadable\n",
                    (unsigned long long)best_lo);
        return out;
    }
    double h = KeystreamEntropy(buf, sizeof(buf));
    bool   shape = KeystreamShapeOK(buf, sizeof(buf));
    std::printf("[autodisc-fname] ScanResolver: cluster @ 0x%llX  distinct=%d  H=%.3f  shape=%s\n",
                (unsigned long long)best_lo, best_distinct, h, shape ? "ok" : "BAD");

    if (!shape || h < 6.0) {
        std::printf("[autodisc-fname] ScanResolver: cluster failed entropy/shape gate — reject\n");
        return out;
    }

    out.keystream_rva = best_lo;
    out.entropy       = h;
    out.cluster_size  = best_distinct;
    out.found         = true;
    std::printf("[autodisc-fname] ScanResolver: keystream candidate = 0x%llX  H=%.3f\n",
                (unsigned long long)out.keystream_rva, out.entropy);
    return out;
}

// =============================================================================
// One-shot wrapper — pick the keystream RVA using the offset probe first, and
// fall back to the structural scan if every offset fails. Returns 0 on total
// failure. Logs everything under the [autodisc-fname] tag so patch-day triage
// can read the decision trail end-to-end.
// =============================================================================
inline uint64_t AutoDiscoverFNameKeystream(IMemoryReader& reader,
                                          uint64_t module_base,
                                          uint64_t simd_anchor_rva,
                                          uint64_t fname_fn_rva)
{
    std::printf("[autodisc-fname] === keystream rediscovery ===\n");
    std::printf("[autodisc-fname]   anchor (SIMD cluster) = 0x%llX\n",
                (unsigned long long)simd_anchor_rva);
    std::printf("[autodisc-fname]   resolver fn           = 0x%llX\n",
                (unsigned long long)fname_fn_rva);

    KeystreamProbeResult probe = ProbeKeystreamOffsets(reader, module_base, simd_anchor_rva);
    if (probe.found) {
        std::printf("[autodisc-fname] WIN via offset probe: rva=0x%llX (+0x%llX from anchor)\n",
                    (unsigned long long)probe.best_rva,
                    (unsigned long long)probe.best_offset);
        return probe.best_rva;
    }

    std::printf("[autodisc-fname] offset probe failed — engaging resolver structural scan\n");
    ResolverKeystreamScan scan = ScanResolverForKeystream(reader, module_base, fname_fn_rva);
    if (scan.found) {
        std::printf("[autodisc-fname] WIN via structural fallback: rva=0x%llX\n",
                    (unsigned long long)scan.keystream_rva);
        return scan.keystream_rva;
    }

    std::printf("[autodisc-fname] LOSS: both probe + structural fallback returned nothing\n");
    return 0;
}

} // namespace FNameFuncFinder
