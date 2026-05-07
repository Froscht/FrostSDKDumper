#pragma once

// =============================================================================
// auto_chunks_emu.h — Function-discovery + Unicorn emulation chunks-array probe
//
// On CL-1177146 (and likely future ARC patches) the chunks-array is NOT a
// static field of GUObjectArray — it's recomputed on every access via a SIMD
// decrypt + virtual call inside chunks_manager. Tier 1 BFS through static
// memory therefore can never find it.
//
// This module recovers the chunks-array WITHOUT extracting any patch-specific
// SIMD constants, by:
//
//   1. Anchor: find any rip-rel SIMD load (MOVDQA / PSHUFLW / MOVDQU) in
//      .text whose target lands inside GUObjectArray's first 0x180 bytes.
//      The anchor is stable across patches because GUObjectArray itself is
//      auto-discovered and the encrypted blob lives somewhere in it
//      regardless of layout (CL-1177146=+0x10, 20260428=+0xB0, 20260421=+0x00).
//
//   2. Function bounds: walk back from the load to the previous CC padding
//      (universal x64 ABI — MSVC inserts INT3 between functions).
//
//   3. Stage-A emulation: run the function in Unicorn with a 60-instruction
//      limit + lazy page faulting from live memory. After the limit, scan
//      every GP register and the lo64 of every XMM register for a heap
//      pointer that LOOKS like chunks_manager (heap, not in module, has a
//      module-range vtable at +0x60 — the chunks-subarray-vtable indirection).
//
//   4. Stage-B emulation: for each candidate chunks_manager, try vtable
//      indices 3 / 5 / 7 (the known indices across patches CL-1177146 / older
//      / 20260428 / 20260421). For each, set up Unicorn with rcx = sub_array
//      pointer and rdx = pointer to a 16-byte stack buffer (loaded from
//      chunks_manager + N for several N candidates); call the vt function;
//      read xmm0 / rax for chunks_array.
//
//   5. Validate: chunks_array must point to N chunks where each chunk's
//      first qword (FUObjectItem.Object) is a heap UObject with module
//      vtable. Same oracle as the existing layout-BFS probe.
//
// Patch resilience:
//   - Anchor (data ref to GUObjectArray) — survives layout shifts
//   - Function bounds — universal x64 ABI
//   - Body shape — Unicorn runs whatever SIMD ops the patch uses
//   - vt-index extraction — try multiple indices
//   - chunks_array validator — depends only on heap shape (FUObjectItem
//     stride 20, .Object at +0, vtable in module)
//
// All five layers are patch-shape independent. The only fixed assumption is
// that the chunks-subarray vtable is at chunks_manager+0x60 — this has been
// stable across CL-1177146 / 20260428 / 20260421. If it shifts, broaden to
// scan multiple offsets.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unordered_set>
#include <unicorn/unicorn.h>

#include "memreader_iface.h"
#include "arc_decrypt.h"
#include "auto_discovery.h"
#include "sig_scanner_v2.h"
#include "func_analyzer.h"
#include "emu_engine.h"

namespace AutoChunksEmu {

struct Result {
    uint64_t ChunksManager   = 0;
    uint64_t ChunksArray     = 0;
    uint64_t DecryptFnRva    = 0;
    int      VtIndex         = 0;
    uint32_t InnerBlobOff    = 0;
    int      NumChunks       = 0;
    uint32_t NumElements     = 0;
    bool     Valid           = false;
};

inline bool IsHeapPtr(uint64_t p) {
    return p > 0x10000ULL && p < 0x800000000000ULL;
}
inline bool InModule(uint64_t p, uint64_t base, uint64_t size) {
    return p >= base && p < base + size;
}
inline bool IsHeapNonModule(uint64_t p, uint64_t base, uint64_t size) {
    return IsHeapPtr(p) && !InModule(p, base, size);
}

// Cheap prologue-shape check. Real x64 functions start with one of:
//   push reg / sub rsp, imm / mov [rsp+X], reg / lea / mov rax, gs:[60h] /
//   xor / or / and reg, reg / cmp / test / call / jmp short.
// Embedded-CC false positives (CC inside an instruction encoding rather than
// pad) typically land on bytes that don't match any valid x64 entrypoint.
inline bool LooksLikePrologue(const uint8_t* p) {
    if (!p) return false;
    uint8_t b0 = p[0], b1 = p[1], b2 = p[2];
    // push rbx/rbp/rsi/rdi (single byte 53/55/56/57)
    if (b0 == 0x53 || b0 == 0x55 || b0 == 0x56 || b0 == 0x57) return true;
    // push r12..r15 (41 5C/5D/5E/5F)
    if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) return true;
    // sub rsp, imm8: 48 83 EC ??
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xEC) return true;
    // sub rsp, imm32: 48 81 EC ?? ?? ?? ??
    if (b0 == 0x48 && b1 == 0x81 && b2 == 0xEC) return true;
    // mov [rsp+X], rXX: 48 89 5C/4C/54/74/7C 24 ??  (rbx/rcx/rdx/rsi/rdi)
    if (b0 == 0x48 && b1 == 0x89 && (b2 == 0x5C || b2 == 0x4C || b2 == 0x54 ||
        b2 == 0x74 || b2 == 0x7C) && p[3] == 0x24) return true;
    // mov [rsp+X], r8..r15: 4C 89 ?? 24 ??
    if (b0 == 0x4C && b1 == 0x89 && p[3] == 0x24) return true;
    // mov rax, qword ptr gs:[60h]: 65 48 8B 04 25 60 00 00 00
    if (b0 == 0x65 && b1 == 0x48 && b2 == 0x8B) return true;
    // mov rax, gs:[60h]: 65 48 A1 ...
    if (b0 == 0x65 && b1 == 0x48 && b2 == 0xA1) return true;
    // mov reg, rcx (preserve ICALL arg): 48 89 C8/D1/...
    if (b0 == 0x48 && b1 == 0x89 && b2 >= 0xC0 && b2 <= 0xCF) return true;
    // mov rax, rcx (48 8B C1) — common entry-stub idiom
    if (b0 == 0x48 && b1 == 0x8B && b2 == 0xC1) return true;
    // xor eax, eax (33 C0) at function head — rare but valid
    if (b0 == 0x33 && b1 == 0xC0) return true;
    // jmp rel8 / rel32 — tail-call thunks
    if (b0 == 0xE9 || b0 == 0xEB) return true;
    // ret (C3) / ret imm16 (C2) — single-instruction stub
    if (b0 == 0xC3 || b0 == 0xC2) return true;
    // test reg, reg: 48 85 ??
    if (b0 == 0x48 && b1 == 0x85) return true;
    // mov rXX, [rcx]: 48 8B (commonly 48 8B 01/09/11/19/...)
    if (b0 == 0x48 && b1 == 0x8B) return true;
    // lea rax, [rip+...]: 48 8D 05 ?? ?? ?? ??
    if (b0 == 0x48 && b1 == 0x8D) return true;
    // and rsp, -16: 48 83 E4 F0 (alignment thunk)
    if (b0 == 0x48 && b1 == 0x83 && b2 == 0xE4) return true;
    return false;
}

// Walk back from `code_rva` to find the function start. Uses CC padding as
// the boundary heuristic, then validates with LooksLikePrologue. If the
// initial CC-walk lands on a byte that doesn't look like a valid x64
// entrypoint (i.e. the CC was an embedded immediate, not real INT3 padding),
// keep walking back to find the next CC.
inline uint64_t WalkBackToFunctionStart(const SigScanV2::Scanner& scanner, uint64_t code_rva) {
    uint64_t cur = code_rva;
    for (int attempt = 0; attempt < 6; ++attempt) {
        uint64_t fn = FuncAnalyze::FindFunctionStart(scanner, cur);
        if (!fn || fn >= cur) return fn;  // walkback exhausted / no movement
        const uint8_t* p = scanner.GetLocalPtr(fn);
        if (LooksLikePrologue(p)) return fn;
        // Bogus walkback (CC was embedded, not pad). Restart search from one
        // byte before the rejected start so we look for an earlier CC.
        if (fn == 0) return 0;
        cur = fn - 1;
    }
    // Out of attempts — return the most recent CC-walkback result anyway.
    return FuncAnalyze::FindFunctionStart(scanner, code_rva);
}

// Find every rip-rel SIMD/MOV load in .text whose target lands in
// [GUObjectArray, GUObjectArray+0x180]. Each is a candidate "this function
// reads the encrypted GUObjectArray blob".
inline std::vector<uint64_t> FindGUObjectArrayLoaders(
    const SigScanV2::Scanner& scanner, uint64_t guobj_rva)
{
    std::vector<uint64_t> hits;
    auto try_pat = [&](const char* sig, int disp_off, int total_len) {
        auto raw = scanner.ScanSection(sig, ".text");
        for (uint64_t rva : raw) {
            const uint8_t* p = scanner.GetLocalPtr(rva);
            if (!p) continue;
            int32_t disp = 0;
            std::memcpy(&disp, p + disp_off, 4);
            uint64_t target = rva + total_len + (int64_t)disp;
            if (target >= guobj_rva && target < guobj_rva + 0x180) {
                hits.push_back(rva);
            }
        }
    };
    // MOVDQA xmm0..xmm7, [rip+disp32]:  66 0F 6F /r disp32 (8 bytes total when /r=000..111+disp32)
    try_pat("66 0F 6F 05 ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 0D ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 15 ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 1D ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 25 ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 2D ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 35 ?? ?? ?? ??", 4, 8);
    try_pat("66 0F 6F 3D ?? ?? ?? ??", 4, 8);
    // MOVQ xmm0..xmm7, [rip+disp32]:  F3 0F 7E /r disp32 (8 bytes)
    try_pat("F3 0F 7E 05 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 0D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 15 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 1D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 25 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 2D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 35 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 7E 3D ?? ?? ?? ??", 4, 8);
    // PSHUFLW xmm, [rip+disp32], imm:  F2 0F 70 /r disp32 imm (9 bytes)
    try_pat("F2 0F 70 05 ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 0D ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 15 ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 1D ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 25 ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 2D ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 35 ?? ?? ?? ?? ??", 4, 9);
    try_pat("F2 0F 70 3D ?? ?? ?? ?? ??", 4, 9);
    // MOVDQU xmm0..xmm7, [rip+disp32]:  F3 0F 6F /r disp32 (8 bytes)
    try_pat("F3 0F 6F 05 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 0D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 15 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 1D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 25 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 2D ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 35 ?? ?? ?? ??", 4, 8);
    try_pat("F3 0F 6F 3D ?? ?? ?? ??", 4, 8);
    // MOVAPS xmm0..xmm7, [rip+disp32]:  0F 28 /r disp32 (7 bytes)
    try_pat("0F 28 05 ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 0D ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 15 ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 1D ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 25 ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 2D ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 35 ?? ?? ?? ??", 3, 7);
    try_pat("0F 28 3D ?? ?? ?? ??", 3, 7);
    // MOVUPS xmm0..xmm7, [rip+disp32]:  0F 10 /r disp32 (7 bytes)
    try_pat("0F 10 05 ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 0D ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 15 ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 1D ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 25 ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 2D ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 35 ?? ?? ?? ??", 3, 7);
    try_pat("0F 10 3D ?? ?? ?? ??", 3, 7);

    // Dedup & sort
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
}

// Pre-map a 16 KB window around `addr` from live memory into Unicorn so the
// emulated function can read GUObjectArray / chunks_manager / .rdata SIMD
// constants without faulting out.
inline void PreMapWindow(EmuEngine& emu, uint64_t addr) {
    emu.PreMapRange(addr & ~0xFFFULL, 0x4000);
}

// Stage-A: emulate `fn_start` with insn_limit. Scan output regs for
// candidate chunks_manager pointers. Returns up to 8 candidates.
inline std::vector<uint64_t> EmulateAndScanForChunksManager(
    EmuEngine& emu, uint64_t fn_start, uint64_t module_base,
    const AutoDiscovery::ModuleBounds& bounds, IMemoryReader& reader)
{
    std::vector<uint64_t> candidates;
    constexpr uint64_t FAKE_TEB = 0x00007FFFFFFE0000ULL;
    constexpr uint64_t FAKE_PEB = 0x7FFD0000ULL;
    constexpr uint64_t SENTINEL = 0xDEAD0000ULL;
    constexpr int      INSN_LIMIT = 60;

    // TEB + PEB (Wine-canonical) — many functions touch gs:[0x60] (PEB ptr).
    uc_mem_map(emu.UC(), FAKE_TEB, 0x1000, UC_PROT_ALL);
    uint8_t teb_zero[0x1000] = {};
    uc_mem_write(emu.UC(), FAKE_TEB, teb_zero, sizeof(teb_zero));
    uint64_t self_ptr = FAKE_TEB;
    uc_mem_write(emu.UC(), FAKE_TEB + 0x30, &self_ptr, 8);
    uc_mem_write(emu.UC(), FAKE_TEB + 0x60, &FAKE_PEB, 8);
    emu.SetGSBase(FAKE_TEB);
    emu.MapGamePage(FAKE_PEB);

    // Pre-map GUObjectArray window (encrypted blob lives there).
    PreMapWindow(emu, module_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE);

    emu.ResetCPU();
    // Push sentinel as return address so RET exits cleanly.
    uint64_t rsp = emu.ReadReg(UC_X86_REG_RSP);
    rsp -= 8;
    emu.EmuWrite(rsp, &SENTINEL, 8);
    emu.WriteReg(UC_X86_REG_RSP, rsp);

    // Most candidate fns take 0 or 1 args. Initialize rcx to a benign value
    // (our scratch buffer) so guards like `if (rcx) ...` don't NPE.
    constexpr uint64_t SCRATCH = 0x10000ULL;
    uc_mem_map(emu.UC(), SCRATCH, 0x1000, UC_PROT_ALL);
    uint8_t scratch_zero[0x1000] = {};
    uc_mem_write(emu.UC(), SCRATCH, scratch_zero, sizeof(scratch_zero));
    emu.WriteReg(UC_X86_REG_RCX, SCRATCH);

    uc_err er = emu.Run(module_base + fn_start, SENTINEL,
                        /*timeout_us*/200'000, /*max_insns*/INSN_LIMIT);
    (void)er;  // most likely UC_ERR_INSN_INVALID or limit reached — that's fine

    // Scan all 64-bit GP registers + lo64 of XMM0..XMM15 for plausible
    // chunks_manager candidates. A candidate is heap, not in module, and has
    // a module-range vtable at +0x60 (the chunks-subarray vtable).
    auto try_candidate = [&](uint64_t v) {
        if (!IsHeapNonModule(v, module_base, bounds.ImageSize)) return;
        uint64_t vt_holder = 0;
        if (!reader.Read(v + 0x60, &vt_holder, 8)) return;
        if (!InModule(vt_holder, module_base, bounds.ImageSize)) return;
        for (uint64_t existing : candidates) if (existing == v) return;
        candidates.push_back(v);
    };

    static constexpr int kGpRegs[] = {
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,
        UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
        UC_X86_REG_R14, UC_X86_REG_R15,
    };
    for (int reg : kGpRegs) {
        try_candidate(emu.ReadReg(reg));
    }
    for (int i = UC_X86_REG_XMM0; i <= UC_X86_REG_XMM15 && candidates.size() < 8; ++i) {
        uint8_t bytes[16] = {};
        uc_reg_read(emu.UC(), i, bytes);
        uint64_t lo = 0;
        std::memcpy(&lo, bytes, 8);
        try_candidate(lo);
    }
    return candidates;
}

// Validate `chunks_array` by reading first N chunk pointers and confirming
// each chunk[0] is a heap UObject with module vtable. Returns chunks-passed
// count.
inline int ValidateChunksArray(IMemoryReader& reader, uint64_t chunks_array,
                                uint64_t module_base,
                                const AutoDiscovery::ModuleBounds& bounds,
                                int probe_n)
{
    int valid = 0;
    for (int i = 0; i < probe_n; ++i) {
        uint64_t chunk_ptr = 0;
        if (!reader.Read(chunks_array + (uint64_t)i * 8, &chunk_ptr, 8)) break;
        if (!IsHeapNonModule(chunk_ptr, module_base, bounds.ImageSize)) break;
        uint64_t obj = 0;
        if (!reader.Read(chunk_ptr, &obj, 8)) break;
        if (!IsHeapNonModule(obj, module_base, bounds.ImageSize)) break;
        uint64_t vt = 0;
        if (!reader.Read(obj, &vt, 8)) break;
        if (!InModule(vt, module_base, bounds.ImageSize)) break;
        ++valid;
    }
    return valid;
}

// Stage-B: try emulating chunks_manager's vt[N] with the inner blob from
// chunks_manager+blob_off. Returns chunks_array on success, 0 otherwise.
inline uint64_t TryVtCallForChunksArray(EmuEngine& emu, IMemoryReader& reader,
                                        uint64_t module_base,
                                        const AutoDiscovery::ModuleBounds& bounds,
                                        uint64_t chunks_manager,
                                        int vt_index, uint32_t blob_off,
                                        int probe_n)
{
    constexpr uint64_t FAKE_TEB = 0x00007FFFFFFE0000ULL;
    constexpr uint64_t SENTINEL = 0xDEAD1000ULL;
    constexpr uint64_t SCRATCH  = 0x11000ULL;

    uint64_t vt_holder_addr = chunks_manager + 0x60;
    uint64_t vtable_ptr = 0;
    if (!reader.Read(vt_holder_addr, &vtable_ptr, 8)) return 0;
    if (!InModule(vtable_ptr, module_base, bounds.ImageSize)) return 0;

    uint64_t vt_fn = 0;
    if (!reader.Read(vtable_ptr + (uint64_t)vt_index * 8, &vt_fn, 8)) return 0;
    if (!InModule(vt_fn, module_base, bounds.ImageSize)) return 0;

    uint8_t blob[16] = {};
    if (!reader.Read(chunks_manager + blob_off, blob, 16)) return 0;

    // Pre-map chunks_manager + vt_fn + blob site
    PreMapWindow(emu, chunks_manager);
    PreMapWindow(emu, vt_fn);
    PreMapWindow(emu, vtable_ptr);

    // Setup scratch buffer for blob
    uc_mem_map(emu.UC(), SCRATCH & ~0xFFFULL, 0x1000, UC_PROT_ALL);
    uc_mem_write(emu.UC(), SCRATCH, blob, 16);

    emu.ResetCPU();
    uint64_t rsp = emu.ReadReg(UC_X86_REG_RSP);
    rsp -= 8;
    emu.EmuWrite(rsp, &SENTINEL, 8);
    emu.WriteReg(UC_X86_REG_RSP, rsp);
    emu.WriteReg(UC_X86_REG_RCX, vt_holder_addr);
    emu.WriteReg(UC_X86_REG_RDX, SCRATCH);
    emu.SetGSBase(FAKE_TEB);

    uc_err er = emu.Run(vt_fn, SENTINEL, /*timeout*/300'000, /*max*/300);
    (void)er;

    // chunks_array might be in xmm0.lo64 or rax — try both
    uint8_t xmm0_bytes[16] = {};
    uc_reg_read(emu.UC(), UC_X86_REG_XMM0, xmm0_bytes);
    uint64_t xmm0_lo = 0;
    std::memcpy(&xmm0_lo, xmm0_bytes, 8);
    uint64_t rax = emu.ReadReg(UC_X86_REG_RAX);

    for (uint64_t cand : {xmm0_lo, rax}) {
        if (!IsHeapNonModule(cand, module_base, bounds.ImageSize)) continue;
        if (ValidateChunksArray(reader, cand, module_base, bounds, probe_n) >= 2) {
            return cand;
        }
    }
    return 0;
}

// Top-level: discover chunks_array via function-emulation.
//
// `pe_path` is needed for EmuEngine PE-on-disk fallback (VMP-cold pages).
// On success, `out` is filled with chunks_array + chunks_manager + metadata.
inline Result Discover(IMemoryReader& reader, uint64_t module_base,
                       const SigScanV2::Scanner& scanner,
                       const AutoDiscovery::ModuleBounds& bounds,
                       const char* pe_path, uint64_t emu_map_size)
{
    Result out;
    if (!bounds.Valid) return out;

    // Read NumElements. The field has migrated across patches:
    //   CL-1177146: +0x30  (plain u32)
    //   CL-1177678: +0xFC  (plain u32 — listener arrays / serial-counter
    //                       ahead of it pushed the count further out)
    // Probe both; first one in the plausible live-count range (1000..2M) wins.
    // The encrypted chunks_manager pipeline at GUObjectArray+0xC0 is unchanged
    // across both — only the count field moved.
    uint64_t guobj_abs = module_base + ArcDecrypt::RVA_GOBJECT_ARRAY_BASE;
    uint32_t num_elements = 0;
    static constexpr uint32_t kCountOffs[] = { 0xFC, 0x30 };
    uint32_t count_off_used = 0;
    for (uint32_t off : kCountOffs) {
        uint32_t cand = 0;
        if (!reader.Read(guobj_abs + off, &cand, 4)) continue;
        if (cand >= 1000 && cand <= 2'000'000) {
            num_elements = cand;
            count_off_used = off;
            break;
        }
    }
    if (!num_elements) {
        std::printf("[autoemu] no NumElements found at +0xFC or +0x30 in plausible range; "
                    "skipping emu discovery\n");
        return out;
    }
    std::printf("[autoemu] NumElements=%u @ +0x%X (good)\n", num_elements, count_off_used);
    out.NumElements = num_elements;
    out.NumChunks   = (num_elements + 0xFFFF) / 0x10000;
    int probe_n = std::min(out.NumChunks, 4);
    if (probe_n < 2) probe_n = 2;

    auto hits = FindGUObjectArrayLoaders(scanner, ArcDecrypt::RVA_GOBJECT_ARRAY_BASE);
    std::printf("[autoemu] %zu rip-rel loaders found targeting GUObjectArray's first 0x180 bytes\n",
        hits.size());
    if (hits.empty()) return out;

    // Build distinct function-start list from hits (many hits may map to
    // the same function via multiple SIMD loads in its body).
    //
    // Cap at 256 distinct fn_starts. The previous 12-cap stopped before
    // reaching the documented chunks-manager fn at RVA 0x4BD190 — hits
    // are processed in ascending order and 12 unique walkbacks were filled
    // by lower-RVA candidates (most of them embedded-CC false positives).
    // 256 covers the full search range; each emulation is fast (~60 insns).
    std::vector<uint64_t> fn_starts;
    std::unordered_set<uint64_t> seen;
    size_t walkback_failed = 0, walkback_dup = 0;
    for (uint64_t rva : hits) {
        uint64_t fn = WalkBackToFunctionStart(scanner, rva);
        if (!fn) { ++walkback_failed; continue; }
        if (!seen.insert(fn).second) { ++walkback_dup; continue; }
        fn_starts.push_back(fn);
        if (fn_starts.size() >= 256) break;
    }
    std::printf("[autoemu] %zu distinct candidate functions (cap=256, walkback_failed=%zu, dup=%zu)\n",
        fn_starts.size(), walkback_failed, walkback_dup);

    EmuEngine emu;
    if (!emu.Initialize(&reader, module_base, emu_map_size, pe_path)) {
        std::printf("[autoemu] EmuEngine init failed\n");
        return out;
    }

    // Inner-blob offset candidates within chunks_manager. CL-1177146 uses
    // +0x90; older patches may differ. Try the most common ones.
    static constexpr uint32_t kBlobOffs[] = { 0x90, 0xB0, 0x70, 0x80, 0xA0 };
    static constexpr int      kVtIndices[] = { 3, 7, 5, 1, 4, 6 };

    for (uint64_t fn : fn_starts) {
        std::printf("[autoemu] candidate fn @ rva=0x%llX — emulating\n",
            (unsigned long long)fn);
        auto cands = EmulateAndScanForChunksManager(emu, fn, module_base, bounds, reader);
        if (cands.empty()) {
            std::printf("[autoemu]   no chunks_manager candidate registers\n");
            continue;
        }
        std::printf("[autoemu]   %zu chunks_manager candidate(s):", cands.size());
        for (uint64_t c : cands) std::printf(" 0x%llX", (unsigned long long)c);
        std::printf("\n");

        for (uint64_t cand : cands) {
            for (int vt_idx : kVtIndices) {
                for (uint32_t blob_off : kBlobOffs) {
                    uint64_t arr = TryVtCallForChunksArray(emu, reader, module_base,
                                                          bounds, cand, vt_idx,
                                                          blob_off, probe_n);
                    if (!arr) continue;
                    out.ChunksManager = cand;
                    out.ChunksArray   = arr;
                    out.DecryptFnRva  = fn;
                    out.VtIndex       = vt_idx;
                    out.InnerBlobOff  = blob_off;
                    out.Valid         = true;
                    std::printf("[autoemu] SUCCESS — chunks_manager=0x%llX chunks_array=0x%llX "
                                "vt[%d] blob_off=+0x%X\n",
                        (unsigned long long)cand, (unsigned long long)arr,
                        vt_idx, blob_off);
                    return out;
                }
            }
        }
    }

    std::printf("[autoemu] no working (chunks_manager, vt[N], blob_off) combination found\n");
    return out;
}

inline Result g_LastResult;

}  // namespace AutoChunksEmu
