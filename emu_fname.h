#pragma once
// =============================================================================
// DEPRECATED for the SDK dumper hot path (since 2026-04-13).
//
// The SDKDumper now uses the version-specific wrappers:
//   • emu_fname_xbox.h  → EmuFNameXbox  (Xbox 1.1137 — verified entry RVAs)
//   • emu_fname_steam.h → EmuFNameSteam (Steam — stub, RVAs TBD)
//
// This generic wrapper is retained for the standalone CLI test modes
// (--emu-fname, --emu-real, --emu-inner) which exercise individual
// inner decryptors at user-supplied RVAs. New code should use one of
// the version-specific wrappers above.
// =============================================================================
// emu_fname.h — call the live game's FName decrypt routine inside Unicorn.
//
// In live ARC 1.1137 the function we found at RVA 0x1329D7F has this shape:
//
//   void Decrypt(uint8_t* encrypted_entry  /*RCX*/,
//                wchar_t* output_buffer    /*RDX*/);
//
// where `encrypted_entry` is a pointer to an FNameEntry inside the FNamePool:
//
//   struct FNameEntry {
//       uint16_t header;        // top bit = wide flag, low 10 bits = length
//       uint8_t  bytes[length]; // encrypted chars (one of 6 inner decryptors
//                               // is selected based on header)
//   };
//
// To call this function we point RCX at a live game address (the pool
// entry) — Unicorn's lazy-fault hook will pull the page from HyperVReader
// (or PE fallback) on first access, so we don't have to copy anything in
// ourselves. RDX points at a scratch buffer in the emulator's SCRATCH
// region, which we read back after the call.
// =============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "emu_engine.h"

namespace EmuFNameNS {

class EmuFName {
public:
    bool Init(EmuEngine* engine, uint64_t module_base, uint64_t func_rva) {
        if (!engine || !engine->IsReady()) {
            std::printf("[FNameEmu] engine not ready\n");
            return false;
        }
        m_engine     = engine;
        m_module     = module_base;
        m_funcAbs    = module_base + func_rva;
        m_funcRVA    = func_rva;
        std::printf("[FNameEmu] target func @ rva=0x%llX abs=0x%llX\n",
                    (unsigned long long)func_rva,
                    (unsigned long long)m_funcAbs);
        return true;
    }

    // Toggle verbose per-call logging. Defaults to true for standalone
    // test runs; the SDKDumper integration flips it off before batch
    // resolution of 67960+ names.
    void SetVerbose(bool v) { m_verbose = v; }

    // Call the FName decrypt routine with `entry_abs_addr` (a live game
    // address pointing at an encrypted FNameEntry in the pool) and return
    // the decoded string. Empty string on failure.
    //
    // `try_wide` controls whether the output is interpreted as UTF-16
    // (true) or 8-bit ANSI (false). The reference tool always reads it
    // as wide, but ARC's pool entries are commonly 8-bit.
    std::string Decrypt(uint64_t entry_abs_addr, bool try_wide = false) {
        if (!m_engine || !m_engine->IsReady()) return {};

        // Reset CPU and stack so each call is independent.
        m_engine->ResetCPU();

        // Allocate a 0x1000 scratch buffer for the output. Use INPUT_BASE
        // and OUTPUT_BASE which the engine pre-mapped for us.
        const uint64_t out_addr = EmuEngineNS::EmuEngine::OUTPUT_BASE;
        std::vector<uint8_t> zeros(0x1000, 0);
        m_engine->EmuWrite(out_addr, zeros.data(), zeros.size());

        // x64 ABI: at function entry, RSP % 16 == 8 (because the caller's
        // CALL pushed 8 bytes). Subtract 0x28 (0x20 shadow space + 0x08
        // simulated return address) so the callee's MOVDQA stack accesses
        // stay 16-byte aligned after its prologue.
        const uint64_t rsp = EmuEngineNS::EmuEngine::STACK_BASE
                           + EmuEngineNS::EmuEngine::STACK_SIZE - 0x28;
        m_engine->WriteReg(UC_X86_REG_RSP, rsp);

        // Sentinel return address — when the function RETs, RIP jumps
        // here and uc_emu_start exits cleanly.
        const uint64_t sentinel = EmuEngineNS::EmuEngine::SENTINEL_RIP;
        m_engine->EmuWrite(rsp, &sentinel, 8);

        // RCX = live pool-entry pointer, RDX = output buffer.
        m_engine->WriteReg(UC_X86_REG_RCX, entry_abs_addr);
        m_engine->WriteReg(UC_X86_REG_RDX, out_addr);
        m_engine->WriteReg(UC_X86_REG_R8,  0);
        m_engine->WriteReg(UC_X86_REG_R9,  0);
        m_engine->WriteReg(UC_X86_REG_RAX, 0);

        if (m_verbose) {
            std::printf("[FNameEmu] calling 0x%llX with RCX=0x%llX RDX=0x%llX\n",
                        (unsigned long long)m_funcAbs,
                        (unsigned long long)entry_abs_addr,
                        (unsigned long long)out_addr);
        }

        // Run with a generous instruction budget. The decrypt loops in the
        // 6 inner per-char decryptors run for at most ~500 iterations of
        // ~5 instructions each, plus prologue/epilogue. 200k is plenty.
        uc_err err = m_engine->Run(m_funcAbs,
                                    EmuEngineNS::EmuEngine::SENTINEL_RIP,
                                    /*timeout_us*/ 5'000'000,
                                    /*max_insns */ 200'000);

        if (err != UC_ERR_OK) {
            // Silently fail — errors are expected for bad entry headers.
            // Verbose mode still logs to verbose-only callers (--emu-real etc).
            return {};
        }

        uint64_t ret_rax = m_engine->ReadReg(UC_X86_REG_RAX);
        if (m_verbose) {
            std::printf("[FNameEmu] returned, RAX=0x%llX (interpreted as length)\n",
                        (unsigned long long)ret_rax);
        }

        // The function may return:
        //   - the length in EAX, or
        //   - an output pointer, or
        //   - garbage if we picked the wrong target
        // Cap to a sane range either way.
        size_t guess_len = (size_t)(ret_rax & 0xFFFF);
        if (guess_len == 0 || guess_len > 1024) guess_len = 64;

        // Read the first 256 bytes of output as a hex dump so we can see
        // exactly what came back regardless of encoding guess.
        uint8_t raw[256] = {};
        m_engine->EmuRead(out_addr, raw, sizeof(raw));
        if (m_verbose) {
            std::printf("[FNameEmu] output[0..63]: ");
            for (int j = 0; j < 64; ++j) std::printf("%02X ", raw[j]);
            std::printf("\n");
        }

        // Decode best-effort
        std::string out;
        if (try_wide) {
            for (size_t j = 0; j < guess_len && j * 2 + 1 < sizeof(raw); ++j) {
                uint16_t wc = (uint16_t)raw[j * 2] | ((uint16_t)raw[j * 2 + 1] << 8);
                if (wc == 0) break;
                out.push_back(wc < 0x80 ? (char)wc : '?');
            }
        } else {
            for (size_t j = 0; j < guess_len && j < sizeof(raw); ++j) {
                uint8_t c = raw[j];
                if (c == 0) break;
                out.push_back((c >= 0x20 && c < 0x7F) ? (char)c : '?');
            }
        }
        return out;
    }

    // Smoke-test one of the 6 per-char decryptors directly with synthetic
    // input. We write a fake "FName entry" into INPUT_BASE, set RCX=INPUT,
    // RDX=OUTPUT, and call. The decryptor reads u16 length from [RCX],
    // copies/decrypts bytes from [RCX+2] into [RDX], and returns the
    // length in EAX (for the variants that have that ABI).
    //
    // `inner_func_rva` is one of {0x1331B80, 0x1333240, 0x133330F,
    //  0x1333390, 0x133AF9E, 0x133B020}.
    bool TestInnerDecryptor(uint64_t inner_func_rva,
                            const uint8_t* fake_entry, size_t fake_len)
    {
        if (!m_engine || !m_engine->IsReady()) return false;

        const uint64_t in_addr  = EmuEngineNS::EmuEngine::INPUT_BASE;
        const uint64_t out_addr = EmuEngineNS::EmuEngine::OUTPUT_BASE;

        // Zero output, write fake entry to input
        std::vector<uint8_t> zeros(0x800, 0);
        m_engine->EmuWrite(out_addr, zeros.data(), zeros.size());
        m_engine->EmuWrite(in_addr,  zeros.data(), zeros.size());
        m_engine->EmuWrite(in_addr,  fake_entry, fake_len);

        m_engine->ResetCPU();

        // x64 ABI stack setup
        const uint64_t rsp = EmuEngineNS::EmuEngine::STACK_BASE
                           + EmuEngineNS::EmuEngine::STACK_SIZE - 0x28;
        m_engine->WriteReg(UC_X86_REG_RSP, rsp);
        const uint64_t sentinel = EmuEngineNS::EmuEngine::SENTINEL_RIP;
        m_engine->EmuWrite(rsp, &sentinel, 8);

        m_engine->WriteReg(UC_X86_REG_RCX, in_addr);
        m_engine->WriteReg(UC_X86_REG_RDX, out_addr);
        m_engine->WriteReg(UC_X86_REG_R8,  0);
        m_engine->WriteReg(UC_X86_REG_R9,  0);
        m_engine->WriteReg(UC_X86_REG_RAX, 0);

        const uint64_t func_abs = m_module + inner_func_rva;
        std::printf("[FNameEmu/inner] calling 0x%llX  RCX=in(0x%llX) RDX=out(0x%llX) "
                    "  fake entry: ",
                    (unsigned long long)func_abs,
                    (unsigned long long)in_addr,
                    (unsigned long long)out_addr);
        for (size_t j = 0; j < fake_len && j < 32; ++j) std::printf("%02X ", fake_entry[j]);
        std::printf("\n");

        uc_err err = m_engine->Run(func_abs,
                                    EmuEngineNS::EmuEngine::SENTINEL_RIP,
                                    /*timeout_us*/ 5'000'000,
                                    /*max_insns */ 200'000);
        if (err != UC_ERR_OK) {
            uint64_t fail_rip = m_engine->ReadReg(UC_X86_REG_RIP);
            std::printf("[FNameEmu/inner] ERR %s @RIP=0x%llX (RVA=0x%llX) "
                        "fault=0x%llX type=%d\n",
                        uc_strerror(err),
                        (unsigned long long)fail_rip,
                        (unsigned long long)(fail_rip - m_module),
                        (unsigned long long)m_engine->LastFaultAddr(),
                        m_engine->LastFaultType());
            uint8_t insn[16] = {};
            if (m_engine->EmuRead(fail_rip, insn, sizeof(insn))) {
                std::printf("[FNameEmu/inner]   insn @RIP: ");
                for (int j = 0; j < 16; ++j) std::printf("%02X ", insn[j]);
                std::printf("\n");
            }
            return false;
        }

        uint64_t rax = m_engine->ReadReg(UC_X86_REG_RAX);
        std::printf("[FNameEmu/inner] OK  RAX=0x%llX\n", (unsigned long long)rax);
        uint8_t out[64] = {};
        m_engine->EmuRead(out_addr, out, sizeof(out));
        std::printf("[FNameEmu/inner] output[0..63]: ");
        for (int j = 0; j < 64; ++j) std::printf("%02X ", out[j]);
        std::printf("\n");
        return true;
    }

    // Set the game's PEB pointer. Required for the TLS-mixing decrypt
    // that the outer FName function uses (mixes PEB + constant via
    // gs:[0x60]). Call before first DecryptByIndex().
    void SetGamePeb(uint64_t peb) { m_gamePeb = peb; }

    // Call the OUTER FName→string function that takes an FName struct
    // `{uint32 CompIndex, uint32 Number}` in [RCX] and writes a wide
    // string to [RDX]. Returns the decoded string.
    //
    // This bypasses the broken ResolveFNameSlot pool-walk entirely — the
    // game's own function handles everything: CIdx decrypt → pool walk →
    // entry decrypt → char decrypt → output.
    std::string DecryptByIndex(uint32_t comp_index, uint32_t number = 0) {
        if (!m_engine || !m_engine->IsReady()) return {};

        // Section-budget guard: if the engine has lazy-faulted close to its
        // 4096-section ceiling, rebuild it before this call. After rebuild
        // the fake TEB is gone, so re-arm it below by clearing m_tebReady.
        m_engine->MaybeReset(/*headroom*/ 64);
        if (m_engineEpoch != m_engine->Epoch()) {
            m_tebReady = false;
            m_engineEpoch = m_engine->Epoch();
        }

        // One-time (per-engine-epoch): map a fake TEB page and set GS_BASE
        //   gs:[0x08] = stack base (top of our emulator stack)
        //   gs:[0x10] = stack limit (bottom of our emulator stack)
        //   gs:[0x30] = self-pointer (required by some TEB walkers)
        //   gs:[0x58] = TLS array ptr (NULL — we don't have real TLS)
        //   gs:[0x60] = PEB pointer (for the TLS-mixed decrypt)
        if (!m_tebReady) {
            constexpr uint64_t FAKE_TEB = 0x00007FFF'FFFE0000ULL;
            uc_err e = uc_mem_map(m_engine->UC(), FAKE_TEB, 0x1000, UC_PROT_ALL);
            if (e != UC_ERR_OK && e != UC_ERR_MAP) {
                std::printf("[FNameEmu] failed to map fake TEB: %s\n", uc_strerror(e));
                return {};
            }
            // Zero the page first
            uint8_t zeros[0x1000] = {};
            uc_mem_write(m_engine->UC(), FAKE_TEB, zeros, sizeof(zeros));

            uint64_t stack_base  = EmuEngineNS::EmuEngine::STACK_BASE
                                 + EmuEngineNS::EmuEngine::STACK_SIZE;
            uint64_t stack_limit = EmuEngineNS::EmuEngine::STACK_BASE;
            uint64_t self_ptr    = FAKE_TEB;
            uint64_t tls_null    = 0;

            uc_mem_write(m_engine->UC(), FAKE_TEB + 0x08, &stack_base,  8);
            uc_mem_write(m_engine->UC(), FAKE_TEB + 0x10, &stack_limit, 8);
            uc_mem_write(m_engine->UC(), FAKE_TEB + 0x30, &self_ptr,    8);
            uc_mem_write(m_engine->UC(), FAKE_TEB + 0x58, &tls_null,    8);
            if (m_gamePeb) {
                uc_mem_write(m_engine->UC(), FAKE_TEB + 0x60, &m_gamePeb, 8);
            }
            m_engine->SetGSBase(FAKE_TEB);
            m_tebReady = true;
            if (m_verbose) {
                std::printf("[FNameEmu] fake TEB @ 0x%llX  stack=[0x%llX..0x%llX]  PEB=0x%llX\n",
                            (unsigned long long)FAKE_TEB,
                            (unsigned long long)stack_limit,
                            (unsigned long long)stack_base,
                            (unsigned long long)m_gamePeb);
            }
        }

        const uint64_t in_addr  = EmuEngineNS::EmuEngine::INPUT_BASE;
        const uint64_t out_addr = EmuEngineNS::EmuEngine::OUTPUT_BASE;

        // Write FName struct to INPUT_BASE: {CompIndex, Number}
        uint32_t fname[2] = { comp_index, number };
        m_engine->EmuWrite(in_addr, fname, sizeof(fname));

        // Zero output
        uint8_t zeros[0x800] = {};
        m_engine->EmuWrite(out_addr, zeros, sizeof(zeros));

        m_engine->ResetCPU();

        const uint64_t rsp = EmuEngineNS::EmuEngine::STACK_BASE
                           + EmuEngineNS::EmuEngine::STACK_SIZE - 0x28;
        m_engine->WriteReg(UC_X86_REG_RSP, rsp);
        const uint64_t sentinel = EmuEngineNS::EmuEngine::SENTINEL_RIP;
        m_engine->EmuWrite(rsp, &sentinel, 8);

        m_engine->WriteReg(UC_X86_REG_RCX, in_addr);
        m_engine->WriteReg(UC_X86_REG_RDX, out_addr);
        m_engine->WriteReg(UC_X86_REG_R8,  0);
        m_engine->WriteReg(UC_X86_REG_R9,  0);
        m_engine->WriteReg(UC_X86_REG_RAX, 0);
        // Pre-set RBP for sub-functions that expect the caller's frame
        // (e.g. 0x133B16D does MOV [RBP+0x760], RAX early in its prologue).
        m_engine->WriteReg(UC_X86_REG_RBP, rsp);

        if (m_verbose) {
            std::printf("[FNameEmu/idx] calling 0x%llX with {idx=%u, num=%u}\n",
                        (unsigned long long)m_funcAbs, comp_index, number);
        }

        uc_err err = m_engine->Run(m_funcAbs,
                                    EmuEngineNS::EmuEngine::SENTINEL_RIP,
                                    /*timeout_us*/ 10'000'000,
                                    /*max_insns */ 500'000);

        if (err != UC_ERR_OK) {
            return {};
        }

        uint64_t rax = m_engine->ReadReg(UC_X86_REG_RAX);
        uint64_t rdi = m_engine->ReadReg(UC_X86_REG_RDI);
        uint64_t rsi = m_engine->ReadReg(UC_X86_REG_RSI);

        if (m_verbose) {
            std::printf("[FNameEmu/idx] returned RAX=0x%llX RDI=0x%llX RSI=0x%llX\n",
                        (unsigned long long)rax,
                        (unsigned long long)rdi,
                        (unsigned long long)rsi);
        }

        // The output might be:
        // a) Flat UTF-16 at OUTPUT_BASE (if function writes directly)
        // b) An FString at OUTPUT_BASE: {Data*, Count, Max} where Data*
        //    points into emulator memory (or game heap)
        // c) Via RAX as a pointer to the result string
        //
        // Check all three by scanning OUTPUT_BASE for an FString header
        // (qword pointer followed by a small count), then reading the
        // pointed-to data, then trying flat UTF-16.

        uint8_t out_raw[64] = {};
        m_engine->EmuRead(out_addr, out_raw, sizeof(out_raw));

        if (m_verbose) {
            std::printf("[FNameEmu/idx] output[0..63]: ");
            for (int j = 0; j < 64; ++j) std::printf("%02X ", out_raw[j]);
            std::printf("\n");
        }

        // Try FString: {wchar_t* Data @ +0, int32 Count @ +8, int32 Max @ +0xC}
        uint64_t fstr_data = 0;
        int32_t  fstr_count = 0;
        std::memcpy(&fstr_data, out_raw, 8);
        std::memcpy(&fstr_count, out_raw + 8, 4);

        std::string out;

        if (fstr_data > 0x1000 && fstr_data < 0x7FFFFFFFFFFFULL &&
            fstr_count > 0 && fstr_count < 1024)
        {
            // FString path: deref Data pointer and read wide chars
            uint8_t str_buf[2048] = {};
            m_engine->EmuRead(fstr_data, str_buf, (size_t)fstr_count * 2);
            out.reserve(fstr_count);
            for (int32_t j = 0; j < fstr_count; ++j) {
                uint16_t wc = (uint16_t)str_buf[j*2] | ((uint16_t)str_buf[j*2+1] << 8);
                if (wc == 0) break;
                out.push_back(wc < 0x80 ? (char)wc : '?');
            }
            if (m_verbose && !out.empty()) {
                std::printf("[FNameEmu/idx] FString → \"%s\"\n", out.c_str());
            }
        }

        if (out.empty()) {
            // Try flat UTF-16 at OUTPUT_BASE
            for (size_t j = 0; j + 1 < sizeof(out_raw); j += 2) {
                uint16_t wc = (uint16_t)out_raw[j] | ((uint16_t)out_raw[j+1] << 8);
                if (wc == 0) break;
                out.push_back(wc < 0x80 ? (char)wc : '?');
            }
        }

        if (m_verbose && !out.empty()) {
            std::printf("[FNameEmu/idx] → \"%s\"\n", out.c_str());
        }

        // If nothing came out, scan the STACK region for any non-zero
        // wide strings that the function might have written to its local
        // frame (0x10C0 bytes below RSP at deepest).
        if (out.empty() && m_verbose) {
            uint64_t cur_rsp = m_engine->ReadReg(UC_X86_REG_RSP);
            // The function's deepest frame was RSP - 0x10D8 (3 pushes + SUB 0x10C0).
            // Scan from there upward looking for printable wide strings.
            const uint64_t scan_base = (cur_rsp > 0x1200) ? (cur_rsp - 0x1200) : EmuEngineNS::EmuEngine::STACK_BASE;
            uint8_t stk[0x200] = {};
            m_engine->EmuRead(scan_base, stk, sizeof(stk));
            // Look for a run of 4+ printable UTF-16 chars (0x20..0x7E in low byte, 0x00 in high)
            for (size_t j = 0; j + 8 < sizeof(stk); j += 2) {
                int pcount = 0;
                for (size_t k = j; k + 1 < sizeof(stk); k += 2) {
                    uint8_t lo = stk[k], hi = stk[k+1];
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) ++pcount;
                    else break;
                }
                if (pcount >= 3) {
                    std::printf("[FNameEmu/idx] stack printable @ 0x%llX + %zu: \"",
                                (unsigned long long)scan_base, j);
                    for (size_t k = j; k + 1 < sizeof(stk); k += 2) {
                        uint8_t lo = stk[k], hi = stk[k+1];
                        if (hi == 0 && lo >= 0x20 && lo <= 0x7E) std::putchar(lo);
                        else break;
                    }
                    std::printf("\"\n");
                    break;
                }
            }
        }

        return out;
    }

    uint64_t FuncRVA() const { return m_funcRVA; }

private:
    EmuEngine* m_engine     = nullptr;
    uint64_t   m_module     = 0;
    uint64_t   m_funcRVA    = 0;
    uint64_t   m_funcAbs    = 0;
    uint64_t   m_gamePeb    = 0;
    bool       m_verbose    = true;
    bool       m_tebReady   = false;
    uint32_t   m_engineEpoch = 0;   // tracks EmuEngine::Epoch() so we re-arm TEB after Reset()
};

} // namespace EmuFNameNS

using EmuFName = EmuFNameNS::EmuFName;
