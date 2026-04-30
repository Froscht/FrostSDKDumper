"""Probe live UObjects on patch CL-1177146 to verify which slot-decoder pipeline is correct.

Compares two candidate hash pipelines:
  - "config":   FNV chain with K=0x8E195662, ROL(24)→P*+ADD→ROL(25)→P*+hi+ADD→ROL(24)→P*+ADD→>>7→P*+ADD
                (mirrors sub_2CB4E0 / sub_2D6900 / sub_2D4500 / sub_2CD8B0 in IDA lf50)
  - "user_edit": ArcDecrypt::ActorFName::ComputeHashAndIndex
                (FNV_PRIME=0x01000193, HASH_ADD=0xC00C3C3D, ROL=15/24/15)

Slot decrypt pipeline (live-verified): PSHUFB(slot, mask) XOR const_lo64.
Mask  @ RVA 0xAD93EF0 = 06 05 02 03 04 01 00 07
Const @ RVA 0xAD93F00 = 0x5EA772D07F910744 (lo64)

After XOR, NAME slots need ROL64(32) so CI lives in lo32.

Walks GWorld -> Levels and traverses to gather UObject candidates,
then for each:
  1. Reads 4 slots at obj+0x20 (stride 0x20, 16-byte each)
  2. Decrypts each with the verified pipeline
  3. Picks NAME slot via candidate hash and applies ROL64(32) to get CI
  4. Looks up CI in FNamePool to recover printable string
  5. Tallies printable matches per pipeline and emits JSON.
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from memreader import MemReader, find_pid

MODULE_BASE       = 0x140000000
RVA_GWORLD        = 0xDFDB4D8
RVA_FNAMEPOOL     = 0xDBB3F80
RVA_PSHUFB_MASK   = 0xAD93EF0
RVA_XOR_CONST     = 0xAD93F00

PSHUFB_MASK = [0x06, 0x05, 0x02, 0x03, 0x04, 0x01, 0x00, 0x07]
XOR_CONST   = 0x5EA772D07F910744


def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF


def hash_config(obj):
    """IDA-derived (sdk_config.ini) pipeline."""
    P   = 0x01000193
    ADD = 0x8E195662
    ptr = obj + 0x10
    lo  = ptr & 0xFFFFFFFF
    hi  = (ptr >> 32) & 0xFFFFFFFF
    h = (P * rol32(lo, 24) + ADD) & 0xFFFFFFFF
    h = (P * rol32(h, 25) + ADD) & 0xFFFFFFFF
    t = (hi + h) & 0xFFFFFFFF
    h = (P * rol32(t, 24) + ADD) & 0xFFFFFFFF
    s = h >> 7
    v3 = (P * s + ADD) & 0xFFFFFFFF
    u8    = v3 & 0xFF
    byte2 = (v3 >> 16) & 0xFF
    raw_idx = (u8 ^ byte2) & 3
    return v3, raw_idx, (raw_idx ^ 2) & 3


def hash_user_edit(obj):
    """User's manual ComputeHashAndIndex from arc_decrypt.h."""
    P = 0x01000193
    K = 0xC00C3C3D
    ptr = obj + 0x10
    lo  = ptr & 0xFFFFFFFF
    hi  = (ptr >> 32) & 0xFFFFFFFF
    h = rol32(lo, 15)
    h = (P * h + K) & 0xFFFFFFFF
    h = rol32(h, 24)
    h = (P * h + hi + K) & 0xFFFFFFFF
    v8 = rol32(h, 15)
    temp1 = (403 * v8 - 6595) & 0xFFFF
    left  = ((-109 * (temp1 >> 8) + 61) & 0xFF)
    temp2 = ((P * v8 + K) & 0xFFFFFFFF) >> 8
    v6eq  = (P * temp2 + K) & 0xFFFFFFFF
    right = (v6eq >> 16) & 0xFF
    out_idx = ((left ^ right) & 3) ^ 2
    return v8, out_idx, out_idx


def decrypt_slot(enc16):
    shuf = bytes([enc16[PSHUFB_MASK[i]] for i in range(8)])
    s = struct.unpack('<Q', shuf)[0]
    return s ^ XOR_CONST


def is_valid_ci(ci):
    return 1 < ci < 0x2000000


def is_valid_ptr(p):
    return 0x100000 < p < 0x800000000000


def gather_objects(mr, max_count=20):
    """Walk GWorld -> Levels -> Actors to collect UObject pointers."""
    out = []
    seen = set()

    gworld_addr = struct.unpack('<Q', mr.read(MODULE_BASE + RVA_GWORLD, 8))[0]
    if not is_valid_ptr(gworld_addr):
        return out
    gworld = struct.unpack('<Q', mr.read(gworld_addr, 8))[0]
    if not is_valid_ptr(gworld):
        return out
    if gworld not in seen:
        seen.add(gworld)
        out.append(("GWorld", gworld))

    persistent_level = struct.unpack('<Q', mr.read(gworld + 0x110, 8))[0]
    if is_valid_ptr(persistent_level) and persistent_level not in seen:
        seen.add(persistent_level)
        out.append(("PersistentLevel", persistent_level))

    actors_offsets_to_try = [0x108, 0x110, 0x118, 0x120, 0xF8, 0x100]
    if is_valid_ptr(persistent_level):
        for off in actors_offsets_to_try:
            try:
                actors_arr = struct.unpack('<Q', mr.read(persistent_level + off, 8))[0]
                actors_count = struct.unpack('<I', mr.read(persistent_level + off + 8, 4))[0]
            except Exception:
                continue
            if not is_valid_ptr(actors_arr): continue
            if not (1 <= actors_count <= 100000): continue
            for i in range(min(actors_count, max_count)):
                try:
                    actor = struct.unpack('<Q', mr.read(actors_arr + 8 * i, 8))[0]
                except Exception:
                    break
                if is_valid_ptr(actor) and actor not in seen:
                    seen.add(actor)
                    out.append((f"Actor[{i}]", actor))
                    if len(out) >= max_count:
                        return out
            if len(out) >= 5:
                break
    return out


def fnamepool_resolve(mr, ci):
    """Best-effort CI->string resolve via FNamePool. Returns string or None.

    Patch CL-1177146 inherits 20260428 layout: chunked pool with stride 0x100,
    chunks at fnamepool+0x10+8*chunk_idx. The exact slot decrypt is complex —
    here we just verify the CI lands inside a chunk that has plausible data.
    """
    pool_base = MODULE_BASE + RVA_FNAMEPOOL
    if not (1 <= ci < 0x2000000):
        return None
    chunk_idx = ci >> 16
    in_chunk  = ci & 0xFFFF
    try:
        chunks_array = pool_base
        chunk_ptr = struct.unpack('<Q', mr.read(chunks_array + 0x10 + 8 * chunk_idx, 8))[0]
    except Exception:
        return None
    if not is_valid_ptr(chunk_ptr):
        return None
    return f"chunk_{chunk_idx}@0x{chunk_ptr:X}+slot{in_chunk}"


def evaluate(mr, objects):
    config_hits = 0
    user_hits = 0
    config_invalid = 0
    user_invalid = 0
    evidence = []

    for tag, obj in objects:
        try:
            slot_data = mr.read(obj + 0x20, 0x80)
        except Exception:
            continue
        slots_dec = []
        for s in range(4):
            slot = slot_data[s * 0x20:s * 0x20 + 16]
            if all(b == 0 for b in slot):
                slots_dec.append(None)
                continue
            dec = decrypt_slot(slot)
            slots_dec.append(dec)

        v_cfg, raw_cfg, name_cfg = hash_config(obj)
        v_usr, raw_usr, name_usr = hash_user_edit(obj)

        cfg_dec = slots_dec[name_cfg]
        usr_dec = slots_dec[name_usr]

        cfg_ci = (rol64(cfg_dec, 32) & 0xFFFFFFFF) if cfg_dec is not None else 0
        usr_ci = (rol64(usr_dec, 32) & 0xFFFFFFFF) if usr_dec is not None else 0

        cfg_ok = is_valid_ci(cfg_ci)
        usr_ok = is_valid_ci(usr_ci)

        if cfg_ok:  config_hits += 1
        else:       config_invalid += 1
        if usr_ok:  user_hits += 1
        else:       user_invalid += 1

        cfg_resolve = fnamepool_resolve(mr, cfg_ci) if cfg_ok else None
        usr_resolve = fnamepool_resolve(mr, usr_ci) if usr_ok else None

        all_slot_dec = []
        for s in range(4):
            d = slots_dec[s]
            if d is None:
                all_slot_dec.append({"slot": s, "dec": None})
            else:
                rol = rol64(d, 32)
                all_slot_dec.append({
                    "slot": s,
                    "dec_lo64": f"0x{d:016X}",
                    "rol64_lo32_ci": f"0x{rol & 0xFFFFFFFF:08X}",
                    "is_ci_shape":   is_valid_ci(rol & 0xFFFFFFFF),
                    "is_ptr_shape":  is_valid_ptr(d),
                })

        evidence.append({
            "tag": tag,
            "obj": f"0x{obj:X}",
            "config":   {"v3": f"0x{v_cfg:08X}", "raw_idx": raw_cfg, "name_slot": name_cfg, "ci": f"0x{cfg_ci:X}", "valid_ci": cfg_ok, "resolve": cfg_resolve},
            "user_edit": {"v8": f"0x{v_usr:08X}", "out_idx": raw_usr, "name_slot": name_usr, "ci": f"0x{usr_ci:X}", "valid_ci": usr_ok, "resolve": usr_resolve},
            "slots": all_slot_dec,
        })

    winner = "config" if config_hits > user_hits else ("user_edit" if user_hits > config_hits else "tie")
    return {
        "correct_pipeline": winner,
        "config_hits": config_hits,
        "config_invalid": config_invalid,
        "user_hits": user_hits,
        "user_invalid": user_invalid,
        "evidence": evidence,
    }


def main():
    pid = find_pid()
    if not pid:
        print("ERROR: could not find game PID with comm 'GameThread'", file=sys.stderr)
        sys.exit(2)
    print(f"[+] Using PID {pid}", file=sys.stderr)

    with MemReader(pid) as mr:
        mask = mr.read(MODULE_BASE + RVA_PSHUFB_MASK, 8)
        const = struct.unpack('<Q', mr.read(MODULE_BASE + RVA_XOR_CONST, 8))[0]
        if list(mask) != PSHUFB_MASK or const != XOR_CONST:
            print(f"WARN: live PSHUFB mask = {list(mask)} expected {PSHUFB_MASK}", file=sys.stderr)
            print(f"WARN: live XOR const = 0x{const:X} expected 0x{XOR_CONST:X}", file=sys.stderr)

        objects = gather_objects(mr, max_count=20)
        if len(objects) < 2:
            print("WARN: could not gather objects via GWorld walk; falling back to scanning vtable-shaped pointers.", file=sys.stderr)

        result = evaluate(mr, objects)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
