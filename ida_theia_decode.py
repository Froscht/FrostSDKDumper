# =============================================================================
# ARC Raiders Theia string decoder for IDA Pro.
#
# Usage: File -> Script File -> pick this file.
#        (auto: full sweep + comment on every decoded string pointer)
#
# Interactive: after load, use theia_decode(0x14BAA1050) to decode any address.
#
# Port of FrostSDKDumper/theia_static.h. Self-solves keystream by scoring
# candidate keys at each byte position against C++ identifier char frequency;
# no hardcoded constants (survives PRNG-additive-constant patches).
#
# Reveals: UEnum / UScriptStruct / UFunction / UDelegateFunction descriptor
# names + all members. UClass names NOT reachable (16-byte encrypted blob path).
# =============================================================================

import ida_bytes, ida_segment, ida_name, ida_kernwin, idc, idaapi
import struct, time

SOLVE_LEN = 192
COMMENT_PREFIX = "[theia] "
MIN_STRING_LEN = 3
MAX_STRING_LEN = 128


def wrap_byte(v):
    v = v & 0xFF
    A = -47 if ((v - 0x50) & 0xFFFFFFFF) < 0x2F else 0
    if ((v - 0x21) & 0xFFFFFFFF) < 0x2F: A = 47
    x = (v + A) & 0xFFFFFFFF
    F = 1 if ((x - 53) & 0xFFFFFFFF) >= 5 else 0
    B = 5 if ((x - 48) & 0xFFFFFFFF) < 5 else (F * 5 - 5)
    y = (x + B) & 0xFFFFFFFF
    C2 = -13 if ((y - 110) & 0xFFFFFFFF) < 13 else 0
    if ((y - 97) & 0xFFFFFFFF) < 13: C2 = 13
    z = (y + C2) & 0xFFFFFFFF
    D = -13 if ((z - 78) & 0xFFFFFFFF) < 13 else 0
    if ((z - 65) & 0xFFFFFFFF) < 13: D = 13
    w = (z + D) & 0xFFFFFFFF
    E = 209 if ((w - 80) & 0xFFFFFFFF) < 0x2F else 0
    if ((w - 33) & 0xFFFFFFFF) < 0x2F: E = 47
    return (w + E) & 0xFF


# WRAP[key][cipher] = wrap_byte(key ^ (int8)cipher)
def _build_wrap_table():
    tbl = [[0]*256 for _ in range(32)]
    for k in range(32):
        for c in range(256):
            sc = c if c < 128 else c - 256
            sc &= 0xFFFFFFFF
            tbl[k][c] = wrap_byte(k ^ sc)
    return tbl

WRAP = _build_wrap_table()


CHAR_WEIGHTS_RAW = {
    'a':-2.88,'b':-4.74,'c':-3.46,'d':-4.14,'e':-2.34,'f':-4.76,'g':-4.60,
    'h':-4.63,'i':-2.86,'j':-6.92,'k':-5.53,'l':-3.62,'m':-3.79,'n':-2.79,
    'o':-3.00,'p':-3.52,'q':-7.07,'r':-2.99,'s':-3.00,'t':-2.51,'u':-3.73,
    'v':-5.26,'w':-6.74,'x':-4.31,'y':-4.48,'z':-4.43,'A':-4.24,'B':-4.64,
    'C':-4.25,'D':-4.74,'E':-4.43,'F':-4.84,'G':-4.96,'H':-7.07,'I':-4.78,
    'J':-9.28,'K':-6.32,'L':-5.94,'M':-4.77,'N':-5.02,'O':-5.85,'P':-4.75,
    'Q':-7.16,'R':-4.80,'S':-4.35,'T':-4.92,'U':-5.84,'V':-5.61,'W':-6.15,
    'X':-7.51,'Y':-9.38,'Z':-8.23,'0':-5.50,'1':-5.22,'2':-4.24,'3':-4.37,
    '4':-4.89,'5':-5.60,'6':-5.13,'7':-5.67,'8':-5.50,'9':-5.55,'_':-3.12,
}
CHAR_WEIGHTS_NO1 = [-16.0]*256
CHAR_WEIGHTS_1ST = [-16.0]*256
for ch, w in CHAR_WEIGHTS_RAW.items():
    CHAR_WEIGHTS_NO1[ord(ch)] = w
    if not ch.isdigit(): CHAR_WEIGHTS_1ST[ord(ch)] = w
for ch, w in {':':-6.0,'<':-7.5,'>':-7.5,',':-7.5,'.':-7.5,'/':-7.5,' ':-7.5}.items():
    CHAR_WEIGHTS_NO1[ord(ch)] = w


def _is_name_char(c, first):
    if 0x41 <= c <= 0x5A: return True
    if 0x61 <= c <= 0x7A: return True
    if c == 0x5F: return True
    if not first and 0x30 <= c <= 0x39: return True
    return False


def _is_alive_char(c, first):
    if _is_name_char(c, first): return True
    if first: return False
    return c in (0x3A, 0x3C, 0x3E, 0x2C, 0x2E, 0x2F, 0x20)


def _get_section(name):
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if s and ida_segment.get_segm_name(s) == name:
            return s
    return None


def _read_bytes(ea, n):
    b = ida_bytes.get_bytes(ea, n)
    return b if b else b''


def solve_keystream():
    rdata = _get_section('.rdata')
    if not rdata:
        print("[theia] .rdata segment not found"); return None
    ida_kernwin.msg("[theia] reading .rdata (%d bytes)...\n" % rdata.size())
    data = _read_bytes(rdata.start_ea, rdata.size())
    if not data:
        print("[theia] .rdata read failed"); return None
    base = ida_nalt.get_imagebase() if hasattr(idaapi, 'get_imagebase') else idaapi.get_imagebase()
    rd_start = rdata.start_ea
    rd_end   = rdata.end_ea
    bufs = []
    ida_kernwin.msg("[theia] collecting candidates (this walks .rdata)...\n")
    for off in range(0, len(data) - 8, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if v < rd_start or v >= rd_end: continue
        idx = v - rd_start
        if idx + SOLVE_LEN > len(data): continue
        buf = data[idx:idx+SOLVE_LEN]
        if any(b == 0 for b in buf[:8]): continue
        bufs.append(buf)
    ida_kernwin.msg("[theia] %d candidate ciphertext buffers\n" % len(bufs))
    if len(bufs) < 2000:
        print("[theia] too few candidates, solve unreliable"); return None
    n = len(bufs)
    alive = bytearray(b'\x01' * n)
    key = []
    first_hits = 0; first_total = 0
    t0 = time.time()
    for pos in range(SOLVE_LEN):
        total = sum(alive)
        if total < 8: break
        weights_tbl = CHAR_WEIGHTS_1ST if pos == 0 else CHAR_WEIGHTS_NO1
        best_w = -1e300; runner = -1e300; best_k = 0; best_hits = 0
        for k in range(32):
            wrap_k = WRAP[k]
            w = 0.0; hits = 0
            for j in range(n):
                if not alive[j]: continue
                ch = wrap_k[bufs[j][pos]]
                w += weights_tbl[ch]
                if _is_name_char(ch, pos == 0): hits += 1
            w /= total
            if w > best_w:
                runner = best_w; best_w = w; best_k = k; best_hits = hits
            elif w > runner:
                runner = w
        if pos and (best_w - runner) < 0.15: break
        key.append(best_k)
        if pos == 0:
            first_hits = best_hits; first_total = total
        wrap_k = WRAP[best_k]
        for j in range(n):
            if not alive[j]: continue
            ch = wrap_k[bufs[j][pos]]
            if not _is_alive_char(ch, pos == 0):
                alive[j] = 0
    dt = time.time() - t0
    if len(key) < 16 or first_total < 2000 or first_hits*4 < first_total*3:
        print("[theia] weak solve: %d pos, %d/%d at pos 0" % (len(key), first_hits, first_total))
        return None
    print("[theia] solved keystream: %d positions, %d/%d (%.1f%%) at pos 0 (%.1fs)" %
          (len(key), first_hits, first_total, 100.0*first_hits/first_total, dt))
    return bytes(key)


import ida_nalt


def _decrypt(cipher, keystream):
    n = min(len(cipher), len(keystream))
    out = bytearray()
    for i in range(n):
        sc = cipher[i]
        if sc >= 128: sc = (sc - 256) & 0xFFFFFFFF
        ch = wrap_byte((keystream[i] ^ sc) & 0xFFFFFFFF)
        if ch == 0: break
        out.append(ch)
    return out.decode('ascii', errors='replace')


def _is_plausible(s, allow_colon=True):
    if not s or len(s) > MAX_STRING_LEN: return False
    for c in s:
        o = ord(c)
        if 0x41 <= o <= 0x5A or 0x61 <= o <= 0x7A or 0x30 <= o <= 0x39 or o == 0x5F: continue
        if allow_colon and c == ':': continue
        return False
    return True


# ─── Global keystream loaded on script exec ──────────────────────────────────
_KEYSTREAM = None


def theia_load():
    """(Re)solve the keystream. Call this again if the binary changes."""
    global _KEYSTREAM
    _KEYSTREAM = solve_keystream()
    return _KEYSTREAM is not None


def theia_decode(ea):
    """Decode a Theia-encrypted string at address ea. Returns the plaintext
    or None if it doesn't look plausible."""
    if _KEYSTREAM is None:
        print("[theia] not loaded — run theia_load() first"); return None
    b = _read_bytes(ea, len(_KEYSTREAM))
    if not b: return None
    s = _decrypt(b, _KEYSTREAM)
    if _is_plausible(s) and len(s) >= MIN_STRING_LEN: return s
    return None


def theia_sweep():
    """Walk .rdata for every qword pointing into .rdata, decode target,
    tag with a repeatable comment '[theia] <plaintext>'. Idempotent."""
    if _KEYSTREAM is None:
        print("[theia] not loaded — run theia_load() first"); return
    rdata = _get_section('.rdata')
    if not rdata:
        print("[theia] .rdata segment not found"); return
    data = _read_bytes(rdata.start_ea, rdata.size())
    rd_start = rdata.start_ea; rd_end = rdata.end_ea
    tagged = 0; seen = set()
    t0 = time.time()
    for off in range(0, len(data) - 8, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if v < rd_start or v >= rd_end: continue
        idx = v - rd_start
        if idx + 8 > len(data): continue
        if data[idx] == 0: continue
        end = min(idx + len(_KEYSTREAM), len(data))
        s = _decrypt(data[idx:end], _KEYSTREAM)
        if not _is_plausible(s) or len(s) < MIN_STRING_LEN: continue
        target_ea = v
        if target_ea in seen: continue
        seen.add(target_ea)
        cmt = COMMENT_PREFIX + s
        idc.set_cmt(target_ea, cmt, 1)  # 1 = repeatable
        # also tag the qword itself so xref clicks show the plaintext
        idc.set_cmt(rd_start + off, cmt, 1)
        tagged += 1
        if tagged % 1000 == 0:
            ida_kernwin.msg("[theia] tagged %d ...\n" % tagged)
    dt = time.time() - t0
    print("[theia] sweep done: %d unique strings commented in %.1fs" % (tagged, dt))


def theia_find(needle):
    """Find every decoded string containing `needle` (case-insensitive).
    Prints VA + plaintext for each hit."""
    if _KEYSTREAM is None:
        print("[theia] not loaded — run theia_load() first"); return
    rdata = _get_section('.rdata')
    if not rdata: return
    data = _read_bytes(rdata.start_ea, rdata.size())
    rd_start = rdata.start_ea; rd_end = rdata.end_ea
    kw = needle.lower(); seen = set(); hits = 0
    for off in range(0, len(data) - 8, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if v < rd_start or v >= rd_end: continue
        idx = v - rd_start
        if idx + 8 > len(data): continue
        if data[idx] == 0: continue
        end = min(idx + len(_KEYSTREAM), len(data))
        s = _decrypt(data[idx:end], _KEYSTREAM)
        if not _is_plausible(s) or len(s) < MIN_STRING_LEN: continue
        if v in seen: continue
        seen.add(v)
        if kw in s.lower():
            print("  0x%X = %s" % (v, s))
            hits += 1
    print("[theia] %d matches for '%s'" % (hits, needle))


# ─── Auto-run ────────────────────────────────────────────────────────────────
print("=" * 60)
print("ARC Theia string decoder")
print("=" * 60)
if theia_load():
    print()
    print("Ready. Commands:")
    print("  theia_decode(ea)       decode single address")
    print("  theia_find('needle')   find strings by substring")
    print("  theia_sweep()          annotate every decoded string with a comment")
    print()
    print("Auto-running theia_sweep()...")
    theia_sweep()
else:
    print("[theia] keystream solve failed — see messages above")
