#!/usr/bin/env python3
"""ue57_native_names.py — overlay UE 5.7 source member names onto Native_0xNNN
lines in SDK_Output.txt.

Approach:
    1. Parse every C++ header under Engine/Source/Runtime + Engine/Source/Editor
       for `class UXxx/AXxx/FXxx : public YYY { ... }`.
    2. Inside each class body, record the sequence of member declarations
       with (name, type, is_uproperty). Order is source-order, which the
       compiler follows modulo alignment.
    3. Read SDK_Output.txt, walk its namespaces (each == one class/struct
       block). For each block, collect the reflected properties (UPROPERTY
       — already named in the SDK) and the Native_0xNNN gaps.
    4. Anchor the source stream against the reflected properties by name.
       Everything between two anchors is a run of non-UPROPERTY members;
       assign them to the SDK's Native_0xNNN gaps in that offset window
       when both size AND type-family match.

Type-family matching is deliberately loose. Real UE fields carry FVector /
FRotator / FString / bit-flags / TWeakObjectPtr, and the SDK output types
Native holes as `float / int32_t / ? / TArray<...> / <Class>*`. We only
require the categories agree (a UE `float DefaultFOV` may not overwrite a
`TArray<UObject*>` hole).

Deliberately do NOT emit a name when the anchor window is unclear or the
type does not match — the failure mode we want is "no name" not "wrong
name". CLAUDE.md's LockedFOV incident (misplacing a field by one slot)
came from trusting source-order without type/size checks; the checks are
the fix.

Usage:
    python3 ue57_native_names.py --ue /home/frost/Downloads/UnrealEngine-5.7 \\
        --sdk /media/frost/Coding\\ Stuf/Linux/FrostSDKDumper/SDK_Output.txt \\
        --out SDK_Output.named.txt
"""
from __future__ import annotations
import argparse, os, re, sys, json
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ────────────────────────────────────────────────────────────────────────
# UE header parser
# ────────────────────────────────────────────────────────────────────────

# `class ENGINE_API AActor : public UObject`, `class UWorld : public UObject`,
# `USTRUCT() struct FVector { ... }` — pick up the class name and its parent.
CLASS_RE = re.compile(
    r'\bclass\s+(?:[A-Z][A-Z0-9_]*_API\s+)?'
    r'([UAF][A-Za-z_][A-Za-z0-9_]*)'
    r'(?:\s*:\s*public\s+([UAF][A-Za-z_][A-Za-z0-9_]*))?'
)
STRUCT_RE = re.compile(
    r'\bstruct\s+(?:[A-Z][A-Z0-9_]*_API\s+)?'
    r'(F[A-Za-z_][A-Za-z0-9_]*)'
    r'(?:\s*:\s*public\s+([UAF][A-Za-z_][A-Za-z0-9_]*))?'
)

MEMBER_RE = re.compile(
    r'^\s*'
    r'(?:mutable\s+|static\s+|thread_local\s+|typename\s+)*'      # storage
    r'(?:const\s+|volatile\s+)*'                                    # cv
    r'([A-Za-z_][\w:<>,\s\*&]*?)'                                    # type
    r'\s+([A-Za-z_]\w*)'                                             # name
    r'(?:\s*(\[[^\]]*\]|\s*:\s*\d+))?'                                # array/bitfield
    r'\s*(?:=[^;]*)?\s*;'                                             # optional init
)

TYPE_NORMALIZE = re.compile(r'\s+')

# Category classification for the SDK hole comment types.
def type_family(t: str) -> str:
    t = t.strip()
    if not t: return 'unknown'
    # Bare arrays.
    if 'TArray' in t or 'TSparseArray' in t or 'TSet' in t or 'TMap' in t:
        return 'container'
    if 'TWeakObjectPtr' in t or 'TSoftObjectPtr' in t or 'TSoftClassPtr' in t or 'TObjectPtr' in t:
        return 'ptr'
    if t.endswith('*'):
        return 'ptr'
    lc = t.lower()
    if lc in ('float','double'): return 'float'
    if lc.startswith('int') or lc.startswith('uint') or lc in ('bool','byte','uint8','int8','int16','uint16','int32','uint32','int64','uint64'):
        return 'int'
    if t.startswith('F') and t[1:2].isupper():
        return 'struct'
    if 'FVector' in t or 'FRotator' in t or 'FQuat' in t or 'FTransform' in t or 'FString' in t or 'FName' in t or 'FText' in t:
        return 'struct'
    return 'unknown'

# The SDK output types Native holes using these labels.
SDK_TYPE_FAMILY = {
    '?':                'unknown',
    'float':            'float',
    'double':           'float',
    'bool':             'int',
    'uint8_t':          'int',
    'int8_t':           'int',
    'uint16_t':         'int',
    'int16_t':          'int',
    'uint32_t':         'int',
    'int32_t':          'int',
    'uint64_t':         'int',
    'int64_t':          'int',
}
def sdk_type_family(t: str) -> str:
    t = t.strip()
    if t in SDK_TYPE_FAMILY: return SDK_TYPE_FAMILY[t]
    if t.startswith('TArray<') or t.startswith('TSet<') or t.startswith('TMap<'):
        return 'container'
    if t.endswith('*'): return 'ptr'
    if t == 'FName' or t == 'FString' or t == 'FText': return 'struct'
    if t.startswith('F') and (len(t) > 1 and t[1].isupper()): return 'struct'
    return 'unknown'

# A member as parsed from source.
class SourceMember:
    __slots__ = ('name','type','is_uproperty','family')
    def __init__(self, name, type_, is_uprop):
        self.name = name
        self.type = type_
        self.is_uproperty = is_uprop
        self.family = type_family(type_)

# One parsed class/struct.
class SourceType:
    __slots__ = ('name','parent','members')
    def __init__(self, name, parent):
        self.name = name
        self.parent = parent
        self.members: List[SourceMember] = []

def parse_header(path: str, types: Dict[str, SourceType]):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    except OSError:
        return

    # Kill line comments and block comments to simplify matching. Preserve
    # newlines so line numbers still roughly match for error messages.
    text = re.sub(r'//[^\n]*', '', text)
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.S)

    # Very simple brace tracker. Splits into class bodies keyed by the class
    # name introduced by their preceding `class X : public Y {`.
    i = 0
    n = len(text)
    class_stack: List[Tuple[str, int]] = []   # (name, brace_depth_at_entry)
    depth = 0
    active: Optional[SourceType] = None
    last_line_had_uprop = False

    def flush_body(body: str, cls: SourceType):
        nonlocal last_line_had_uprop
        # Walk line by line so we can track UPROPERTY() markers.
        prev_upprop = False
        for line in body.splitlines():
            s = line.strip()
            if not s:
                prev_upprop = False
                continue
            if s.startswith('UPROPERTY') or s.startswith('UFUNCTION') or s.startswith('UPARAM'):
                # Marker attaches to the next member decl.
                prev_upprop = s.startswith('UPROPERTY')
                continue
            if s.startswith('#') or s.startswith('friend ') or s.startswith('template'):
                prev_upprop = False
                continue
            m = MEMBER_RE.match(line)
            if not m:
                # Reset the marker if this line is not a member and not a
                # marker either (e.g. an access specifier, a nested class
                # opening brace, an inline function body).
                if s in ('public:','private:','protected:'): pass
                else: prev_upprop = False
                continue
            type_, name = m.group(1).strip(), m.group(2).strip()
            # Skip method decls that MEMBER_RE would still match: anything
            # whose type ends in ')' means the type-column ate the args.
            if '(' in line[:line.find(name) if name in line else -1]:
                prev_upprop = False
                continue
            # `class X;` forward decls end up here — skip them.
            if type_ in ('class','struct','enum','union'):
                prev_upprop = False
                continue
            cls.members.append(SourceMember(name, type_, prev_upprop))
            prev_upprop = False

    # Iterate: find `class X` or `struct FX`, then the following body.
    scan = 0
    while scan < n:
        # Look for the next class/struct declaration.
        cm = CLASS_RE.search(text, scan)
        sm = STRUCT_RE.search(text, scan)
        candidates = []
        if cm: candidates.append((cm.start(), cm, 'class'))
        if sm: candidates.append((sm.start(), sm, 'struct'))
        if not candidates:
            break
        candidates.sort()
        pos, match, _ = candidates[0]
        name = match.group(1)
        parent = match.group(2) if match.lastindex and match.lastindex >= 2 else None
        # Find the opening brace after this match.
        brace = text.find('{', match.end())
        semi  = text.find(';', match.end())
        # If a `;` shows up before `{`, this is a forward decl.
        if brace < 0 or (0 <= semi < brace):
            scan = match.end()
            continue
        # Find matching close.
        depth = 1
        j = brace + 1
        while j < n and depth > 0:
            c = text[j]
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            elif c == '"':
                # Skip string literal.
                j = text.find('"', j + 1)
                if j < 0: break
            j += 1
        if depth != 0: break
        body = text[brace+1:j-1]
        if name not in types:
            types[name] = SourceType(name, parent)
        flush_body(body, types[name])
        scan = j

# ────────────────────────────────────────────────────────────────────────
# Walk the UE source tree.
# ────────────────────────────────────────────────────────────────────────

def build_index(ue_root: str) -> Dict[str, SourceType]:
    types: Dict[str, SourceType] = {}
    roots = [
        os.path.join(ue_root, 'Engine', 'Source', 'Runtime'),
        os.path.join(ue_root, 'Engine', 'Source', 'Developer'),
    ]
    count = 0
    for root in roots:
        for dp, dn, fn in os.walk(root):
            for name in fn:
                if not name.endswith('.h'): continue
                parse_header(os.path.join(dp, name), types)
                count += 1
                if count % 500 == 0:
                    sys.stderr.write(f'\r[ue57] parsed {count} headers, {len(types)} types  ')
                    sys.stderr.flush()
    sys.stderr.write(f'\r[ue57] parsed {count} headers, {len(types)} types  \n')
    return types

# ────────────────────────────────────────────────────────────────────────
# SDK_Output.txt parser + renamer.
# ────────────────────────────────────────────────────────────────────────

NS_START_RE = re.compile(r'^namespace ([A-Za-z_][A-Za-z0-9_]*) \{')
NS_END_RE   = re.compile(r'^\} // namespace')

# `constexpr uint32_t Name             = 0x30;  // typename // size=0x8 // n=2`
FIELD_RE = re.compile(
    r'^constexpr uint32_t\s+(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//\s*([^/]+?)\s*//\s*(.*)$'
)

class SdkField:
    __slots__ = ('name','offset','type','tail','is_native','is_pad','line_no')
    def __init__(self, name, off, type_, tail, line_no):
        self.name = name
        self.offset = off
        self.type = type_.strip()
        self.tail = tail
        self.is_native = 'native' in tail
        self.is_pad = self.type == 'uint8_t' and 'Padding' in tail
        self.line_no = line_no

def emit_named_sdk(sdk_path: str, out_path: str, types: Dict[str, SourceType]):
    with open(sdk_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    # Walk one namespace at a time.
    named = 0
    scanned = 0
    matched_classes = 0

    result: List[str] = []
    i = 0
    while i < len(lines):
        m = NS_START_RE.match(lines[i])
        if not m:
            result.append(lines[i])
            i += 1
            continue
        cls_name = m.group(1)
        result.append(lines[i])
        block_start = i + 1
        # Find block end.
        j = block_start
        while j < len(lines) and not NS_END_RE.match(lines[j]):
            j += 1
        block = lines[block_start:j]

        # Parse block into SdkField objects.
        fields: List[SdkField] = []
        for k, ln in enumerate(block):
            fm = FIELD_RE.match(ln.strip())
            if not fm: continue
            fields.append(SdkField(
                fm.group(1),
                int(fm.group(2), 16),
                fm.group(3),
                fm.group(4),
                k))

        native_fields = [f for f in fields if f.is_native]
        scanned += len(native_fields)
        # SDK strips the A/U/F prefix off type names — `namespace Level` is
        # actually `ULevel`, `namespace PlayerCameraManager` is `APlayerCameraManager`.
        # Try each prefix; first hit wins.
        src = None
        for prefix in ('U', 'A', 'F'):
            key = prefix + cls_name
            if key in types:
                src = types[key]
                break
        if src is None and cls_name in types:
            src = types[cls_name]
        if not native_fields or src is None:
            result.extend(block)
            result.append(lines[j] if j < len(lines) else '')
            i = j + 1
            continue
        matched_classes += 1

        # Extract UPROPERTY anchors present in both SDK and source. We do
        # this by name — a source UPROPERTY name that appears in the SDK
        # block is an anchor. The anchor's SDK offset pins where in the
        # source stream we are.
        src_by_name = {sm.name: si for si, sm in enumerate(src.members) if sm.is_uproperty}
        anchors: List[Tuple[int,int]] = []   # (src_idx, sdk_offset)
        for f in fields:
            if f.is_native or f.is_pad: continue
            si = src_by_name.get(f.name)
            if si is not None:
                anchors.append((si, f.offset))
        anchors.sort()

        if len(anchors) < 2:
            # Not enough anchors — cannot confidently assign names.
            result.extend(block)
            result.append(lines[j] if j < len(lines) else '')
            i = j + 1
            continue

        # Helpers reused for both the window pass and the class-wide fallback.
        def hole_size(f: SdkField) -> int:
            m = re.search(r'size=0x([0-9A-Fa-f]+)', f.tail)
            return int(m.group(1), 16) if m else 0
        SIZE_HINT = {'float': 4, 'int': None, 'ptr': 8, 'container': 16, 'struct': None, 'unknown': None}
        def matches(sm: SourceMember, f: SdkField) -> bool:
            fam_sdk = sdk_type_family(f.type)
            sz = hole_size(f)
            if sm.family != fam_sdk and fam_sdk != 'unknown' and sm.family != 'unknown':
                return False
            sz_hint = SIZE_HINT[sm.family]
            if sz_hint is not None and sz > 0 and sz_hint != sz:
                return False
            return True
        def assign(f: SdkField, sm: SourceMember, provenance: str):
            line = block[f.line_no]
            block[f.line_no] = re.sub(
                r'Native_0x[0-9A-Fa-f]+', sm.name, line, count=1)
            block[f.line_no] = block[f.line_no].replace(' // native', f' // {provenance}')
            nonlocal named
            named += 1

        used_src: set = set()
        # First pass: source-order-respecting anchor windows.
        for a in range(len(anchors) - 1):
            si_lo, off_lo = anchors[a]
            si_hi, off_hi = anchors[a + 1]
            src_between = [
                (idx, m) for idx, m in enumerate(src.members)
                if si_lo < idx < si_hi and not m.is_uproperty and idx not in used_src
            ]
            holes = [
                (fi, f) for fi, f in enumerate(fields)
                if f.is_native and off_lo < f.offset < off_hi
                   and 'Native_' in block[f.line_no]  # still unassigned
            ]
            if not src_between or not holes:
                continue
            for fi, f in holes:
                for si, sm in src_between:
                    if si in used_src: continue
                    if not matches(sm, f): continue
                    assign(f, sm, '(ue57)')
                    used_src.add(si)
                    break

        # Class-wide fallback for unresolved Native_0x holes. UE reorders
        # fields for some classes (ULevel::Actors sits in source-order
        # BEFORE OwningWorld but in memory AFTER); source-order alone gets
        # them wrong. Anything left unresolved after the anchor pass gets
        # matched loosely by family+size across the whole class.
        for fi, f in enumerate(fields):
            if not f.is_native: continue
            if 'Native_' not in block[f.line_no]: continue
            for si, sm in enumerate(src.members):
                if sm.is_uproperty: continue
                if si in used_src: continue
                if not matches(sm, f): continue
                assign(f, sm, '(ue57?)')  # `?` marks looser match
                used_src.add(si)
                break

        result.extend(block)
        if j < len(lines):
            result.append(lines[j])
        i = j + 1

    with open(out_path, 'w', encoding='utf-8') as f:
        f.writelines(result)
    sys.stderr.write(f'[ue57] matched {matched_classes} classes, named {named}/{scanned} native fields\n')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--ue', required=True, help='UnrealEngine-5.7 root')
    ap.add_argument('--sdk', required=True, help='SDK_Output.txt path')
    ap.add_argument('--out', required=True, help='output path for annotated SDK')
    ap.add_argument('--cache', help='optional JSON cache of parsed types')
    args = ap.parse_args()

    types = None
    if args.cache and os.path.exists(args.cache):
        with open(args.cache, 'r') as f:
            raw = json.load(f)
        types = {}
        for name, entry in raw.items():
            st = SourceType(name, entry['parent'])
            st.members = [
                SourceMember(m['name'], m['type'], m['uprop'])
                for m in entry['members']]
            types[name] = st
        sys.stderr.write(f'[ue57] loaded {len(types)} types from cache\n')
    else:
        types = build_index(args.ue)
        if args.cache:
            with open(args.cache, 'w') as f:
                json.dump({
                    n: {
                        'parent': t.parent,
                        'members': [{'name': m.name, 'type': m.type, 'uprop': m.is_uproperty}
                                    for m in t.members],
                    }
                    for n, t in types.items()
                }, f)

    emit_named_sdk(args.sdk, args.out, types)

if __name__ == '__main__':
    main()
