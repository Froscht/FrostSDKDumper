#!/usr/bin/env python3
"""
Post-process FrostDumper's SDK_Output.txt by overlaying refSDK ground truth.

For each `namespace XXX` (= struct/class) in SDK_Output.txt:
  1. Find matching `struct FXXX` or `class UXXX` in refSDK/*.hpp
  2. For each `Prop_CI<n>_...` or `Prop_CI0_Off...` placeholder property,
     match by OFFSET to the refSDK field at that offset
  3. Replace placeholder name + type with refSDK truth

Output: SDK_Output_enriched.txt — same structure but with real names + types.
"""
import os, re, sys
from collections import defaultdict
from glob import glob

SDK_DIR = '/media/frost/Coding Stuf/Linux/FrostSDKDumper'
REF_DIR = f'{SDK_DIR}/refSDK/SDK'
OUTPUT = f'{SDK_DIR}/SDK_Output.txt'
ENRICHED = f'{SDK_DIR}/SDK_Output_enriched.txt'

# --- Parse refSDK ---
# Patterns:
#   struct FXXX  /  class UXXX
#   field-line: TYPE  NAME ;  // 0xOFFSET(0xSIZE)(...flags...)

STRUCT_RE = re.compile(r'^(?:struct\s+(F\w+)|class\s+(U\w+)\s*(?::\s*public\s+\w+)?)\s*$')
FIELD_RE = re.compile(
    r'^\s*([\w<>:,\s\*&]+?)\s+(\w+)(?:\[\d+\])?\s*;\s*'
    r'//\s*0x([0-9A-Fa-f]+)\(0x([0-9A-Fa-f]+)\)'
)
# Bitfield form:  `uint8 bFoo : 1;  // 0xOFFSET(0xSIZE)(...)`
BITFIELD_RE = re.compile(
    r'^\s*(\w+)\s+(\w+)\s*:\s*\d+\s*;\s*'
    r'//\s*0x([0-9A-Fa-f]+)\(0x([0-9A-Fa-f]+)\)'
)

def parse_ref():
    """Return {struct_name: [(field_name, offset, size, type), ...]}."""
    result = defaultdict(list)
    files = glob(f'{REF_DIR}/*.hpp')
    print(f'[+] Scanning {len(files)} refSDK files…', file=sys.stderr)
    for fpath in files:
        try:
            with open(fpath, encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception: continue
        cur_struct = None
        in_struct = False
        brace_depth = 0
        for line in lines:
            m = STRUCT_RE.match(line.strip())
            if m:
                cur_struct = m.group(1) or m.group(2)
                in_struct = True
                brace_depth = 0
                continue
            if in_struct:
                brace_depth += line.count('{') - line.count('}')
                if cur_struct:
                    bm = BITFIELD_RE.match(line)
                    if bm:
                        ftype, fname, foff, fsize = bm.groups()
                        result[cur_struct].append((
                            fname, int(foff, 16), int(fsize, 16),
                            f'{ftype} (bitfield)'
                        ))
                    else:
                        fm = FIELD_RE.match(line)
                        if fm:
                            ftype, fname, foff, fsize = fm.groups()
                            result[cur_struct].append((
                                fname, int(foff, 16), int(fsize, 16), ftype.strip()
                            ))
                if brace_depth < 0 or line.strip() == '};':
                    in_struct = False
                    cur_struct = None
    return result

def normalize_name(n):
    """SDK_Output uses bare names like 'ARFilter'; refSDK uses 'FARFilter'/'UARFilter'.
    Try both forms."""
    return [n, f'F{n}', f'U{n}', f'A{n}', f'E{n}']

def main():
    ref = parse_ref()
    print(f'[+] Parsed {len(ref)} ref structs/classes', file=sys.stderr)

    if not os.path.exists(OUTPUT):
        print(f'[!] {OUTPUT} not found', file=sys.stderr)
        return 1

    with open(OUTPUT) as f:
        sdk_lines = f.readlines()

    enriched = []
    cur_namespace = None
    matched_ref = None
    enriched_count = 0
    inserted_count = 0
    namespace_match_count = 0
    ns_buffer = []           # holds lines between `namespace X {` and `}`
    ns_existing_offsets = set()  # offsets the dumper already found

    PROP_LINE = re.compile(r'^(\s*)constexpr uint32_t\s+(\S+)\s*=\s*0x([0-9A-Fa-f]+);\s*//\s*(.*?)\s*$')
    NS_LINE = re.compile(r'^namespace\s+(\w+)\s*\{')
    NS_END = re.compile(r'^\}\s*//\s*namespace\s+(\w+)')

    def flush_namespace():
        """Emit ns_buffer with refSDK fields inserted for any offset NOT already present."""
        nonlocal inserted_count
        if matched_ref is not None:
            # Insert refSDK fields for missing offsets, sorted ascending
            inserts = []
            for fname, foff, fsize, ftype in sorted(matched_ref[1], key=lambda x: x[1]):
                if foff not in ns_existing_offsets:
                    inserts.append(
                        f'    constexpr uint32_t {fname:<40} = 0x{foff:X};  // {ftype}  // size=0x{fsize:X}  // [from refSDK]\n'
                    )
                    inserted_count += 1
            # Insert refSDK fields at the START of the namespace body
            enriched.extend(inserts)
        enriched.extend(ns_buffer)
        ns_buffer.clear()
        ns_existing_offsets.clear()

    for line in sdk_lines:
        ns_m = NS_LINE.match(line)
        if ns_m:
            # Starting a new namespace — flush whatever buffer was open
            if cur_namespace is not None:
                flush_namespace()
            cur_namespace = ns_m.group(1)
            matched_ref = None
            for variant in normalize_name(cur_namespace):
                if variant in ref:
                    matched_ref = (variant, ref[variant])
                    namespace_match_count += 1
                    break
            enriched.append(line)
            continue

        if NS_END.match(line):
            flush_namespace()
            enriched.append(line)
            cur_namespace = None
            matched_ref = None
            continue

        if cur_namespace is not None:
            pm = PROP_LINE.match(line)
            if pm and matched_ref:
                indent, prop_name, prop_off_hex, comment = pm.groups()
                prop_off = int(prop_off_hex, 16)
                ns_existing_offsets.add(prop_off)
                # Find ref field at this offset
                replaced = False
                for fname, foff, fsize, ftype in matched_ref[1]:
                    if foff == prop_off:
                        new_line = f'{indent}constexpr uint32_t {fname:<40} = 0x{prop_off:X};  // {ftype}  // size=0x{fsize:X}\n'
                        ns_buffer.append(new_line)
                        enriched_count += 1
                        replaced = True
                        break
                if not replaced:
                    ns_buffer.append(line)
                continue

            ns_buffer.append(line)
            continue

        enriched.append(line)

    # In case the file didn't end on `} // namespace`
    if cur_namespace is not None:
        flush_namespace()

    with open(ENRICHED, 'w') as f:
        f.writelines(enriched)

    print(f'[+] Matched {namespace_match_count} namespaces against refSDK', file=sys.stderr)
    print(f'[+] Enriched {enriched_count} existing property lines', file=sys.stderr)
    print(f'[+] Inserted {inserted_count} new property lines from refSDK', file=sys.stderr)
    print(f'[+] Wrote {ENRICHED}', file=sys.stderr)
    return 0

if __name__ == '__main__':
    sys.exit(main())
