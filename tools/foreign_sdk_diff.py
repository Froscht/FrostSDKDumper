#!/usr/bin/env python3
import argparse
import os
import re
import sys
from collections import defaultdict

RX_FOREIGN_TYPE = re.compile(r'^(class|struct)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*public\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$')
RX_FOREIGN_ENUM = re.compile(r'^enum class\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[A-Za-z0-9_ ]+$')
RX_FOREIGN_FIELD = re.compile(r'^\s*[A-Za-z_][^\s]*(?:\s*\*|\s*&|\s*<[^;]*>)?\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*\d+)?\s*;\s*(?://\s*(0x[0-9A-Fa-f]+))?')
RX_OUR_TYPE_HDR = re.compile(r'^//\s*(Class|Struct)\s+(?://)?(.+?)\s*$')
RX_OUR_NAMESPACE = re.compile(r'^namespace\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{')
RX_OUR_FIELD = re.compile(r'^constexpr\s+uint32_t\s+([A-Za-z_][A-Za-z0-9_]*)\s+=\s+0x([0-9A-Fa-f]+)\s*;')
RX_OUR_ENUM_HDR = re.compile(r'^//\s*Enum\s+(.+?)\s*$')

def parse_foreign(base_dir):
    types = {}
    def load(fname, kind_hint):
        path = os.path.join(base_dir, fname)
        if not os.path.exists(path):
            return
        cur = None
        cur_kind = None
        with open(path, 'r', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')
                m = RX_FOREIGN_TYPE.match(line)
                if m:
                    cur_kind = m.group(1)
                    cur = m.group(2)
                    if cur.startswith(('U','A','I')):
                        base = cur[1:]
                    elif cur.startswith(('F','T','E')):
                        base = cur[1:]
                    else:
                        base = cur
                    types.setdefault(base, {'kind': cur_kind, 'raw': cur, 'fields': set(), 'field_offsets': {}})
                    continue
                if line == '};':
                    cur = None
                    continue
                if cur is None:
                    continue
                mf = RX_FOREIGN_FIELD.match(line)
                if mf:
                    name = mf.group(1)
                    off = mf.group(2)
                    if name.startswith('Pad_'):
                        continue
                    if cur.startswith(('U','A','I','F','T','E')):
                        base = cur[1:]
                    else:
                        base = cur
                    types.setdefault(base, {'kind': cur_kind, 'raw': cur, 'fields': set(), 'field_offsets': {}})
                    types[base]['fields'].add(name)
                    if off:
                        types[base]['field_offsets'][name] = int(off, 16)
    load('Class.cpp', 'class')
    load('Struct.cpp', 'struct')
    return types

def parse_foreign_enums(base_dir):
    enums = {}
    path = os.path.join(base_dir, 'Enum.cpp')
    if not os.path.exists(path):
        return enums
    cur = None
    cur_entries = set()
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n')
            m = RX_FOREIGN_ENUM.match(line)
            if m:
                cur = m.group(1)
                if cur.startswith('E') and len(cur) > 1 and cur[1].isupper():
                    cur = cur[1:]
                cur_entries = set()
                enums[cur] = cur_entries
                continue
            if line == '};':
                cur = None
                continue
            if cur is None:
                continue
            s = line.strip()
            if '=' in s:
                lhs = s.split('=')[0].strip()
                if '::' in lhs:
                    lhs = lhs.split('::')[-1]
                lhs = lhs.rstrip(',').strip()
                if lhs:
                    cur_entries.add(lhs)
    return enums

def parse_our(path):
    types = {}
    enums = {}
    cur_type = None
    cur_kind = None
    cur_ns = None
    in_enum = False
    with open(path, 'r', errors='replace') as fh:
        for line in fh:
            line = line.rstrip('\n')
            m = RX_OUR_TYPE_HDR.match(line)
            if m:
                cur_kind = m.group(1)
                path_name = m.group(2)
                base = path_name.split('.')[-1] if '.' in path_name else path_name
                cur_type = base
                in_enum = False
                continue
            me = RX_OUR_ENUM_HDR.match(line)
            if me:
                path_name = me.group(1)
                base = path_name.split('.')[-1] if '.' in path_name else path_name
                cur_type = base
                enums.setdefault(cur_type, set())
                in_enum = True
                cur_kind = None
                continue
            mn = RX_OUR_NAMESPACE.match(line)
            if mn:
                cur_ns = mn.group(1)
                if cur_type and cur_kind:
                    types.setdefault(cur_type, {'kind': cur_kind, 'fields': set(), 'field_offsets': {}})
                continue
            if line.startswith('} // namespace'):
                cur_ns = None
                cur_type = None
                cur_kind = None
                in_enum = False
                continue
            if in_enum and cur_type:
                s = line.strip()
                if s.startswith('constexpr int64_t'):
                    parts = s.split()
                    if len(parts) >= 3:
                        enums[cur_type].add(parts[2])
                continue
            mf = RX_OUR_FIELD.match(line.strip())
            if mf and cur_type and cur_kind:
                name = mf.group(1)
                off = int(mf.group(2), 16)
                if name.startswith(('Pad_', 'Native_', '__Pad')):
                    continue
                if name.endswith('__Item'):
                    continue
                types[cur_type]['fields'].add(name)
                types[cur_type]['field_offsets'][name] = off
    return types, enums

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--foreign', default='/home/frost/Downloads/SDK')
    ap.add_argument('--ours', default='/media/frost/Coding Stuf/Linux/FrostSDKDumper/SDK_Output.txt')
    ap.add_argument('--out', default='/media/frost/Coding Stuf/Linux/FrostSDKDumper/foreign_diff.txt')
    ap.add_argument('--min-missing', type=int, default=1)
    args = ap.parse_args()

    print(f'[diff] parsing foreign SDK: {args.foreign}')
    ft = parse_foreign(args.foreign)
    fe = parse_foreign_enums(args.foreign)
    print(f'[diff]   foreign types={len(ft)}  enums={len(fe)}')

    print(f'[diff] parsing our SDK: {args.ours}')
    ot, oe = parse_our(args.ours)
    print(f'[diff]   our types={len(ot)}  enums={len(oe)}')

    only_foreign_types = sorted(set(ft) - set(ot))
    only_our_types = sorted(set(ot) - set(ft))
    both = sorted(set(ft) & set(ot))

    missing_fields = defaultdict(list)
    extra_fields = defaultdict(list)
    off_mismatch = defaultdict(list)
    for name in both:
        f_flds = ft[name]['fields']
        o_flds = ot[name]['fields']
        miss = sorted(f_flds - o_flds)
        extra = sorted(o_flds - f_flds)
        if miss: missing_fields[name] = miss
        if extra: extra_fields[name] = extra
        for fn in (f_flds & o_flds):
            fo = ft[name]['field_offsets'].get(fn)
            oo = ot[name]['field_offsets'].get(fn)
            if fo is not None and oo is not None and fo != oo:
                off_mismatch[name].append((fn, fo, oo))

    only_foreign_enums = sorted(set(fe) - set(oe))
    only_our_enums = sorted(set(oe) - set(fe))
    both_enums = sorted(set(fe) & set(oe))
    enum_missing = defaultdict(list)
    for en in both_enums:
        miss = sorted(fe[en] - oe[en])
        if miss: enum_missing[en] = miss

    with open(args.out, 'w') as f:
        f.write('=== Foreign SDK diff report ===\n')
        f.write(f'foreign root: {args.foreign}\n')
        f.write(f'our SDK:      {args.ours}\n\n')

        f.write(f'== Type coverage ==\n')
        f.write(f'  both:            {len(both)}\n')
        f.write(f'  only foreign:    {len(only_foreign_types)}\n')
        f.write(f'  only ours:       {len(only_our_types)}\n\n')

        f.write(f'== Types only in foreign SDK ({len(only_foreign_types)}) ==\n')
        for n in only_foreign_types:
            f.write(f'  {ft[n]["raw"]}\n')
        f.write('\n')

        f.write(f'== Types with missing fields ({sum(1 for v in missing_fields.values() if len(v) >= args.min_missing)}) ==\n')
        for n in sorted(missing_fields, key=lambda x: -len(missing_fields[x])):
            miss = missing_fields[n]
            if len(miss) < args.min_missing: continue
            f.write(f'  {n}  missing {len(miss)}:\n')
            for fn in miss[:40]:
                off = ft[n]['field_offsets'].get(fn)
                if off is not None:
                    f.write(f'    - {fn}  (foreign offset 0x{off:X})\n')
                else:
                    f.write(f'    - {fn}\n')
            if len(miss) > 40:
                f.write(f'    ... and {len(miss)-40} more\n')
        f.write('\n')

        f.write(f'== Offset mismatches ({sum(len(v) for v in off_mismatch.values())}) ==\n')
        for n in sorted(off_mismatch, key=lambda x: -len(off_mismatch[x]))[:100]:
            f.write(f'  {n}:\n')
            for fn, fo, oo in off_mismatch[n][:20]:
                f.write(f'    {fn}  foreign=0x{fo:X}  ours=0x{oo:X}\n')
        f.write('\n')

        f.write(f'== Enum coverage ==\n')
        f.write(f'  both:            {len(both_enums)}\n')
        f.write(f'  only foreign:    {len(only_foreign_enums)}\n')
        f.write(f'  only ours:       {len(only_our_enums)}\n\n')

        f.write(f'== Enums with missing entries ==\n')
        for en in sorted(enum_missing, key=lambda x: -len(enum_missing[x]))[:200]:
            miss = enum_missing[en]
            f.write(f'  {en}  missing {len(miss)}: {", ".join(miss[:30])}\n')

    print(f'[diff] report written: {args.out}')
    print(f'[diff]   {len(only_foreign_types)} types only in foreign')
    print(f'[diff]   {sum(len(v) for v in missing_fields.values())} missing fields across {len(missing_fields)} types')
    print(f'[diff]   {sum(len(v) for v in off_mismatch.values())} field-offset mismatches')

if __name__ == '__main__':
    main()
