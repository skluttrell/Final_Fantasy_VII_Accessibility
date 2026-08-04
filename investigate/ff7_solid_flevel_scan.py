#!/usr/bin/env python3
"""
ff7_solid_flevel_scan.py -- game-wide scan for the SOLID opcode (0xC7)
in field scripts (2026-08-04, pass 7 of the SOLID investigation).

WHY: the exe-side work proved field_event_data +0x5F is THE engine
tangibility gate (SOLID handler 0x61C9DD stores the script arg there;
the movement collision test 0x637724 skips any model with +0x5F != 0).
This script confirms the REPORTED scenario offline: the unconscious
guards at the Sector 1 station (game start) should carry SOLID(1) in
their scripts -- proving the pathfinder's false "blocked by guard"
reports come from ignoring this flag, before any code ships.

METHOD: identical flevel parsing to ff7_line_trigger_catalog.py
(LGP TOC -> LZS -> section table -> script section entities; opcode
lengths/branch math verbatim from cebix/ff7tools). For every entity in
every maplist field, flow-walk ALL 32 script slots and record each
reachable SOLID (0xC7) with its argument byte (engine semantics:
0 = solid, nonzero = intangible). Full detail for the opening-route
fields; game-wide counts for scale.
"""
import sys, os, struct, datetime
from collections import defaultdict

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"solid_flevel_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

# -- opcode table (cebix/ff7tools, identical to ff7_line_trigger_catalog.py) -----
OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1,
    1, 14, 5, 5, -1, -1, 1, 0,
    1, 2, 1, 2, 5, 6, 7, 8,
    7, 8, -1, -1, -1, -1, -1, -1,
    10, 1, 4, 2, 2, 8, 1, 1,
    0, 0, 1, 1, 4, 6, 1, 9,
    3, 3, 3, 1, 1, 3, 4, 7,
    5, 5, 5, 3, 0, 0, 0, 0,
    2, 4, 5, 1, -1, 4, -1, 4,
    6, 3, 1, 1, -1, 4, -1, 4,
    9, 5, 3, 1, 1, 2, 6, 6,
    4, 4, 4, 6, 7, 9, 7, 0,
    9, 1, 4, 5, 5, 0, 8, 0,
    8, 1, 6, 8, 0, 3, 2, 5,
    3, 1, 2, 3, 3, 7, 3, 4,
    3, 4, 2, 2, 2, 2, 1, 2,
    3, 4, 3, 3, 3, 3, 4, 3,
    4, 3, 4, 3, 4, 3, 4, 3,
    4, 3, 4, 3, 4, 2, 2, 2,
    2, 2, 3, 4, 5, 6, 6, 10,
    1, 1, 2, 2, 1, 10, 8, 8,
    5, 5, 1, 3, 0, 5, 2, 2,
    4, 4, 3, 2, 5, 5, 1, 3,
    4, 3, 2, 4, 4, 3, -1, 1,
    10, 7, 14, 11, 0, 2, 2, 1,
    1, 1, 3, 2, 2, 2, 1, 1,
    12, 1, 1, 15, 9, 9, 3, 3,
    2, 0, 14, 1, 3, 0, 0, 10,
    3, 3, 2, 2, 2, 4, 4, 4,
    6, 9, 9, 4, 4, 7, 7, 10,
    1, 4, 13, 1, 1, 1, 1, 3,
    1, 0, 2, 1, 1, 5, 2, 0,
]
SPECIAL_LEN = {0xF5: 1, 0xF6: 4, 0xF7: 2, 0xF8: 2, 0xF9: 0, 0xFA: 0,
               0xFB: 1, 0xFC: 1, 0xFD: 2, 0xFE: 0, 0xFF: 0}
OP_RET, OP_RETTO, OP_SPCAL, OP_KAWAI = 0x00, 0x07, 0x0F, 0x28
OP_GMOVR = 0xFF
OP_CHAR = 0xA1
OP_SOLID = 0xC7

def instr_size(code, off):
    op = code[off]
    ln = OPLEN[op]
    if ln < 0:
        return None
    if op == OP_SPCAL:
        sub = code[off + 1] if off + 1 < len(code) else None
        if sub not in SPECIAL_LEN:
            return None
        return SPECIAL_LEN[sub] + 2
    if op == OP_KAWAI:
        sz = code[off + 1] if off + 1 < len(code) else 0
        return sz if sz >= 3 else None
    return ln + 1

def branch_target(code, off):
    op = code[off]
    if op == 0x10:
        return off + code[off + 1] + 1
    if op == 0x11:
        return off + (code[off + 1] | (code[off + 2] << 8)) + 1
    if op == 0x12:
        return off - code[off + 1]
    if op == 0x13:
        return off - (code[off + 1] | (code[off + 2] << 8))
    if op == 0x14:
        return off + code[off + 5] + 5
    if op == 0x15:
        return off + (code[off + 5] | (code[off + 6] << 8)) + 5
    if op in (0x16, 0x18):
        return off + code[off + 7] + 7
    if op in (0x17, 0x19):
        return off + (code[off + 7] | (code[off + 8] << 8)) + 7
    if op in (0x30, 0x31, 0x32):
        return off + code[off + 3] + 3
    if op in (0xCB, 0xCC):
        return off + code[off + 2] + 2
    return None

def walk(code, entry, errors):
    seen = {}
    stack = [entry]
    guard = 8192
    while stack and guard > 0:
        off = stack.pop()
        while 0 <= off < len(code) and off not in seen and guard > 0:
            guard -= 1
            op = code[off]
            sz = instr_size(code, off)
            if sz is None:
                errors.append((off, op))
                break
            seen[off] = op
            if op in (OP_RET, OP_RETTO, OP_GMOVR):
                break
            t = branch_target(code, off)
            if t is not None:
                if op in (0x10, 0x11, 0x12, 0x13):
                    off = t
                    continue
                stack.append(t)
            off += sz
    return seen

# -- flevel + maplist ------------------------------------------------------------
CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
if not lgp_path:
    print("ERROR: flevel.lgp not found")
    sys.exit(1)
print(f"Reading: {lgp_path}")
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = []
for i in range(n_files):
    off = 16 + i * 27
    nm = data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower()
    toc.append((nm, struct.unpack_from('<I', data, off + 20)[0]))

def lzs_decompress(src, max_out):
    out = bytearray()
    win = bytearray(4096)
    wpos = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if len(out) >= max_out or i >= n:
                break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b)
                win[wpos] = b
                wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n:
                    i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4)
                length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b)
                    win[wpos] = b
                    wpos = (wpos + 1) & 0xFFF
                    if len(out) >= max_out:
                        break
    return bytes(out)

mo = next((o for nm, o in toc if nm == 'maplist'), None)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
start = next((s for s in (0, 2)
              if mraw[s + 122 * 32:s + 123 * 32].split(b'\0')[0] == b'nmkin_2'),
             None)
if start is None:
    print("ERROR: maplist anchor failed")
    sys.exit(1)
name_to_ids = {}
fid = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        name_to_ids.setdefault(nm, []).append(fid)
    fid += 1
print(f"maplist: {fid} ids, {len(name_to_ids)} named\n")

# -- the scan --------------------------------------------------------------------
# Opening route: train arrival through Reactor 1. md1stin = the station
# platform where the FMV guards fall.
DETAIL_FIELDS = {'md1stin', 'md1_1', 'md1_2', 'nrthmk', 'elevtr1',
                 'nmkin_1', 'nmkin_2', 'nmkin_3', 'nmkin_4', 'nmkin_5',
                 'tin_1', 'tin_2'}

stats = dict(fields=0, ents_with_solid=0, solid_on_ops=0, solid_off_ops=0,
             fields_with_solid=0, walk_errors=0)
field_rows = defaultdict(list)

for fname, entry_off in toc:
    if fname not in name_to_ids:
        continue
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    raw = data[entry_off + 24:entry_off + 24 + flen]
    if len(raw) < 8:
        continue
    dec = lzs_decompress(raw[4:], 4 * 1024 * 1024)
    if len(dec) < 6 + 36:
        continue
    sec_offs = struct.unpack_from('<9I', dec, 6)
    if sec_offs[0] != 0x2A or any(sec_offs[i] >= sec_offs[i + 1]
                                  for i in range(8)):
        continue
    sc = sec_offs[0] + 4
    if sc + 0x20 > len(dec):
        continue
    n_ent = dec[sc + 2]
    wstr = struct.unpack_from('<H', dec, sc + 4)[0]
    n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
    tab = 0x20 + n_ent * 8 + n_akao * 4
    if sc + tab + n_ent * 64 > len(dec) or wstr <= tab:
        continue
    code = dec[sc:sc + wstr]
    stats['fields'] += 1

    def slot_offs(e):
        return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]

    ename = lambda e: dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
        .split(b'\0')[0].decode('ascii', 'replace')

    field_has = False
    for e in range(n_ent):
        errors = []
        offs = slot_offs(e)
        ent_solids = []   # (slot, arg)
        has_char = False
        # slot 0 entry doubles as the "no script" sentinel for later
        # slots in some fields; walk each distinct offset once
        seen_offs = set()
        for s in range(32):
            if offs[s] >= len(code) or offs[s] in seen_offs:
                continue
            seen_offs.add(offs[s])
            reach = walk(code, offs[s], errors)
            for off, op in reach.items():
                if op == OP_SOLID and off + 1 < len(code):
                    ent_solids.append((s, code[off + 1]))
                elif op == OP_CHAR:
                    has_char = True
        stats['walk_errors'] += len(errors)
        if ent_solids:
            stats['ents_with_solid'] += 1
            field_has = True
            for s, arg in ent_solids:
                if arg == 0:
                    stats['solid_on_ops'] += 1
                else:
                    stats['solid_off_ops'] += 1
            if fname in DETAIL_FIELDS:
                field_rows[fname].append(
                    (e, ename(e), has_char, sorted(set(ent_solids))))
    if field_has:
        stats['fields_with_solid'] += 1

print("===== opening-route detail =====")
for fname in sorted(DETAIL_FIELDS):
    rows = field_rows.get(fname, [])
    print(f"\n{fname}: {len(rows)} entities with SOLID")
    for e, nm, has_char, solids in rows:
        ops = ", ".join(f"slot{s}:SOLID({a})" for s, a in solids)
        print(f"  ent {e:2d} '{nm}' char={int(has_char)}  {ops}")

print("\n===== game-wide stats =====")
for k, v in stats.items():
    print(f"  {k}: {v}")
print("\nDone.")
