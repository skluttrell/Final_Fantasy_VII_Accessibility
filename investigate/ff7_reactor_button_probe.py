#!/usr/bin/env python3
"""
ff7_reactor_button_probe.py -- where is the No.1 reactor elevator button?
(2026-07-31, task-3 follow-up)

The game-wide prop catalog (ff7_prop_interact_catalog.py) found NO
talk-scripted model entity in nmkin_1/nmkin_2, yet the tester pressed a
working elevator button there. Either the button is a LINE entity
(already in the line catalog -- then the question is why the browser
didn't offer it) or a model entity using a script slot other than 1.

This probe dumps EVERYTHING about the two fields: every entity, its
name, LINE coords or CHAR model binding (with label), and which script
slots 0..7 are non-empty plus the evidence ops each reaches. One look
settles it.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"reactor_button_probe_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# reuse the catalog's tables by textual import would re-run it; keep this
# probe self-contained with the same verbatim tables instead.
OPLEN = [
    0, 2, 2, 2, 2, 2, 2, 1, 1, 14, 5, 5, -1, -1, 1, 0,
    1, 2, 1, 2, 5, 6, 7, 8, 7, 8, -1, -1, -1, -1, -1, -1,
    10, 1, 4, 2, 2, 8, 1, 1, 0, 0, 1, 1, 4, 6, 1, 9,
    3, 3, 3, 1, 1, 3, 4, 7, 5, 5, 5, 3, 0, 0, 0, 0,
    2, 4, 5, 1, -1, 4, -1, 4, 6, 3, 1, 1, -1, 4, -1, 4,
    9, 5, 3, 1, 1, 2, 6, 6, 4, 4, 4, 6, 7, 9, 7, 0,
    9, 1, 4, 5, 5, 0, 8, 0, 8, 1, 6, 8, 0, 3, 2, 5,
    3, 1, 2, 3, 3, 7, 3, 4, 3, 4, 2, 2, 2, 2, 1, 2,
    3, 4, 3, 3, 3, 3, 4, 3, 4, 3, 4, 3, 4, 3, 4, 3,
    4, 3, 4, 3, 4, 2, 2, 2, 2, 2, 3, 4, 5, 6, 6, 10,
    1, 1, 2, 2, 1, 10, 8, 8, 5, 5, 1, 3, 0, 5, 2, 2,
    4, 4, 3, 2, 5, 5, 1, 3, 4, 3, 2, 4, 4, 3, -1, 1,
    10, 7, 14, 11, 0, 2, 2, 1, 1, 1, 3, 2, 2, 2, 1, 1,
    12, 1, 1, 15, 9, 9, 3, 3, 2, 0, 14, 1, 3, 0, 0, 10,
    3, 3, 2, 2, 2, 4, 4, 4, 6, 9, 9, 4, 4, 7, 7, 10,
    1, 4, 13, 1, 1, 1, 1, 3, 1, 0, 2, 1, 1, 5, 2, 0,
]
SPECIAL_LEN = {0xF5: 1, 0xF6: 4, 0xF7: 2, 0xF8: 2, 0xF9: 0, 0xFA: 0,
               0xFB: 1, 0xFC: 1, 0xFD: 2, 0xFE: 0, 0xFF: 0}

NAMES = {0x00: 'ret', 0x01: 'req', 0x02: 'reqsw', 0x03: 'reqew',
         0x10: 'skip', 0x11: 'lskip', 0x12: 'back', 0x14: 'if',
         0x15: 'lif', 0x16: 'if2', 0x17: 'lif2', 0x20: 'mgame',
         0x24: 'wait', 0x28: 'kawai', 0x30: 'key', 0x33: 'uc',
         0x39: 'gold+', 0x40: 'mes', 0x43: 'mpnam', 0x48: 'ask',
         0x58: 'stitm', 0x5B: 'smtra', 0x60: 'MJUMP', 0x6D: 'idlck',
         0x70: 'batle', 0x80: 'set', 0x82: 'biton', 0xA0: 'pc',
         0xA1: 'CHAR', 0xA2: 'dfanm', 0xA3: 'anime', 0xA4: 'VISI',
         0xA5: 'xyzi', 0xC2: 'LADER', 0xC7: 'solid', 0xD0: 'LINE',
         0xD3: 'SLINE', 0xF1: 'se', 0xF2: 'akao', 0x7E: 'tlkon'}

def instr_size(code, off):
    op = code[off]
    ln = OPLEN[op]
    if ln < 0:
        return None
    if op == 0x0F:
        sub = code[off + 1] if off + 1 < len(code) else None
        if sub not in SPECIAL_LEN:
            return None
        return SPECIAL_LEN[sub] + 2
    if op == 0x28:
        sz = code[off + 1] if off + 1 < len(code) else 0
        return sz if sz >= 3 else None
    return ln + 1

def branch_target(code, off):
    op = code[off]
    if op == 0x10: return off + code[off + 1] + 1
    if op == 0x11: return off + (code[off + 1] | (code[off + 2] << 8)) + 1
    if op == 0x12: return off - code[off + 1]
    if op == 0x13: return off - (code[off + 1] | (code[off + 2] << 8))
    if op == 0x14: return off + code[off + 5] + 5
    if op == 0x15: return off + (code[off + 5] | (code[off + 6] << 8)) + 5
    if op in (0x16, 0x18): return off + code[off + 7] + 7
    if op in (0x17, 0x19): return off + (code[off + 7] | (code[off + 8] << 8)) + 7
    if op in (0x30, 0x31, 0x32): return off + code[off + 3] + 3
    if op in (0xCB, 0xCC): return off + code[off + 2] + 2
    return None

def walk(code, entry):
    seen, stack, guard = {}, [entry], 8192
    while stack and guard > 0:
        off = stack.pop()
        while 0 <= off < len(code) and off not in seen and guard > 0:
            guard -= 1
            sz = instr_size(code, off)
            if sz is None:
                break
            seen[off] = code[off]
            if code[off] in (0x00, 0x07, 0xFF):
                break
            t = branch_target(code, off)
            if t is not None:
                if code[off] in (0x10, 0x11, 0x12, 0x13):
                    off = t
                    continue
                stack.append(t)
            off += sz
    return seen

CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\data\field\flevel.lgp",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\data\field\flevel.lgp",
]
lgp_path = next((c for c in CANDIDATES if os.path.isfile(c)), None)
data = open(lgp_path, 'rb').read()
n_files = struct.unpack_from('<I', data, 12)[0]
toc = {}
for i in range(n_files):
    off = 16 + i * 27
    nm = data[off:off + 20].split(b'\0')[0].decode('ascii', 'replace').lower()
    toc[nm] = struct.unpack_from('<I', data, off + 20)[0]

def lzs_decompress(src, max_out):
    out = bytearray(); win = bytearray(4096); wpos = 0xFEE
    i, n = 0, len(src)
    while i < n and len(out) < max_out:
        ctrl = src[i]; i += 1
        for bit in range(8):
            if len(out) >= max_out or i >= n: break
            if ctrl & (1 << bit):
                b = src[i]; i += 1
                out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
            else:
                if i + 1 >= n: i = n; break
                b1, b2 = src[i], src[i + 1]; i += 2
                pos = b1 | ((b2 & 0xF0) << 4); length = (b2 & 0x0F) + 3
                for k in range(length):
                    b = win[(pos + k) & 0xFFF]
                    out.append(b); win[wpos] = b; wpos = (wpos + 1) & 0xFFF
                    if len(out) >= max_out: break
    return bytes(out)

def parse_model_labels(dec, sec_offs):
    base = sec_offs[2] + 4
    if base + 6 > len(dec): return []
    n_models = struct.unpack_from('<H', dec, base + 2)[0]
    if n_models > 64: return []
    labels, p = [], base + 6
    for _ in range(n_models):
        if p + 2 > len(dec): return []
        nl = struct.unpack_from('<H', dec, p)[0]
        if nl > 132 or p + 2 + nl > len(dec): return []
        label = dec[p + 2:p + 2 + nl].split(b'\0')[0].decode('ascii', 'replace').lower()
        p += 2 + nl
        if p + 46 > len(dec): return []
        n_anims = struct.unpack_from('<H', dec, p + 14)[0]
        p += 46
        for _ in range(n_anims):
            if p + 2 > len(dec): return []
            alen = struct.unpack_from('<H', dec, p)[0]
            if alen > 132: return []
            p += 2 + alen + 2
        labels.append(label)
    return labels

for fname in (sys.argv[1:] or ('nmkin_1', 'nmkin_2')):
    entry_off = toc[fname]
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    dec = lzs_decompress(data[entry_off + 24:entry_off + 24 + flen][4:],
                         4 * 1024 * 1024)
    sec_offs = struct.unpack_from('<9I', dec, 6)
    sc = sec_offs[0] + 4
    n_ent = dec[sc + 2]
    wstr = struct.unpack_from('<H', dec, sc + 4)[0]
    n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
    tab = 0x20 + n_ent * 8 + n_akao * 4
    code = dec[sc:sc + wstr]
    labels = parse_model_labels(dec, sec_offs)
    print(f"=== {fname}: {n_ent} entities, {len(labels)} models ===")
    for e in range(n_ent):
        nm = dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
            .split(b'\0')[0].decode('ascii', 'replace')
        offs = [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]
        # default (empty) slots share the same offset as the next entity's
        # slot table start or point at a lone ret; treat "same offset as
        # slot 31 default" heuristically by walking and checking ops.
        row = [f"ent={e:2d} '{nm}'"]
        init = walk(code, offs[0])
        char_off = next((o for o, op in init.items() if op == 0xA1), None)
        line_off = next((o for o, op in init.items() if op in (0xD0, 0xD3)), None)
        if char_off is not None:
            mi = code[char_off + 1]
            row.append(f"CHAR model={mi} "
                       f"'{labels[mi] if mi < len(labels) else '?'}'")
        if line_off is not None:
            coords = struct.unpack_from('<6h', code, line_off + 1) \
                if code[line_off] == 0xD0 else None
            row.append(f"LINE {coords}")
        print("  " + "  ".join(row))
        for s in range(0, 32):
            reach = walk(code, offs[s])
            ops = set(reach.values()) - {0x00}
            if not ops:
                continue
            names = [NAMES.get(op, f"{op:02X}") for op in sorted(ops)]
            print(f"      slot{s}: {' '.join(names)}")


