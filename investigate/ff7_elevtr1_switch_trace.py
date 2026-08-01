#!/usr/bin/env python3
"""
ff7_elevtr1_switch_trace.py -- who shows "Switch On." in elevtr1?
(2026-08-01; the reactor elevator switch is invisible to the pathfinder)

Live-log facts (2026-08-01 09:44 session): in elevtr1 (field 121) the
runtime line array holds ONLY 'jp0' and the only models are Cloud,
Barret (parked, vis=0) and Jessie -- yet OK at the wall panel produced
MSG win=0 id=45 "Switch On.". No line, no talkable prop = nothing the
browser can list from engine state. This script finds the actual
mechanism in the field data:

  1. decode the TEXT section; confirm which text id is "Switch On.";
  2. linear-scan the script code block for MES (0x40) opcodes whose
     text-id operand matches, and locate each hit inside the entity
     script-slot table (which entity, which slot range);
  3. dump a full instruction listing of the OWNING slot (and anything
     that req's it), with KEY (0x30-0x32) and PXYZI/if-constant
     details decoded -- the suspected script-hotspot pattern.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"elevtr1_switch_trace_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
NAMES = {0x00: 'ret', 0x01: 'req', 0x02: 'reqsw', 0x03: 'reqew', 0x07: 'retto',
         0x10: 'skip', 0x11: 'lskip', 0x12: 'back', 0x13: 'lback',
         0x14: 'if', 0x15: 'lif', 0x16: 'if2', 0x17: 'lif2', 0x18: 'if2u',
         0x20: 'mgame', 0x24: 'wait', 0x25: 'nfade', 0x28: 'kawai',
         0x30: 'KEY', 0x31: 'KEYON', 0x32: 'KEYOF', 0x33: 'uc',
         0x40: 'MES', 0x43: 'mpnam', 0x48: 'ask', 0x50: 'wsize', 0x52: 'wmode',
         0x58: 'stitm', 0x60: 'MJUMP', 0x64: 'scr2d', 0x66: 'scr2dc',
         0x70: 'batle', 0x73: 'pgtdr', 0x74: 'getpc', 0x75: 'PXYZI',
         0x7E: 'tlkon', 0x80: 'set', 0x82: 'biton',
         0xA0: 'pc', 0xA1: 'CHAR', 0xA2: 'dfanm', 0xA3: 'anime',
         0xA4: 'VISI', 0xA5: 'xyzi', 0xA8: 'move', 0xB3: 'dir',
         0xC7: 'solid', 0xD0: 'LINE', 0xE0: 'bgon', 0xE1: 'bgoff',
         0xF1: 'se', 0xF2: 'akao'}

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

fname = 'elevtr1'
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

ename = lambda e: dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
    .split(b'\0')[0].decode('ascii', 'replace')

def slot_offs(e):
    return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
            for s in range(32)]

# ---- 1. text section --------------------------------------------------------------
# The dialog TEXT block is at the script section's wstr offset: u16 count?
# Format: at sc+wstr: u16 offset table (relative to the table start).
tbase = sc + wstr
n_texts = struct.unpack_from('<H', dec, tbase)[0] // 2  # first offset / 2
def decode_ff7(b, off):
    out = []
    while off < len(b):
        c = b[off]; off += 1
        if c == 0xFF: break
        if c == 0xE7: out.append(' ')
        elif 0x00 <= c <= 0xDF: out.append(chr(c + 0x20))
        else: out.append(f'{{{c:02X}}}')
    return ''.join(out)

print(f"=== {fname}: {n_ent} entities, text entries ~{n_texts} ===")
switch_ids = []
for tid in range(min(n_texts, 80)):
    toff = struct.unpack_from('<H', dec, tbase + tid * 2)[0]
    s = decode_ff7(dec, tbase + toff)
    if s.strip():
        tag = ""
        if 'switch' in s.lower():
            switch_ids.append(tid)
            tag = "   <<<<"
        print(f"  text[{tid:2d}]: {s[:70]!r}{tag}")

# ---- 2. find MES ops with those ids ------------------------------------------------
print(f"\n=== MES ops using text id(s) {switch_ids} ===")
def owning_slot(off):
    """(entity, slot) whose script region contains code offset off —
    region = [slot_off, next distinct offset)."""
    best = None
    for e in range(n_ent):
        offs = slot_offs(e)
        for s in range(32):
            if offs[s] <= off:
                if best is None or offs[s] > best[2] or \
                   (offs[s] == best[2] and (e, s) < (best[0], best[1])):
                    if best is None or offs[s] >= best[2]:
                        best = (e, s, offs[s])
    return best

hits = []
for off in range(tab, len(code) - 2):
    if code[off] == 0x40 and code[off + 2] in switch_ids:
        hits.append(off)
        e_s = owning_slot(off)
        print(f"  MES at code+0x{off:X} win={code[off+1]} id={code[off+2]}"
              f"  owner ent={e_s[0]} '{ename(e_s[0])}' slot={e_s[1]}"
              f" (slot off 0x{e_s[2]:X})")

# ---- 3. full listing of each owner slot + req scan ---------------------------------
def disasm(entry, limit=120):
    off = entry
    n = 0
    while off < len(code) and n < limit:
        op = code[off]
        sz = instr_size(code, off)
        if sz is None:
            print(f"    +0x{off:X}: ?? {op:02X}")
            break
        args = ' '.join(f'{b:02X}' for b in code[off + 1:off + sz])
        print(f"    +0x{off:X}: {NAMES.get(op, f'{op:02X}'):6s} {args}")
        if op in (0x00, 0x07):
            break
        off += sz
        n += 1

seen_slots = set()
for off in hits:
    e, s, so = owning_slot(off)
    if (e, s) in seen_slots:
        continue
    seen_slots.add((e, s))
    print(f"\n--- ent={e} '{ename(e)}' slot={s} @ 0x{so:X} ---")
    disasm(so)

print("\n=== req/reqsw/reqew calls in the whole code block (who starts what) ===")
for off in range(tab, len(code) - 2):
    if code[off] in (0x01, 0x02, 0x03):
        te, arg = code[off + 1], code[off + 2]
        ts = arg & 0x1F
        e_s = owning_slot(off)
        if te < n_ent:
            print(f"  +0x{off:X}: {NAMES[code[off]]} -> ent={te} "
                  f"'{ename(te)}' slot={ts} pri={arg >> 5}   "
                  f"(from ent={e_s[0]} '{ename(e_s[0])}' slot={e_s[1]})")
