#!/usr/bin/env python3
"""
ff7_graveyard_train_dump.py -- Train Graveyard (fields 144/145,
mds7st1/mds7st2) full script dump (2026-08-09).

WHY: play session log.10 (2026-08-09) -- returning to Sector 7 through
the graveyard, the player circled field 145 for ~10 minutes and quit.
The screen's train-hopping puzzle (walkthrough: "Hop into the brownish
train on the right to move the other train out of the way. Finish the
job by also hopping in the upper train.") is invisible to the mod:
every LINE trigger in 144/145 is entity-named literally 'line', so the
browser speaks "line 1".."line 11" with no hint which one boards a
train, and the two z=352 SCENE lines that move trains are
indistinguishable from the climb-over-the-wreck lines. Runtime log also
shows two lines (ent 8, ent 10 in 145) ABSENT from the engine's line
array -- script-disabled, i.e. puzzle state exists.

WHAT: for each target field, print
  - the entity table (names, which declare LINE, coords);
  - a full disassembly of every entity's script slots (dedup by offset,
    range = slot offset .. next slot offset), with decoded operands for
    the opcodes that matter to the puzzle: LINE/SLINE/LINON (trigger
    geometry + enable/disable), MJUMP (exits), LADER (climbs), IDLCK
    (walkmesh gate), VISI/SOLID/TLKON, if-family conditionals and
    set/biton/bitof writes (bank:addr -- the puzzle flags), req family
    (cross-entity calls), mes/ask (dialog), xyzi/move/axyzi (train
    positions).

Offsets/lengths/branch math verbatim from ff7_line_trigger_catalog.py
(cebix/ff7tools table). Output is a readable disassembly, not a
classifier -- the reading happens in the session, findings go to
research doc / PARKED per the usual flow.
"""
import sys, os, struct, datetime

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"graveyard_train_dump_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

TARGET_IDS = {144, 145}

# -- opcode operand-length table (cebix/ff7tools, verbatim) ---------------------
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

# mnemonics for readability (cebix names; only ones we print specially
# need decoding, the rest still get a name where known)
NAMES = {
    0x00: 'ret', 0x01: 'req', 0x02: 'reqsw', 0x03: 'reqew', 0x04: 'preq',
    0x05: 'prqsw', 0x06: 'prqew', 0x07: 'retto', 0x0F: 'spcal',
    0x10: 'skip', 0x11: 'lskip', 0x12: 'back', 0x13: 'lback',
    0x14: 'if', 0x15: 'lif', 0x16: 'if2', 0x17: 'lif2',
    0x18: 'if2u', 0x19: 'lif2u', 0x20: 'mgame', 0x21: 'tutor',
    0x24: 'wait', 0x25: 'nfade', 0x28: 'kawai', 0x30: 'key',
    0x31: 'keyon', 0x32: 'keyof', 0x33: 'uc', 0x36: 'wspcl',
    0x37: 'wnumb', 0x40: 'mes', 0x41: 'mpara', 0x42: 'mpra2',
    0x43: 'mpnam', 0x48: 'ask', 0x50: 'wsize', 0x52: 'wmode',
    0x58: 'stitm', 0x59: 'dlitm', 0x5A: 'ckitm',
    0x60: 'MJUMP', 0x64: 'scr2d', 0x66: 'scr2dc', 0x68: 'scr2dl',
    0x6D: 'IDLCK', 0x70: 'batle', 0x71: 'btlon', 0x75: 'pxyzi',
    0x7E: 'tlkon', 0x80: 'set', 0x81: 'set2', 0x82: 'biton',
    0x83: 'bitof', 0x86: 'plus2', 0x95: 'inc', 0x97: 'dec',
    0xA0: 'pc', 0xA1: 'char', 0xA2: 'dfanm', 0xA3: 'anime',
    0xA4: 'VISI', 0xA5: 'xyzi', 0xA8: 'move', 0xAA: 'mova',
    0xAB: 'tura', 0xAC: 'animw', 0xAD: 'fmove', 0xAE: 'anime2',
    0xB2: 'msped', 0xB3: 'dir', 0xB5: 'turn', 0xB6: 'dira',
    0xC0: 'jump', 0xC1: 'axyzi', 0xC2: 'LADER', 0xC5: 'talkR',
    0xC6: 'slidR', 0xC7: 'SOLID', 0xD0: 'LINE', 0xD1: 'LINON',
    0xD2: 'mpjpo', 0xD3: 'SLINE', 0xE0: 'bgon', 0xE1: 'bgoff',
    0xE2: 'bgrol', 0xF0: 'music', 0xF1: 'se', 0xF2: 'akao',
    0xFF: 'gmovr',
}

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

CMP = ['==', '!=', '>', '<', '>=', '<=', '&', '^', '|', '&(1<<)', '!&(1<<)']
def cmpname(c):
    return CMP[c] if c < len(CMP) else f'cmp{c}'

def bankpair(b):
    return (b >> 4) & 0xF, b & 0xF

def var(bank, val):
    """Render a script operand: bank 0 = immediate, else var[bank][addr]."""
    return str(val) if bank == 0 else f"V[{bank}][{val}]"

def decode(code, off, size):
    """Human string for the instruction at off (already sized)."""
    op = code[off]
    nm = NAMES.get(op, f'op_{op:02X}')
    o = code[off + 1: off + size]
    def u16(i): return o[i] | (o[i + 1] << 8)
    def s16(i):
        v = u16(i)
        return v - 0x10000 if v >= 0x8000 else v
    if op in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06):        # req family
        return f"{nm} ent={o[0]} pri={o[1] >> 5} script={o[1] & 0x1F}"
    if op == 0x10: return f"skip -> +{o[0] + 1}"
    if op == 0x11: return f"lskip -> +{u16(0) + 1}"
    if op == 0x12: return f"back -> -{o[0]}"
    if op == 0x13: return f"lback -> -{u16(0)}"
    if op in (0x14, 0x15):                                 # if / lif (8-bit)
        b1, b2 = bankpair(o[0])
        tgt = o[3 + 1] + 5 if op == 0x14 else (o[4] | (o[5] << 8)) + 5
        return (f"{nm} {var(b1, o[1])} {cmpname(o[3])} {var(b2, o[2])} "
                f"else-> off+{tgt}")
    if op in (0x16, 0x17, 0x18, 0x19):                     # if2 family (16-bit)
        b1, b2 = bankpair(o[0])
        v1, v2 = u16(1), u16(3)
        c = o[5]
        tgt = (o[6] + 7) if op in (0x16, 0x18) else (u16(6) + 7)
        return (f"{nm} {var(b1, v1)} {cmpname(c)} {var(b2, v2)} "
                f"else-> off+{tgt}")
    if op in (0x30, 0x31, 0x32):                           # key family
        return f"{nm} keys={u16(0):04X} else-> off+{o[2] + 3}"
    if op == 0x33: return f"uc {o[0]}  ; 0=unlock control, 1=lock"
    if op == 0x40: return f"mes win={o[0]} dialog={o[1]}"
    if op == 0x48:
        return (f"ask win={o[1]} dialog={o[2]} first={o[3]} last={o[4]} "
                f"-> V[{o[0] & 0xF}][{o[5]}]")
    if op == 0x60:
        return (f"MJUMP field={u16(0)} x={s16(2)} y={s16(4)} "
                f"tri={u16(6)} dir={o[8]}")
    if op == 0x6D:
        return f"IDLCK tri={u16(0)} lock={o[2]}"
    if op in (0x80, 0x81):                                 # set/set2
        b1, b2 = bankpair(o[0])
        v = o[2] if op == 0x80 else u16(2)
        return f"{nm} V[{b1}][{o[1]}] = {var(b2, v)}"
    if op in (0x82, 0x83, 0x84):                           # biton/bitof/bitxr
        b1, b2 = bankpair(o[0])
        return f"{nm} V[{b1}][{o[1]}] bit {var(b2, o[2])}"
    if op in (0x95, 0x96, 0x97, 0x98):                     # inc/dec
        b = (o[0] >> 4) & 0xF
        return f"{nm} V[{b}][{o[1]}]"
    if op == 0xA4: return f"VISI {o[0]}  ; 1=visible"
    if op == 0xC7: return f"SOLID {o[0]}  ; nonzero=intangible"
    if op == 0x7E: return f"tlkon {o[0]}  ; nonzero=talk off"
    if op == 0xA5:
        b12, b34 = o[0], o[1]
        return (f"xyzi x={s16(2)} y={s16(4)} z={s16(6)} tri={u16(8)}")
    if op == 0xC0:
        return f"jump x={s16(2)} y={s16(4)} tri={u16(6)} steps={u16(8)}"
    if op == 0xC1:
        return f"axyzi ent-var jump ({o!r})"
    if op == 0xC2:
        return (f"LADER x={s16(2)} y={s16(4)} z={s16(6)} tri={u16(8)} "
                f"kf={o[10]} anim={o[11]} dir={o[12]} spd={o[13]}")
    if op == 0xD0:
        x1, y1, z1, x2, y2, z2 = struct.unpack_from('<6h', bytes(o), 0)
        return f"LINE ({x1},{y1},{z1})-({x2},{y2},{z2})"
    if op == 0xD1: return f"LINON {o[0]}  ; 1=enable line, 0=disable"
    if op == 0xD2: return f"mpjpo {o[0]}  ; 1=disable gateways"
    if op == 0xA8: return f"move x={s16(1)} y={s16(3)}"
    if op == 0xAD: return f"fmove x={s16(1)} y={s16(3)}"
    if op == 0xB2: return f"msped speed={u16(1)}"
    if op == 0xB3: return f"dir d={o[1]}"
    if op == 0xE0: return f"bgon area={var(*bankpair(o[0])), o[1], o[2]}"
    if op == 0xE1: return f"bgoff ({o[0]},{o[1]},{o[2]})"
    if op == 0xF1: return f"se ({o.hex()})"
    hexs = o.hex() if len(o) else ''
    return f"{nm} {hexs}"

# -- flevel loading --------------------------------------------------------------
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

# maplist: field id -> name
mo = next((o for nm, o in toc if nm == 'maplist'), None)
mlen = struct.unpack_from('<I', data, mo + 20)[0]
mraw = data[mo + 24:mo + 24 + mlen]
start = next((s for s in (0, 2)
              if mraw[s + 122 * 32:s + 123 * 32].split(b'\0')[0] == b'nmkin_2'),
             None)
if start is None:
    print("ERROR: maplist anchor failed")
    sys.exit(1)
id_to_name = {}
fid = 0
for off in range(start, len(mraw) - 31, 32):
    nm = mraw[off:off + 32].split(b'\0')[0].decode('ascii', 'replace').lower()
    if nm:
        id_to_name[fid] = nm
    fid += 1
targets = {id_to_name[t]: t for t in TARGET_IDS if t in id_to_name}
print(f"targets: {targets}\n")

# LINE-entity script slot semantics, for the header comment per slot
SLOT_NOTE = {0: 'init', 1: '[OK]', 2: 'Move', 3: 'Move2',
             4: 'Go/cross', 5: 'Go1x', 6: 'GoAway'}

for fname, entry_off in toc:
    if fname not in targets:
        continue
    field_id = targets[fname]
    flen = struct.unpack_from('<I', data, entry_off + 20)[0]
    raw = data[entry_off + 24:entry_off + 24 + flen]
    dec = lzs_decompress(raw[4:], 4 * 1024 * 1024)
    sec_offs = struct.unpack_from('<9I', dec, 6)
    sc = sec_offs[0] + 4
    n_ent = dec[sc + 2]
    wstr = struct.unpack_from('<H', dec, sc + 4)[0]
    n_akao = struct.unpack_from('<H', dec, sc + 6)[0]
    tab = 0x20 + n_ent * 8 + n_akao * 4
    code = dec[sc:sc + wstr]

    def ename(e):
        return dec[sc + 0x20 + e * 8: sc + 0x20 + (e + 1) * 8] \
            .split(b'\0')[0].decode('ascii', 'replace')

    def slot_offs(e):
        return [struct.unpack_from('<H', dec, sc + tab + (e * 32 + s) * 2)[0]
                for s in range(32)]

    print("=" * 78)
    print(f"FIELD {field_id} '{fname}'  entities={n_ent}")
    print("=" * 78)

    # global sorted slot-offset list (range ends for linear disasm)
    all_offs = sorted({o for e in range(n_ent) for o in slot_offs(e)})

    for e in range(n_ent):
        offs = slot_offs(e)
        # dedupe: slots sharing an offset with a LOWER slot are empty aliases
        seen_off = {}
        print(f"\n--- entity {e} '{ename(e)}' ---")
        for s in range(32):
            o = offs[s]
            if o in seen_off:
                continue
            seen_off[o] = s
            # empty-slot convention: offset == next slot's offset handled by
            # dedupe; a slot that is just 'ret' prints one line, fine.
            end = next((x for x in all_offs if x > o), wstr)
            # skip slots beyond the script code block
            if o >= len(code):
                continue
            note = SLOT_NOTE.get(s, f's{s}')
            lines = []
            off = o
            truncated = False
            while off < min(end, len(code)):
                sz = instr_size(code, off)
                if sz is None:
                    lines.append(f"    {off:04X}: ?? op={code[off]:02X} (stop)")
                    truncated = True
                    break
                try:
                    txt = decode(code, off, sz)
                except Exception as ex:      # decoder cosmetics must never
                    op = code[off]           # kill the dump -- fall back to hex
                    txt = (f"{NAMES.get(op, f'op_{op:02X}')} "
                           f"{code[off + 1:off + sz].hex()} (dec-err {ex})")
                lines.append(f"    {off:04X}: {txt}")
                off += sz
            if len(lines) == 1 and 'ret' in lines[0]:
                continue                       # pure-ret slot: don't spam
            print(f"  slot {s} ({note}) @ {o:04X}:")
            for ln in lines:
                print(ln)
    print()

print("done.")
