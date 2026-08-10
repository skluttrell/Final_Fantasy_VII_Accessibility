#!/usr/bin/env python3
"""
ff7_reel_semantics_static.py -- second pass over the Tifa/Cait reel
minigame: SYMBOL SEMANTICS + init source + pattern-table contents,
2026-08-09.  Companion to ff7_reel_widget_static.py (same session).

WHAT THE FIRST PASS PROVED (log reel_widget_static_20260809_210819):
  - Reels run INSIDE BMENU state 27 (display_battle_menu jump table
    case -> 0x6E3135), state 26 = Cait (case -> 0x6E2170).
  - Live state: count u8 0xDC3BAC, spin pos s16[0xDC3C00+i*2]
    (+1/frame, /4 = symbol steps), stopped u8[0xDC3C18+i], current
    reel u8 0xDC3C24, input cooldown u8 0xDC3B70, pattern row per
    reel u8[0xDC3A58+i].
  - RESULT FORMULA (byte-proven, tifa_confirm_setup 0x6E3724):
      result[i] = u8[0x91EAD0 + row[i]*16 + ((2 - pos[i]/4) & 0xF)]
    written to 0x9A88B4[i] -- marker = visible slot 2 (center).
  - Cait: pattern base 0x91E9D8, marker slot 1, shift-based position
    ((pos >> (u8[0xDC3B6C]+1)) & 0xF), results -> 0x9A88B0[i].

WHAT THIS PASS ANSWERS:
  1. Symbol VALUE -> meaning (Yeah!/Hit!/Miss).  The sweep found the
     single damage-side reader of 0x9A88B4 at 0x5DD03D -- its
     comparisons give the encoding.  (Draw side: symbol 0 -> sprite
     col 0xE0, 1 -> 0xC0, 2 -> 0xA0.)
  2. Where the reel INIT gets count + pattern rows (writer cluster
     0x6E309C/0x6E30D9 -- disassembled from its fn start): is the
     row the technique index?  That fn's caller gates the whole
     feature's lifetime.
  3. The pattern tables THEMSELVES (.data, offline): hexdump
     0x91E9D8..0x91EBD0 -- symbol distribution per row makes the
     encoding legible (Miss should be the rare symbol on early rows).
  4. Reference: Cait's result consumer cluster (0x5DEDC1..0x5DF480)
     fn listings for the future Cait session.

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_reel_semantics_static.py
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"reel_semantics_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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

import capstone

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if exe_path is None:
    print("ERROR: ff7_en.exe not found")
    sys.exit(1)
data = open(exe_path, 'rb').read()
print(f"Loaded exe: {exe_path}")

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    name = data[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((name, va, vs, rs, ro))

def v2o(va):
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

KNOWN = {
    0xDC3BAC: "REEL_COUNT",
    0xDC3C00: "REEL_POS[i]",
    0xDC3C18: "REEL_STOPPED[i]",
    0xDC3C24: "REEL_CURRENT",
    0xDC3B70: "REEL_INPUT_COOLDOWN",
    0xDC3B6C: "REEL_SPEED_SHIFT (Cait)",
    0xDC3A58: "REEL_PATTERN_ROW[i]",
    0x91EAD0: "TIFA_PATTERN_TABLE",
    0x91E9D8: "CAIT_PATTERN_TABLE",
    0x9A88B4: "TIFA_REEL_RESULTS[i]",
    0x9A88B0: "CAIT_REEL_RESULTS[i]",
    0xDC3C7C: "BATTLE_ACTIVE_SLOT",
    0xDC3C80: "BATTLE_ACTIVE_SLOT2",
    0xDBA498: "BATTLE_CHAR_BLOCK",
    0x91EF9C: "BATTLE_MENU_STATE",
    0x41AB74: "battle_input_check",
    0x745160: "sfx_3arg",
    0x74580A: "cursor_sfx",
    0x99CE0C: "ATTACK_CONTEXT_PTR",
}
def annotate(insn):
    notes = []
    for op in insn.operands:
        vals = []
        if op.type == capstone.x86.X86_OP_IMM:
            vals.append(op.imm & 0xFFFFFFFF)
        elif op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
            vals.append(op.mem.disp & 0xFFFFFFFF)
        for v in vals:
            if v in KNOWN:
                notes.append(KNOWN[v])
            elif 0xDBA498 <= v < 0xDBA498 + 0x440:
                notes.append(f"CHAR_BLOCK+0x{v-0xDBA498:X}")
    return ("   ; " + ", ".join(notes)) if notes else ""

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def find_fn_start(va, back=0x400):
    off = v2o(va)
    for d in range(back):
        o = off - d
        if data[o] == 0x55 and data[o+1] == 0x8B and data[o+2] == 0xEC:
            return va - d
    return va

def disasm_listing(fva, window=0x1800, label=""):
    off = v2o(fva)
    if off is None:
        print(f"!! cannot map 0x{fva:X}")
        return
    max_target = fva
    print()
    print("=" * 76)
    print(f"===== 0x{fva:08X}  {label}")
    print("=" * 76)
    for insn in md.disasm(data[off:off+window], fva):
        if insn.id == 0:
            continue
        if insn.group(capstone.CS_GRP_JUMP):
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_IMM and \
                   fva < op.imm < fva + window:
                    max_target = max(max_target, op.imm)
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}"
              f"{annotate(insn)}")
        if insn.mnemonic == 'ret' and insn.address >= max_target:
            break
        if insn.mnemonic == 'int3':
            break

# 1. Tifa result consumer -- the symbol-semantics witness
f = find_fn_start(0x5DD03D)
disasm_listing(f, window=0x600,
               label=f"Tifa reel-result consumer (fn of 0x5DD03D reader)")

# 2. Tifa reel init -- where count and pattern rows come from
f = find_fn_start(0x6E309C)
disasm_listing(f, window=0x200,
               label=f"Tifa reel init (fn of 0xDC3BAC/0xDC3A58 writers)")

# 3. Pattern tables hexdump
print()
print("=" * 76)
print("===== pattern tables (.data): CAIT rows @0x91E9D8, TIFA rows @0x91EAD0")
print("=" * 76)
for base, name, rows in ((0x91E9D8, "CAIT", 16), (0x91EAD0, "TIFA", 16)):
    o = v2o(base)
    print(f"\n{name} @0x{base:X}:")
    for r in range(rows):
        row = data[o + r*16 : o + r*16 + 16]
        print(f"  row {r:2d}: " + " ".join(f"{b}" for b in row))

# 4. Cait result consumers (reference for the future Cait session)
for va in (0x5DEDC1, 0x5DF480, 0x49FC6D):
    f = find_fn_start(va)
    disasm_listing(f, window=0x400,
                   label=f"Cait reel-result consumer region (fn of 0x{va:X})")

print(f"\nLog saved to: {_log_path}")
