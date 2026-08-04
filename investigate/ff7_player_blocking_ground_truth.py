#!/usr/bin/env python3
"""
ff7_player_blocking_ground_truth.py -- ground-up re-derivation of WHAT
BLOCKS THE PLAYER on a field (2026-08-04).

Tester statement (authoritative domain input): "On screen characters
should never block any path unless there's a story reason." The mod has
assumed since v2.30.22 that solid characters hard-block movement like
walls -- built on a play-log inference (pin distances matching radius
sums), never on the engine's own decision code. This script re-derives
the whole movement-blocking pipeline from scratch, assuming NOTHING
from prior passes:

  1. The per-model movement function (0x636F18 region): full annotated
     disassembly. What tests run (walkmesh try-move 0x6367B7,
     model-vs-model 0x637724), and -- the crux -- what the DECISION
     logic does for the PLAYER vs NPCs when each test fails. A branch
     at 0x63732F consults 0xCC0DBA = FIELD_UC_LOCK (mod-confirmed,
     rest 0 in free play): the uc_lock==0 player path appears to
     COMMIT the move even when model-hits are flagged. Verify by full
     careful read, not the earlier skim.
  2. 0x6367B7 (the walkmesh try-move/commit): confirm it is PURE
     geometry -- triangle edges, neighbors, the IDLCK lock bitfield --
     with zero model/character involvement. This is the function whose
     verdict actually moves or stops the player.
  3. Consumers: who reads the model-hit side effects -- +0x5E
     (0xCC16CE "player bumping model") and the LINE-crossing result
     byte 0xCC0870 -- i.e. what bumps are FOR if not blocking.
  4. 0xCC0DBA writers: confirm only the UC opcode family writes it
     (scripted scenes), so the ignore-models branch is the normal-play
     path.
  5. The two so-far-unexplained +0x72 radius readers at 0x633FBC and
     0x63644E: what are they part of? (Rule out a second blocking
     path.)
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"player_blocking_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

import capstone
from capstone import x86

exe = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
print(f"Reading: {exe}")
data = open(exe, 'rb').read()

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((va, vs, ro, rs))
text_va, text_vs, text_ro, text_rs = secs[0]

def v2o(va):
    r = va - image_base
    for sva, svs, sro, srs in secs:
        if sva <= r < sva + max(svs, srs):
            return sro + (r - sva)
    return None
def o2v(off):
    for sva, svs, sro, srs in secs:
        if sro <= off < sro + srs:
            return image_base + sva + (off - sro)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

EVBASE = 0xCC1670
STATICS = {
    0xCC0DBA: "FIELD_UC_LOCK",
    0xCC0DBE: "MAPJUMP_DISABLED",
    0xCC162C: "PLAYER_MODEL_IDX",
    0xCC0DB0: "N_MODELS(word)",
    0xCC0870: "LINE_CROSS_RESULT",
    0xCC0E3A: "IDLCK_LOCK_BITFIELD",
    0xCFF448: "walkmesh?",
    0xCFF734: "walkmesh tri array?",
    0xCFF744: "walkmesh access pool",
    0xCFF748: "walkmesh access pool2",
    0xCC1F70: "LINE_ARRAY",
}
EVOFF = {0x0C: "pos.x", 0x10: "pos.y", 0x14: "pos.z", 0x36: "+0x36 facing?",
         0x38: "+0x38 facing", 0x5E: "+0x5E bump-flag",
         0x5F: "+0x5F SOLID-OFF", 0x62: "+0x62 visible",
         0x63: "+0x63 move-type", 0x6E: "+0x6E", 0x70: "+0x70",
         0x72: "+0x72 radius", 0x76: "+0x76 speed", 0x78: "+0x78 triangle",
         0x7C: "+0x7C target.x"}

def note_for(ins):
    notes = []
    for op in ins.operands:
        if op.type == x86.X86_OP_MEM:
            d = op.mem.disp & 0xFFFFFFFF
            if d in STATICS:
                notes.append(STATICS[d])
            elif EVBASE <= d < EVBASE + 0x88:
                off = d - EVBASE
                notes.append("event[i]." +
                             EVOFF.get(off, f"+0x{off:X}"))
            elif op.mem.base != 0 and 0 < op.mem.disp <= 0x88 and \
                    op.mem.disp in EVOFF:
                notes.append("(+disp) " + EVOFF[op.mem.disp])
        if op.type == x86.X86_OP_IMM:
            v = op.imm & 0xFFFFFFFF
            if v in STATICS:
                notes.append("imm " + STATICS[v])
    if ins.mnemonic == 'imul' and '0x88' in ins.op_str:
        notes.append("stride 0x88")
    return ("   ; " + ", ".join(notes)) if notes else ""

def dump(title, va, end_va):
    print(f"===== {title}: 0x{va:08X} .. 0x{end_va:08X} =====")
    addr = va
    while addr < end_va:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end_va - addr)], addr):
            progressed = True
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"
                  f"{note_for(ins)}")
            addr = ins.address + ins.size
        if not progressed:
            print(f"  0x{addr:X}: db 0x{data[o]:02X}")
            addr += 1
    print()

# 1. Find the movement function's true start: the steer branch jumps back
#    to 0x636F18; walk backward to the nearest function prologue.
start = 0x636F18
o = v2o(start)
back = start
for k in range(1, 0x120):
    if data[v2o(start - k)] == 0x55 and data[v2o(start - k + 1)] == 0x8B:
        back = start - k
        break
print(f"movement function prologue candidate: 0x{back:X}\n")
dump("PER-MODEL MOVEMENT FUNCTION (part 1)", back, 0x637460)
dump("PER-MODEL MOVEMENT FUNCTION (part 2: trigger tail + slide)",
     0x637460, 0x63772A)

# 2. The walkmesh try-move / commit
dump("WALKMESH TRY-MOVE 0x6367B7", 0x6367B7, 0x6367B7 + 0x260)

# 3a. readers of +0x5E static form 0xCC16CE
print("===== .text refs to 0xCC16CE (+0x5E bump flag) =====")
for target, name in ((0xCC16CE, "+0x5E bump"), (0xCC0870, "LINE result"),
                     (0xCC0DBA, "FIELD_UC_LOCK")):
    needle = struct.pack('<I', target)
    pos = -1
    sites = []
    while True:
        pos = data.find(needle, pos + 1, text_ro + text_rs)
        if pos < 0:
            break
        if pos >= text_ro:
            sites.append(o2v(pos))
    print(f"  0x{target:X} ({name}): {[hex(s) for s in sites]}")
print()

# 3b. context of each 0xCC0DBA site (who WRITES the uc lock?)
needle = struct.pack('<I', 0xCC0DBA)
pos = -1
while True:
    pos = data.find(needle, pos + 1, text_ro + text_rs)
    if pos < 0:
        break
    va = o2v(pos)
    # decode a window around the reference; find the instruction that
    # contains this immediate
    winlo = va - 8
    best = None
    for st in range(winlo, va + 1):
        oo = v2o(st)
        ins = next(iter(md.disasm(data[oo:oo + 12], st)), None)
        if ins and ins.address <= va < ins.address + ins.size:
            best = ins
            break
    if best is not None:
        kind = "WRITE" if best.op_str.startswith(("byte ptr", "word ptr",
                                                  "dword ptr")) else "read"
        print(f"  0xCC0DBA @ 0x{best.address:X} [{kind}]: "
              f"{best.mnemonic} {best.op_str}")
print()

# 5. the two unexplained +0x72 readers
dump("context of +0x72 reader 0x633FBC", 0x633F30, 0x634080)
dump("context of +0x72 reader 0x63644E", 0x6363F0, 0x6364C0)

print("Done.")
