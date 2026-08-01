#!/usr/bin/env python3
"""
ff7_timer_window_static.py -- find the "countdown clock is ON SCREEN" flag
(2026-08-01; tester report: a save loaded MID-COUNTDOWN keeps ticking but
the mod reports "no active timer").

THE PROBLEM the mod cannot currently solve: without a live STTIM call
this process run, a ticking savemap value is ambiguous between
  (a) a STALE leftover -- the 2026-07-20 report: an escape ENDED with
      time on the clock and the value kept ticking invisibly across the
      save (vanilla hides it because the clock WINDOW closed), and
  (b) a REAL timer from a save made during a countdown (this report;
      newly reachable, and 7H/Echo-S shortens the reactor timer to 5
      minutes so testers meet it sooner).
v2.30.8 chose to suppress, which is wrong for (b).

THE DISCRIMINATOR should be the CLOCK WINDOW: vanilla draws it only
while a countdown is really running, which is exactly why the stale
case was invisible to players. If the engine keeps a "clock window
shown" flag, reading it separates (a) from (b) with no guessing.

METHOD (all static, exe on disk -- file VAs are runtime VAs):
  1. locate execute_opcode_table via the documented IDLCK anchor
     (table[0x6D] == 0x61E29F), then disassemble the WSPCL handler
     (opcode 0x36) -- WSPCL is what creates the special clock window;
     report every static address it WRITES (candidate flags / window id).
  2. scan .text for every instruction referencing COUNTDOWN_TIMER_SECONDS
     (0xDC08BC) and COUNTDOWN_TIMER_MS (0xDC08C0): the RENDERER and the
     TICKER are in there, and whatever branch guards them is the
     "active" condition we want.
  3. for each such site, print a window of context so the guarding
     flag/compare is readable.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"timer_window_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

exe_path = next(c for c in (
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
) if os.path.isfile(c))
print(f"Reading: {exe_path}")
data = open(exe_path, 'rb').read()

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

# ---- 1. WSPCL handler ------------------------------------------------------------
IDLCK = 0x0061E29F
needle = struct.pack('<I', IDLCK)
pos, t_off = -1, None
while True:
    pos = data.find(needle, pos + 1)
    if pos < 0:
        break
    cand = pos - 0x6D * 4
    if cand >= 0 and all(
            image_base <= struct.unpack_from('<I', data, cand + k * 4)[0]
            < image_base + 0x00A00000 for k in range(256)):
        t_off = cand
        break
h_wspcl = struct.unpack_from('<I', data, t_off + 0x36 * 4)[0]
h_sttim = struct.unpack_from('<I', data, t_off + 0x38 * 4)[0]
print(f"opcode table @ 0x{o2v(t_off):X}")
print(f"  [0x36] WSPCL = 0x{h_wspcl:08X}")
print(f"  [0x38] STTIM = 0x{h_sttim:08X}  (mod already hooks this)\n")

def dump(fva, length, title, mark_addrs=()):
    print(f"===== {title} @ 0x{fva:X} =====")
    off = v2o(fva)
    writes = []
    addr, end = fva, fva + length
    while addr < end:
        o = v2o(addr)
        progressed = False
        for ins in md.disasm(data[o:o + (end - addr)], addr):
            progressed = True
            note = ""
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    d = op.mem.disp & 0xFFFFFFFF
                    if 0x900000 <= d < 0xDE0000:
                        if op.access & capstone.CS_AC_WRITE:
                            writes.append((ins.address, d,
                                           f"{ins.mnemonic} {ins.op_str}"))
                            note += "   ; WRITE static"
                        if d in mark_addrs:
                            note += "   ; <<< TIMER FIELD"
            print(f"  0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{note}")
            addr = ins.address + ins.size
            if ins.mnemonic.startswith('ret'):
                addr = end
                break
        if not progressed:
            addr += 1
    print()
    return writes

TSEC, TMS = 0x00DC08BC, 0x00DC08C0
w = dump(h_wspcl, 0x200, "WSPCL handler (opcode 0x36)", {TSEC, TMS})
print("WSPCL static writes (window-state candidates):")
for a, d, t in w:
    print(f"  0x{a:X}: [0x{d:08X}] {t}")

# ---- 2/3. every reference to the timer fields ------------------------------------
for label, target in (("COUNTDOWN_TIMER_SECONDS", TSEC),
                      ("COUNTDOWN_TIMER_MS", TMS)):
    print(f"\n===== references to {label} (0x{target:08X}) =====")
    needle = struct.pack('<I', target)
    pos = text_ro - 1
    end = text_ro + text_rs
    sites = []
    while True:
        pos = data.find(needle, pos + 1, end)
        if pos < 0:
            break
        # decode the instruction that contains this operand
        for back in range(2, 12):
            start = pos - back
            ins = next(iter(md.disasm(data[start:start + 16], o2v(start))), None)
            if ins and start + ins.size >= pos + 4:
                acc = []
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_MEM and \
                       (op.mem.disp & 0xFFFFFFFF) == target:
                        if op.access & capstone.CS_AC_WRITE: acc.append('W')
                        if op.access & capstone.CS_AC_READ:  acc.append('R')
                sites.append((ins.address, f"{ins.mnemonic} {ins.op_str}",
                              '/'.join(acc) or '?'))
                break
    for va, txt, acc in sites:
        print(f"  0x{va:X} [{acc}]: {txt}")

    print(f"\n  --- context around each {label} site ---")
    for va, txt, acc in sites:
        print(f"\n  ### 0x{va:X} ({acc}) ###")
        start_va = va - 0x50
        o = v2o(start_va)
        if o is None:
            continue
        a = start_va
        while a <= va + 0x30:
            oo = v2o(a)
            got = False
            for ins in md.disasm(data[oo:oo + (va + 0x30 - a + 16)], a):
                got = True
                mark = "  <<<" if ins.address == va else ""
                print(f"    0x{ins.address:X}: {ins.mnemonic} {ins.op_str}{mark}")
                a = ins.address + ins.size
                if a > va + 0x30:
                    break
            if not got:
                a += 1
print("\nDone.")
