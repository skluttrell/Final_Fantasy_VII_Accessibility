#!/usr/bin/env python3
"""
ff7_menu_mask_static.py -- why does the Materia row NOT say ", not
available" before the 7th Heaven hideout scene, while PHS does?
(user report 2026-08-04)

BACKGROUND (research doc / v2.32): the mod appends ", not available" to
a main-menu row when its bit is set in MENU_DISABLED_ROWS 0xDC1130
(u16, bit N = row N refuses activation; found via the bit test at
0x6CA4CD inside main-menu sub 0x6CA346).  The user now reports that the
MATERIA row (cursor index 2) does NOT get the suffix in the early game
even though the game refuses/grays it until the 7th Heaven hideout
materia tutorial -- while other story-locked rows apparently DO.

HYPOTHESIS TO TEST: FF7's savemap carries TWO menu masks (community
docs: a "menu visibility" mask and a "menu locking" mask).  If
0xDC1130 mirrors only ONE of them and the early-game Materia lock
lives in the OTHER, the mod reads the wrong (or an incomplete) signal.
The gray the sighted player sees may be driven by either mask -- or by
something else entirely (e.g. an inventory check).  Static analysis
answers this without guessing:

  1. Sweep .text for EVERY instruction referencing 0xDC1130 (and the
     adjacent words 0xDC112C/0xDC1132/0xDC1134 in case the menu module
     keeps paired copies).  Classify read vs write.
  2. Disassemble the writer's surrounding code to see WHERE the value
     comes from (expected: a savemap address in 0xDBFD38..0xDC0E2C --
     the instruction names it directly, no layout guessing needed).
  3. Disassemble the main-menu handler region 0x6CA346..0x6CA750
     (covers the known bit test 0x6CA4CD) and annotate every mask /
     savemap reference -- shows exactly which mask gates ACTIVATION.
  4. Sweep .text for the discovered savemap mask addresses to find all
     other consumers (the row DRAW code that grays, the field-opcode
     handler that writes them) -- if the gray reads a different mask
     than the activation refusal, that is the bug mechanism.
  5. Ground truth from real saves: both installs have early-game saves
     (Mako Reactor 1, BEFORE the hideout scene => Materia locked,
     PHS locked).  Dump the discovered mask words + story progress from
     every occupied slot.  Whichever mask has bit 2 (Materia) set in
     those saves is the one the mod must speak from.

Row order (player-corrected v2.31.1): 0=Item 1=Magic 2=Materia 3=Equip
4=Status 5=Order 6=Limit 7=Config 8=PHS 9=Save 10=Quit.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"menu_mask_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

SAVEMAP_BASE = 0xDBFD38          # GIL 0xDC08B4 = savemap+0xB7C (research §4)
SAVEMAP_END  = SAVEMAP_BASE + 0x10F4
KNOWN = {
    0xDC1130: "MENU_DISABLED_ROWS",
    0xDC1154: "MENU_CURSOR",
    0xDC12DC: "MENU_OPEN",
    0xDC1324: "MENU_FOCUS_MODE",
    0xDC118C: "CHARSEL_CURSOR",
    0xDC1288: "CHARSEL_CHOSEN",
    0xDC08DC: "STORY_PROGRESS(+0xBA4)",
    0xDC08B4: "SAVEMAP_GIL(+0xB7C)",
}
def note_for(va):
    if va in KNOWN:
        return KNOWN[va]
    if SAVEMAP_BASE <= va < SAVEMAP_END:
        return f"SAVEMAP+0x{va - SAVEMAP_BASE:X}"
    return None

def imm_refs(target):
    """Every .text instruction whose encoding contains the packed imm32
    `target` AND that capstone confirms actually uses it as a memory
    displacement or immediate (byte-scan alone false-positives on
    overlapping encodings)."""
    needle = struct.pack('<I', target)
    hits = []
    pos = text_ro - 1
    end = text_ro + text_rs
    while True:
        pos = data.find(needle, pos + 1, end)
        if pos < 0:
            break
        # Disassemble a window starting a bit before the hit so the
        # instruction containing the imm decodes with its real start.
        for back in range(1, 12):
            start_off = pos - back
            if start_off < text_ro:
                continue
            va = o2v(start_off)
            ins = next(md.disasm(data[start_off:start_off + 16], va), None)
            if ins is None:
                continue
            if start_off + ins.size <= pos + 3:
                continue  # imm not inside this instruction
            if f"0x{target:x}" in ins.op_str:
                hits.append((ins.address, ins.mnemonic, ins.op_str,
                             ins.bytes.hex()))
                break
    # dedupe (several `back` values can land the same instruction)
    seen, out = set(), []
    for h in hits:
        if h[0] not in seen:
            seen.add(h[0])
            out.append(h)
    return out

def classify(mnemonic, op_str, target):
    t = f"0x{target:x}"
    dst = op_str.split(',')[0]
    if mnemonic.startswith(('mov', 'and', 'or', 'xor', 'add', 'sub',
                            'inc', 'dec')) and t in dst and '[' in dst:
        return "WRITE" if ',' in op_str or mnemonic in ('inc', 'dec') \
            else "?"
    if mnemonic in ('cmp', 'test', 'bt'):
        return "read(test)"
    return "read"

# ---------------------------------------------------------------------------
print("===== 1. all .text refs to 0xDC112C / 0xDC1130 / 0xDC1132 / 0xDC1134 =====")
mask_writers = []
for target in (0xDC112C, 0xDC1130, 0xDC1132, 0xDC1134):
    refs = imm_refs(target)
    print(f"\n-- 0x{target:X} ({note_for(target) or 'unnamed'}): "
          f"{len(refs)} refs")
    for va, mn, ops, raw in refs:
        kind = classify(mn, ops, target)
        print(f"  0x{va:08X}  {mn} {ops}   [{kind}]  ({raw})")
        if kind == "WRITE":
            mask_writers.append((target, va))

# ---------------------------------------------------------------------------
print("\n===== 2. context around each WRITE (where does the value come from?) =====")
ctx_savemap_addrs = set()
for target, wva in mask_writers:
    print(f"\n-- writer of 0x{target:X} at 0x{wva:08X}, context -0x60..+0x30:")
    start = wva - 0x60
    o = v2o(start)
    # find a clean decode start: walk forward until a decode lands exactly
    # on the writer instruction
    for adj in range(0x30):
        good = False
        for ins in md.disasm(data[o + adj:o + adj + 0xA0], start + adj):
            if ins.address == wva:
                good = True
            if ins.address > wva:
                break
        if good:
            for ins in md.disasm(data[o + adj:o + adj + 0xA0], start + adj):
                ann = ""
                for tok in ins.op_str.replace('[', ' ').replace(']', ' ')\
                        .replace(',', ' ').split():
                    if tok.startswith('0x'):
                        try:
                            n = note_for(int(tok, 16))
                        except ValueError:
                            n = None
                        if n:
                            ann = f"   ; {n}"
                            a = int(tok, 16)
                            if SAVEMAP_BASE <= a < SAVEMAP_END:
                                ctx_savemap_addrs.add(a)
                mark = "  <<<" if ins.address == wva else ""
                print(f"  0x{ins.address:08X}  {ins.mnemonic} {ins.op_str}"
                      f"{ann}{mark}")
                if ins.address > wva + 0x18:
                    break
            break

# ---------------------------------------------------------------------------
print("\n===== 3. main-menu handler 0x6CA346..0x6CA750 (bit test at 0x6CA4CD) =====")
addr, end = 0x6CA346, 0x6CA750
o = v2o(addr)
for ins in md.disasm(data[o:o + (end - addr)], addr):
    ann = ""
    for tok in ins.op_str.replace('[', ' ').replace(']', ' ')\
            .replace(',', ' ').split():
        if tok.startswith('0x'):
            try:
                n = note_for(int(tok, 16))
            except ValueError:
                n = None
            if n:
                ann = f"   ; {n}"
                a = int(tok, 16)
                if SAVEMAP_BASE <= a < SAVEMAP_END:
                    ctx_savemap_addrs.add(a)
    mark = "  <<< known bit test" if ins.address == 0x6CA4CD else ""
    if ann or mark or ins.mnemonic in ('bt', 'call'):
        print(f"  0x{ins.address:08X}  {ins.mnemonic} {ins.op_str}{ann}{mark}")

# ---------------------------------------------------------------------------
print("\n===== 4. consumers of savemap addresses discovered above =====")
for a in sorted(ctx_savemap_addrs):
    refs = imm_refs(a)
    print(f"\n-- SAVEMAP+0x{a - SAVEMAP_BASE:X} (0x{a:X}): {len(refs)} refs")
    for va, mn, ops, raw in refs:
        kind = classify(mn, ops, a)
        print(f"  0x{va:08X}  {mn} {ops}   [{kind}]")

# ---------------------------------------------------------------------------
print("\n===== 5. ground truth from real saves (early game = Materia locked) =====")
SAVE_FILES = [
    r"C:\Users\sklut\OneDrive\Documents\Square Enix\FINAL FANTASY VII Steam\user_37780394\save00.ff7",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\save\save00.ff7",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\save\save05.ff7",
]
SLOT = 4340   # savemap image, 1:1 with runtime 0xDBFD38..0xDC0E2C
HDR = 9
ROWS = ["Item", "Magic", "Materia", "Equip", "Status", "Order", "Limit",
        "Config", "PHS", "Save"]

def ff7text(bs):
    out = []
    for b in bs:
        if b == 0xFF:
            break
        c = b + 0x20
        out.append(chr(c) if 0x20 <= c < 0x7F else '?')
    return ''.join(out)

def mask_bits(w):
    on = [ROWS[i] for i in range(10) if (w >> i) & 1]
    return f"0x{w:04X} [{', '.join(on) if on else 'none'}]"

dump_offsets = sorted({a - SAVEMAP_BASE for a in ctx_savemap_addrs})
for path in SAVE_FILES:
    if not os.path.isfile(path):
        print(f"\n(missing) {path}")
        continue
    raw = open(path, 'rb').read()
    print(f"\n{path}  ({len(raw)} bytes)")
    n_slots = (len(raw) - HDR) // SLOT
    for s in range(n_slots):
        blk = raw[HDR + s * SLOT: HDR + (s + 1) * SLOT]
        if len(blk) < SLOT or not any(blk):
            continue
        name = ff7text(blk[8:24])
        level = blk[4]
        story = struct.unpack_from('<H', blk, 0xBA4)[0]
        print(f"  slot {s:2}: name='{name}' lv={level} "
              f"story_progress={story}")
        for off in dump_offsets:
            w = struct.unpack_from('<H', blk, off)[0]
            print(f"      savemap+0x{off:X} = {mask_bits(w)}")

print("\nDone.")
