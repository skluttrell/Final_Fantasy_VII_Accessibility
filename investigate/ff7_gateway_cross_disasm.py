#!/usr/bin/env python3
"""
ff7_gateway_cross_disasm.py -- Decode the engine's gateway-crossing test and
the consumers of the MAPJUMP transition globals (2026-08-02, follow-up to
ff7_screen_construction_static.py).

WHY:
  The first pass established (all static, exe on disk):
    - MAPJUMP (0x60) writes its args into the modules-global block via
      [0xCBF9D8] (= 0xCC0D88): +0x02 dest field id, +0x04/+0x06 dest X/Y,
      +0x22 dest triangle, +0x24 dest DIRECTION, +0x26 phase counter,
      +0x01 (= GAME_MODE 0xCC0D89) held at 1 while the jump runs.
    - DIR/GETDIR proved field_event_data +0x38 (rotation_curr_value) is the
      authoritative facing byte.
    - 0xCFF454 (parsed triggers header) has exactly ONE writer (0x6211DA)
      and a reader doing stride-0x18 (=24, sizeof gateway record) math at
      0x63C135, immediately before field_loop (0x63C17F).
  What's left to see in the listings:
    Q-A: does the 0x63C135 function walk gateways[12] (hdr+0x38) against the
         player position and, on a hit, fill the SAME modules-global fields
         MAPJUMP fills -- and which gateway-record byte (+0x14..+0x17) lands
         in +0x24 (arrival facing)?
    Q-B: who READS 0xCC0DAC (pending direction) / 0xCC0D8A (pending field id)
         -- the arrival-placement code that should end in a write to
         field_event_data +0x38.

HOW:
  1. Precise xref sweep for the transition globals with a fixed classifier.
     The first script's classifier took the FIRST decode that spanned the
     raw hit; bytes like 0D/15 immediately before a disp32 decode as
     'or/adc eax, imm32' and shadow the real 'mov reg, [imm32]' -- so this
     version collects ALL candidate decodes and prefers the one whose
     MEMORY operand displacement equals the target (imm-only matches are
     reported as weak 'imm?' refs, usually misdecodes of the same site).
  2. Full annotated disasm of three regions the first pass flagged:
       0x63BF60..0x63C260  gateway-walk + field_loop head   (Q-A)
       0x623480..0x6236C0  early triggers-header readers (parse-time users)
       0x62E480..0x62EA20  mid-module readers (trigger/door boxes?)
     Every absolute global gets its known name inlined so the listing reads
     like commented source; [reg+disp] with small disp is flagged as a
     struct field so gateway-record (+0x00..+0x17) and modules (+0x00..
     +0x2C) accesses stand out.

Output teed to a timestamped log (standing investigation-script rule).
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed.")
    sys.exit(1)

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gateway_cross_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def find_exe_path():
    try:
        out = subprocess.check_output(
            ['wmic', 'process', 'where', "name='ff7_en.exe'", 'get', 'ExecutablePath'],
            text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            line = line.strip()
            if line.lower().endswith('.exe'):
                return line
    except Exception:
        pass
    for cand in (
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
        r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    ):
        if os.path.isfile(cand):
            return cand
    raise RuntimeError("Could not locate ff7_en.exe")

exe_path = find_exe_path()
print(f"Reading exe: {exe_path}")
data = open(exe_path, 'rb').read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size
sections = []
for i in range(num_sections):
    off = section_off + i * 40
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    chars = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((va, vs, rp, rs, chars))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp, srs, _ in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def off_to_va(off):
    for sva, svs, srp, srs, _ in sections:
        if srp <= off < srp + srs:
            return image_base + sva + (off - srp)
    return None

def is_code_va(va):
    rva = va - image_base
    for sva, svs, _, _, chars in sections:
        if sva <= rva < sva + svs:
            return bool(chars & 0x20000000)
    return False

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

# Known-global annotation table: every name the research doc has already
# pinned in this neighborhood, plus the transition fields derived by the
# first pass (modules base 0xCC0D88 + MAPJUMP's write offsets).
KNOWN = {
    0xCFF454: "TRIGGERS_HDR_PTR",
    0xCFF594: "FIELD_FILE_BUFFER",
    0xCFF748: "ACCESS_POOL_PTR",
    0xCBF9D8: "MODULES_PTR(->0xCC0D88)",
    0xCC0D88: "modules+0",
    0xCC0D89: "GAME_MODE(modules+1)",
    0xCC0D8A: "DEST_FIELD_ID(modules+2)",
    0xCC0D8C: "DEST_X(modules+4)",
    0xCC0D8E: "DEST_Y(modules+6)",
    0xCC0DAA: "DEST_TRIANGLE(modules+0x22)",
    0xCC0DAC: "DEST_DIRECTION(modules+0x24)",
    0xCC0DAE: "JUMP_PHASE(modules+0x26)",
    0xCC0964: "CURRENT_ENTITY",
    0xCC0CF8: "SCRIPT_PC[]",
    0xCBF5E8: "SCRIPT_PTR",
    0xCC0B60: "EVENT_DATA_PTR",
    0xCC162C: "PLAYER_MODEL_ID",
    0xCC15D0: "FIELD_ID",
    0xCBFB70: "ENTITY_MODEL_MAP",
    0xCC0E3A: "TRIANGLE_LOCK_BITS",
    0xCFF3D8: "CAMERA_ROT_MATRIX",
}

def annotate(insn):
    notes = []
    for i, op in enumerate(insn.operands):
        if op.type == capstone.x86.X86_OP_MEM:
            m = op.mem
            if m.base == 0 and m.index == 0 and m.disp in KNOWN:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                notes.append(f"{'W' if is_write else 'R'} {KNOWN[m.disp]}")
            elif m.base == 0 and m.index == 0 and m.disp > 0x400000:
                notes.append(f"GLOBAL 0x{m.disp:08X}")
            elif m.base != 0 and 0 < m.disp < 0x300:
                is_write = (i == 0 and insn.mnemonic.startswith(
                    ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                notes.append(f"{'W' if is_write else 'R'} +0x{m.disp:X}({op.size}B)")
        elif op.type == capstone.x86.X86_OP_IMM and op.imm in KNOWN:
            notes.append(f"imm={KNOWN[op.imm]}")
    return notes

def disasm_region(lo, hi, title):
    print("=" * 74)
    print(f"REGION {title}: 0x{lo:08X}..0x{hi:08X}")
    print("=" * 74)
    va = lo
    while va < hi:
        off = va_to_off(va)
        if off is None:
            print(f"  0x{va:08X}  (unmapped)")
            return
        decoded = False
        for insn in md.disasm(data[off:off + (hi - va)], va):
            decoded = True
            notes = annotate(insn)
            print(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
                  + (f"   ; {' | '.join(notes)}" if notes else ""))
            va = insn.address + insn.size
        if not decoded:
            print(f"  0x{va:08X}  db 0x{data[off]:02X}  (undecodable, +1)")
            va += 1
    print()

# -- Part 1: precise xrefs of the transition globals ------------------------------
print("#" * 74)
print("# Part 1: xrefs of the MAPJUMP transition globals (fixed classifier)")
print("#" * 74 + "\n")

def xref_sweep(target, name):
    pat = struct.pack('<I', target)
    print(f"--- {name} (0x{target:08X}) ---")
    p = data.find(pat)
    strong = []
    while p != -1:
        va = off_to_va(p)
        if va is not None and is_code_va(va):
            best = None          # prefer decode whose MEM disp == target
            weak = None
            for back in range(1, 12):
                start = p - back
                if start < 0:
                    continue
                insns = list(md.disasm(data[start:start + 16], off_to_va(start)))
                if not insns:
                    continue
                insn = insns[0]
                hit_va = off_to_va(p)
                if not (insn.address <= hit_va < insn.address + insn.size):
                    continue
                for i, op in enumerate(insn.operands):
                    if op.type == capstone.x86.X86_OP_MEM and op.mem.disp == target \
                       and op.mem.base == 0 and op.mem.index == 0:
                        is_write = (i == 0 and insn.mnemonic.startswith(
                            ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
                        best = (insn, 'WRITE' if is_write else 'read')
                        break
                    if op.type == capstone.x86.X86_OP_IMM and op.imm == target and weak is None:
                        weak = (insn, 'imm?')
                if best:
                    break
            chosen = best or weak
            if chosen:
                insn, cls = chosen
                if cls != 'imm?':
                    strong.append((insn.address, cls))
                    print(f"  {cls:<5} 0x{insn.address:08X}  {insn.mnemonic} {insn.op_str}")
        p = data.find(pat, p + 1)
    if not strong:
        print("  (no strong mem-operand xrefs -- engine uses [MODULES_PTR]+disp only)")
    print()
    return strong

for tgt, nm in [(0xCC0D8A, "DEST_FIELD_ID"), (0xCC0DAA, "DEST_TRIANGLE"),
                (0xCC0DAC, "DEST_DIRECTION"), (0xCC0DAE, "JUMP_PHASE")]:
    xref_sweep(tgt, nm)

# -- Part 2: the flagged regions --------------------------------------------------
print("#" * 74)
print("# Part 2: annotated regions")
print("#" * 74 + "\n")

disasm_region(0x63BF60, 0x63C260, "gateway walk + field_loop head (Q-A)")
disasm_region(0x623480, 0x6236C0, "early triggers-header readers")
disasm_region(0x62E480, 0x62EA20, "mid-module header readers (door boxes?)")

print("INTERPRETATION CHECKLIST:")
print(" - In region 1, find the loop over hdr+0x38 (stride 0x18): the compare")
print("   chain is the crossing test; the store path after a hit should write")
print("   DEST_FIELD_ID/DEST_X/DEST_Y/DEST_TRIANGLE/DEST_DIRECTION -- note")
print("   WHICH record offset (+0x14..+0x17) feeds DEST_DIRECTION.")
print(" - Any read of DEST_DIRECTION followed by a write to event_data +0x38")
print("   = the arrival placement code (facing applied on load).")
print(f"\nLog saved to: {_log_path}")
