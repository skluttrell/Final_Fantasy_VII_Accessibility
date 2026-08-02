#!/usr/bin/env python3
"""
ff7_screen_construction_static.py -- Answer the open "how is a field screen
constructed" questions statically from ff7_en.exe on disk (2026-08-02).

WHY (the user's navigation-system question set, before any mod changes):
  The assembled model of field construction (research doc §4/§5/§14) leaves
  three load-bearing gaps this script closes without touching the live game:

  Q1. FACING: which field_event_data byte is the model's facing direction?
      FFNx's struct names a cluster (+0x36 rotation_value, +0x38
      rotation_curr_value, turn-step fields between) but the mod has never
      confirmed which byte the DIR opcode (0xB3) actually writes. DIR is the
      script-side "face this way NOW" primitive, and GETDIR (0xB7) is the
      read-back -- whatever offset BOTH touch is the authoritative facing.
      DIRA (0xB6) turns toward a party member -- same struct, corroboration.

  Q2. TRANSITIONS: what does MAPJUMP (0x60) actually DO? Its handler must
      stash field id / x / y / triangle / direction somewhere the main field
      loop consumes next frame. Those globals are the engine's transition-
      request interface -- the exact place a future navigation feature can
      watch to know "a transition to field N was just requested" (and the
      place gateway-crossing code must ALSO write, see Q3).

  Q3. CONSTRUCTION + GATEWAY CROSSING: who WRITES the two globals every
      field feature already reads -- FIELD_FILE_BUFFER 0xCFF594 (raw file)
      and FIELD_TRIGGERS_HEADER_PTR 0xCFF454 (parsed triggers) -- and who
      READS 0xCFF454? The writers pin the construction routine (candidate
      hook points, and evidence for the single-buffer claim); the readers
      include the engine's gateway-crossing test, which should reveal which
      of the gateway record's 4 unknown bytes (+0x14..+0x17) it consumes --
      the presumed arrival-facing byte.

HOW (all from the exe on disk -- zero live process interaction):
  1. Resolve execute_opcode_table exactly like ff7_line_triggers_static.py
     (grc(0x60BACF,0x80) -> gav(^,0x10D); FFNx's own MESSAGE+0x3B==E8 check).
  2. Disassemble DIR/DIRA/GETDIR/MAPJUMP handlers. New vs the line-trigger
     script: struct-relative operand tracking ([reg+disp] with small disp) so
     per-model field offsets surface, plus one-level callee expansion because
     MAPJUMP-style handlers often delegate to a helper.
  3. Raw-byte scan of the whole file for the little-endian constants
     0xCFF594 / 0xCFF454 / 0xCFF748, then DISASM-CONFIRM each code hit
     (lesson from v2.30.38: raw E8/immediate scans false-positive inside
     operands -- every hit must decode to an instruction whose operand IS the
     constant). Classified read/write/address-of, with context windows
     printed for trigger-header readers so the gateway-crossing code's
     record-offset usage is visible in the log.

Output: annotated listings + summaries, teed to a timestamped log
(standing rule: investigation scripts never require manual copy-paste).

Requires capstone (already in investigate/venv).
"""
import sys, os, struct, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

# -- tee logging (required for all investigation scripts) -----------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"screen_construction_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# -- locate the exe on disk ------------------------------------------------------
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
with open(exe_path, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

# -- minimal PE parse ------------------------------------------------------------
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size
sections = []          # (name, va, vsize, rawptr, rawsize, characteristics)
for i in range(num_sections):
    off = section_off + i * 40
    name = data[off:off+8].split(b'\0')[0].decode('ascii', 'replace')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, off + 8)
    chars = struct.unpack_from('<I', data, off + 36)[0]
    sections.append((name, va, vs, rp, rs, chars))

def va_to_off(va):
    rva = va - image_base
    for _, sva, svs, srp, srs, _ in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def off_to_va(off):
    for _, sva, svs, srp, srs, _ in sections:
        if srp <= off < srp + srs:
            return image_base + sva + (off - srp)
    return None

def section_of_va(va):
    rva = va - image_base
    for name, sva, svs, _, _, chars in sections:
        if sva <= rva < sva + svs:
            return name, bool(chars & 0x20000000)   # IMAGE_SCN_MEM_EXECUTE
    return None, False

def grc(addr, offset):
    off = va_to_off(addr + offset)
    if off is None or data[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', data, off + 1)[0]
    return addr + offset + 5 + rel

def gav(addr, offset):
    off = va_to_off(addr + offset)
    return struct.unpack_from('<I', data, off)[0] if off is not None else None

CODE_LO, CODE_HI = 0x401000, 0x9FFFFF

# -- Step 1: resolve the opcode table --------------------------------------------
FIELD_INIT_EVENT = 0x60BACF
execute_opcode = grc(FIELD_INIT_EVENT, 0x80)
print(f"execute_opcode       = grc(0x{FIELD_INIT_EVENT:X}, 0x80)  = "
      f"{'0x%08X' % execute_opcode if execute_opcode else 'FAIL'}")
if not execute_opcode or not (CODE_LO <= execute_opcode <= CODE_HI):
    print("CHAIN INVALID -- execute_opcode out of range, aborting.")
    sys.exit(1)

table_va = gav(execute_opcode, 0x10D)
print(f"execute_opcode_table = gav(^, 0x10D)            = 0x{table_va:08X}")
table_off = va_to_off(table_va)
if table_off is None:
    print("CHAIN INVALID -- table VA not in any section, aborting.")
    sys.exit(1)
entries = struct.unpack_from('<256I', data, table_off)

msg = entries[0x40]
msg_ok = CODE_LO <= msg <= CODE_HI
call_ok = msg_ok and data[va_to_off(msg + 0x3B)] == 0xE8
print(f"\nCross-checks:")
print(f"  table[0x40] MESSAGE = 0x{msg:08X}  in exe code range   {'OK' if msg_ok else '** FAIL **'}")
print(f"  MESSAGE+0x3B byte = 0x{data[va_to_off(msg + 0x3B)]:02X}  expect E8         {'OK' if call_ok else '** FAIL **'}")
if not (msg_ok and call_ok):
    print("CROSS-CHECKS FAILED -- aborting.")
    sys.exit(1)
print("ALL CROSS-CHECKS PASSED.\n")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def disasm_handler(va, max_bytes=0x600, label=""):
    """Linear disasm from va with forward-jump extension past early RETs.
    Tracks:
      abs_writes/abs_reads  {global_addr: [va,...]}  -- [imm32] operands
      struct_writes/reads   {disp: [(va, opsize)]}   -- [reg(+reg*s)+disp],
                            0 < disp < 0x100: per-model struct fields (the
                            facing offset must appear here for DIR/GETDIR)
      calls                 [target_va,...]          -- E8 callees
    """
    off = va_to_off(va)
    code = data[off:off + max_bytes]
    lines = []
    abs_writes, abs_reads = {}, {}
    struct_writes, struct_reads = {}, {}
    calls = []
    max_fwd = va
    end_va = va + max_bytes
    for insn in md.disasm(code, va):
        markers = []
        if insn.group(capstone.CS_GRP_JUMP) and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            tgt = insn.operands[0].imm
            if va < tgt < end_va:
                max_fwd = max(max_fwd, tgt)
        if insn.mnemonic == 'call' and insn.operands and \
           insn.operands[0].type == capstone.x86.X86_OP_IMM:
            calls.append(insn.operands[0].imm)
        for i, op in enumerate(insn.operands):
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            m = op.mem
            is_write = (i == 0 and insn.mnemonic.startswith(
                ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
            if m.base == 0 and m.index == 0 and m.disp > 0x400000:
                d = abs_writes if is_write else abs_reads
                d.setdefault(m.disp, []).append(insn.address)
                markers.append(f"{'W' if is_write else 'R'} GLOBAL[0x{m.disp:08X}]")
            elif m.base != 0 and 0 < m.disp < 0x100:
                d = struct_writes if is_write else struct_reads
                d.setdefault(m.disp, []).append((insn.address, op.size))
                markers.append(f"{'W' if is_write else 'R'} FIELD +0x{m.disp:02X} ({op.size}B)")
            elif m.base == 0 and m.index != 0 and m.disp > 0x400000:
                markers.append(f"ARRAY[0x{m.disp:08X} + reg*{m.scale}]")
        lines.append(f"  0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}"
                     + (f"   ; {' | '.join(markers)}" if markers else ""))
        if insn.mnemonic.startswith('ret') and insn.address >= max_fwd:
            break
    return dict(lines=lines, abs_writes=abs_writes, abs_reads=abs_reads,
                struct_writes=struct_writes, struct_reads=struct_reads,
                calls=calls, label=label, va=va)

def print_handler(h):
    print(f"{'='*74}")
    print(f"{h['label']} = 0x{h['va']:08X}")
    print(f"{'='*74}")
    for ln in h['lines']:
        print(ln)
    print(f"\n  -- {h['label']} summary --")
    for a in sorted(h['abs_writes']):
        print(f"  WRITES GLOBAL 0x{a:08X}  at {', '.join('0x%X' % x for x in h['abs_writes'][a])}")
    for dsp in sorted(h['struct_writes']):
        sites = h['struct_writes'][dsp]
        szs = ','.join(str(s) for _, s in sites)
        print(f"  WRITES FIELD +0x{dsp:02X} ({szs}B) at {', '.join('0x%X' % v for v, _ in sites)}")
    for dsp in sorted(h['struct_reads']):
        sites = h['struct_reads'][dsp]
        print(f"  reads  FIELD +0x{dsp:02X}      at {', '.join('0x%X' % v for v, _ in sites)}")
    if h['abs_reads']:
        print(f"  reads globals: {', '.join('0x%08X' % a for a in sorted(h['abs_reads']))}")
    if h['calls']:
        print(f"  calls: {', '.join('0x%08X' % c for c in h['calls'])}")
    print()

# -- Step 2: Q1 + Q2 -- the four opcode handlers ---------------------------------
print("#" * 74)
print("# Q1/Q2: DIR / DIRA / GETDIR (facing offset) + MAPJUMP (transition ifc)")
print("#" * 74 + "\n")

TARGETS = [
    (0xB3, "DIR",     "set model facing NOW (args: bank byte + direction byte)"),
    (0xB6, "DIRA",    "turn toward party member (corroboration)"),
    (0xB7, "GETDIR",  "read facing back into script var (the read side)"),
    (0x60, "MAPJUMP", "scripted field transition (field,x,y,tri,dir)"),
]
seen_callees = set()
for opc, name, desc in TARGETS:
    va = entries[opc]
    if not (CODE_LO <= va <= CODE_HI):
        print(f"table[0x{opc:02X}] {name}: address 0x{va:08X} out of range -- skipped\n")
        continue
    h = disasm_handler(va, label=f"table[0x{opc:02X}] {name}  ({desc})")
    print_handler(h)
    # One-level callee expansion: MAPJUMP-style handlers often just parse args
    # and delegate; the interesting global stores live in the helper.
    for c in h['calls'][:4]:
        if c in seen_callees or not (CODE_LO <= c <= CODE_HI):
            continue
        seen_callees.add(c)
        ch = disasm_handler(c, label=f"  callee 0x{c:08X} (from {name})")
        print_handler(ch)

# -- Step 3: Q3 -- xref sweep for the construction globals ------------------------
print("#" * 74)
print("# Q3: who writes/reads FIELD_FILE_BUFFER / TRIGGERS_HEADER / ACCESS pool")
print("#" * 74 + "\n")

XREF_TARGETS = [
    (0xCFF594, "FIELD_FILE_BUFFER",        "raw field file pointer"),
    (0xCFF454, "FIELD_TRIGGERS_HEADER_PTR","parsed section-7 triggers header"),
    (0xCFF748, "ACCESS_POOL_PTR",          "engine's parsed walkmesh adjacency"),
]

def disasm_confirm(hit_off):
    """A raw 4-byte constant hit is only an xref if an instruction decodes
    across it with that constant as a memory disp or immediate. x86 is
    variable-length, so try several start points before the hit; restart
    past undecodable bytes (the capstone silent-truncation lesson)."""
    hit_va = off_to_va(hit_off)
    if hit_va is None:
        return None
    for back in range(1, 12):          # opcode+modrm+sib prefixes: disp starts 1-11 bytes in
        start = hit_off - back
        if start < 0:
            continue
        code = data[start:start + 16]
        insns = list(md.disasm(code, off_to_va(start)))
        if not insns:
            continue
        insn = insns[0]
        if not (insn.address <= hit_va < insn.address + insn.size):
            continue
        return insn
    return None

def classify(insn, target):
    """read / write / addr-of for the target constant inside insn."""
    for i, op in enumerate(insn.operands):
        if op.type == capstone.x86.X86_OP_MEM and op.mem.disp == target \
           and op.mem.base == 0:
            is_write = (i == 0 and insn.mnemonic.startswith(
                ('mov', 'and', 'or', 'xor', 'add', 'sub', 'inc', 'dec')))
            return 'WRITE' if is_write else 'read'
        if op.type == capstone.x86.X86_OP_IMM and op.imm == target:
            return 'addr-of'
    return None

def disasm_window(center_va, before=0x30, after=0x90, hdr_reg_note=False):
    """Context listing around an xref, restarting past undecodable bytes.
    Marks [reg+disp] accesses with disp in the gateway/trigger array range
    (0x38..0x2D8 from the header base) -- the gateway-crossing signature."""
    start = center_va - before
    end = center_va + after
    out = []
    va = start
    while va < end:
        off = va_to_off(va)
        if off is None:
            break
        chunk = data[off:off + (end - va)]
        decoded = False
        for insn in md.disasm(chunk, va):
            decoded = True
            mark = " <== XREF" if insn.address <= center_va < insn.address + insn.size else ""
            gw = []
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base != 0 \
                   and 0x38 <= op.mem.disp < 0x2D8:
                    gw.append(f"hdr+0x{op.mem.disp:X}?")
            note = (f"   ; {' '.join(gw)}" if gw else "")
            out.append(f"    0x{insn.address:08X}  {insn.mnemonic:<8} {insn.op_str}{note}{mark}")
            va = insn.address + insn.size
        if not decoded:
            out.append(f"    0x{va:08X}  ?? undecodable, restarting +1")
            va += 1
    return out

for target, name, desc in XREF_TARGETS:
    pat = struct.pack('<I', target)
    hits = []
    p = data.find(pat)
    while p != -1:
        hits.append(p)
        p = data.find(pat, p + 1)
    print(f"{'='*74}")
    print(f"{name} (0x{target:08X})  -- {desc}: {len(hits)} raw hits")
    print(f"{'='*74}")
    confirmed = []
    for hoff in hits:
        va = off_to_va(hoff)
        if va is None:
            continue
        sec, is_code = section_of_va(va)
        if not is_code:
            print(f"  data hit in {sec} at VA 0x{va:08X} (initialized data / table)")
            continue
        insn = disasm_confirm(hoff)
        if insn is None:
            print(f"  code-section hit at 0x{va:08X}: no clean decode -- unconfirmed")
            continue
        cls = classify(insn, target)
        if cls is None:
            print(f"  code-section hit at 0x{va:08X}: decodes but constant is not "
                  f"an operand ({insn.mnemonic} {insn.op_str}) -- false positive")
            continue
        confirmed.append((insn.address, cls, insn))
        print(f"  {cls:<7} 0x{insn.address:08X}  {insn.mnemonic} {insn.op_str}")
    writes = [c for c in confirmed if c[1] == 'WRITE']
    print(f"\n  {name}: {len(confirmed)} confirmed xrefs, {len(writes)} writes")
    # Context windows: all writers (construction routine), and for the
    # triggers header also every reader (hunting the gateway-crossing test).
    want_windows = writes if target != 0xCFF454 else confirmed
    for va, cls, insn in want_windows:
        print(f"\n  -- context around {cls} at 0x{va:08X} --")
        for ln in disasm_window(va):
            print(ln)
    print()

print(f"{'='*74}")
print("INTERPRETATION CHECKLIST (fill from the listings above):")
print(" 1. DIR+GETDIR shared FIELD offset = the authoritative facing byte")
print("    (expect +0x36 rotation_value and/or +0x38 rotation_curr_value).")
print(" 2. MAPJUMP's absolute-global writes = the transition-request interface;")
print("    note which callee writes them and keep the list for the gateway cmp.")
print(" 3. 0xCFF594/0xCFF454 WRITE sites = the construction routine(s); a")
print("    single writer footprint supports the one-screen-in-memory claim.")
print(" 4. 0xCFF454 reader windows with hdr+0x38..0x2D8 marks = gateway/door")
print("    trigger consumers; look for a +0x14-in-record byte read feeding the")
print("    same globals MAPJUMP writes (arrival facing).")
print(f"\nLog saved to: {_log_path}")
