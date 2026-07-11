#!/usr/bin/env python3
"""
ff7_kernel2_dispatch_map.py -- Static extraction of the battle action-name
dispatch mapping from ff7_en.exe on disk (2026-07-11).

CONTEXT (see kernel2_consumer_disasm_20260711_104639.log):
  The battle flash-message dispatcher sub_6D1CC0 routes each commandID
  (0x00-0x20) through:
      branch_idx = byte[0x6D70A8 + commandID]        (byte remap table)
      jmp dword[0x6D7080 + branch_idx*4]             (jump table)
  Each branch target calls get_kernel_text(SECTION, action_idx, 8) with a
  hardcoded SECTION, except one branch (0x6D1EAF) that calls sub_6D70F1
  (enemy-attack name copy into static buffer 0xDC3640).

  Known branch target -> section mapping (from the disasm):
      0x6D1DCD -> section 0    (widget type 4)
      0x6D1DF4 -> section 6    (widget type 8)
      0x6D1E1B -> section 4    (widget type 8)
      0x6D1E41 -> section 3    (widget type 9)
      0x6D1E68 -> section 2    (widget type 9)
      0x6D1E8C -> section 9    (widget type 9)
      0x6D1EAF -> ENEMY ATTACK (sub_6D70F1 -> buffer 0xDC3640)
      0x6D1ECA -> section 4    (no widget set)
      0x6D1EE5 -> section 0, idx forced 0 (default for cmd > 0x20)

THIS SCRIPT:
  1. Reads both tables from the exe and prints commandID -> branch -> section
     for every command 0x00-0x20. This becomes the hardcoded cmd->section
     table in the v2.7 DLL implementation.
  2. Disassembles kernel2_get_text (0x419457, found as the relative call at
     get_kernel_text+0xF7) to locate the global pointer table for the
     decompressed kernel2 text sections, so a live Python experiment can
     replicate the full name lookup without calling game code.
  3. Also disassembles sub_6D70F1 (enemy-attack name copier) to find the
     source table it copies from (expected: the 0x9A9484 stride-0x20 table
     already live-verified for Machine Gun/Tonfa/Bite/Tentacle).

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
    f"kernel2_dispatch_map_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
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
    default = r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe"
    if os.path.isfile(default):
        return default
    raise RuntimeError("Could not locate ff7_en.exe -- pass path manually")

exe_path = find_exe_path()
print(f"Reading exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0'
coff_off = e_lfanew + 4
machine, num_sections = struct.unpack_from('<HH', data, coff_off)
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size
sections = []
for i in range(num_sections):
    off = section_off + i * 40
    name = data[off:off+8].rstrip(b'\0').decode('ascii', 'replace')
    virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, off + 8)
    sections.append((name, virt_addr, virt_size, raw_ptr, raw_size))

def va_to_off(va):
    rva = va - image_base
    for name, sva, svs, srp, srs in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def read_va(va, size):
    off = va_to_off(va)
    return data[off:off+size] if off is not None else None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# -- 1. dispatch tables ----------------------------------------------------------
BYTE_TABLE  = 0x006D70A8   # branch_idx = byte[BYTE_TABLE + commandID]
JUMP_TABLE  = 0x006D7080   # target = dword[JUMP_TABLE + branch_idx*4]

BRANCH_SECTION = {
    0x6D1DCD: ('kernel-text section 0', 0),
    0x6D1DF4: ('kernel-text section 6', 6),
    0x6D1E1B: ('kernel-text section 4 (item namespace)', 4),
    0x6D1E41: ('kernel-text section 3', 3),
    0x6D1E68: ('kernel-text section 2', 2),
    0x6D1E8C: ('kernel-text section 9', 9),
    0x6D1EAF: ('ENEMY ATTACK via sub_6D70F1 -> 0xDC3640', None),
    0x6D1ECA: ('kernel-text section 4 (item namespace)', 4),
    0x6D1EE5: ('kernel-text section 0, idx=0 (default)', 0),
}

# Known command menu IDs from battle testing (2026-07-05) for annotation.
CMD_NAMES = {
    0x01: 'Attack', 0x02: 'Magic', 0x03: 'Summon?', 0x04: 'Item',
    0x05: 'Steal?', 0x06: 'Steal', 0x07: 'Sense?', 0x0D: 'E.Skill?',
    0x14: 'Limit Break', 0x17: 'Change?', 0x1B: 'Chocobuckle?',
    0x20: 'enemy attack',
}

byte_tbl = read_va(BYTE_TABLE, 0x21)
n_branches = max(byte_tbl) + 1
jump_tbl_raw = read_va(JUMP_TABLE, 4 * n_branches)
jump_tbl = [struct.unpack_from('<I', jump_tbl_raw, i*4)[0] for i in range(n_branches)]

print("=" * 80)
print("Jump table @ 0x6D7080:")
for i, tgt in enumerate(jump_tbl):
    desc, _ = BRANCH_SECTION.get(tgt, (f'UNKNOWN target', None))
    print(f"  [{i}] -> 0x{tgt:08X}  {desc}")

print()
print("=" * 80)
print("commandID -> branch -> section  (the v2.7 lookup table)")
print("=" * 80)
for cmd in range(0x21):
    bidx = byte_tbl[cmd]
    tgt = jump_tbl[bidx] if bidx < len(jump_tbl) else None
    desc, sect = BRANCH_SECTION.get(tgt, ('UNKNOWN', None)) if tgt else ('OUT OF RANGE', None)
    name = CMD_NAMES.get(cmd, '')
    print(f"  cmd 0x{cmd:02X} {name:<14} branch[{bidx}] -> 0x{tgt:08X}  {desc}")

# -- 2. kernel2_get_text (0x419457): find the section pointer table --------------
def disasm_stream(start_va, size, title, stop_at_ret=True):
    print()
    print("=" * 80)
    print(f"{title}   [0x{start_va:08X} ...]")
    print("=" * 80)
    blob = read_va(start_va, size)
    va, pos = start_va, 0
    while pos < len(blob):
        insns = list(md.disasm(blob[pos:pos+16], va, count=1))
        if not insns:
            print(f"  0x{va:08X}:  db 0x{blob[pos]:02X}")
            pos += 1; va += 1
            continue
        insn = insns[0]
        note = ''
        # flag absolute memory operands (globals) for table hunting
        if '[0x' in insn.op_str or ' 0x9' in insn.op_str or ' 0x7' in insn.op_str:
            note = '   <== global ref'
        print(f"  0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}{note}")
        pos += insn.size; va += insn.size
        if insn.mnemonic == 'ret' and stop_at_ret:
            break

disasm_stream(0x00419457, 0x1E5, "kernel2_get_text (sub_419457)")

# -- 3. sub_6D70F1: enemy-attack name copier --------------------------------------
disasm_stream(0x006D70F1, 0x100, "sub_6D70F1 (enemy-attack name -> 0xDC3640)")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
