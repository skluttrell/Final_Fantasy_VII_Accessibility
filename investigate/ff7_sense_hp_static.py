#!/usr/bin/env python3
"""
ff7_sense_hp_static.py -- Statically pin down the battle actor-vars array
base (FFNx battle_ai_context) so the Sense HP readout reads the right
fields (2026-07-13).

WHY:
  The v2.10 target-name disasm (target_name_disasm_20260713_094151.log)
  showed get_kernel_text section 7 appends, for actors with display-flag
  bit 0x40 set at u8[0x9A8B39 + slot*0x44] (the "Sensed" flag -- the game
  only shows enemy HP in the target window after Sense), a formatted pair:

      word1 = u16[0x9A8B4C + slot*0x44]     ; display struct (cached cur HP?)
      word2 = u16[0x9AB10C + slot*0x68]     ; actor-vars struct field

  FFNx's battle_actor_vars (ff7.h) is exactly 0x68 bytes with
  currentMP/maxMP at +0x28/+0x2A and currentHP/maxHP at +0x2C/+0x30.
  Whether word2 is currentHP or maxHP depends on where actor_vars[0]
  starts:
      base 0x9AB0DC -> 0x9AB10C = +0x30 = maxHP   (and 0x9AB0E0 = stateFlags)
      base 0x9AB0E0 -> 0x9AB10C = +0x2C = currentHP (and 0x9AB0E0 = statusMask)
  The mod wants to read BOTH fields directly (i32 cur + i32 max), so the
  base must be certain.

WHAT:
  FFNx resolves the context as:
      battle_context = get_absolute_value(battle_sub_41CCB2, 0x5F)
  i.e. the u32 immediate at file VA 0x41CCB2+0x5F (FFNx function names embed
  their addresses). actor_vars[0] = battle_context + 0x3C (9 header bytes +
  pad + 23 u16 masks + u32 partyGil, all confirmed against the ff7.h struct).
  This script:
    1. disassembles 0x41CCB2..+0x90 so we can SEE the instruction whose
       immediate sits at +0x5F (guards against reading a misaligned operand);
    2. prints battle_context, actor_vars base, and the absolute addresses of
       statusMask/stateFlags/currentMP/maxMP/currentHP/maxHP for slot 0;
    3. maps the two section-7 disasm reads (0x9AB0E0 status-append gate and
       0x9AB10C HP word) onto those fields;
    4. disassembles the string helper 0x419491 (battle kernel-string source)
       for the record.

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
    f"sense_hp_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
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
    raise RuntimeError("Could not locate ff7_en.exe -- pass path manually")

exe_path = find_exe_path()
print(f"Reading exe: {exe_path}")
with open(exe_path, 'rb') as f:
    data = f.read()
print(f"  {len(data):,} bytes\n")

# -- minimal PE parser -------------------------------------------------------------
e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
assert data[e_lfanew:e_lfanew+4] == b'PE\0\0', "not a valid PE file"
coff_off = e_lfanew + 4
num_sections = struct.unpack_from('<HH', data, coff_off)[1]
opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
opt_off = coff_off + 20
image_base = struct.unpack_from('<I', data, opt_off + 28)[0]
section_off = opt_off + opt_hdr_size

sections = []
for i in range(num_sections):
    off = section_off + i * 40
    virt_size, virt_addr, raw_size, raw_ptr = struct.unpack_from('<IIII', data, off + 8)
    sections.append((virt_addr, virt_size, raw_ptr))

def va_to_off(va):
    rva = va - image_base
    for sva, svs, srp in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def disasm_region(start_va, end_va, title, highlight_va=None):
    print("=" * 88)
    print(f"{title}   [0x{start_va:08X} - 0x{end_va:08X})")
    print("=" * 88)
    off = va_to_off(start_va)
    if off is None:
        print("  !! VA not mapped")
        return
    blob = data[off: off + (end_va - start_va)]
    va, pos = start_va, 0
    while pos < len(blob):
        insns = list(md.disasm(blob[pos:pos+16], va, count=1))
        if not insns:
            print(f"  0x{va:08X}:  db 0x{blob[pos]:02X}")
            pos += 1; va += 1
            continue
        insn = insns[0]
        mark = ''
        if highlight_va is not None and insn.address <= highlight_va < insn.address + insn.size:
            mark = f'   <<< contains byte +0x{highlight_va - start_va:X} (the FFNx operand offset)'
        print(f"  0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}{mark}")
        pos += insn.size; va += insn.size
        if insn.mnemonic == 'ret':
            break
    print()

# 1. Show the instruction context around battle_sub_41CCB2 + 0x5F.
SUB = 0x0041CCB2
OPERAND_VA = SUB + 0x5F
disasm_region(SUB, SUB + 0x90, "battle_sub_41CCB2 head", highlight_va=OPERAND_VA)

# 2. Read the immediate exactly as FFNx get_absolute_value does.
battle_context = struct.unpack_from('<I', data, va_to_off(OPERAND_VA))[0]
print(f"battle_context (u32 at 0x41CCB2+0x5F) = 0x{battle_context:08X}")

# battle_ai_context header: 10 bytes (9 fields + pad), 23 u16 masks, u32 partyGil.
actor_vars = battle_context + 0x3C
print(f"actor_vars[0] = battle_context + 0x3C = 0x{actor_vars:08X}\n")

fields = [
    ("statusMask (u32)", 0x00), ("stateFlags (u32)", 0x04),
    ("formationID (u16)", 0x24),
    ("currentMP (u16)", 0x28), ("maxMP (u16)", 0x2A),
    ("currentHP (i32)", 0x2C), ("maxHP (i32)", 0x30),
]
print("slot-0 field addresses (stride 0x68 per slot):")
for name, offs in fields:
    print(f"  {name:<18} 0x{actor_vars + offs:08X}")
print()

print("section-7 disasm reads mapped onto the struct:")
for read_va, what in ((0x9AB0E0, "status-append gate (u32, bit 0x40)"),
                      (0x9AB10C, "HP word appended after Sense (u16)")):
    delta = read_va - actor_vars
    name = next((n for n, o in fields if o == delta), f"+0x{delta:X} (?)")
    print(f"  0x{read_va:08X} = actor_vars + 0x{delta:02X} -> {name}   [{what}]")
print()

# 3. The battle kernel-string helper used for the labels (for the record).
disasm_region(0x00419491, 0x00419491 + 0x50, "string helper sub_419491")

print(f"Log saved to: {_log_path}")
_log_file.close()
