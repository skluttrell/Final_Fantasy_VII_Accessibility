#!/usr/bin/env python3
"""
ff7_target_name_disasm.py -- Static disassembly of get_kernel_text's TARGET
NAME branch in ff7_en.exe (on disk), to complete the enemy-name derivation
for battle target announcements (2026-07-13).

WHY:
  kernel2_consumer_disasm_20260711_104639.log (dump range ended at 0x41983C)
  already revealed the ENEMY half of the game's own target-name lookup, at
  0x4197D3 (the "idx < 6" branch of one of get_kernel_text's battle sections):

      edx = idx * 0x10
      eax = movsx( u16[0x9A8794 + edx] )      ; formation slot -> record index
      eax = eax * 0xB8 + 0x9A8E9C             ; 0xB8 = scene.bin enemy record
      copy(dest=0x9A80F0, src=eax, len=0x20)  ; record starts with 32-byte name

  So: 0x9A8794 = per-enemy-slot table (stride 0x10, u16 record index, movsx =>
  signed, -1 plausible for empty), 0x9A8E9C = the 3 loaded scene.bin enemy
  records (stride 0xB8, FF7-encoded name in bytes 0-0x1F).

  But the dump cut off mid-branch at 0x41983C, right after
      ecx = (idx + 4) * 0x44
  -- indexing some per-ACTOR-SLOT table with stride 0x44 (idx+4 = actor slot
  4-9). That is almost certainly the "MP A"/"MP B" duplicate-name suffix
  logic the targeting UI shows, and we want to replicate the game's labeling
  exactly. The party branch ("idx >= 6" -> 0x4199A8) was also beyond the dump
  and should show where party target names come from.

WHAT:
  Disassemble 0x41983C..0x419A80 (rest of the function incl. the jump table
  region), plus re-print 0x4197D3..0x41983C for contiguous context. Same
  linear-stream approach as ff7_kernel2_consumer_disasm.py (re-syncs after
  undecodable bytes; adequate for a known-code region), with the same
  absolute-address store/load markers so new globals stand out.

Output: annotated listing; every absolute [imm32] memory operand is marked so
the suffix table / party-name source addresses can be read straight off.

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
    f"target_name_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    # 2026 rerelease install first (the one this session targets), 2013 second.
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
pe_off = e_lfanew
assert data[pe_off:pe_off+4] == b'PE\0\0', "not a valid PE file"
coff_off = pe_off + 4
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

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def disasm_region(start_va, end_va, title):
    print("=" * 88)
    print(f"{title}   [0x{start_va:08X} - 0x{end_va:08X})")
    print("=" * 88)
    off = va_to_off(start_va)
    if off is None:
        print("  !! VA not mapped in any section")
        return
    blob = data[off: off + (end_va - start_va)]
    va = start_va
    pos = 0
    while pos < len(blob):
        insns = list(md.disasm(blob[pos:pos+16], va, count=1))
        if not insns:
            print(f"  0x{va:08X}:  db 0x{blob[pos]:02X}")
            pos += 1
            va += 1
            continue
        insn = insns[0]
        # Mark any absolute [imm32] operand so new globals stand out.
        marker = ''
        if '[0x' in insn.op_str and '+' not in insn.op_str.split('[', 1)[1].split(']')[0]:
            addr_str = insn.op_str.split('[0x', 1)[1].split(']')[0]
            try:
                marker = f'>>> global 0x{int(addr_str, 16):08X}'
            except ValueError:
                pass
        line = f"  0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}"
        if marker:
            line = f"{line:<64} {marker}"
        print(line)
        pos += insn.size
        va += insn.size

# The enemy-name branch (context re-print) and everything the 07-11 dump
# missed: the 0x44-stride table access, the party branch at 0x4199A8, the
# section jump table at 0x419A38, and the copy helper at 0x419A48.
disasm_region(0x004197D3, 0x00419A38, "get_kernel_text battle target-name branches")

# The 4-entry section jump table (data, not code): print raw dwords.
print("=" * 88)
print("section jump table at 0x419A38 (sections 6..9)")
print("=" * 88)
off = va_to_off(0x00419A38)
for i in range(4):
    tgt = struct.unpack_from('<I', data, off + i * 4)[0]
    print(f"  section {6 + i}: handler 0x{tgt:08X}")
print()

# The copy helper the enemy branch calls with (dest, src, 0x20).
disasm_region(0x00419A48, 0x00419B00, "copy helper sub_419A48")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
