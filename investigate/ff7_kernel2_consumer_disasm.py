#!/usr/bin/env python3
"""
ff7_kernel2_consumer_disasm.py -- Static disassembly of the kernel2 request
CONSUMER path in ff7_en.exe (on disk) to find where the looked-up text
pointer is actually stored (2026-07-11).

WHY:
  Live verification today (kernel2_result_verify_20260711_103423.log) proved:
    - the request struct 0xDC38E8 (pending/section/idx) updates at flash time
      (magic cast -> sect=2 idx=30), exactly as documented; but
    - the documented result pointer 0xDC208C stays 0x00000000 through every
      battle action, and a 20ms sweep of 0xDC2000-0xDC2200 / 0xDC3800-0xDC3A00
      (kernel2_result_hunt) found no other slot lighting up with text either.
  So the "result -> 0xDC208C" note in FFVII-Accessibility-Research.md section
  14 is wrong (or menu-only). The consumer must put sub_41963C's return value
  somewhere else: a different global, a stack local passed onward, or a
  register consumed immediately by the flash-text renderer.

WHAT:
  Disassemble, from the exe file on disk (immune to FFNx patches):
    1. sub_41963C itself -- the real kernel2 lookup. Every store to an
       absolute address (mov [imm32], ...) is printed, as is the value in
       EAX at each RET, so we can see whether IT writes a result global.
    2. The consumer/dispatcher region 0x6D7200-0x6D7500 (contains the real
       CALL to 0x41963C at 0x6D72C6, per kernel2_xref_scan 2026-07-05) --
       what happens to EAX immediately after that CALL is the answer:
         mov [imm32], eax      -> result global = imm32 (poll it!)
         mov [ebp-X], eax      -> stack local; must trace further calls
         push eax / mov reg    -> passed onward; print the following CALL
    3. The dispatcher sub_6D1CC0 head (0x6D1CC0-0x6D1F00) for the same
       pattern, since the research doc pairs it with the consumer.

  Linear disassembly desyncs on embedded data, so each region is disassembled
  as a straight stream but re-synced at CALL/RET boundaries; for our purpose
  (small, known-code regions) this is adequate -- flagged if capstone stalls.

Output: full annotated listing of each region with >>> markers on:
  - the CALL to 0x41963C
  - every store of EAX to an absolute address after that call
  - every absolute-address store in sub_41963C

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
    f"kernel2_consumer_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    default = r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe"
    if os.path.isfile(default):
        return default
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
md.detail = True

LOOKUP_FN = 0x0041963C   # sub_41963C, the real kernel2 lookup
KNOWN_CALL_SITE = 0x006D72C6

def disasm_region(start_va, end_va, title):
    """Disassemble [start_va, end_va) as a linear stream, printing every
    instruction. Marks CALLs to LOOKUP_FN and absolute-address stores.
    Returns list of (insn, marker) for post-analysis."""
    print("=" * 88)
    print(f"{title}   [0x{start_va:08X} - 0x{end_va:08X})")
    print("=" * 88)
    off = va_to_off(start_va)
    if off is None:
        print("  !! VA not mapped in any section")
        return []
    blob = data[off: off + (end_va - start_va)]
    results = []
    va = start_va
    pos = 0
    while pos < len(blob):
        insns = list(md.disasm(blob[pos:pos+16], va, count=1))
        if not insns:
            # Undecodable byte: print and skip one byte (keeps us moving past
            # embedded data; a run of these means we lost sync).
            print(f"  0x{va:08X}:  db 0x{blob[pos]:02X}")
            pos += 1
            va += 1
            continue
        insn = insns[0]
        marker = ''
        # CALL to the lookup function?
        if insn.mnemonic == 'call':
            try:
                tgt = int(insn.op_str, 16)
                if tgt == LOOKUP_FN:
                    marker = '>>> CALL kernel2 lookup sub_41963C'
            except ValueError:
                pass
        # Store to an absolute address (mov [imm32], reg / mov [imm32], imm)?
        if insn.mnemonic == 'mov' and insn.op_str.startswith('dword ptr ['):
            # capstone renders absolute stores as: dword ptr [0xdc38e8], eax
            inner = insn.op_str[len('dword ptr ['):]
            if inner[:2] == '0x':
                addr_str = inner.split(']')[0]
                try:
                    abs_addr = int(addr_str, 16)
                    src = insn.op_str.split(',', 1)[1].strip()
                    marker = f'>>> STORE to global 0x{abs_addr:08X}  (src={src})'
                except ValueError:
                    pass
        line = f"  0x{insn.address:08X}:  {insn.mnemonic:<8} {insn.op_str}"
        if marker:
            line = f"{line:<64} {marker}"
        print(line)
        results.append((insn.address, insn.mnemonic, insn.op_str, marker))
        pos += insn.size
        va += insn.size
        if insn.mnemonic == 'ret':
            # Stop at first RET only for the lookup-function listing; caller
            # regions continue (multiple functions in the window).
            if title.startswith('sub_41963C'):
                break
    print()
    return results

# 1. The lookup function itself.
disasm_region(LOOKUP_FN, LOOKUP_FN + 0x200, "sub_41963C (real kernel2 lookup)")

# 2. The consumer region containing the known real CALL site 0x6D72C6.
consumer = disasm_region(0x006D7200, 0x006D7500,
                         "consumer region around CALL site 0x6D72C6")

# 3. The dispatcher head named alongside the consumer in the research doc.
disasm_region(0x006D1CC0, 0x006D1F00, "dispatcher sub_6D1CC0 head")

# -- focused post-analysis: what happens to EAX right after the known call? ------
print("=" * 88)
print("POST-ANALYSIS: instructions following CALL sub_41963C in consumer region")
print("=" * 88)
after = False
count = 0
for addr, mn, ops, marker in consumer:
    if addr == KNOWN_CALL_SITE or 'CALL kernel2 lookup' in marker:
        after = True
        print(f"  CALL at 0x{addr:08X}")
        continue
    if after:
        print(f"    +{count}: 0x{addr:08X}  {mn} {ops}   {marker}")
        count += 1
        if count >= 12 or mn == 'ret':
            after = False
            count = 0

print(f"\nLog saved to: {_log_path}")
_log_file.close()
