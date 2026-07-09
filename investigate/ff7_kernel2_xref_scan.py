#!/usr/bin/env python3
"""
ff7_kernel2_xref_scan.py -- Static disassembly scan of ff7_en.exe (on disk,
not live memory) for every instruction that references the kernel2 request
struct fields (0x00DC38E8 pending / 0x00DC38EC section / 0x00DC38F0 idx),
confirmed by ff7_kernel2_scan.py as written by sub_6D71FA.

Goal: sub_6D71FA is a *queue* function -- it stores section/idx and sets
pending=1 but does not return a text pointer. Some other function must poll
pending, perform the actual kernel2 lookup, and produce a result (likely a
pointer stored back into the same struct region, or returned to a caller).
This script finds every code site that touches these addresses so we can
identify that consumer function.

Requires capstone (pip installed into investigate/venv).
"""
import sys, os, struct, ctypes, datetime, subprocess

try:
    import capstone
except ImportError:
    print("ERROR: capstone not installed. Run: venv/Scripts/python.exe -m pip install capstone")
    sys.exit(1)

# -- tee logging ---------------------------------------------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_xref_scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

# -- locate the exe on disk -----------------------------------------------------
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

# -- minimal PE parser -----------------------------------------------------------
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

print(f"Image base: 0x{image_base:08X}")
print("Sections:")
for name, va, vs, rp, rs in sections:
    print(f"  {name:<10} VA=0x{image_base+va:08X}  size=0x{vs:06X}  file_off=0x{rp:06X}")
print()

def va_to_off(va):
    rva = va - image_base
    for name, sva, svs, srp, srs in sections:
        if sva <= rva < sva + svs:
            return srp + (rva - sva)
    return None

def off_to_va(off):
    for name, sva, svs, srp, srs in sections:
        if srp <= off < srp + srs:
            return image_base + sva + (off - srp)
    return None

# -- targets to search for -------------------------------------------------------
TARGETS = {
    0x00DC38E8: "request_pending",
    0x00DC38EC: "section",
    0x00DC38F0: "idx",
    0x00DC38F4: "+0x0C (unknown, past idx)",
    0x00DC38F8: "+0x10 (unknown)",
    0x00DC38FC: "+0x14 (unknown)",
}

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

print("=" * 88)
print("Scanning executable sections for references to kernel2 request struct fields")
print("(raw byte pattern search, then local disassembly to confirm alignment --")
print(" linear whole-section disassembly desyncs on embedded data in a binary")
print(" this large, so it is not used as the primary detection method)")
print("=" * 88)

# Raw byte pattern search: find every 4-byte little-endian occurrence of each
# target VA anywhere in an executable section, then try to align a real
# instruction on top of it by disassembling small windows starting a few
# bytes earlier (0..7). This finds both direct-address forms (mov [imm32])
# and the byte still works even if capstone's whole-section stream desynced.
hits = []
seen = set()
for name, sva, svs, srp, srs in sections:
    if svs == 0:
        continue
    blob = data[srp:srp+srs]
    for target_va, label in TARGETS.items():
        pattern = struct.pack('<I', target_va)
        start = 0
        while True:
            pos = blob.find(pattern, start)
            if pos < 0:
                break
            start = pos + 1
            match_off = srp + pos
            match_va = off_to_va(match_off)
            if match_va is None:
                continue
            # Try aligning an instruction so the 4-byte immediate sits right
            # at this position: back up 0..7 bytes and disassemble forward.
            for back in range(0, 8):
                probe_off = match_off - back
                if probe_off < srp:
                    break
                probe_va = off_to_va(probe_off)
                window = data[probe_off:probe_off+16]
                insns = list(md.disasm(window, probe_va))
                if not insns:
                    continue
                insn = insns[0]
                # Does this single decoded instruction span exactly up to
                # (and past) the 4-byte immediate we matched?
                if insn.address <= match_va < insn.address + insn.size and \
                   match_va + 4 <= insn.address + insn.size:
                    key = (insn.address, target_va)
                    if key in seen:
                        continue
                    seen.add(key)
                    hits.append((insn.address, insn.mnemonic, insn.op_str, label, name))
                    break

print(f"\nFound {len(hits)} candidate instruction(s):\n")
hits.sort()
for addr, mnem, ops, label, secname in hits:
    print(f"  [{secname}] 0x{addr:08X}  {mnem} {ops}    <- {label}")

if hits:
    print("\n" + "=" * 88)
    print("Context disassembly around each hit (20 instructions before/after)")
    print("=" * 88)
    for addr, mnem, ops, label, secname in hits:
        off = va_to_off(addr)
        if off is None:
            continue
        # Disassemble a window of raw bytes around the hit and locate the hit
        # instruction inside the stream by re-disassembling from a safe
        # earlier aligned point (start of containing section is safest,
        # but that's slow; instead back up 64 bytes and hope alignment holds).
        window_start_off = max(off - 64, 0)
        window = data[window_start_off:off+96]
        window_va = off_to_va(window_start_off)
        print(f"\n  --- around 0x{addr:08X} ({label}) ---")
        insns = list(md.disasm(window, window_va))
        for insn in insns:
            marker = "  >>>" if insn.address == addr else "     "
            print(f"{marker} 0x{insn.address:08X}  {insn.mnemonic} {insn.op_str}")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
