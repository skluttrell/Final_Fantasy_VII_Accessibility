#!/usr/bin/env python3
"""
ff7_kernel2_scan.py — Find the kernel2 section 8 data for ability name lookup.

Background:
  sub_6D71FA ("get_kernel_text") turns out to be a QUEUE function, not a
  return function.  It sets:
    [0x00DC38E8] = 1   (request pending flag)
    [0x00DC38EC] = section
    [0x00DC38F0] = idx
  and returns void.  No text pointer is returned.

  However display_battle_action_text_42782A also references 0x009ADF0C twice
  and calls 0x006892E5 — those are the actual kernel2 data accesses.

  This script investigates:
  PHASE 1 — Read the memory around 0x009ADF0C (the kernel2 data pointer
             region).  0x009ADF0C is in FF7's BSS; the 4-byte DWORD at that
             address may BE the kernel2 base pointer (pointer-to-pointer), or
             it may be the data itself.

  PHASE 2 — Hex-dump sub_6892E5 (the function called by display_battle_action_text
             just before RET) from the exe file, to understand how it retrieves
             text.

  PHASE 3 — If kernel2 data can be located, dump section 8 entries (ability
             names) as raw bytes, then convert each from FF7 encoding to ASCII
             using the standard FF7 character table.

  PHASE 4 — Verify by checking actionIdx values observed in battle (from the
             Phase 2 live monitor: party Attack→idx=2, enemy→idx=1 or 2) against
             the decoded section 8 strings.

  Result:
    A confirmed address for the kernel2 section 8 base (or a pointer to it),
    plus a mapping of idx→name so we can implement the lookup in the DLL.

HOW TO RUN:
  Start FF7 and get into normal gameplay (field map or battle menu is fine).
  Then run this script.  FF7 must be running so we can read live memory.
"""

import ctypes
import os
import struct
import subprocess
import sys
import time

PROCESS_NAME = "ff7_en.exe"
IMAGE_BASE   = 0x00400000

# Address referenced twice by display_battle_action_text_42782A.
# In the Phase 1 scan it appeared as a data reference in two different
# instructions near the end of the function, suggesting it is important.
KERNEL2_CANDIDATE_PTR = 0x009ADF0C

# The function called by display_battle_action_text just before RET.
# Probably does the actual kernel2 string rendering.
SUB_6892E5 = 0x006892E5

# The kernel2 request structure laid out by sub_6D71FA (queue function):
#   [0x00DC38E8] DWORD  request_pending flag (1 = pending)
#   [0x00DC38EC] DWORD  section (8 = action names)
#   [0x00DC38F0] DWORD  idx
KERNEL2_REQ_BASE = 0x00DC38E8
KERNEL2_REQ_SIZE = 0x20  # read a few extra DWORDs beyond the known fields

# Kernel2 section 8 is the battle command / action name section.
# FF7 kernel2 format: uint16_t offsets[count], then FF7-encoded strings.
# We dump up to this many entries.
SECTION_8_MAX_ENTRIES = 64

# How many bytes of sub_6892E5 to hex-dump.
FUNC_DUMP_BYTES = 128

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


# ── FF7 character decoding ────────────────────────────────────────────────────
# Standard FF7 PC (Steam) character table for dialog / kernel2 text.
# Maps raw byte → printable ASCII.  0xFF = string terminator.  0xE7-0xFE are
# control codes (color, wait, etc.).  Missing entries map to '?'.
FF7_CHAR_TABLE = {
    # Uppercase letters
    0x41: 'A', 0x42: 'B', 0x43: 'C', 0x44: 'D', 0x45: 'E',
    0x46: 'F', 0x47: 'G', 0x48: 'H', 0x49: 'I', 0x4A: 'J',
    0x4B: 'K', 0x4C: 'L', 0x4D: 'M', 0x4E: 'N', 0x4F: 'O',
    0x50: 'P', 0x51: 'Q', 0x52: 'R', 0x53: 'S', 0x54: 'T',
    0x55: 'U', 0x56: 'V', 0x57: 'W', 0x58: 'X', 0x59: 'Y',
    0x5A: 'Z',
    # Lowercase letters
    0x61: 'a', 0x62: 'b', 0x63: 'c', 0x64: 'd', 0x65: 'e',
    0x66: 'f', 0x67: 'g', 0x68: 'h', 0x69: 'i', 0x6A: 'j',
    0x6B: 'k', 0x6C: 'l', 0x6D: 'm', 0x6E: 'n', 0x6F: 'o',
    0x70: 'p', 0x71: 'q', 0x72: 'r', 0x73: 's', 0x74: 't',
    0x75: 'u', 0x76: 'v', 0x77: 'w', 0x78: 'x', 0x79: 'y',
    0x7A: 'z',
    # Digits
    0x30: '0', 0x31: '1', 0x32: '2', 0x33: '3', 0x34: '4',
    0x35: '5', 0x36: '6', 0x37: '7', 0x38: '8', 0x39: '9',
    # Punctuation / symbols
    0x20: ' ', 0x21: '!', 0x22: '"', 0x23: '#', 0x24: '$',
    0x25: '%', 0x26: '&', 0x27: "'", 0x28: '(', 0x29: ')',
    0x2A: '*', 0x2B: '+', 0x2C: ',', 0x2D: '-', 0x2E: '.',
    0x2F: '/', 0x3A: ':', 0x3B: ';', 0x3C: '<', 0x3D: '=',
    0x3E: '>', 0x3F: '?', 0x40: '@',
}


def decode_ff7_string(data, max_len=64):
    """
    Decode an FF7-encoded string (0xFF-terminated) to ASCII.
    Returns (text, raw_bytes_consumed).
    """
    out  = []
    i    = 0
    while i < len(data) and i < max_len:
        b = data[i]
        if b == 0xFF:
            i += 1
            break
        ch = FF7_CHAR_TABLE.get(b)
        if ch is not None:
            out.append(ch)
        elif 0x20 <= b < 0xFF:
            out.append(f'[{b:02X}]')
        else:
            out.append(f'[{b:02X}]')
        i += 1
    return ''.join(out), i


# ── Output / logging ──────────────────────────────────────────────────────────
class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file

    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
        self._log.flush()

    def flush(self):
        self._terminal.flush()
        self._log.flush()

    def __getattr__(self, name):
        return getattr(self._terminal, name)


# ── Process helpers ───────────────────────────────────────────────────────────
def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if exe_name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def open_process(pid):
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
    return handle if handle else None


def read_bytes_vm(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                  buf, n, ctypes.byref(read))
    if not ok or read.value < n:
        return None
    return bytes(buf)


def read_u32(handle, addr):
    b = read_bytes_vm(handle, addr, 4)
    return struct.unpack('<I', b)[0] if b else None


def read_u16(handle, addr):
    b = read_bytes_vm(handle, addr, 2)
    return struct.unpack('<H', b)[0] if b else None


# ── PE / exe file helpers ─────────────────────────────────────────────────────
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010


class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize",        ctypes.c_ulong),
        ("th32ModuleID",  ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("GlblcntUsage",  ctypes.c_ulong),
        ("ProccntUsage",  ctypes.c_ulong),
        ("modBaseAddr",   ctypes.c_void_p),
        ("modBaseSize",   ctypes.c_ulong),
        ("hModule",       ctypes.c_void_p),
        ("szModule",      ctypes.c_char * 256),
        ("szExePath",     ctypes.c_char * 260),
    ]


def find_module_path(pid, module_name):
    snap = k32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        return None
    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    path = None
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            name = me.szModule.decode('ascii', errors='ignore').lower()
            if name == module_name.lower():
                path = me.szExePath.decode('utf-8', errors='replace')
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return path


def load_exe(pid=None):
    FALLBACK = (r"C:\Program Files (x86)\Steam\steamapps\common"
                r"\FINAL FANTASY VII\ff7_en.exe")
    path = None
    if pid is not None:
        path = find_module_path(pid, PROCESS_NAME)
    if path is None or not os.path.exists(path):
        path = FALLBACK
    if not os.path.exists(path):
        return None, None
    try:
        with open(path, 'rb') as f:
            return f.read(), path
    except OSError:
        return None, None


def parse_pe_sections(exe_data):
    pe_off  = struct.unpack_from('<I', exe_data, 0x3C)[0]
    nsec    = struct.unpack_from('<H', exe_data, pe_off +  6)[0]
    oph_sz  = struct.unpack_from('<H', exe_data, pe_off + 20)[0]
    sec_off = pe_off + 24 + oph_sz
    sections = []
    for i in range(nsec):
        s      = sec_off + i * 40
        name   = exe_data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsz    = struct.unpack_from('<I', exe_data, s +  8)[0]
        va     = struct.unpack_from('<I', exe_data, s + 12)[0]
        rawsz  = struct.unpack_from('<I', exe_data, s + 16)[0]
        rawoff = struct.unpack_from('<I', exe_data, s + 20)[0]
        sections.append((name, va, vsz, rawoff, rawsz))
    return sections


def va_to_file_offset(exe_data, va):
    rva      = va - IMAGE_BASE
    sections = parse_pe_sections(exe_data)
    for (name, virt_addr, virt_size, raw_offset, raw_size) in sections:
        span = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + span:
            return raw_offset + (rva - virt_addr)
    return None


def read_from_file(exe_data, va, length):
    off = va_to_file_offset(exe_data, va)
    if off is None or off + length > len(exe_data):
        return None
    return exe_data[off: off + length]


# ── Hex dump ──────────────────────────────────────────────────────────────────
def hex_dump(data, base_va, label, width=16):
    print(f"\n  {'─'*72}")
    print(f"  {label}")
    if base_va is not None:
        print(f"  base VA = 0x{base_va:08X}   ({len(data)} bytes)")
    print(f"  {'─'*72}")
    for row in range(0, len(data), width):
        chunk     = data[row:row + width]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        if base_va is not None:
            print(f"  +{row:#06x}  {hex_part:<{width*3}}  {ascii_part}")
        else:
            print(f"  {row:04X}  {hex_part:<{width*3}}  {ascii_part}")


# ── Phase 1: investigate 0x009ADF0C ──────────────────────────────────────────
def phase1_kernel2_ptr(handle):
    """
    Read and analyse the memory region at/around KERNEL2_CANDIDATE_PTR.
    0x009ADF0C was referenced twice in display_battle_action_text.

    Pattern 1: if [0x009ADF0C] is a pointer to kernel2 data elsewhere in BSS,
               follow it and inspect the target.
    Pattern 2: if 0x009ADF0C itself IS the base of a section pointer array,
               the DWORDs there will point to valid BSS strings.
    """
    print()
    print("=" * 72)
    print("  PHASE 1 — Investigate 0x009ADF0C (kernel2 data pointer candidate)")
    print("=" * 72)

    if handle is None:
        print("  ERROR: FF7 must be running for Phase 1")
        return None

    # Read 64 bytes around the candidate address.
    region_start = KERNEL2_CANDIDATE_PTR - 0x10
    region_data  = read_bytes_vm(handle, region_start, 0x50)
    if region_data is None:
        print(f"  ERROR: could not read memory at 0x{region_start:08X}")
        return None

    hex_dump(region_data, region_start,
             f'Memory at 0x{region_start:08X}..0x{region_start+0x50:08X}')

    # Interpret each DWORD in the region as a potential pointer.
    print()
    print("  DWORD values around 0x009ADF0C (potential pointers):")
    print(f"  {'Address':<14}  {'DWORD value':<14}  Interpretation")
    print(f"  {'─'*14}  {'─'*14}  {'─'*40}")
    for i in range(0, len(region_data) - 3, 4):
        va  = region_start + i
        val = struct.unpack_from('<I', region_data, i)[0]
        marker = '  ← KERNEL2_CANDIDATE_PTR' if va == KERNEL2_CANDIDATE_PTR else ''
        if 0x00400000 <= val <= 0x00DE0000:
            tag = f'→ VA 0x{val:08X} (in FF7 range)'
        elif val == 0:
            tag = 'NULL'
        elif val < 0x1000:
            tag = f'small int ({val})'
        else:
            tag = f'0x{val:08X} (outside FF7 range)'
        print(f"  0x{va:08X}    {val:#012x}  {tag}{marker}")

    # Follow the pointer at 0x009ADF0C if it's valid.
    ptr_val = read_u32(handle, KERNEL2_CANDIDATE_PTR)
    if ptr_val is None:
        print(f"\n  ERROR: could not read DWORD at 0x{KERNEL2_CANDIDATE_PTR:08X}")
        return None

    print(f"\n  Value AT 0x009ADF0C = 0x{ptr_val:08X}")

    if 0x00400000 <= ptr_val <= 0x00DE0000:
        print(f"  This is a valid FF7 VA — following pointer...")
        target_data = read_bytes_vm(handle, ptr_val, 64)
        if target_data:
            hex_dump(target_data, ptr_val, f'Target at 0x{ptr_val:08X}')

            # Check if target looks like a kernel2 section offset table:
            # first uint16 == count * 2 (i.e., the first offset IS the start
            # of data, which means count * 2 bytes of offsets precede the
            # first string, so offset[0] / 2 = num_entries).
            first_u16 = struct.unpack_from('<H', target_data, 0)[0]
            if 0 < first_u16 < 512 and (first_u16 % 2 == 0):
                num_entries = first_u16 // 2
                print(f"\n  First uint16 = {first_u16} → possibly {num_entries} entries"
                      f" (kernel2 section offset table?)")
                return ptr_val
    else:
        print(f"  Value 0x{ptr_val:08X} is not a valid FF7 pointer.")
        print("  Checking if 0x009ADF0C itself is the base of a kernel2 section array...")

    return None


# ── Phase 2: hex-dump sub_6892E5 ─────────────────────────────────────────────
def phase2_sub_6892E5(exe_data):
    """
    Hex-dump sub_6892E5 from the exe file.  This is called by
    display_battle_action_text just before RET — probably the function that
    actually retrieves or renders the kernel2 text.
    """
    print()
    print("=" * 72)
    print("  PHASE 2 — Hex-dump sub_6892E5 (called just before RET in display_battle)")
    print("=" * 72)

    data = read_from_file(exe_data, SUB_6892E5, FUNC_DUMP_BYTES)
    if data is None:
        print(f"  ERROR: could not read exe bytes at VA 0x{SUB_6892E5:08X}")
        return

    hex_dump(data, SUB_6892E5, f'sub_6892E5  [original file bytes]  first {FUNC_DUMP_BYTES} bytes')

    # Quick analysis: find all CALL rel32 and data refs.
    calls = []
    data_refs = []
    for i in range(len(data) - 4):
        b = data[i]
        if b == 0xE8 and i + 5 <= len(data):
            rel    = struct.unpack_from('<i', data, i + 1)[0]
            target = SUB_6892E5 + i + 5 + rel
            calls.append((i, target))
            i += 4
        elif b in (0xA1, 0xA3) and i + 5 <= len(data):
            addr = struct.unpack_from('<I', data, i + 1)[0]
            if 0x00400000 <= addr <= 0x00DE0000:
                data_refs.append((i, addr))
        elif b in (0x8B, 0x89) and i + 6 <= len(data):
            modrm = data[i + 1]
            if (modrm & 0xC7) == 0x05:
                addr = struct.unpack_from('<I', data, i + 2)[0]
                if 0x00400000 <= addr <= 0x00DE0000:
                    data_refs.append((i, addr))

    print()
    if calls:
        print("  CALL rel32 targets in sub_6892E5:")
        for off, tgt in calls:
            print(f"    +{off:#06x}  →  0x{tgt:08X}")
    else:
        print("  No CALL rel32 in first", FUNC_DUMP_BYTES, "bytes")

    if data_refs:
        print("  Data references (abs32) in sub_6892E5:")
        for off, addr in data_refs:
            print(f"    +{off:#06x}  →  0x{addr:08X}")


# ── Phase 3: dump kernel2 section 8 ──────────────────────────────────────────
def phase3_dump_section8(handle, section8_base):
    """
    Given the base address of kernel2 section 8, read the offset table and
    decode the first SECTION_8_MAX_ENTRIES ability name strings.

    Kernel2 section format:
      uint16_t offsets[N]   — offsets[i] = byte offset from section start to string[i]
      <string data>         — FF7-encoded 0xFF-terminated strings

    offsets[0] is always N*2 (= byte offset to first string, so N = offsets[0]/2).
    """
    if handle is None or section8_base is None:
        return

    print()
    print("=" * 72)
    print(f"  PHASE 3 — Decode kernel2 section 8 at 0x{section8_base:08X}")
    print("=" * 72)

    # Read first 2 bytes to get the offset to first string = N*2.
    first_off_bytes = read_bytes_vm(handle, section8_base, 2)
    if first_off_bytes is None:
        print(f"  ERROR: could not read at 0x{section8_base:08X}")
        return

    first_off  = struct.unpack('<H', first_off_bytes)[0]
    if first_off == 0 or first_off > 1024 or (first_off % 2 != 0):
        print(f"  First uint16 = {first_off:#06x} — does not look like a valid offset table")
        print(f"  (expected a small even number, e.g. 0x20-0x80 for section 8)")
        return

    num_entries = first_off // 2
    print(f"  First offset = {first_off} = 0x{first_off:04X} → {num_entries} entries in section 8")

    # Read the full offset table.
    table_bytes = read_bytes_vm(handle, section8_base, first_off)
    if table_bytes is None:
        print(f"  ERROR: could not read offset table ({first_off} bytes)")
        return

    # Read enough data to cover all strings.  Estimate max string data = 64 bytes each.
    read_size = first_off + num_entries * 64
    section_data = read_bytes_vm(handle, section8_base, read_size)
    if section_data is None:
        print(f"  ERROR: could not read section data ({read_size} bytes)")
        section_data = table_bytes  # fall back to just the table

    print()
    print(f"  {'idx':<5}  {'offset':<8}  String")
    print(f"  {'─'*5}  {'─'*8}  {'─'*40}")

    for i in range(min(num_entries, SECTION_8_MAX_ENTRIES)):
        off = struct.unpack_from('<H', table_bytes, i * 2)[0]
        if off >= len(section_data):
            print(f"  {i:<5}  {off:#06x}   [offset {off} beyond read buffer]")
            continue
        text, consumed = decode_ff7_string(section_data[off:], max_len=64)
        raw_preview = ' '.join(f'{b:02X}' for b in section_data[off: off+min(consumed, 8)])
        print(f"  {i:<5}  {off:#06x}   {text!r:<32}  raw=[{raw_preview}]")


# ── Phase 4: also dump the kernel2 request struct live ───────────────────────
def phase4_request_struct(handle):
    """
    Read the kernel2 request structure at 0x00DC38E8 to confirm our decoding
    of sub_6D71FA and to see its current state.
    """
    print()
    print("=" * 72)
    print("  PHASE 4 — Read kernel2 request struct at 0x00DC38E8")
    print("=" * 72)

    if handle is None:
        print("  FF7 not running — skipping")
        return

    data = read_bytes_vm(handle, KERNEL2_REQ_BASE, KERNEL2_REQ_SIZE)
    if data is None:
        print(f"  ERROR: could not read at 0x{KERNEL2_REQ_BASE:08X}")
        return

    print()
    print("  Decoded kernel2 request struct (from sub_6D71FA disassembly):")
    pending = struct.unpack_from('<I', data, 0)[0]
    section = struct.unpack_from('<i', data, 4)[0]
    idx     = struct.unpack_from('<i', data, 8)[0]
    print(f"  [0x{KERNEL2_REQ_BASE:08X}]  request_pending = {pending}")
    print(f"  [0x{KERNEL2_REQ_BASE+4:08X}]  section         = {section}")
    print(f"  [0x{KERNEL2_REQ_BASE+8:08X}]  idx             = {idx}")
    print()

    # Dump next 8 DWORDs in case the result pointer follows.
    print("  Following DWORDs (may include result pointer or related fields):")
    for i in range(4, KERNEL2_REQ_SIZE // 4):
        va  = KERNEL2_REQ_BASE + i * 4
        val = struct.unpack_from('<I', data, i * 4)[0]
        tag = ''
        if 0x00400000 <= val <= 0x00DE0000:
            tag = f'  ← valid VA 0x{val:08X}'
        elif val == 0:
            tag = '  (zero)'
        print(f"  [0x{va:08X}]  = 0x{val:08X}{tag}")

    hex_dump(data, KERNEL2_REQ_BASE, 'Raw bytes of the request struct')


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"kernel2_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Kernel2 Section 8 Investigation")
        print("Goal: find ability name lookup data for battle action TTS.")
        print()

        pid = find_pid(PROCESS_NAME)
        if pid:
            print(f"FF7 running (PID {pid})")
            handle = open_process(pid)
            if not handle:
                print("  (OpenProcess failed)")
                handle = None
        else:
            print("ERROR: FF7 must be running for this script.  Start FF7 first.")
            return

        exe_data, exe_path = load_exe(pid)
        if exe_data is None:
            print("ERROR: could not load ff7_en.exe from disk.")
            return
        print(f"Loaded exe: {exe_path}  ({len(exe_data):,} bytes)")

        # Phase 1: investigate 0x009ADF0C
        section8_base = phase1_kernel2_ptr(handle)

        # Phase 2: hex-dump sub_6892E5
        phase2_sub_6892E5(exe_data)

        # Phase 3: if we found section 8 base, dump the entries
        if section8_base:
            phase3_dump_section8(handle, section8_base)
        else:
            print()
            print("=" * 72)
            print("  PHASE 3 — Skipped (section 8 base not yet identified)")
            print("=" * 72)
            print()
            print("  Manual path: look at PHASE 2 output to find the function that")
            print("  reads kernel2 data, then follow the data references to the actual")
            print("  section pointer array.")

        # Phase 4: kernel2 request struct
        phase4_request_struct(handle)

        print()
        print("=" * 72)
        print("  SUMMARY")
        print("=" * 72)
        print()
        print("  sub_6D71FA (confirmed): queue function — stores section/idx to globals,")
        print("  does NOT return a text pointer.  FFNx's 'get_kernel_text' naming is")
        print("  a misnomer for this specific entry point.")
        print()
        print("  Next: examine PHASE 2 output for sub_6892E5 data references.")
        print("  The actual kernel2 section pointer array should be reachable from")
        print("  one of those addresses.")

    except KeyboardInterrupt:
        print("\n  [Stopped by user]")
    finally:
        if handle:
            k32.CloseHandle(handle)
        print(f"\nLog saved to: {log_path}")
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
