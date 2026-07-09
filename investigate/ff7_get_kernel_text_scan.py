#!/usr/bin/env python3
"""
ff7_get_kernel_text_scan.py — Find the real get_kernel_text address.

Background:
  The battle action DLL needs get_kernel_text(section, idx, stride) to convert
  actionIdx values into human-readable ability names from the kernel2.bin data.

  sub_6D71FA (= 0x6D71FA) is the get_kernel_text function, confirmed by:
    get_relative_call(display_battle_action_text_42782A, 0x77) = 0x6D71FA
    FFNx ff7_data.h: get_kernel_text = get_relative_call(draw_status_limit_level_stats, 0x10C)

  Calling 0x6D71FA crashes because FFNx hooks it and its trampoline calls an
  address (0x016E4E3C) that is not mapped in this game installation.

This script:
  PHASE 1 — Read the original file bytes of sub_6D71FA and hex-dump them so
             we can manually decode what the function does and potentially
             reimplement it ourselves.

  PHASE 2 — Scan the exe code section for all CALL 0x6D71FA sites.  Each site
             at VA X is a potential caller.  If FFNx ff7_data.h is correct,
             one site is at draw_status_limit_level_stats + 0x10C.  We report
             all sites with X and (X - 0x10C) so the user can identify which
             one is draw_status_limit_level_stats.

  PHASE 3 — If FF7 is running: verify the caller addresses are real by reading
             a few bytes from live memory, and check whether calling each one's
             (X - 0x10C) looks like a function entry (first byte = push/sub ESP).

HOW TO RUN:
  Start FF7 (optional but recommended for Phase 3), then run this script.
  If FF7 is not running, Phases 1 and 2 still work from the exe file on disk.
"""

import ctypes
import os
import struct
import subprocess
import sys
import time

PROCESS_NAME = "ff7_en.exe"
IMAGE_BASE   = 0x00400000

# The function we know is get_kernel_text (confirmed from battle action scan).
# All callers of this VA are candidate "draw_status_limit_level_stats + 0x10C".
GET_KERNEL_TEXT_VA = 0x006D71FA

# According to FFNx ff7_data.h:
#   get_kernel_text = get_relative_call(draw_status_limit_level_stats, 0x10C)
# So the relevant call site is at draw_status_limit_level_stats + 0x10C.
EXPECTED_CALL_OFFSET_IN_CALLER = 0x10C

# How many bytes to dump for the hex dump (Phase 1).
HEX_DUMP_BYTES = 64

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


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


def read_bytes_from_process(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, n,
                                  ctypes.byref(read))
    if not ok or read.value < n:
        return None
    return bytes(buf)


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
    """
    Return (exe_data_bytes, exe_path) for ff7_en.exe.
    If pid is given, tries to find the path from the running process first.
    Falls back to the standard Steam install path.
    """
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
    """
    Return list of (name, virt_addr, virt_size, raw_offset, raw_size) for all
    PE sections.
    """
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
    print(f"  base VA = 0x{base_va:08X}   ({len(data)} bytes)")
    print(f"  {'─'*72}")
    for row in range(0, len(data), width):
        chunk = data[row:row + width]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f"  +{row:#06x}  {hex_part:<{width*3}}  {ascii_part}")


# ── Phase 1 ───────────────────────────────────────────────────────────────────
def phase1_hex_dump(exe_data):
    """
    Read the original (unpatched) bytes of get_kernel_text from the exe file
    and print a hex dump for manual decoding.

    The function (sub_6D71FA) is 33 bytes long (RET at file offset +0x21
    from function start, confirmed by previous scan).  We read 64 bytes to
    include a little padding.

    Key things to look for in the dump:
      - Function prologue: 55 (PUSH EBP), 8B EC (MOV EBP,ESP), 53/56/57 (PUSH reg)
      - IMUL: 0F AF (imul r32,r/m32) or 6B/69 with reg operand
      - ADD:  05 E8 38 DC 00 — this is ADD EAX,0x00DC38E8 (kernel2 base pointer)
      - Indirect CALL: FF D0/D1/D2/D3 (CALL EAX/ECX/EDX/EBX)
      - Direct CALL: E8 rel32
      - Return: C3 (plain RET), or C2 nn nn (RET n for stdcall)
    """
    print()
    print("=" * 72)
    print("  PHASE 1 — HEX DUMP: sub_6D71FA (get_kernel_text candidate)")
    print("=" * 72)

    data = read_from_file(exe_data, GET_KERNEL_TEXT_VA, HEX_DUMP_BYTES)
    if data is None:
        print(f"  ERROR: VA 0x{GET_KERNEL_TEXT_VA:08X} not found in exe sections")
        return

    hex_dump(data, GET_KERNEL_TEXT_VA, 'sub_6D71FA  [original file bytes]')

    # Also annotate key byte positions the previous scan identified.
    print()
    print("  Known landmarks (from previous battle_action_scan.py run):")
    print("  +0x04  ADD EAX,imm32  → imm32 = 0x00DC38E8  (kernel2 base?)")
    print("  +0x21  RET  (function end = 33 bytes total)")
    print()
    print("  How to decode manually:")
    print("  - Look for E8/FF patterns indicating CALL instructions")
    print("  - FF D0=CALL EAX, FF D1=CALL ECX, FF D2=CALL EDX, FF D3=CALL EBX")
    print("  - FF 15 [4 bytes] = CALL [abs32]")
    print("  - 0F AF = 2-byte opcode prefix for IMUL r32,r/m32")
    print("  - 05 [4 bytes] = ADD EAX,imm32")
    print("  - 8B 45 xx = MOV EAX,[EBP+xx]  (read arg from stack)")
    print()

    # Quick analysis: does the function contain any CALL?
    calls_e8 = []
    calls_ff = []
    for i in range(len(data) - 4):
        b = data[i]
        if b == 0xE8:
            rel    = struct.unpack_from('<i', data, i + 1)[0]
            target = GET_KERNEL_TEXT_VA + i + 5 + rel
            calls_e8.append((i, target))
        elif b == 0xFF:
            next_b = data[i + 1] if i + 1 < len(data) else 0
            # FF /2 = CALL r/m32.  ModRM reg field = (next_b >> 3) & 7 == 2
            if (next_b & 0x38) == 0x10:
                calls_ff.append((i, next_b))

    if calls_e8:
        print("  ★ CALL rel32 found in original bytes:")
        for off, target in calls_e8:
            print(f"    +{off:#06x}  →  0x{target:08X}")
    else:
        print("  ○ No CALL rel32 (E8) found — function may use indirect CALL")

    if calls_ff:
        print("  ★ Possible CALL r/m32 (FF /2) found:")
        regs = ['EAX','ECX','EDX','EBX','ESP','EBP','ESI','EDI']
        for off, modrm in calls_ff:
            mod = (modrm >> 6) & 3
            rm  = modrm & 7
            if mod == 3:
                print(f"    +{off:#06x}  CALL {regs[rm]}")
            elif mod == 0 and rm == 5:
                abs32 = struct.unpack_from('<I', data, off + 2)[0]
                print(f"    +{off:#06x}  CALL [0x{abs32:08X}]")
            else:
                print(f"    +{off:#06x}  CALL [mem]  (ModRM={modrm:#04x})")
    else:
        print("  ○ No CALL r/m32 (FF /2) found")


# ── Phase 2 ───────────────────────────────────────────────────────────────────
def phase2_find_callers(exe_data):
    """
    Scan the entire code section of the exe for E8 rel32 instructions that
    target GET_KERNEL_TEXT_VA (0x6D71FA).

    For each caller at VA X, we also report (X - EXPECTED_CALL_OFFSET_IN_CALLER)
    which would be draw_status_limit_level_stats if FFNx ff7_data.h is correct.
    We also read a few bytes around the caller to give context.
    """
    print()
    print("=" * 72)
    print("  PHASE 2 — CALLER SCAN: find all CALL 0x6D71FA sites in exe")
    print("=" * 72)
    print()

    sections = parse_pe_sections(exe_data)
    callers  = []

    # The code section in FF7 is typically named '.text' or code-flagged.
    # We scan all sections that could contain code (virt_addr in plausible range).
    for (sec_name, virt_addr, virt_size, raw_offset, raw_size) in sections:
        # Only scan sections that map to the FF7 code range (0x400000–0xC00000 VA)
        sec_va_start = IMAGE_BASE + virt_addr
        sec_va_end   = sec_va_start + max(virt_size, raw_size)
        if sec_va_start < 0x00400000 or sec_va_start > 0x00C00000:
            continue
        raw_end = raw_offset + raw_size
        if raw_end > len(exe_data):
            raw_end = len(exe_data)
        section_data = exe_data[raw_offset: raw_end]
        if len(section_data) < 5:
            continue

        print(f"  Scanning section '{sec_name}' "
              f"VA=0x{sec_va_start:08X}..0x{sec_va_end:08X} "
              f"({len(section_data)} bytes)...")

        for i in range(len(section_data) - 4):
            if section_data[i] != 0xE8:
                continue
            rel    = struct.unpack_from('<i', section_data, i + 1)[0]
            # The instruction is at VA = sec_va_start + i
            instr_va = sec_va_start + i
            target   = instr_va + 5 + rel
            if target == GET_KERNEL_TEXT_VA:
                callers.append((instr_va, sec_name))

    print()
    if not callers:
        print("  ✗ No callers found for 0x6D71FA — check IMAGE_BASE or section scan range")
        return callers

    print(f"  Found {len(callers)} caller(s) of 0x{GET_KERNEL_TEXT_VA:08X}:")
    print()
    print(f"  {'Caller VA':<14}  {'Section':<8}  "
          f"{'draw_status_limit_level_stats?':<34}  Context bytes")
    print(f"  {'─'*14}  {'─'*8}  {'─'*34}  {'─'*20}")

    for (caller_va, sec_name) in sorted(callers):
        candidate_fn_va = caller_va - EXPECTED_CALL_OFFSET_IN_CALLER
        # Read 8 bytes of context: 3 before the call, the E8 call itself (5)
        ctx_start_va = caller_va - 3
        ctx_bytes    = read_from_file(exe_data, ctx_start_va, 8)
        ctx_hex = ' '.join(f'{b:02X}' for b in ctx_bytes) if ctx_bytes else '?'
        print(f"  0x{caller_va:08X}     {sec_name:<8}  "
              f"0x{candidate_fn_va:08X}                      "
              f"[{ctx_hex}]")

    print()
    print(f"  'draw_status_limit_level_stats?' column = caller_va - 0x{EXPECTED_CALL_OFFSET_IN_CALLER:X}")
    print(f"  If FFNx ff7_data.h is correct, exactly ONE of these is draw_status_limit_level_stats.")
    print()
    print("  To identify which one:")
    print("  - Function starts typically begin with 55 (PUSH EBP) or 53/56/57 (PUSH reg)")
    print("  - Check the 'candidate function VA' bytes in the hex dump below")
    return callers


def phase2_check_candidates(exe_data, callers):
    """
    For each candidate draw_status_limit_level_stats VA, read and display
    the first 8 bytes from the exe file to help identify function starts.
    """
    if not callers:
        return

    print("  Candidate function starts (first 8 bytes from file):")
    print()

    seen = set()
    for (caller_va, _sec) in sorted(callers):
        candidate_va = caller_va - EXPECTED_CALL_OFFSET_IN_CALLER
        if candidate_va in seen:
            continue
        seen.add(candidate_va)

        fn_bytes = read_from_file(exe_data, candidate_va, 8)
        if fn_bytes is None:
            print(f"    0x{candidate_va:08X}  [could not read from file]")
            continue

        hex_part   = ' '.join(f'{b:02X}' for b in fn_bytes)
        # Heuristic: does this look like a function prologue?
        looks_like_start = (
            fn_bytes[0] in (0x55, 0x53, 0x56, 0x57)  # PUSH EBP/EBX/ESI/EDI
            or (fn_bytes[0] == 0x83 and fn_bytes[1] == 0xEC)   # SUB ESP, imm8
            or (fn_bytes[0] == 0x81 and fn_bytes[1] == 0xEC)   # SUB ESP, imm32
        )
        marker = '  ← plausible function start' if looks_like_start else ''
        print(f"    0x{candidate_va:08X}  [{hex_part}]{marker}")

    print()


# ── Phase 3 ───────────────────────────────────────────────────────────────────
def phase3_live_verify(handle, exe_data, callers):
    """
    If FF7 is running, verify that the caller VA bytes in live memory match
    the file (confirming FFNx hasn't trampolined those call sites).
    """
    if handle is None:
        print("  FF7 not running — skipping live verification")
        return

    print("=" * 72)
    print("  PHASE 3 — LIVE VERIFY: check caller sites in running process")
    print("=" * 72)
    print()

    for (caller_va, sec_name) in sorted(callers):
        live_bytes = read_bytes_from_process(handle, caller_va, 5)
        file_bytes = read_from_file(exe_data, caller_va, 5)

        if live_bytes is None:
            print(f"  0x{caller_va:08X}  [could not read from process]")
            continue

        live_hex = ' '.join(f'{b:02X}' for b in live_bytes)
        file_hex = ' '.join(f'{b:02X}' for b in file_bytes) if file_bytes else '?'

        if live_bytes == file_bytes:
            status = "UNPATCHED (matches file)"
        elif live_bytes[0] == 0xE9:
            # Still a CALL? No — E9 is JMP, meaning FFNx patched this caller too.
            status = "PATCHED by FFNx (JMP at entry)"
        elif live_bytes[0] == 0xE8:
            # Still a CALL instruction — compute live target
            live_rel = struct.unpack_from('<i', live_bytes, 1)[0]
            live_tgt = caller_va + 5 + live_rel
            status = f"CALL → 0x{live_tgt:08X} (live)"
        else:
            status = f"MODIFIED  live=[{live_hex}]  file=[{file_hex}]"

        print(f"  0x{caller_va:08X}  {status}")

    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_name   = f"get_kernel_text_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path   = os.path.join(script_dir, log_name)
    log_file   = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 get_kernel_text Investigation Scan")
        print("Find the real address so battle action TTS can announce ability names.")
        print()

        # Try to find running FF7 (optional)
        pid = find_pid(PROCESS_NAME)
        if pid:
            print(f"FF7 is running (PID {pid})  — will use for Phase 3 live verify")
            handle = open_process(pid)
            if not handle:
                print("  (OpenProcess failed — Phase 3 will be skipped)")
                handle = None
        else:
            print("FF7 is not running — Phases 1 and 2 will run from file only")
        print()

        exe_data, exe_path = load_exe(pid)
        if exe_data is None:
            print("ERROR: could not load ff7_en.exe from disk.")
            print("  Check that FF7 is installed at the default Steam path, or")
            print("  start FF7 so the process path can be detected automatically.")
            return
        print(f"Loaded exe: {exe_path}  ({len(exe_data):,} bytes)")

        # Phase 1: hex dump
        phase1_hex_dump(exe_data)

        # Phase 2: caller scan
        callers = phase2_find_callers(exe_data)
        phase2_check_candidates(exe_data, callers)

        # Phase 3: live verify (only if FF7 is running)
        if handle and callers:
            phase3_live_verify(handle, exe_data, callers)

        # Summary
        print("=" * 72)
        print("  SUMMARY")
        print("=" * 72)
        print()
        print(f"  get_kernel_text VA (confirmed): 0x{GET_KERNEL_TEXT_VA:08X}")
        print()
        print("  Problem: calling 0x6D71FA crashes because FFNx hooks it and")
        print("  its trampoline calls 0x016E4E3C which is unmapped.")
        print()
        print("  Solutions (pick one):")
        print("  A) Reimplement get_kernel_text ourselves based on the hex dump above.")
        print("     The function reads kernel2 data from 0x00DC38E8 and returns a pointer.")
        print("     Once we understand the ~33-byte body, replicate in C++ directly.")
        print()
        if callers:
            seen = set()
            for (caller_va, _) in callers:
                candidate = caller_va - EXPECTED_CALL_OFFSET_IN_CALLER
                if candidate not in seen:
                    seen.add(candidate)
                    print(f"  B) Use draw_status_limit_level_stats at candidate VA"
                          f" 0x{candidate:08X}")
                    print(f"     Then: get_kernel_text = get_relative_call(0x{candidate:08X},"
                          f" 0x{EXPECTED_CALL_OFFSET_IN_CALLER:X})")
                    print(f"     Verify: read_relative_call(0x{candidate:08X} + 0x10C) should"
                          f" == 0x{GET_KERNEL_TEXT_VA:08X}")
        print()
        print("  C) Skip get_kernel_text entirely; use actionIdx ranges to approximate")
        print("     ability names (e.g. idx 0-12 = magic tier, etc.).")

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
