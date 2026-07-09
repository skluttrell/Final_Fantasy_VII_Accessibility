#!/usr/bin/env python3
"""
ff7_kernel2_section_dump.py — Targeted dump of kernel2 string sections.

Background:
  ff7_kernel2_strings_scan.py found string data in three clusters:
    Cluster 0: 0x0091A8C0  "Item","Magic" — identified as main-menu/config text
    Cluster 1: 0x0091F254  "Attack","Fire","Ice","Summon" — likely kernel2 command+spell names
    Cluster 2: 0x0097CAD6  "Attack","Bolt" with multi-FF padding — unknown table

  Phase 2 of the previous script only analysed Cluster 0 and looked back only
  512 bytes.  This script targets Cluster 1 and Cluster 2 with wider windows,
  proper FF7 string parsing, and section-start heuristics.

  Goal: find the base addresses of the sections that hold battle command names
  and magic/ability names so we can implement direct index→name lookup in
  BattleActionThread.

PHASE 1 — Read 2048 bytes BEFORE 0x0091F254 and look for the section start.
          A kernel2 section starts with:
            uint16_t  N          (number of entries)
            uint16_t  offsets[N] (byte offset from section start to each string)
          followed immediately by the FF7-encoded string data.
          The first entry's offset == N*2+2 (past the count+table).

PHASE 2 — Decode every string from the section start through the full Cluster 1
          range (0x0091F254–0x00922CDB).  Print index, raw bytes, decoded text.

PHASE 3 — Dump Cluster 2 (0x0097CA80–0x0097CB80) to identify its structure.

PHASE 4 — Read the kernel2 section pointer array.
          sub_6D71FA stores (section, idx) to globals at 0x00DC38E8+4/+8.
          Some code reads those globals and maps section→data pointer.
          That code likely uses a fixed BSS pointer array.  Search backwards
          from 0x0091F254 in 4-byte steps looking for a DWORD that equals
          0x0091F254 or the section start we find.  If found, the array
          is the kernel2 section pointer table.

HOW TO RUN:
  Start FF7 — title screen is sufficient (kernel2 is loaded at startup).
"""

import ctypes
import os
import struct
import subprocess
import sys
import time

PROCESS_NAME = "ff7_en.exe"

# Cluster 1 anchor — "Attack" (FF7-encoded) found by previous scan.
CLUSTER1_ATTACK_VA = 0x0091F254

# Cluster 2 anchor — second "Attack" hit with multi-FF padding.
CLUSTER2_ATTACK_VA = 0x0097CAD6

# How many entries to decode in Phase 2.
MAX_DECODE = 256

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


# ── FF7 text decoding ─────────────────────────────────────────────────────────
def decode_ff7(data, max_len=128):
    """
    Decode FF7-encoded text.  Stored byte + 0x20 = ASCII char (0x00-0x5E range).
    0xFF = terminator.  Control bytes printed as [XX].
    Returns (decoded_string, bytes_consumed_including_FF).
    """
    out = []
    i = 0
    for b in data[:max_len]:
        i += 1
        if b == 0xFF:
            break
        if b <= 0x5E:
            ch = chr(b + 0x20)
            out.append(ch if ch.isprintable() else f'[{b:02X}]')
        elif b == 0xE0:
            out.append('\\n')
        elif 0xEA <= b <= 0xF2:
            names = ['Cloud','Barret','Tifa','Aerith','RedXIII',
                     'Yuffie','CaitSith','Vincent','Cid']
            out.append(f'<{names[b - 0xEA]}>')
        else:
            out.append(f'[{b:02X}]')
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
    if not ok or read.value < 1:
        return None
    return bytes(buf[:read.value])


def read_u16(handle, addr):
    b = read_bytes_vm(handle, addr, 2)
    return struct.unpack('<H', b)[0] if b and len(b) == 2 else None


def read_u32(handle, addr):
    b = read_bytes_vm(handle, addr, 4)
    return struct.unpack('<I', b)[0] if b and len(b) == 4 else None


# ── Hex dump ──────────────────────────────────────────────────────────────────
def hex_dump(data, base_va, label, width=16):
    print(f"\n  {'-'*72}")
    print(f"  {label}")
    if base_va is not None:
        print(f"  base VA = 0x{base_va:08X}   ({len(data)} bytes)")
    print(f"  {'-'*72}")
    for row in range(0, len(data), width):
        chunk      = data[row:row + width]
        hex_part   = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
        # FF7-decoded interpretation of each byte.
        ff7_part = ''.join(
            chr(b + 0x20) if (b <= 0x5E and chr(b + 0x20).isprintable()) else '.'
            for b in chunk
        )
        print(f"  +{row:#06x}  {hex_part:<{width*3}}  raw:{ascii_part}  ff7:{ff7_part}")


# ── Section-start heuristic ───────────────────────────────────────────────────
def find_section_start(handle, anchor_va, lookback=0x1000):
    """
    Try to find the kernel2 section start by looking for a uint16 offset table.
    A valid section start at VA S has:
      *(uint16*)(S)     = N  (entry count)
      *(uint16*)(S+2)   = offsets[0]  should equal N*2+2 (or N*2 if no count)
      S + offsets[0]    == anchor_va  (first string IS our "Attack" hit)
    We also accept offsets[0] = N*2 (count stored separately or no count field).

    anchor_va: VA of the first string in the section (= CLUSTER1_ATTACK_VA).
    Returns (section_start_va, N, offsets_start_format) or None.
    """
    pre_start = anchor_va - lookback
    pre_data  = read_bytes_vm(handle, pre_start, lookback)
    if pre_data is None:
        return None

    for back in range(2, lookback - 2, 2):
        cand_va     = anchor_va - back
        data_offset = lookback - back  # index into pre_data for this candidate

        if data_offset + 4 > len(pre_data):
            continue

        first_u16 = struct.unpack_from('<H', pre_data, data_offset)[0]
        # first_u16 should be the offset of the first string from section start,
        # which equals anchor_va - cand_va = back.
        if first_u16 != back:
            continue
        # Sanity: first_u16 must be even, small, and nonzero.
        if first_u16 == 0 or first_u16 > 0x2000 or (first_u16 % 2 != 0):
            continue
        # N = number of entries = first_u16 // 2  (no count prefix)
        # OR N = (first_u16 - 2) // 2             (with uint16 count prefix)
        for has_count in (False, True):
            if has_count:
                if data_offset < 2:
                    continue
                N   = struct.unpack_from('<H', pre_data, data_offset - 2)[0]
                exp = N * 2 + 2  # count(2) + N offsets(N*2)
            else:
                N   = first_u16 // 2
                exp = N * 2      # N offsets(N*2)
            if first_u16 != exp:
                continue
            if N == 0 or N > 512:
                continue
            # Verify a few more offsets are sane (increasing, within range).
            ok = True
            prev_off = first_u16
            for i in range(1, min(N, 8)):
                tbl_idx = data_offset + i * 2
                if tbl_idx + 2 > len(pre_data):
                    ok = False
                    break
                off_i = struct.unpack_from('<H', pre_data, tbl_idx)[0]
                if off_i <= prev_off or off_i > 0x10000:
                    ok = False
                    break
                prev_off = off_i
            if ok:
                return cand_va, N, has_count

    return None


# ── Phase 1 — Find section start ─────────────────────────────────────────────
def phase1_find_start(handle):
    print()
    print("=" * 72)
    print(f"  PHASE 1 — Search for section start before 0x{CLUSTER1_ATTACK_VA:08X}")
    print("=" * 72)

    # First, show the raw bytes immediately before the hit.
    dump_start = CLUSTER1_ATTACK_VA - 0x80
    dump_data  = read_bytes_vm(handle, dump_start, 0x100)
    if dump_data:
        hex_dump(dump_data, dump_start,
                 f'256 bytes centered on 0x{CLUSTER1_ATTACK_VA:08X} (Attack hit)')

    result = find_section_start(handle, CLUSTER1_ATTACK_VA, lookback=0x1000)
    if result is None:
        print()
        print("  AUTO-DETECT FAILED.  Trying wider lookback (8 KB)...")
        result = find_section_start(handle, CLUSTER1_ATTACK_VA, lookback=0x8000)

    if result:
        section_va, N, has_count = result
        fmt = "with count prefix" if has_count else "offset-table-only"
        print()
        print(f"  ★ Section start found: 0x{section_va:08X}  ({fmt})")
        print(f"    N = {N} entries")
        return section_va, N
    else:
        print()
        print("  Could not auto-detect section start.")
        print("  The section may not start with a standard uint16 offset table,")
        print("  or strings are stored in fixed-width slots.")
        print()
        print("  Showing 512 bytes before Attack for manual inspection:")
        pre_start = CLUSTER1_ATTACK_VA - 0x200
        pre_data  = read_bytes_vm(handle, pre_start, 0x200 + 0x20)
        if pre_data:
            hex_dump(pre_data, pre_start,
                     f'512 bytes before 0x{CLUSTER1_ATTACK_VA:08X}')
        return None, None


# ── Phase 2 — Decode section strings ─────────────────────────────────────────
def phase2_decode_section(handle, section_va, N):
    """Read the offset table and decode all entries."""
    print()
    print("=" * 72)
    va_str = f"0x{section_va:08X}" if section_va is not None else "unknown"
    print(f"  PHASE 2 — Decode section at {va_str}  ({N if N else '?'} entries)")
    print("=" * 72)

    if section_va is None:
        # Fallback: just walk forward from the Attack hit and print strings.
        print()
        print("  No section start — walking forward from Attack hit and printing")
        print("  every FF7-terminated string (stops at 256 entries or 0xB000 bytes).")
        print()
        walk_va  = CLUSTER1_ATTACK_VA
        end_va   = CLUSTER1_ATTACK_VA + 0x4000
        idx      = 0
        print(f"  {'idx':<5}  {'VA':<12}  {'raw bytes':<28}  String")
        print(f"  {'-'*5}  {'-'*12}  {'-'*28}  {'-'*40}")
        while walk_va < end_va and idx < MAX_DECODE:
            data = read_bytes_vm(handle, walk_va, 32)
            if data is None:
                break
            text, consumed = decode_ff7(data)
            raw = ' '.join(f'{b:02X}' for b in data[:consumed])
            print(f"  {idx:<5}  0x{walk_va:08X}  [{raw:<27}]  {text!r}")
            walk_va += consumed
            # Skip any inter-string padding (zero bytes).
            while walk_va < end_va:
                b = read_bytes_vm(handle, walk_va, 1)
                if b and b[0] == 0x00:
                    walk_va += 1
                else:
                    break
            idx += 1
        return

    # Read the full offset table.
    print()
    print(f"  {'idx':<5}  {'offset':<8}  {'raw bytes':<30}  String")
    print(f"  {'-'*5}  {'-'*8}  {'-'*30}  {'-'*40}")
    for i in range(min(N, MAX_DECODE)):
        off_va = section_va + i * 2
        off_bytes = read_bytes_vm(handle, off_va, 2)
        if not off_bytes or len(off_bytes) < 2:
            print(f"  {i:<5}  [unreadable offset]")
            break
        off = struct.unpack('<H', off_bytes)[0]
        str_va   = section_va + off
        str_data = read_bytes_vm(handle, str_va, 48)
        if str_data is None:
            print(f"  {i:<5}  {off:#06x}   [unreadable string at 0x{str_va:08X}]")
            continue
        text, consumed = decode_ff7(str_data)
        raw = ' '.join(f'{b:02X}' for b in str_data[:consumed])
        print(f"  {i:<5}  {off:#06x}   [{raw:<29}]  {text!r}")

    print()
    print(f"  ★ Section base: 0x{section_va:08X}")
    print(f"    Lookup formula: off = *(uint16*)(0x{section_va:08X} + idx*2)")
    print(f"                    text = (char*)(0x{section_va:08X} + off)")


# ── Phase 3 — Cluster 2 dump ──────────────────────────────────────────────────
def phase3_cluster2(handle):
    print()
    print("=" * 72)
    print(f"  PHASE 3 — Cluster 2 dump around 0x{CLUSTER2_ATTACK_VA:08X}")
    print("=" * 72)

    dump_start = CLUSTER2_ATTACK_VA - 0x80
    dump_data  = read_bytes_vm(handle, dump_start, 0x180)
    if dump_data:
        hex_dump(dump_data, dump_start,
                 f'384 bytes centered on Cluster 2 Attack hit')

    # Walk strings forward from the cluster 2 start.
    print()
    print("  Walking strings forward from 0x{:08X}:".format(CLUSTER2_ATTACK_VA))
    print()
    print(f"  {'VA':<12}  {'raw bytes':<30}  String")
    print(f"  {'-'*12}  {'-'*30}  {'-'*40}")
    walk_va = CLUSTER2_ATTACK_VA
    for _ in range(64):
        data = read_bytes_vm(handle, walk_va, 40)
        if data is None:
            break
        text, consumed = decode_ff7(data)
        raw = ' '.join(f'{b:02X}' for b in data[:consumed])
        print(f"  0x{walk_va:08X}  [{raw:<29}]  {text!r}")
        walk_va += consumed
        # Skip padding bytes (0x00 or 0xFF).
        while True:
            b = read_bytes_vm(handle, walk_va, 1)
            if b and b[0] in (0x00, 0xFF):
                walk_va += 1
            else:
                break


# ── Phase 4 — Search for kernel2 section pointer array ───────────────────────
def phase4_pointer_array(handle, section_va):
    """
    Look for a DWORD pointer that equals section_va somewhere in BSS
    (0x007BA000–0x00F51000).  Such a pointer would be part of the kernel2
    section table used by the text lookup code.
    """
    print()
    print("=" * 72)
    print("  PHASE 4 — Search BSS for DWORD pointer → section start")
    print("=" * 72)

    if section_va is None:
        print()
        print("  Skipped — no confirmed section start from Phase 1.")
        return

    target = section_va
    print()
    print(f"  Looking for DWORD == 0x{target:08X} in VA range 0x007BA000–0x00F51000")

    SEARCH_START = 0x007BA000
    SEARCH_END   = 0x00F51000
    CHUNK        = 0x10000
    found        = []
    addr         = SEARCH_START

    while addr < SEARCH_END:
        chunk_size = min(CHUNK, SEARCH_END - addr)
        data = read_bytes_vm(handle, addr, chunk_size)
        if data is None:
            addr += chunk_size
            continue
        pos = 0
        while True:
            # Search for little-endian encoding of target.
            needle = struct.pack('<I', target)
            idx = data.find(needle, pos)
            if idx < 0:
                break
            va = addr + idx
            if va % 4 == 0:  # only aligned DWORDs
                found.append(va)
            pos = idx + 1
        addr += len(data)

    if not found:
        print(f"  No pointers to 0x{target:08X} found in BSS.")
        print("  Kernel2 section data may be at a heap address, or the section")
        print("  start heuristic found the wrong address.")
    else:
        print(f"  Found {len(found)} pointer(s):")
        for ptr_va in found[:20]:
            # Show surrounding context (might be an array element).
            ctx = []
            for delta in range(-3, 4):
                v = read_u32(handle, ptr_va + delta * 4)
                ctx.append(f'0x{v:08X}' if v is not None else '????????')
            print(f"  ★ 0x{ptr_va:08X}  context: [{', '.join(ctx)}]")
        print()
        print("  If the pointers above are part of a consecutive array, that array")
        print("  is the kernel2 section pointer table.  The index of our pointer")
        print("  in the array == the section number sub_6D71FA uses (0-based).")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"kernel2_section_dump_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Kernel2 Section Dump")
        print("Identify section structure and base addresses for ability name lookup.")
        print()

        pid = find_pid(PROCESS_NAME)
        if not pid:
            print("ERROR: ff7_en.exe not running.  Start FF7 first.")
            return
        print(f"FF7 running (PID {pid})")
        print()

        handle = open_process(pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        section_va, N = phase1_find_start(handle)
        phase2_decode_section(handle, section_va, N)
        phase3_cluster2(handle)
        phase4_pointer_array(handle, section_va)

        print()
        print("=" * 72)
        print("  SUMMARY")
        print("=" * 72)
        print()
        if section_va:
            print(f"  Cluster 1 section base: 0x{section_va:08X}  ({N} entries)")
            print()
            print("  Next steps:")
            print(f"  1. Confirm 'Attack' is idx 0 (should be — it IS the first string)")
            print(f"  2. Add to ff7_addresses.h:  KERNEL2_CMD_NAMES = 0x{section_va:08X}")
            print(f"  3. In BattleActionThread: decode action name via:")
            print(f"       uint16_t off = *reinterpret_cast<uint16_t*>(0x{section_va:08X} + cmdIdx*2);")
            print(f"       const char* ff7str = reinterpret_cast<char*>(0x{section_va:08X} + off);")
            print(f"       std::wstring name = FF7Text::Decode(ff7str);")
        else:
            print("  Section start not confirmed.  Review Phase 1 hex dump above.")
            print("  Look for a block of small even uint16 values before 'Attack'.")

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
