#!/usr/bin/env python3
"""
ff7_kernel2_strings_scan.py — Locate kernel2 ability/spell name strings in live memory.

Background:
  sub_6892E5 and the nearby sub_68930C reference two hardcoded BSS addresses:
    0x00910480  — passed to sub_65FB40 as a font/style argument
    0x009104A0  — passed to sub_65FF59 as a data argument

  We need to find the actual kernel2 section data that holds ability names.
  Rather than tracing more code, this script scans the entire BSS range of
  the running game for known FF7-encoded ability and spell name strings.
  When found, the surrounding memory reveals the section's offset table,
  which gives us the base address to use in the DLL.

  FF7 Steam PC text encoding:
    byte + 0x20 = ASCII character  (for bytes 0x00-0x5E)
    0x5F-0xDF  = extended table (accented/special chars)
    0xFF        = string terminator
    0xE0        = newline
    0xEA-0xF2  = character name tokens (Cloud, Barret, etc.)

    IMPORTANT: "Attack" in memory is NOT 0x41 0x74 ... (ASCII).
    It is 0x21 0x54 0x54 0x41 0x43 0x4B FF — each byte is char−0x20.

  Scan targets (known strings, properly FF7-encoded):
    "Attack"  21 54 54 41 43 4B FF   — basic physical attack command
    "Magic"   2D 41 47 49 43 FF      — magic command
    "Item"    29 54 45 4D FF         — item command
    "Fire"    26 49 52 45 FF         — Fire spell (kernel2 magic section)
    "Ice"     29 43 45 FF            — Ice spell
    "Bolt"    22 4F 4C 54 FF         — Bolt spell (Thunder in later games)
    "Cure"    23 55 52 45 FF         — Cure spell

  PHASE 1 — Scan FF7 BSS for all target strings.  Report each address and
            print 32 bytes before it (the offset table preceding the string).

  PHASE 2 — For the most promising hit, try to read back the full offset
            table and reconstruct the section (decode each entry).

  PHASE 3 — Also inspect 0x009104A0 and 0x00910480 directly (the two
            hardcoded addresses in sub_6892E5 / sub_68930C).

HOW TO RUN:
  Start FF7 and wait until past the loading screen (title screen is fine).
  The kernel2 data is decompressed into BSS at startup.
"""

import ctypes
import os
import struct
import subprocess
import sys
import time

PROCESS_NAME  = "ff7_en.exe"

# VA range to scan: FF7's .data / BSS section.
# From the section table: .data VA=0x007BA000, size covers up to ~0x00F51000.
# We scan a sub-range that's likely to contain kernel2 text data.
SCAN_START = 0x00500000   # below .text end to catch all possible locations
SCAN_END   = 0x00F80000   # upper bound of FF7 BSS (.data section ends ~0x00F51000)

CHUNK_SIZE = 0x10000  # 64 KB per read chunk

# Addresses of interest from sub_6892E5 / sub_68930C hex dump.
ADDR_FONT_STYLE = 0x00910480  # passed to render function
ADDR_DATA_ARG   = 0x009104A0  # passed to text-object creation function

def _ff7(s):
    """Encode an ASCII string into FF7 byte values (char - 0x20, then 0xFF terminator)."""
    return bytes([ord(c) - 0x20 for c in s] + [0xFF])


# Known string patterns to search for in FF7 encoding (byte = ASCII − 0x20).
# Each entry: (label, encoded_bytes_including_0xFF_terminator)
TARGETS = [
    ("Attack",  _ff7("Attack")),    # 21 54 54 41 43 4B FF
    ("Magic",   _ff7("Magic")),     # 2D 41 47 49 43 FF
    ("Item",    _ff7("Item")),      # 29 54 45 4D FF
    ("Summon",  _ff7("Summon")),    # 33 55 4D 4D 4F 4E FF
    ("W-Magic", _ff7("W-Magic")),   # 37 0D 2D 41 47 49 43 FF
    ("Fire",    _ff7("Fire")),      # 26 49 52 45 FF
    ("Ice",     _ff7("Ice")),       # 29 43 45 FF
    ("Bolt",    _ff7("Bolt")),      # 22 4F 4C 54 FF
    ("Cure",    _ff7("Cure")),      # 23 55 52 45 FF
    ("Sense",   _ff7("Sense")),     # 33 45 4E 53 45 FF
]

# How many strings to decode in Phase 2 section reconstruction.
MAX_DECODE = 96

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


# ── FF7 text decoding ─────────────────────────────────────────────────────────
def decode_ff7(data, max_len=64):
    """
    Decode FF7-encoded text.
    Encoding rule: stored_byte + 0x20 = ASCII character (for bytes 0x00-0x5E).
    0xFF = string terminator.  Other control bytes printed as [XX].
    """
    out = []
    for b in data[:max_len]:
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
    return ''.join(out)


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


def read_u32(handle, addr):
    b = read_bytes_vm(handle, addr, 4)
    return struct.unpack('<I', b)[0] if b and len(b) == 4 else None


# ── Hex dump ──────────────────────────────────────────────────────────────────
def hex_dump(data, base_va, label, width=16):
    print(f"\n  {'─'*72}")
    print(f"  {label}")
    if base_va is not None:
        print(f"  base VA = 0x{base_va:08X}   ({len(data)} bytes)")
    print(f"  {'─'*72}")
    for row in range(0, len(data), width):
        chunk      = data[row:row + width]
        hex_part   = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in chunk)
        print(f"  +{row:#06x}  {hex_part:<{width*3}}  {ascii_part}")


# ── Phase 1: string scan ──────────────────────────────────────────────────────
def phase1_scan(handle):
    """
    Scan FF7 BSS for known ability/spell name strings.
    Returns list of (label, va, pattern) for all hits found.
    """
    print()
    print("=" * 72)
    print(f"  PHASE 1 — Scan 0x{SCAN_START:08X}–0x{SCAN_END:08X} for known strings")
    print("=" * 72)
    print()
    print(f"  Searching for: {', '.join(label for label, _ in TARGETS)}")
    print()

    hits = []
    addr = SCAN_START

    while addr < SCAN_END:
        chunk_size = min(CHUNK_SIZE, SCAN_END - addr)
        data = read_bytes_vm(handle, addr, chunk_size)
        if data is None:
            addr += chunk_size
            continue

        for label, pattern in TARGETS:
            pos = 0
            while True:
                idx = data.find(pattern, pos)
                if idx < 0:
                    break
                va = addr + idx
                hits.append((label, va, pattern))
                pos = idx + 1

        addr += len(data)
        if addr % 0x100000 == 0 or addr >= SCAN_END:
            mb = (addr - SCAN_START) // 0x100000
            total_mb = (SCAN_END - SCAN_START) // 0x100000
            print(f"  Scanned {mb}/{total_mb} MB...  ({len(hits)} hits so far)")

    if not hits:
        print("  No matches found.  Kernel2 data may not be loaded yet,")
        print("  or the encoding differs from standard ASCII.")
        return []

    # Sort by VA.
    hits.sort(key=lambda x: x[1])

    print()
    print(f"  Found {len(hits)} hit(s):")
    print()
    print(f"  {'String':<10}  {'VA':<12}  Context (16 bytes at VA)")
    print(f"  {'─'*10}  {'─'*12}  {'─'*50}")

    shown = set()
    for label, va, pattern in hits:
        ctx = read_bytes_vm(handle, va, 16) or b''
        ctx_hex = ' '.join(f'{b:02X}' for b in ctx)
        # Mark clusters: consecutive hits within 4KB are probably same section.
        prev_va = max((h[1] for h in hits if h[1] < va), default=0)
        gap = va - prev_va if prev_va > 0 else 0
        gap_str = f'  (+{gap:#x} from prev)' if prev_va > 0 and va not in shown else ''
        print(f"  {label:<10}  0x{va:08X}  [{ctx_hex}]{gap_str}")
        shown.add(va)

    return hits


# ── Phase 2: section reconstruction ──────────────────────────────────────────
def phase2_reconstruct(handle, hits):
    """
    For the cluster of hits with the smallest VAs (most likely the main
    kernel2 section), try to back-trace to the section start.

    A kernel2 section begins with a uint16_t offset table:
      offsets[0] = N*2  (where N = number of entries; first string starts at byte N*2)
      offsets[i] = byte offset from section start to entry i's string

    We search backwards from the first hit to find a consistent offset table.
    """
    if not hits:
        return

    print()
    print("=" * 72)
    print("  PHASE 2 — Section reconstruction from first hit cluster")
    print("=" * 72)

    # Group hits into clusters (within 0x4000 bytes of each other).
    clusters = []
    current  = [hits[0]]
    for h in hits[1:]:
        if h[1] - current[-1][1] < 0x4000:
            current.append(h)
        else:
            clusters.append(current)
            current = [h]
    clusters.append(current)

    print()
    print(f"  {len(clusters)} cluster(s) of hits:")
    for i, cl in enumerate(clusters):
        vas = [h[1] for h in cl]
        print(f"    Cluster {i}: {len(cl)} hits  VA range 0x{min(vas):08X}–0x{max(vas):08X}")
        for h in cl:
            print(f"      {h[0]:<10}  0x{h[1]:08X}")

    # Work on the first cluster.
    cluster = clusters[0]
    first_va = cluster[0][1]

    print()
    print(f"  Analysing cluster 0 (first hit at 0x{first_va:08X})...")

    # The hit is the START of the string.  The offset table precedes it.
    # Read 512 bytes before the hit to search for the table start.
    pre_size = min(0x200, first_va - SCAN_START)
    pre_data = read_bytes_vm(handle, first_va - pre_size, pre_size + 0x100)
    if pre_data is None:
        print("  ERROR: could not read memory before first hit")
        return

    # Try each possible offset-table start: if offsets[0] == N*2 and
    # offsets[0]/2 * 2 == first offset, and the offset points exactly to
    # our known hit (first_va - candidate_base == offsets[0]), then
    # candidate_base is the section start.
    section_start = None
    for back in range(2, pre_size - 2, 2):
        cand_base_va = first_va - pre_size + (pre_size - back)
        cand_offset  = pre_size - back  # index into pre_data

        # Read first_off = potential offsets[0]
        if cand_offset + 2 > len(pre_data):
            continue
        first_off = struct.unpack_from('<H', pre_data, cand_offset)[0]
        if first_off == 0 or first_off > 0x800 or (first_off % 2 != 0):
            continue

        # first_off should equal the byte distance from section_start to the
        # first string, which is also first_va - cand_base_va.
        dist = first_va - cand_base_va
        if dist == first_off:
            section_start = cand_base_va
            print(f"  ★ Candidate section start: 0x{section_start:08X}")
            print(f"    offsets[0] = {first_off} = 0x{first_off:04X}"
                  f"  → {first_off // 2} entries")
            break

    if section_start is None:
        # Fall back: show the 64 bytes before the first hit as a hex dump
        # so we can inspect manually.
        show_start = max(first_va - 64, SCAN_START)
        show_data  = read_bytes_vm(handle, show_start, 128) or b''
        hex_dump(show_data, show_start,
                 f'64 bytes before first hit at 0x{first_va:08X}')
        print()
        print("  Could not auto-detect section start.  Review hex dump above:")
        print("  Look for a block of small even uint16 values — that is the")
        print("  offset table.  The first uint16 = N*2 (N = number of entries).")
        return

    # Read and decode the full section.
    first_off_val = struct.unpack_from('<H', pre_data, pre_size - (first_va - section_start))[0]
    num_entries   = first_off_val // 2
    # Estimate section data size.
    read_size     = first_off_val + num_entries * 32
    section_data  = read_bytes_vm(handle, section_start, read_size)
    if section_data is None:
        print(f"  ERROR: could not read section data at 0x{section_start:08X}")
        return

    print()
    print(f"  Section at 0x{section_start:08X}: {num_entries} entries")
    print()
    print(f"  {'idx':<5}  {'offset':<8}  String")
    print(f"  {'─'*5}  {'─'*8}  {'─'*48}")

    for i in range(min(num_entries, MAX_DECODE)):
        off_bytes = read_bytes_vm(handle, section_start + i * 2, 2)
        if not off_bytes or len(off_bytes) < 2:
            break
        off = struct.unpack('<H', off_bytes)[0]
        if off >= len(section_data):
            print(f"  {i:<5}  {off:#06x}   [offset beyond buffer]")
            continue
        text = decode_ff7(section_data[off:])
        raw  = ' '.join(f'{b:02X}' for b in section_data[off:off+min(8, len(section_data)-off)])
        print(f"  {i:<5}  {off:#06x}   {text!r:<40}  [{raw}]")

    print()
    print(f"  ★ Use 0x{section_start:08X} as the section base in ff7_addresses.h")
    print(f"  ★ Lookup: off = *(uint16*)(base + idx*2);  text = base + off;")


# ── Phase 3: inspect hardcoded BSS addresses ──────────────────────────────────
def phase3_hardcoded(handle):
    """
    Read the two hardcoded addresses from sub_6892E5 / sub_68930C and
    print what's there.  One or both might be kernel2 section pointers
    or the kernel2 section data directly.
    """
    print()
    print("=" * 72)
    print("  PHASE 3 — Inspect hardcoded BSS addresses from sub_6892E5 area")
    print("=" * 72)

    for label, addr in [("0x00910480 (font/style arg)", ADDR_FONT_STYLE),
                        ("0x009104A0 (data arg to sub_65FF59)", ADDR_DATA_ARG)]:
        print()
        print(f"  Address: {label}")
        data = read_bytes_vm(handle, addr, 64)
        if data is None:
            print(f"    ERROR: could not read at 0x{addr:08X}")
            continue
        hex_dump(data, addr, f'64 bytes at 0x{addr:08X}')

        # Show the DWORD at addr as a potential pointer.
        ptr = read_u32(handle, addr)
        if ptr and 0x00400000 <= ptr <= 0x00F80000:
            print(f"\n    First DWORD = 0x{ptr:08X} (valid VA — might be a pointer)")
            target = read_bytes_vm(handle, ptr, 32)
            if target:
                th = ' '.join(f'{b:02X}' for b in target)
                print(f"    Target: [{th}]")
        elif ptr == 0:
            print(f"\n    First DWORD = NULL (0x009ADF0C was also null at title screen)")
            print(f"    May be populated only during battle — re-run during/after a battle")
        else:
            print(f"\n    First DWORD = 0x{ptr:08X}" if ptr else "    First DWORD = (unreadable)")

        # Try to interpret as FF7 text directly.
        text = decode_ff7(data[:32])
        if any(ch.isalpha() for ch in text):
            print(f"\n    Decoded as FF7 text: {text!r}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"kernel2_strings_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Kernel2 String Search")
        print("Locate ability/spell name data in live process memory.")
        print()

        pid = find_pid(PROCESS_NAME)
        if not pid:
            print("ERROR: ff7_en.exe not running.  Start FF7 first.")
            return
        print(f"FF7 running (PID {pid})")

        handle = open_process(pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        hits = phase1_scan(handle)
        if hits:
            phase2_reconstruct(handle, hits)
        phase3_hardcoded(handle)

        print()
        print("=" * 72)
        print("  NEXT STEPS")
        print("=" * 72)
        print()
        print("  If Phase 2 found the section start:")
        print("    → Add the section base address to ff7_addresses.h")
        print("    → In BattleActionThread: idx = actionIdx;")
        print("       off = *(uint16*)(section_base + idx*2);")
        print("       text = (char*)(section_base + off);   // FF7-encoded")
        print("    → Pass through FF7Text::Decode() for TTS")
        print()
        print("  If no hits found:")
        print("    → Get into the game (past title screen to field map)")
        print("    → Re-run this script — kernel2 may load lazily")

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
