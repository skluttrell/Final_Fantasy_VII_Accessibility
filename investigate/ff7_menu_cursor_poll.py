#!/usr/bin/env python3
"""
ff7_menu_cursor_poll.py — Find the main-menu cursor by polling change frequency.

The diff-based scan (ff7_menu_cursor_scan.py) produced heap addresses in the
0x013xxxxx range that change between game launches.  This script uses the
same poll+histogram approach that found the TITLE_CURSOR in ff7_title_poll.py,
but runs the scan and the immediate verify in ONE game session so heap
addresses are valid the entire time.

TWO SCAN PHASES in the same session:

  PHASE 1 — BSS/static-data region only (0x400000–0xDE0000 = first ~14 MB)
    If the cursor is in a static struct this phase finds it directly.
    The menu-state heap block may also live here if FF7's menu uses a static
    global pointer to a fixed allocation (common pattern in late-1990s C).

  PHASE 2 — Full range (0x400000–0x02000000 = 28 MB), immediately after Phase 1.
    Covers the heap allocation range (~0x0100000–0x0200000) where the menu
    block was seen in the previous run.  Same session = same heap addresses.

HOW TO USE:
  1. Load FF7 into a FIELD MAP.
  2. Run this script.  When it beeps, open the MAIN MENU.
  3. Move the cursor UP and DOWN through all options repeatedly — aim for
     20 + direction presses, spaced ~1 second apart.
  4. Close the menu, return to the field.
  5. Press Ctrl+C.
  6. Study the histogram.  The cursor byte changes once per button press;
     animation bytes change every poll (~200 ms = ~5x per second).
     Look for the count that matches your press count (20 ish moves).
  7. If Phase 1 finds it, great — it is in static data.
     If only Phase 2 finds it, it is heap-allocated and we need a pointer scan
     to find the static variable that points at the heap block.

Note: The script continues polling after you close the menu too.  Bytes that
stop changing when the menu closes (i.e., changed only while in the menu and
returned to a constant value after closing) are the most interesting.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound
from collections import defaultdict, Counter
import struct

PROCESS_NAME = "ff7_en.exe"

# Phase 1: static BSS / data region — where persistent FF7 state lives.
PHASE1_START = 0x00400000
PHASE1_END   = 0x00DE0000   # covers BSS up through MENU_OBJECTS at 0xDC0FC0

# Phase 2: include heap where the menu block was seen in the previous scan.
PHASE2_START = 0x00400000
PHASE2_END   = 0x02000000   # full 28 MB

POLL_MS      = 200          # poll interval in milliseconds

FIELD_ID_ADDR = 0xCC15D0   # known from ff7_addresses.h

PROCESS_VM_READ = 0x0410
MEM_COMMIT      = 0x1000
PAGE_GUARD      = 0x100
PAGE_NOACCESS   = 0x01


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', ctypes.c_ulong),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             ctypes.c_ulong),
        ('Protect',           ctypes.c_ulong),
        ('Type',              ctypes.c_ulong),
    ]


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak_wait(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=60
        )
    except Exception:
        pass


def beep_start():
    winsound.Beep(900, 200)


def beep_phase():
    winsound.Beep(600, 120)
    winsound.Beep(900, 120)
    winsound.Beep(1200, 200)


def beep_done():
    winsound.Beep(600, 150)
    winsound.Beep(900, 150)
    winsound.Beep(1200, 300)


def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True
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


def read_byte(handle, addr):
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok   = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    if ok and read.value == 1:
        return buf.raw[0]
    return None


def read_int16(handle, addr):
    buf  = ctypes.create_string_buffer(2)
    read = ctypes.c_size_t(0)
    ok   = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 2, ctypes.byref(read))
    if ok and read.value == 2:
        return struct.unpack_from('<h', buf.raw)[0]
    return None


def readable_regions(handle, start, end):
    mbi  = MEMORY_BASIC_INFORMATION()
    addr = start
    k32  = ctypes.windll.kernel32
    while addr < end:
        ret = k32.VirtualQueryEx(
            handle, ctypes.c_void_p(addr),
            ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not ret:
            break
        region_end = addr + mbi.RegionSize
        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_NOACCESS)
                and not (mbi.Protect & PAGE_GUARD)):
            size = min(region_end, end) - addr
            if size > 0:
                yield (addr, size)
        addr = max(region_end, addr + 1)


def read_all(handle, start, end):
    """Read entire [start, end) range. Returns dict {base: bytearray}."""
    k32    = ctypes.windll.kernel32
    result = {}
    chunk  = 65536
    buf    = ctypes.create_string_buffer(chunk)
    read   = ctypes.c_size_t(0)
    for base, size in readable_regions(handle, start, end):
        data   = bytearray()
        offset = 0
        while offset < size:
            n  = min(chunk, size - offset)
            ok = k32.ReadProcessMemory(
                handle, ctypes.c_void_p(base + offset),
                buf, n, ctypes.byref(read))
            got = read.value if ok else 0
            data.extend(buf.raw[:got] if got else b'\x00' * n)
            if got and got < n:
                data.extend(b'\x00' * (n - got))
            offset += n
        result[base] = data
    return result


def poll_phase(handle, scan_start, scan_end, label, press_target):
    """
    Poll [scan_start, scan_end) until Ctrl+C.  Return (change_count, last_values).
    change_count[addr] = number of polls where this byte changed.
    """
    print(f"\n{'='*60}")
    print(f"  PHASE: {label}")
    print(f"  Range: 0x{scan_start:08X}–0x{scan_end:08X} "
          f"({(scan_end - scan_start) // 1024} KB)")
    print(f"  Press Ctrl+C when done moving the cursor ~{press_target} times.")
    print(f"{'='*60}")

    prev         = read_all(handle, scan_start, scan_end)
    poll_count   = 0
    change_count = defaultdict(int)
    last_values  = {}

    for base, data in prev.items():
        for i, b in enumerate(data):
            last_values[base + i] = b

    beep_start()

    try:
        while True:
            time.sleep(POLL_MS / 1000.0)
            curr = read_all(handle, scan_start, scan_end)
            poll_count += 1

            for base, data_new in curr.items():
                data_old = prev.get(base)
                if data_old is None:
                    continue
                n = min(len(data_old), len(data_new))
                for i in range(n):
                    if data_old[i] != data_new[i]:
                        addr = base + i
                        change_count[addr] += 1
                        last_values[addr]   = data_new[i]

            prev = curr

            if poll_count % 10 == 0:
                elapsed = poll_count * POLL_MS / 1000
                print(f"  {elapsed:.0f}s  {len(change_count)} addrs changed", flush=True)

    except KeyboardInterrupt:
        print()

    print(f"  Stopped: {poll_count} polls ({poll_count * POLL_MS / 1000:.1f}s)")
    return change_count, last_values, poll_count


def report(label, change_count, last_values, poll_count, press_target):
    """Print histogram and candidates for one poll phase."""
    print(f"\n{'='*60}")
    print(f"  RESULTS: {label}")
    print(f"{'='*60}")

    if not change_count:
        print("  No changes detected in this range.")
        return

    ranked = sorted(change_count.items(), key=lambda x: x[1])
    count_hist = Counter(cnt for _, cnt in ranked)

    print(f"  Total addresses that changed: {len(change_count)}")
    print()
    print("  HISTOGRAM (change count → number of addresses at that count)")
    print("  The cursor byte should appear near the count matching your")
    print(f"  number of direction presses (target: ~{press_target}).")
    print()
    lo  = max(1, press_target - 10)
    hi  = press_target + 15
    any_printed = False
    for n in range(1, hi + 1):
        freq = count_hist.get(n, 0)
        if freq > 0:
            bar  = '#' * min(freq, 50)
            mark = " <-- TARGET RANGE" if lo <= n <= hi else ""
            print(f"  {n:5d}  {freq:7d}  {bar}{mark}")
            any_printed = True
        elif any_printed and n > hi:
            break
    print()

    # Candidates: changed count in [lo, hi] AND last value in 0–9 (menu range)
    cands = [(addr, cnt, last_values.get(addr, -1))
             for addr, cnt in ranked
             if lo <= cnt <= hi]
    small = [(a, c, v) for a, c, v in cands if 0 <= v <= 9]

    print(f"  Candidates (count {lo}–{hi}, any last value): {len(cands)}")
    print(f"  Of those with last value 0–9 (menu cursor range): {len(small)}")
    print()

    if small:
        print(f"  {'Address':>10}  {'Count':>5}  {'LastVal':>7}  Note")
        print(f"  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*40}")
        for addr, cnt, v in small[:60]:
            if v == 8:
                note = "<-- 0-indexed QUIT (no PHS): strong cursor candidate"
            elif v == 9:
                note = "<-- 0-indexed QUIT (with PHS): strong cursor candidate"
            elif v <= 9:
                note = f"<-- value {v} (menu range)"
            else:
                note = ""
            print(f"  0x{addr:08X}  {cnt:5d}  {v:7}  {note}")

    if not small and cands:
        print("  No candidates with last value 0–9.  Top 20 by last value:")
        for addr, cnt, v in sorted(cands, key=lambda x: x[2])[:20]:
            print(f"  0x{addr:08X}  count={cnt}  last={v}")

    # Also report static-range candidates separately
    static_small = [(a, c, v) for a, c, v in small if a < 0x00DE0000]
    if static_small:
        print()
        print("  *** STATIC-RANGE CANDIDATES (address < 0xDE0000) ***")
        print("  These are in BSS/data — always at the same address between runs!")
        for addr, cnt, v in static_small:
            print(f"  0x{addr:08X}  count={cnt}  last={v}  <-- STABLE ADDRESS")


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"menu_poll_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found. Start the game first.")
            print(f"ERROR: {PROCESS_NAME} not running.")
            print(f"\nLog saved to: {log_path}")
            return

        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
        if not handle:
            speak_wait("Cannot open FF7. Try running as Administrator.")
            print("ERROR: OpenProcess failed.")
            print(f"\nLog saved to: {log_path}")
            return

        print(f"PID: {pid}")

        field_id = read_int16(handle, FIELD_ID_ADDR)
        if field_id is None or field_id == 0:
            speak_wait("Not in a field map. Load a save and enter a field first.")
            print(f"ERROR: FIELD_ID = {field_id!r}. Must be non-zero.")
            print(f"\nLog saved to: {log_path}")
            return
        print(f"FIELD_ID = {field_id}")
        print()

        PRESS_TARGET = 20

        speak_wait(
            "Two-phase scan. "
            "For each phase, I will beep once when polling starts. "
            "Open the main menu, then press Up and Down through all options "
            f"about {PRESS_TARGET} times, spacing each press about one second apart. "
            "Then close the menu and press Control C to stop each phase. "
            "Phase 1 scans the small static-data region. "
            "Phase 2 scans the full range including the heap. "
            "Starting Phase 1 now — beep means go."
        )

        # --- PHASE 1: static BSS range only ---
        c1, v1, p1 = poll_phase(
            handle, PHASE1_START, PHASE1_END,
            "Phase 1 — static BSS/data (0x400000–0xDE0000)",
            PRESS_TARGET
        )
        report("Phase 1 — static BSS/data", c1, v1, p1, PRESS_TARGET)

        # Check if anything useful was found in static range
        static_hits = [(a, c, v1.get(a,-1)) for a,c in c1.items()
                       if c1[a] > 3 and 0 <= v1.get(a,-1) <= 9]
        if static_hits:
            speak_wait(
                "Phase 1 found candidates in the static data range. "
                "Check the log — these will be stable between game launches."
            )
        else:
            speak_wait(
                "Phase 1 found nothing obvious in the static range. "
                "Starting Phase 2 — the full heap-inclusive scan. "
                "Open the menu again and repeat cursor moves, then Control C."
            )

        beep_phase()

        # --- PHASE 2: full range (same session = same heap addresses) ---
        c2, v2, p2 = poll_phase(
            handle, PHASE2_START, PHASE2_END,
            "Phase 2 — full range (0x400000–0x2000000)",
            PRESS_TARGET
        )
        report("Phase 2 — full range", c2, v2, p2, PRESS_TARGET)

        # Cross-phase: addresses found in BOTH phases with same last value
        both = {a for a in c1 if a in c2}
        if both:
            print(f"\n  Addresses in BOTH phases: {len(both)}")
            for a in sorted(both)[:20]:
                print(f"  0x{a:08X}  phase1_count={c1[a]}  phase2_count={c2[a]}"
                      f"  last={v2.get(a,'?')}")

        # Phase 2 heap hits (not in static range)
        heap_small = [(a, c, v2.get(a,-1)) for a,c in c2.items()
                      if a >= 0x00DE0000
                      and abs(c - PRESS_TARGET) <= 12
                      and 0 <= v2.get(a,-1) <= 9]
        if heap_small:
            print(f"\n  === HEAP CANDIDATES (Phase 2, 0xDE0000+) ===")
            print(f"  These addresses are valid THIS SESSION only.")
            print(f"  A pointer scan is needed to find the stable base pointer.")
            for addr, cnt, v in sorted(heap_small, key=lambda x: abs(x[1]-PRESS_TARGET))[:20]:
                print(f"  0x{addr:08X}  count={cnt}  last={v}")

        print(f"\nLog saved to: {log_path}")
        beep_done()
        speak_wait("Scan complete. Check the log.")

    finally:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
