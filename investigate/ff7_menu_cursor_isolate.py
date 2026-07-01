#!/usr/bin/env python3
"""
ff7_menu_cursor_isolate.py — Find the main-menu cursor address by subtraction.

PROBLEM WITH PREVIOUS SCANS:
  The poll scan found 0x00CC1B42 but that is a field-script variable that
  freezes when the menu opens, not the actual cursor.  The root cause was that
  prior scans couldn't separate "addresses that change during menu idle" from
  "addresses that change only when the cursor moves."

THIS APPROACH:
  Both phases are taken with the menu already open and the field-script
  completely frozen, so field-script false-positives can never appear.

  Phase A — Menu Idle Baseline (cursor NOT moving, ~10 s)
    Records every address that changes inside the menu even without cursor
    input: animation frames, per-frame timers, rendering counters, etc.
    Call this set: idle_changers.

  Phase B — Menu Navigation (~30 s)
    Records every address that changes while you press Up/Down through all
    options ~20 times.
    Call this set: nav_changers.

  Cursor candidates = nav_changers − idle_changers
    These changed ONLY when you pressed direction buttons, not during idle.

  The cursor byte should have:
    - change count close to number of direction presses (~20)
    - last value in range 0–10 (Item through Quit)

POINTER SCAN (Phase C):
  For any heap candidate (address >= 0xDE0000) the game uses a static pointer
  to reach it.  Phase C scans the stable BSS/data range 0x400000–0xDE0000 for
  DWORD values near the heap candidate so we can use it across sessions.

USAGE:
  1. Start FF7 and load a save file so you are in the field.
  2. Do NOT open the menu yet.
  3. Run this script.  It will guide you with voice cues.
  4. When prompted: open the menu, then DO NOT TOUCH the cursor for ~12 s.
  5. When prompted: move the cursor up and down repeatedly for ~30 s.
  6. When prompted: close the menu and walk around for ~15 s (optional
     pointer-scan context).
  7. Press Ctrl+C any time after Phase B completes; the script will analyse
     and report.

OUTPUT:
  Log file in the same directory as this script.
  Candidates printed and spoken.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound
import struct

PROCESS_NAME = "ff7_en.exe"

# Memory regions to scan.
# We always poll the static BSS range; a separate full-range pass finds heap
# candidates in the same session so the pointer scan is possible.
STATIC_LO = 0x00400000
STATIC_HI = 0x00DE0000   # ~10 MB — stable between runs
HEAP_LO   = 0x00DE0000
HEAP_HI   = 0x02000000   # up to ~28 MB heap region

# Phase timing (seconds).
IDLE_DURATION = 12        # Phase A: keep cursor still inside menu
NAV_DURATION  = 35        # Phase B: move cursor up/down repeatedly
FIELD_DURATION = 15       # Phase C: walk in field for pointer-scan context (optional)

# Snapshot interval (seconds).  Shorter = more temporal resolution.
SNAP_INTERVAL = 0.10      # 10 snapshots/second

# Menu option names for display/speech.
MENU_OPTION_NAMES = {
    0:  "Item",
    1:  "Magic",
    2:  "Equip",
    3:  "Status",
    4:  "Order",
    5:  "Limit",
    6:  "Config",
    7:  "Unknown option 7",   # unlockable — update when seen
    8:  "Unknown option 8",   # unlockable — update when seen
    9:  "Save",
    10: "Quit",
}

PROCESS_VM_READ   = 0x0010
PROCESS_VM_QUERY  = 0x0400
PROCESS_VM_ALL    = PROCESS_VM_READ | PROCESS_VM_QUERY

# ─── Win32 helpers ────────────────────────────────────────────────────────────

k32 = ctypes.windll.kernel32


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
            timeout=90
        )
    except Exception:
        pass


def beep(freq=1000, ms=80):
    winsound.Beep(freq, ms)


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


def open_process(pid):
    handle = k32.OpenProcess(PROCESS_VM_ALL, False, pid)
    return handle if handle else None


def read_region(handle, lo, hi):
    """Read [lo, hi) as a bytearray.  Returns None on failure."""
    size = hi - lo
    buf  = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytearray(buf.raw)
    # Partial reads happen near unmapped pages; still use what we got.
    if read.value > 0:
        return bytearray(buf.raw[:read.value])
    return None


def read_dword(handle, addr):
    buf  = ctypes.create_string_buffer(4)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 4, ctypes.byref(read))
    if ok and read.value == 4:
        return struct.unpack_from('<I', buf.raw)[0]
    return None


def read_byte(handle, addr):
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    if ok and read.value == 1:
        return buf.raw[0]
    return None


# ─── Snapshot polling ─────────────────────────────────────────────────────────

def poll_phase(handle, lo, hi, duration_s, phase_label, countdown_beep=True):
    """
    Snapshot [lo, hi) every SNAP_INTERVAL seconds for duration_s seconds.
    Returns:
      changers : dict addr → change_count
      last_val : dict addr → final byte value
    """
    print(f"\n[{phase_label}] Scanning 0x{lo:08X}–0x{hi:08X} "
          f"({(hi-lo)//1024} KB) for {duration_s}s …")

    # Initial snapshot.
    prev = read_region(handle, lo, hi)
    if prev is None:
        print(f"  ERROR: cannot read region 0x{lo:08X}–0x{hi:08X}")
        return {}, {}

    changers  = {}   # addr → change count
    last_val  = {}   # addr → latest byte value
    deadline  = time.time() + duration_s
    snap_num  = 0
    next_snap = time.time() + SNAP_INTERVAL

    while time.time() < deadline:
        remaining = deadline - time.time()
        # Countdown beeps in the last 5 seconds.
        if countdown_beep and remaining <= 5:
            beep(800, 40)

        # Print progress every 5 snapshots.
        elapsed = duration_s - remaining
        if snap_num % 10 == 0:
            n_changed = len(changers)
            print(f"  {elapsed:5.1f}s  {n_changed} addrs changed so far …",
                  end='\r', flush=True)

        # Wait for next snapshot slot.
        sleep_for = next_snap - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)
        next_snap += SNAP_INTERVAL

        curr = read_region(handle, lo, hi)
        if curr is None:
            continue

        # Diff against previous snapshot.
        compare_len = min(len(prev), len(curr))
        for i in range(compare_len):
            if curr[i] != prev[i]:
                addr = lo + i
                changers[addr]  = changers.get(addr, 0) + 1
                last_val[addr]  = curr[i]

        prev = curr
        snap_num += 1

    elapsed = duration_s
    print(f"\n  Done: {snap_num} snapshots in {elapsed:.1f}s, "
          f"{len(changers)} addresses changed.")

    return changers, last_val


# ─── Pointer scan ─────────────────────────────────────────────────────────────

def pointer_scan(handle, target_addr, window=4096, lo=STATIC_LO, hi=STATIC_HI):
    """
    Scan [lo, hi) for DWORD values in [target_addr - window, target_addr + window].
    Returns list of (static_ptr_addr, dword_value, offset_from_target).
    """
    print(f"\n[Pointer scan] Looking for DWORD pointers near 0x{target_addr:08X} "
          f"(±{window} bytes) in static range 0x{lo:08X}–0x{hi:08X} …")

    buf = read_region(handle, lo, hi)
    if buf is None:
        print("  ERROR: cannot read static region for pointer scan.")
        return []

    results = []
    lo_target = target_addr - window
    hi_target = target_addr + window

    for i in range(0, len(buf) - 3):
        val = struct.unpack_from('<I', buf, i)[0]
        if lo_target <= val <= hi_target:
            static_addr = lo + i
            offset      = val - target_addr
            results.append((static_addr, val, offset))

    print(f"  Found {len(results)} pointer candidates.")
    return results


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"menu_isolate_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            speak_wait("FF7 not found. Start the game and load a save file first.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        # ── Orientation: read FIELD_ID ─────────────────────────────────────
        FIELD_ID_ADDR = 0x00CC15D0
        fid_buf = ctypes.create_string_buffer(2)
        fid_read = ctypes.c_size_t(0)
        k32.ReadProcessMemory(handle, ctypes.c_void_p(FIELD_ID_ADDR),
                              fid_buf, 2, ctypes.byref(fid_read))
        if fid_read.value == 2:
            field_id = struct.unpack_from('<h', fid_buf.raw)[0]
            print(f"FIELD_ID = {field_id}")
        else:
            field_id = -1
            print("FIELD_ID: could not read")

        # ── Phase A: Menu Idle Baseline ────────────────────────────────────
        speak_wait(
            "Phase A. Open the main menu now, but do NOT move the cursor. "
            "Keep the cursor completely still. I will beep when Phase A ends "
            f"in about {IDLE_DURATION} seconds."
        )
        print()
        print("=" * 60)
        print(f"  PHASE A: Menu Idle Baseline ({IDLE_DURATION}s)")
        print("  Open the menu and DO NOT press any direction buttons.")
        print("  We are recording what changes just from being in the menu.")
        print("=" * 60)

        idle_changers, idle_last = poll_phase(
            handle, STATIC_LO, STATIC_HI,
            IDLE_DURATION, "Phase A: Idle")

        beep(880, 200)
        time.sleep(0.2)
        beep(880, 200)

        # ── Phase B: Menu Navigation ───────────────────────────────────────
        speak_wait(
            "Phase B. Now press Up and Down through all menu options repeatedly "
            f"for about {NAV_DURATION} seconds. Go through all options multiple times. "
            "I will beep when done."
        )
        print()
        print("=" * 60)
        print(f"  PHASE B: Menu Navigation ({NAV_DURATION}s)")
        print("  Press Up/Down through ALL menu options ~20 times.")
        print("=" * 60)

        nav_changers, nav_last = poll_phase(
            handle, STATIC_LO, STATIC_HI,
            NAV_DURATION, "Phase B: Navigate")

        beep(1100, 300)
        time.sleep(0.3)
        beep(1100, 300)

        # ── Analysis: subtract idle set from nav set ───────────────────────
        print()
        print("=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        idle_set = set(idle_changers.keys())
        nav_set  = set(nav_changers.keys())

        nav_only       = nav_set - idle_set    # changed in nav but NOT in idle
        idle_only      = idle_set - nav_set    # changed in idle but NOT in nav
        both           = nav_set & idle_set    # changed in both (mostly noise)

        print(f"\n  Idle-only (field-noise, excluded):  {len(idle_only)}")
        print(f"  Both phases (animation/timers):      {len(both)}")
        print(f"  Nav-only (cursor candidates!):       {len(nav_only)}")

        # Filter nav-only candidates: last value must be in menu cursor range.
        cursor_range_candidates = [
            (addr, nav_changers[addr], nav_last.get(addr, 0xFF))
            for addr in nav_only
            if 0 <= nav_last.get(addr, 0xFF) <= 10
        ]

        # Sort by how close the change count is to 20 (expected button presses).
        cursor_range_candidates.sort(key=lambda t: abs(t[1] - 20))

        print(f"\n  Of nav-only: last value 0–10 (menu range):  "
              f"{len(cursor_range_candidates)}")

        if cursor_range_candidates:
            print()
            print("  TOP CURSOR CANDIDATES (sorted by closeness to ~20 presses):")
            print(f"  {'Address':12s}  {'Count':>6}  {'LastVal':>7}  Label")
            print(f"  {'-'*12}  {'-'*6}  {'-'*7}  {'-'*20}")
            for addr, cnt, val in cursor_range_candidates[:20]:
                label = MENU_OPTION_NAMES.get(val, f"val={val}")
                tag   = ""
                if addr < STATIC_HI:
                    tag = "  *** STATIC (stable between runs) ***"
                print(f"  0x{addr:08X}  {cnt:6d}  {val:7d}  {label}{tag}")
        else:
            print("  No nav-only candidates in menu cursor range 0–10.")
            print("  Consider:")
            print("   1. Re-run: make sure Phase A cursor was truly stationary.")
            print("   2. The cursor might be encoded as a different size (int16).")
            print("   3. The cursor might be in the heap range (0xDE0000+).")

        # Also dump all nav-only addresses regardless of value (for reference).
        print()
        print(f"  ALL nav-only addresses (count 5–35, any value) — top 30:")
        nav_only_all = sorted(
            [(addr, nav_changers[addr], nav_last.get(addr, 0xFF))
             for addr in nav_only
             if 5 <= nav_changers.get(addr, 0) <= 35],
            key=lambda t: abs(t[1] - 20)
        )
        print(f"  {'Address':12s}  {'Count':>6}  {'LastVal':>7}")
        print(f"  {'-'*12}  {'-'*6}  {'-'*7}")
        for addr, cnt, val in nav_only_all[:30]:
            static_tag = "  [static]" if addr < STATIC_HI else ""
            print(f"  0x{addr:08X}  {cnt:6d}  {val:7d}{static_tag}")

        # ── Phase C (optional): Pointer scan for heap candidates ───────────
        heap_candidates = [
            (addr, cnt, val)
            for addr, cnt, val in cursor_range_candidates
            if addr >= STATIC_HI
        ]

        if heap_candidates and len(heap_candidates) <= 5:
            speak_wait(
                "Optional Phase C. Close the menu and walk around in the field "
                f"for about {FIELD_DURATION} seconds. "
                "This lets me find the static pointer to the menu cursor. "
                "Press Control C to skip."
            )
            print()
            print("=" * 60)
            print(f"  PHASE C: Pointer scan for heap candidates ({FIELD_DURATION}s)")
            print("  Close the menu and walk around.")
            print("  Press Ctrl+C to skip.")
            print("=" * 60)
            try:
                time.sleep(FIELD_DURATION)
                for heap_addr, cnt, val in heap_candidates:
                    ptrs = pointer_scan(handle, heap_addr)
                    if ptrs:
                        print(f"\n  Pointers to 0x{heap_addr:08X} (count={cnt}, last={val}):")
                        for static_addr, dword_val, offset in ptrs[:20]:
                            print(f"    0x{static_addr:08X}  → 0x{dword_val:08X}  "
                                  f"(offset {offset:+d})")
                    else:
                        print(f"\n  No static pointers found for 0x{heap_addr:08X}.")
            except KeyboardInterrupt:
                print("\n  Phase C skipped.")

        # ── Summary ────────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)

        if cursor_range_candidates:
            best_addr, best_cnt, best_val = cursor_range_candidates[0]
            label = MENU_OPTION_NAMES.get(best_val, f"val={best_val}")
            static_note = ("STATIC (stable between runs)"
                           if best_addr < STATIC_HI
                           else "HEAP (pointer scan needed)")
            print(f"\n  Best candidate: 0x{best_addr:08X}")
            print(f"    Change count: {best_cnt}")
            print(f"    Last value:   {best_val} ({label})")
            print(f"    Address type: {static_note}")

            speak_wait(
                f"Best cursor candidate: address 0x{best_addr:08X}. "
                f"Change count {best_cnt}. Last value {best_val} = {label}. "
                f"Address type: {static_note}."
            )
        else:
            speak_wait("No cursor candidates found. Check the log.")

        print(f"\nLog saved to: {log_path}")
        print()
        print("NEXT STEPS:")
        print("  1. Run ff7_menu_cursor_verify.py with the best candidate address.")
        print("  2. If it is a heap address, update CANDIDATES in verify with the")
        print("     pointer-scan result and dereference at runtime.")
        print("  3. Once confirmed, update MENU_CURSOR in ff7_addresses.h and")
        print("     un-comment the MenuCursorThread spawn in proxy.cpp.")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
