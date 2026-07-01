#!/usr/bin/env python3
"""
ff7_menu_open_scan.py — Find a flag that is set when the main menu is open.

WHY WE NEED THIS:
  The menu cursor address (0x00DC1154) only changes when the cursor moves.
  Two problems result:
    1. False announce at startup: BSS reads 0 (=Item) when the game first
       loads, so the polling thread announces "Item" at new-game load time
       even though no menu is open.
    2. No re-announce on re-open: if the cursor was on Save when the player
       closed the menu, and they reopen the menu with the cursor still on Save,
       the address hasn't changed so nothing is spoken.  The player has to
       press a direction to hear where they are.
  Both problems go away if we gate all menu TTS on a "menu is open" flag.

APPROACH — symmetric toggle scan:
  The flag must toggle when the menu opens and un-toggle when it closes.
  We use three snapshots:

    Snap A  —  in field, menu CLOSED  (baseline)
    Snap B  —  menu OPEN, cursor NOT moving  (hold still)
    Snap C  —  menu CLOSED again  (back in field)

  Candidates: addresses where value changed A→B AND reverted B→C to the
  same value as A.  This symmetric A→B→A pattern is the signature of a
  state-flag, not an animation counter or one-directional accumulator.

  We score candidates:
    - 1-bit toggle (0↔1 or 0↔nonzero) gets priority — cleanest gate
    - Any symmetric toggle is kept as a secondary candidate

USAGE:
  1. Start FF7 and load a save file.  Be in the field, menu closed.
  2. Run this script; it will guide you with voice cues.
  3. When prompted: DO NOT open the menu yet — just stand still so Snap A
     captures the field baseline.  Press Enter (or wait for the beep).
  4. When prompted: open the menu and hold the cursor still.  Beep signals
     when Snap B is taken.
  5. When prompted: close the menu and stand still in the field.  Beep signals
     Snap C.
  6. Results are reported and spoken.
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

STATIC_LO = 0x00400000
STATIC_HI = 0x00DE0000   # ~10 MB stable BSS/data region

# Seconds to wait (with countdown) after each voice cue before snapping.
SETTLE_TIME = 6   # gives the player time to open/close the menu and let it settle

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
PROCESS_VM_ALL   = PROCESS_VM_READ | PROCESS_VM_QUERY

k32 = ctypes.windll.kernel32


# ── I/O helpers ───────────────────────────────────────────────────────────────

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


def beep(freq=1000, ms=120):
    winsound.Beep(freq, ms)


def countdown(seconds, label="Snapping in"):
    for i in range(seconds, 0, -1):
        print(f"  {label}: {i}s …", end='\r', flush=True)
        time.sleep(1)
    print()


# ── Process / memory helpers ──────────────────────────────────────────────────

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
    """Read [lo, hi) as a bytearray.  Returns None on complete failure."""
    size = hi - lo
    buf  = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytearray(buf.raw)
    if read.value > 0:
        return bytearray(buf.raw[:read.value])
    return None


def snap(handle, label):
    print(f"\n  Taking snapshot {label} …", end=' ', flush=True)
    data = read_region(handle, STATIC_LO, STATIC_HI)
    if data is None:
        print("FAILED")
        return None
    print(f"OK ({len(data)//1024} KB)")
    return data


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse(snap_a, snap_b, snap_c):
    """
    Return a list of (addr, val_a, val_b, val_c) for addresses where:
      - val_a != val_b  (changed when menu opened)
      - val_c == val_a  (reverted when menu closed)
    Sorted so clean 0-nonzero-0 toggles come first.
    """
    length = min(len(snap_a), len(snap_b), len(snap_c))
    results = []

    for i in range(length):
        a = snap_a[i]
        b = snap_b[i]
        c = snap_c[i]

        if a == b:
            continue          # didn't change when menu opened
        if c != a:
            continue          # didn't revert when menu closed

        addr = STATIC_LO + i
        results.append((addr, a, b, c))

    # Sort: clean 0↔nonzero toggle first, then by address
    def sort_key(t):
        addr, a, b, _ = t
        is_clean = (a == 0 and b != 0) or (a != 0 and b == 0)
        is_bit   = b in (0, 1) and a in (0, 1)
        return (not is_clean, not is_bit, addr)

    results.sort(key=sort_key)
    return results


def summarise_candidates(candidates):
    """Print candidate table and return a short spoken summary."""
    print(f"\n  Found {len(candidates)} symmetric-toggle candidates:")
    print()
    print(f"  {'Address':12s}  {'A(field)':>8}  {'B(menu)':>7}  {'C(field)':>8}  Notes")
    print(f"  {'-'*12}  {'-'*8}  {'-'*7}  {'-'*8}  {'-'*30}")

    for addr, a, b, c in candidates[:40]:
        notes = []
        if a == 0 and b != 0:
            notes.append("0→nonzero→0 (ideal flag)")
        elif a != 0 and b == 0:
            notes.append("nonzero→0→nonzero")
        if abs(b - a) == 1:
            notes.append("±1 toggle")
        note_str = "; ".join(notes) if notes else ""
        print(f"  0x{addr:08X}  {a:8d}  {b:7d}  {c:8d}  {note_str}")

    if len(candidates) > 40:
        print(f"  … and {len(candidates)-40} more (see log)")

    # Build spoken summary for top candidates.
    if not candidates:
        return "No symmetric toggle candidates found."
    addr, a, b, c = candidates[0]
    return (f"Top candidate: address 0x{addr:08X}. "
            f"Field value {a}, menu value {b}, reverted to {c}. "
            f"{'Clean zero to nonzero flag.' if a == 0 else 'Non-zero field value.'}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"menu_open_{time.strftime('%Y%m%d_%H%M%S')}.log"
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

        # Read FIELD_ID for orientation.
        fid_buf  = ctypes.create_string_buffer(2)
        fid_read = ctypes.c_size_t(0)
        k32.ReadProcessMemory(handle, ctypes.c_void_p(0x00CC15D0),
                              fid_buf, 2, ctypes.byref(fid_read))
        field_id = struct.unpack_from('<h', fid_buf.raw)[0] if fid_read.value == 2 else -1
        print(f"FIELD_ID = {field_id}")
        print()

        # ── Snap A: field, menu closed ────────────────────────────────────
        speak_wait(
            "Snap A. You should be standing in the field with the menu closed. "
            "Do not open the menu. "
            f"I will take the snapshot in {SETTLE_TIME} seconds."
        )
        print("=" * 60)
        print("  SNAP A — Field baseline (menu CLOSED)")
        print("  Do not open the menu.")
        print("=" * 60)
        countdown(SETTLE_TIME, "Snapshot A in")
        snap_a = snap(handle, "A")
        beep(880, 150)
        if snap_a is None:
            speak_wait("Snapshot A failed. Aborting.")
            return

        # ── Snap B: menu open, cursor stationary ──────────────────────────
        speak_wait(
            "Snap B. Open the main menu now. "
            "Do not move the cursor — just open it and hold still. "
            f"I will take the snapshot in {SETTLE_TIME} seconds."
        )
        print()
        print("=" * 60)
        print("  SNAP B — Menu open (cursor STATIONARY)")
        print("  Open the menu and DO NOT press direction buttons.")
        print("=" * 60)
        countdown(SETTLE_TIME, "Snapshot B in")
        snap_b = snap(handle, "B")
        beep(1100, 150)
        if snap_b is None:
            speak_wait("Snapshot B failed. Aborting.")
            return

        # ── Snap C: menu closed again ─────────────────────────────────────
        speak_wait(
            "Snap C. Close the menu and stand still in the field. "
            f"I will take the final snapshot in {SETTLE_TIME} seconds."
        )
        print()
        print("=" * 60)
        print("  SNAP C — Field again (menu CLOSED)")
        print("  Close the menu and stand still.")
        print("=" * 60)
        countdown(SETTLE_TIME, "Snapshot C in")
        snap_c = snap(handle, "C")
        beep(660, 150)
        if snap_c is None:
            speak_wait("Snapshot C failed. Aborting.")
            return

        # ── Analysis ──────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  ANALYSIS — symmetric toggle A→B→A")
        print("=" * 60)
        print()
        print("  Addresses where value changed A→B (menu opened)")
        print("  AND reverted B→C back to A (menu closed).")
        print()

        candidates = analyse(snap_a, snap_b, snap_c)
        summary    = summarise_candidates(candidates)

        # Dump all raw A→B changes for reference (even non-reverting ones).
        ab_changes = 0
        for i in range(min(len(snap_a), len(snap_b))):
            if snap_a[i] != snap_b[i]:
                ab_changes += 1
        print()
        print(f"  Total A→B changes (noise floor): {ab_changes}")
        print(f"  Of those, symmetric A→B→A:       {len(candidates)}")
        print()

        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print()
        if candidates:
            print("  Best candidates for 'menu is open' flag:")
            for addr, a, b, c in candidates[:5]:
                print(f"    0x{addr:08X}  field={a}  menu={b}")
        else:
            print("  No candidates found.")
            print("  Suggestions:")
            print("   - Re-run; make sure the menu was fully open for Snap B")
            print("     and fully closed for Snap A and Snap C.")
            print("   - Try a longer SETTLE_TIME so transitions are complete.")

        print()
        print(f"Log saved to: {log_path}")

        speak_wait(summary + " Check the log for the full list.")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
