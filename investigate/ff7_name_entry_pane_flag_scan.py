#!/usr/bin/env python3
"""
ff7_name_entry_pane_flag_scan.py — Find the "cursor is on the side panel"
flag for the naming screen, via a 3-snapshot A/B/A revert scan.

WHY THIS IS NEEDED (2026-07-12 panel probe result):
  0xDD4574 is the panel BUTTON index (0=Space, 1=Delete, 2=Select, 3=Default
  by on-screen order; 0 and 1 confirmed by Confirm-press effects). But it
  idles at 0 while the cursor is in the letter GRID and retains its last
  value after leaving the panel — so it cannot distinguish "on the panel's
  Space button" from "in the grid". No byte in the DD4400-DD4800 window
  flips on the grid<->panel transition (checked in two live sessions), so
  the pane flag must live elsewhere in the static range.

METHOD (A/B/A snapshot subtraction — same shape as ff7_menu_open_scan.py,
which found MENU_OPEN):
  Snapshot A : cursor parked in the GRID, hands off
  Snapshot B : cursor parked on the SIDE PANEL, hands off
  Snapshot A2: cursor back in the GRID, hands off
  Candidates = bytes where A == A2 (reverted) AND B != A (changed on panel).
  Constantly-churning bytes (frame counters) rarely read equal at the two
  A parks; cursor bytes and 0xDD4574 don't revert (the game retains them);
  the pane flag — grid=X, panel=Y, grid=X — survives exactly.

  Snapshots are single ReadProcessMemory calls over 0x400000-0xDE0000
  (~10.3MB, instant); the player just parks the cursor per voice cue.

OUTPUT: teed to name_entry_pane_flag_<timestamp>.log next to this script.
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"

STATIC_LO = 0x00400000
STATIC_HI = 0x00DE0000

# Known addresses, labeled in the report so the candidate list reads itself.
KNOWN = {
    0x00DD4538: "NAME_ENTRY_COL",
    0x00DD453C: "NAME_ENTRY_ROW",
    0x00DD4574: "PANEL_INDEX (known, non-reverting)",
    0x00DD46F0: "NAME_ENTRY_CARET",
    0x00DD46F8: "NAME_ENTRY_CHAR_INDEX",
    0x00DD46FC: "NAME_ENTRY_ACTIVE",
    0x00CC0D89: "GAME_MODE",
}

SETTLE_S = 2.0   # hands-off settle time after each cue before snapshotting

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
    # Spoken text is also printed so it lands in the tee'd log (project rule).
    print(f"[SPOKEN] {text}")
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


def beep_mark():
    """Single high beep marks the exact snapshot moment (synchronous)."""
    winsound.Beep(1400, 250)


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


def read_region(handle, lo, hi):
    size = hi - lo
    buf  = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytes(buf.raw)
    if read.value > 0:
        return bytes(buf.raw[:read.value])
    return None


def cued_snapshot(handle, instruction):
    """Speak the instruction, wait for the player to comply plus a settle
    period, mark the snapshot moment with a beep, then snapshot."""
    speak_wait(instruction + " I will beep, then take the snapshot. "
               "Keep your hands off until the next instruction.")
    time.sleep(SETTLE_S)
    beep_mark()
    time.sleep(0.3)          # let the beep's own moment pass
    snap = read_region(handle, STATIC_LO, STATIC_HI)
    print(f"  snapshot: {'OK, %d bytes' % len(snap) if snap else 'FAILED'}")
    return snap


# Chunked diff (same pattern as ff7_name_entry_scan.py): compare 4KB
# memoryview slices at C speed, byte-scan only slices that differ.
DIFF_CHUNK = 4096

def diff_positions(a, b):
    """Return the set of offsets where a and b differ."""
    n   = min(len(a), len(b))
    mva = memoryview(a)[:n]
    mvb = memoryview(b)[:n]
    out = set()
    for off in range(0, n, DIFF_CHUNK):
        end = min(off + DIFF_CHUNK, n)
        if mva[off:end] == mvb[off:end]:
            continue
        for i in range(off, end):
            if a[i] != b[i]:
                out.add(i)
    return out


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"name_entry_pane_flag_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found.")
            print("ERROR: ff7_en.exe not running.")
            return
        handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        # ---- Snapshot A: grid ----------------------------------------------
        snap_a = cued_snapshot(
            handle,
            "Pane flag scan. First: make sure the cursor is somewhere in the "
            "LETTER GRID. If you are on the side panel, press Left once. "
            "Then hands off.")
        if snap_a is None:
            speak_wait("Snapshot failed. Stopping.")
            return

        # ---- Snapshot B: panel ---------------------------------------------
        snap_b = cued_snapshot(
            handle,
            "Now move to the SIDE PANEL: press Right slowly until you are "
            "past the last grid column, on the buttons. Up to ten presses. "
            "Then hands off.")
        if snap_b is None:
            speak_wait("Snapshot failed. Stopping.")
            return

        # ---- Snapshot A2: grid again ----------------------------------------
        snap_a2 = cued_snapshot(
            handle,
            "Now press Left once to return to the letter grid. Then hands off.")
        if snap_a2 is None:
            speak_wait("Snapshot failed. Stopping.")
            return

        # ---- Analysis ---------------------------------------------------------
        print("\n" + "=" * 60)
        print("  ANALYSIS: bytes that changed grid->panel AND reverted")
        print("=" * 60)

        changed_ab  = diff_positions(snap_a, snap_b)
        changed_aa2 = diff_positions(snap_a, snap_a2)
        candidates  = sorted(changed_ab - changed_aa2)
        print(f"  grid->panel diffs: {len(changed_ab)}   "
              f"non-reverting (excluded): {len(changed_aa2 & changed_ab)}   "
              f"clean revert candidates: {len(candidates)}")

        print(f"\n  {'Address':12s}  {'grid':>4} {'panel':>5} {'grid2':>5}  Label")
        for i in candidates[:60]:
            addr = STATIC_LO + i
            print(f"  0x{addr:08X}  {snap_a[i]:4d} {snap_b[i]:5d} "
                  f"{snap_a2[i]:5d}  {KNOWN.get(addr, '')}")
        if len(candidates) > 60:
            print(f"  ... and {len(candidates) - 60} more (see counts above)")

        # Also report the known addresses' three values for orientation,
        # whether or not they made the candidate list.
        print("\n  Known addresses across the three snapshots:")
        for addr, label in sorted(KNOWN.items()):
            i = addr - STATIC_LO
            if 0 <= i < min(len(snap_a), len(snap_b), len(snap_a2)):
                print(f"  0x{addr:08X}  {snap_a[i]:4d} {snap_b[i]:5d} "
                      f"{snap_a2[i]:5d}  {label}")

        n = len(candidates)
        speak_wait(f"Scan done. {n} clean candidate"
                   f"{'s' if n != 1 else ''} found. You can finish the "
                   "naming screen normally now. Details are in the log.")
        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
