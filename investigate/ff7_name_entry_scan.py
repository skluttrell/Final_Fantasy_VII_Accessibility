#!/usr/bin/env python3
"""
ff7_name_entry_scan.py — Find every address needed for name-entry-screen TTS,
in a SINGLE visit to the naming screen.

WHY ONE SCRIPT DOES EVERYTHING:
  Unlike the main menu (open any time), the naming screen only appears at
  scripted story moments (Cloud right after the opening battles, Barret a bit
  later, etc.).  Each visit costs the player minutes of intro gameplay, so this
  script front-loads all scan phases AND finishes with a live decode phase —
  no separate verify run needed unless something surprises us.

WHAT WE ALREADY KNOW (anchor / built-in validation):
  0xDD46F8 = name-entry grid cursor COLUMN (0–9), sourced from the Echo mod's
  hext patch '01 - Disable Name Change.txt'.  Phase C (Left/Right presses)
  must re-discover this exact address.  If it does, the methodology is proven
  and the OTHER phases' results can be trusted.  If it doesn't, stop and
  distrust everything.

WHAT WE ARE HUNTING:
  1. ROW cursor (screenshot shows 7 grid rows: A–J / K–T / U–Z,.+- /
     a–j / k–t / u–z:;'" / 0–9).  Expect a byte 0–6 near 0xDD46F8.
  2. COLUMN cursor — validation only, see above.
  3. NAME BUFFER + caret: adding letters (Confirm presses) then deleting them
     (Cancel presses) writes the in-progress name somewhere.  Signature:
     a run of ADJACENT addresses that change once each during the add phase
     and again during the delete phase (each press touches the NEXT cell,
     so per-cell change count is ~1-2, but the cells are contiguous), plus a
     single counter (the caret / current length) that changes on EVERY press
     in both phases and ends <= 12.
  4. SIDE PANEL (Space/Delete/Select/Default): unknown encoding.  Best guess
     is that it's just column 10 (one past the grid) or a separate mode byte.
     Probed interactively in the final live phase rather than scanned.

SCAN DESIGN (frozen-context isolate, technique #3 in the research doc —
same method that found MENU_CURSOR, CONFIG_ROW, SOUND_CURSOR):
  All phases happen with the naming screen open.  Field scripts are frozen
  (menu-module context), so the background churn is only animation/timers,
  which Phase A's idle baseline subtracts out.

  Phase A  IDLE      12 s  touch nothing                    -> baseline set
  Phase B  ROWS      20 s  alternate Up / Down  ~1 press/s  -> row candidates
  Phase C  COLUMNS   20 s  alternate Left / Right           -> column validation
  Phase D  ADD       15 s  press Confirm ~4 times slowly    -> buffer + caret
  Phase E  DELETE    15 s  press Cancel  ~4 times slowly    -> buffer + caret
  (Up/Down and Left/Right are ALTERNATED, not held in one direction, so the
   cursor bounces between two cells and never wraps an edge — wrapping might
   touch extra state, e.g. hopping into the side panel from column 9.)

  Analysis by set subtraction:
    row_cands  = changed(B) - changed(A) - changed(C)
    col_cands  = changed(C) - changed(A) - changed(B)
    buf_cands  = (changed(D) | changed(E)) - changed(A) - changed(B) - changed(C)
  Then a final LIVE DECODE phase polls the best candidates and SPEAKS what it
  sees ("row 3", "letter g", full name readback) while the player navigates
  freely — the player's own ears confirm correctness on the spot.  The name
  buffer readback is self-verifying: navigate to a letter the script names,
  press Confirm, and the script should speak a name ending in that letter.

AUDIO CUE PROTOCOL (lesson from the battle-cursor sessions: the player is
blind and cannot alt-tab to read chat mid-test — everything is self-cued):
  - SAPI speech gives the full instruction for the NEXT phase first.
  - A DOUBLE BEEP (two short high beeps) marks the exact moment to START.
  - A TRIPLE BEEP marks the exact moment to STOP (hands off).
  - SAPI is too slow/imprecise for timing marks (v2.4 lesson) — beeps only.

USAGE:
  1. Start FF7, start a New Game, play until "Please enter a name" appears.
  2. LEAVE THE CURSOR ALONE (wherever it starts is fine) and start this script.
  3. Follow the voice cues.  Total hands-on time is about 2.5 minutes.
  4. After the live phase, the naming screen is still open with a few junk
     letters appended — press Cancel a few times to clean up, then enter the
     real name as usual.  Nothing this script does is written to the game.

OUTPUT:
  Everything printed is also teed to name_entry_scan_<timestamp>.log next to
  this script (project rule: never require manual copy-paste of results).
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound
import struct

PROCESS_NAME = "ff7_en.exe"

# Static BSS/data range — stable across runs, same window every prior menu
# scan used.  The known column cursor (0xDD46F8) is inside it, and menu-module
# state has always been static so far; no heap pass needed unless this fails.
STATIC_LO = 0x00400000
STATIC_HI = 0x00DE0000

# Known anchor: grid column cursor.  Phase C must re-find this.
KNOWN_COLUMN_ADDR = 0x00DD46F8

# Phase durations (seconds).
IDLE_DURATION   = 12
ROWNAV_DURATION = 20
COLNAV_DURATION = 20
ADD_DURATION    = 15
DEL_DURATION    = 15
LIVE_DURATION   = 90

SNAP_INTERVAL = 0.10   # 10 snapshots/second — same as every prior scan

# ---------------------------------------------------------------------------
# The character grid as seen in the player's screenshot (7 rows x 10 cols).
# Row 5 columns 8-9 were hard to read in the screenshot — marked uncertain;
# the live decode phase will tell us if they're wrong (player hears the
# script's guess, presses Confirm, then hears the actual name readback).
# ---------------------------------------------------------------------------
GRID = [
    list("ABCDEFGHIJ"),
    list("KLMNOPQRST"),
    ["U", "V", "W", "X", "Y", "Z", ",", ".", "+", "-"],
    list("abcdefghij"),
    list("klmnopqrst"),
    ["u", "v", "w", "x", "y", "z", ":", ";", "'", '"'],   # cols 8-9 uncertain
    list("0123456789"),
]

# Spoken names for characters SAPI would otherwise mangle or skip.
CHAR_SPOKEN = {
    ",": "comma", ".": "period", "+": "plus", "-": "minus",
    ":": "colon", ";": "semicolon", "'": "apostrophe", '"': "quote",
    " ": "space",
}


def spoken_char(ch):
    """Return a SAPI-friendly spoken form of a grid character.
    Uppercase letters are prefixed so 'B' vs 'b' are distinguishable by ear."""
    if ch in CHAR_SPOKEN:
        return CHAR_SPOKEN[ch]
    if ch.isupper():
        return f"capital {ch}"
    return ch


# ---------------------------------------------------------------------------
# FF7 text decoding for the name buffer readback.
# The PC US table is (ASCII - 0x20) for the whole printable range:
#   0x00 = space, 0x10-0x19 = '0'-'9', 0x21-0x3A = 'A'-'Z', 0x41-0x5A = 'a'-'z'
# 0xFF terminates / fills empty slots.  (Research doc section 12.)
# ---------------------------------------------------------------------------
def decode_ff7_name(raw):
    out = []
    for b in raw:
        if b == 0xFF:
            break
        c = b + 0x20
        out.append(chr(c) if 0x20 <= c <= 0x7E else "?")
    return "".join(out)


PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


class Tee:
    """Mirror everything printed to a log file (project logging rule)."""
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
    """Blocking SAPI speech — used for phase INSTRUCTIONS only, never for
    timing marks (SAPI startup latency is unpredictable; beeps mark time)."""
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


def beep_start():
    """Double high beep = 'begin pressing NOW'."""
    winsound.Beep(1200, 120); time.sleep(0.08); winsound.Beep(1200, 120)


def beep_stop():
    """Triple low beep = 'hands off NOW'."""
    for _ in range(3):
        winsound.Beep(600, 100); time.sleep(0.06)


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
        return bytearray(buf.raw)
    if read.value > 0:
        return bytearray(buf.raw[:read.value])
    return None


def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    if ok and read.value == n:
        return buf.raw
    return None


def read_byte(handle, addr):
    raw = read_bytes(handle, addr, 1)
    return raw[0] if raw is not None else None


# ---------------------------------------------------------------------------
# Snapshot polling — identical mechanics to ff7_menu_cursor_isolate.py.
# ---------------------------------------------------------------------------
def poll_phase(handle, duration_s, phase_label):
    """Snapshot the static range every SNAP_INTERVAL for duration_s.
    Returns (changers: addr->count, last_val: addr->final byte)."""
    print(f"\n[{phase_label}] Scanning 0x{STATIC_LO:08X}-0x{STATIC_HI:08X} "
          f"for {duration_s}s ...")

    prev = read_region(handle, STATIC_LO, STATIC_HI)
    if prev is None:
        print("  ERROR: cannot read static region")
        return {}, {}

    changers  = {}
    last_val  = {}
    deadline  = time.time() + duration_s
    snap_num  = 0
    next_snap = time.time() + SNAP_INTERVAL

    while time.time() < deadline:
        sleep_for = next_snap - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)
        next_snap += SNAP_INTERVAL

        curr = read_region(handle, STATIC_LO, STATIC_HI)
        if curr is None:
            continue

        compare_len = min(len(prev), len(curr))
        for i in range(compare_len):
            if curr[i] != prev[i]:
                addr = STATIC_LO + i
                changers[addr] = changers.get(addr, 0) + 1
                last_val[addr] = curr[i]

        prev = curr
        snap_num += 1
        if snap_num % 20 == 0:
            print(f"  {snap_num} snaps, {len(changers)} addrs changed ...",
                  end='\r', flush=True)

    print(f"\n  Done: {snap_num} snapshots, {len(changers)} addresses changed.")
    return changers, last_val


def run_cued_phase(handle, instruction, duration_s, label):
    """Speak the instruction, mark the start with a double beep, poll, then
    mark the stop with a triple beep.  Keeps every phase's timing identical."""
    speak_wait(instruction + " Start at the double beep. "
               "Stop when you hear three low beeps.")
    beep_start()
    changers, last_val = poll_phase(handle, duration_s, label)
    beep_stop()
    return changers, last_val


# ---------------------------------------------------------------------------
# Candidate analysis helpers
# ---------------------------------------------------------------------------
def rank_cursor_candidates(cands, changers, last_val, max_value, expect_presses):
    """Filter to plausible cursor bytes and sort by closeness to the expected
    press count.  A cursor byte changes once per press; anything changing far
    more often is an animation counter that slipped past the baseline."""
    rows = [(a, changers[a], last_val.get(a, 0xFF))
            for a in cands if last_val.get(a, 0xFF) <= max_value]
    rows.sort(key=lambda t: (abs(t[1] - expect_presses), t[0]))
    return rows


def find_adjacent_clusters(addrs, max_gap=2, min_len=2):
    """Group sorted addresses into runs (gap <= max_gap).  The name buffer
    shows up as a run of contiguous byte cells; isolated singles are noise."""
    clusters = []
    for a in sorted(addrs):
        if clusters and a - clusters[-1][-1] <= max_gap:
            clusters[-1].append(a)
        else:
            clusters.append([a])
    return [c for c in clusters if len(c) >= min_len]


def print_candidates(title, rows, grid_hint=None):
    print(f"\n  {title}:")
    if not rows:
        print("    (none)")
        return
    print(f"    {'Address':12s}  {'Count':>5}  {'Last':>4}  Note")
    for addr, cnt, val in rows[:15]:
        note = ""
        if grid_hint == "row" and val < len(GRID):
            note = f"row {val} starts with '{GRID[val][0]}'"
        elif grid_hint == "col":
            note = f"column {val}"
        if addr == KNOWN_COLUMN_ADDR:
            note += "  <<< KNOWN COLUMN ANCHOR"
        print(f"    0x{addr:08X}  {cnt:5d}  {val:4d}  {note}")


# ---------------------------------------------------------------------------
# Live decode phase — the built-in "verify run"
# ---------------------------------------------------------------------------
def live_decode(handle, row_addr, col_addr, buf_addr, caret_addr):
    """Poll the winning candidates and speak changes while the player
    navigates freely.  This is the same feedback the eventual mod feature
    will give, so if it sounds right here, the addresses are right."""
    print(f"\n[LIVE] row=0x{row_addr:08X} col=0x{col_addr:08X} "
          f"buf={'0x%08X' % buf_addr if buf_addr else 'none'} "
          f"caret={'0x%08X' % caret_addr if caret_addr else 'none'}")

    speak_wait(
        "Live test. Move around the letter grid and listen. I will speak the "
        "letter under the cursor after each move. Also try pressing Confirm "
        "to add a letter, and Cancel to delete one; I will read the name "
        "back. Try moving right past the edge of the grid to reach the side "
        "panel with Space, Delete, Select and Default, and tell Claude "
        "afterwards what you heard there. You have ninety seconds, "
        "starting at the double beep."
    )
    beep_start()

    last_row   = read_byte(handle, row_addr)
    last_col   = read_byte(handle, col_addr)
    last_name  = None
    last_caret = read_byte(handle, caret_addr) if caret_addr else None
    deadline   = time.time() + LIVE_DURATION

    while time.time() < deadline:
        time.sleep(0.10)
        row   = read_byte(handle, row_addr)
        col   = read_byte(handle, col_addr)
        caret = read_byte(handle, caret_addr) if caret_addr else None
        name  = None
        if buf_addr:
            raw = read_bytes(handle, buf_addr, 16)
            if raw is not None:
                name = decode_ff7_name(raw)

        if row is None or col is None:
            continue

        # Cursor moved: speak the grid cell (or raw values when out of the
        # known 7x10 grid — that's the side-panel signature we want logged).
        if row != last_row or col != last_col:
            if row < len(GRID) and col < len(GRID[row]):
                ch = GRID[row][col]
                msg = spoken_char(ch)
            else:
                msg = f"row {row}, column {col}, outside grid"
            print(f"  [CURSOR] row={row} col={col} -> {msg}")
            speak_wait(msg)
            last_row, last_col = row, col

        # Name changed: read it back in full.
        if name is not None and name != last_name:
            if last_name is not None:      # skip the initial capture
                print(f"  [NAME] '{name}' caret={caret}")
                speak_wait(f"Name is now {' '.join(name) if name else 'empty'}")
            last_name = name

        if caret is not None and caret != last_caret:
            print(f"  [CARET] {last_caret} -> {caret}")
            last_caret = caret

    beep_stop()
    speak_wait("Live test finished. You can clean up the name now. "
               "Press Cancel to delete any junk letters, then enter the real "
               "name. Results are in the log.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"name_entry_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found. Get to the naming screen first, "
                       "then run this again.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        # Orientation snapshot: the known column anchor's current value.
        col_now = read_byte(handle, KNOWN_COLUMN_ADDR)
        print(f"Known column anchor 0x{KNOWN_COLUMN_ADDR:08X} = {col_now}")

        # ---- Phase A: idle baseline --------------------------------------
        changers_a, _ = run_cued_phase(
            handle,
            "Phase A, baseline. Hands off everything. Do not press anything "
            f"for {IDLE_DURATION} seconds.",
            IDLE_DURATION, "A idle")

        # ---- Phase B: rows -----------------------------------------------
        changers_b, last_b = run_cued_phase(
            handle,
            "Phase B, rows. Alternate pressing Up and Down, about one press "
            "per second. Up, down, up, down. Do not press left or right.",
            ROWNAV_DURATION, "B rows")

        # ---- Phase C: columns (validation) --------------------------------
        changers_c, last_c = run_cued_phase(
            handle,
            "Phase C, columns. Now alternate Left and Right, about one press "
            "per second. Do not press up or down.",
            COLNAV_DURATION, "C cols")

        # ---- Phase D: add letters ------------------------------------------
        changers_d, last_d = run_cued_phase(
            handle,
            "Phase D, typing. Press the Confirm button four times, slowly, "
            "about one press every three seconds. This adds letters to the "
            "name. That is expected; we will clean it up at the end.",
            ADD_DURATION, "D add")

        # ---- Phase E: delete letters ---------------------------------------
        changers_e, last_e = run_cued_phase(
            handle,
            "Phase E, deleting. Press the Cancel button four times, slowly, "
            "to delete the letters you just added.",
            DEL_DURATION, "E delete")

        # ---- Analysis ------------------------------------------------------
        print("\n" + "=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        set_a = set(changers_a)
        set_b = set(changers_b)
        set_c = set(changers_c)
        set_d = set(changers_d)
        set_e = set(changers_e)

        # Rows must not react to column presses and vice versa — cross-
        # subtracting kills input-event flags that fire on ANY d-pad press
        # (the 0x9ADE30-class pulses from the battle investigation).
        row_cands = set_b - set_a - set_c
        col_cands = set_c - set_a - set_b
        buf_cands = (set_d | set_e) - set_a - set_b - set_c

        print(f"\n  idle changers: {len(set_a)}   row-only: {len(row_cands)}   "
              f"col-only: {len(col_cands)}   type/delete-only: {len(buf_cands)}")

        # ~20 alternating presses expected per nav phase (1/s for 20 s).
        row_rows = rank_cursor_candidates(row_cands, changers_b, last_b,
                                          max_value=6, expect_presses=20)
        col_rows = rank_cursor_candidates(col_cands, changers_c, last_c,
                                          max_value=10, expect_presses=20)

        print_candidates("ROW cursor candidates (value 0-6)", row_rows, "row")
        print_candidates("COLUMN cursor candidates (value 0-10)", col_rows, "col")

        # ---- Validation gate ------------------------------------------------
        anchor_found = any(a == KNOWN_COLUMN_ADDR for a, _, _ in col_rows)
        if anchor_found:
            print(f"\n  VALIDATION PASSED: phase C re-found the known column "
                  f"anchor 0x{KNOWN_COLUMN_ADDR:08X}.")
        else:
            in_c_at_all = KNOWN_COLUMN_ADDR in set_c
            print(f"\n  *** VALIDATION FAILED: 0x{KNOWN_COLUMN_ADDR:08X} not in "
                  f"column candidates (changed during phase C at all: "
                  f"{in_c_at_all}). Treat every other result as suspect. ***")

        # ---- Name buffer ----------------------------------------------------
        clusters = find_adjacent_clusters(buf_cands)
        print(f"\n  NAME BUFFER: adjacent clusters among type/delete-only "
              f"addresses ({len(clusters)} found):")
        buf_addr = None
        for c in clusters:
            base, end = c[0], c[-1]
            # Show the cluster's final bytes decoded as FF7 text — the real
            # name buffer decodes to recognizable letters.
            raw = read_bytes(handle, base, min(end - base + 1, 16))
            decoded = decode_ff7_name(raw) if raw else "?"
            print(f"    0x{base:08X}-0x{end:08X}  len={end-base+1}  "
                  f"decoded now: '{decoded}'")
            if buf_addr is None and decoded:
                buf_addr = base

        # Caret: changes on (almost) every press in BOTH D and E, small value.
        caret_rows = [(a, changers_d.get(a, 0), changers_e.get(a, 0),
                       last_e.get(a, 0xFF))
                      for a in buf_cands
                      if 2 <= changers_d.get(a, 0) <= 8
                      and 2 <= changers_e.get(a, 0) <= 8
                      and last_e.get(a, 0xFF) <= 12]
        caret_rows.sort(key=lambda t: t[0])
        caret_addr = None
        print("\n  CARET candidates (changed ~4x in both add and delete, "
              "value <= 12):")
        if caret_rows:
            for a, cd, ce, v in caret_rows[:10]:
                print(f"    0x{a:08X}  addCount={cd} delCount={ce} last={v}")
            caret_addr = caret_rows[0][0]
        else:
            print("    (none)")

        # ---- Live decode ----------------------------------------------------
        # Use the known anchor for columns regardless of scan outcome; use the
        # top row candidate.  Skip live phase only if we have no row at all.
        if row_rows:
            row_addr = row_rows[0][0]
            live_decode(handle, row_addr, KNOWN_COLUMN_ADDR, buf_addr, caret_addr)
        else:
            speak_wait("No row cursor candidate found, skipping the live "
                       "test. Check the log.")

        # ---- Summary --------------------------------------------------------
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  Column anchor validated: {anchor_found}")
        if row_rows:
            print(f"  ROW cursor:  0x{row_rows[0][0]:08X} "
                  f"(count={row_rows[0][1]}, last={row_rows[0][2]})")
        if buf_addr:
            print(f"  NAME buffer: 0x{buf_addr:08X}")
        if caret_addr:
            print(f"  CARET:       0x{caret_addr:08X}")
        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
