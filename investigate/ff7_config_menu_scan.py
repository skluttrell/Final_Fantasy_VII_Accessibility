#!/usr/bin/env python3
"""
ff7_config_menu_scan.py — Find the Config sub-menu row cursor and open flag.

The Config sub-menu opens when the player selects "Config" (row 7) from the
main menu and presses Confirm.  It has 10 rows:
  0  Window color   (RGB slider / preset)
  1  Sound          (Mono / Stereo)
  2  Controller     (Normal / Custom)
  3  Cursor         (Save / Reset)
  4  ATB            (Active / Wait)
  5  Battle speed   (slider)
  6  Battle msg     (slider)
  7  Field msg      (slider)
  8  Camera angle   (Fixed / Free)
  9  Magic order    (preset / cycle)

We need two addresses before we can implement TTS for this sub-menu:

  CONFIG_ROW   byte, 0–9, changes when the player presses Up/Down
  CONFIG_OPEN  byte/flag, set while config sub-menu is visible, cleared on exit

PHASE A — Idle baseline (~12 s, inside config menu, cursor stationary)
  Captures all background-changers: animation frames, timers, render counters.
  These are the false positives we will subtract away.

PHASE B — Row navigation (~35 s, inside config menu)
  Player presses Up/Down through all 10 rows repeatedly (~20+ presses).
  CONFIG_ROW candidates = addresses in (B changers) − (A changers)
                          with last value in range 0–9.

PHASE C — Config-open toggle scan (3 snapshots)
  Snap 1: field, config closed (main menu also closed)
  Snap 2: config sub-menu open (main menu → Config → Confirm)
  Snap 3: field, config closed again (pressed Cancel out of config + main menu)
  CONFIG_OPEN candidates = addresses where:
    snap1_value != snap2_value  (changed when config opened)
    snap3_value == snap1_value  (returned to original when config closed)
  The symmetric-revert condition filters out irreversible noise.

USAGE:
  1. Start FF7, load a save, stand in the field.
  2. Run this script.  Do NOT open any menu yet.
  3. Follow the voice instructions for each phase:
       Phase A: Open main menu → Config → Confirm, then hold cursor still.
       Phase B: Press Up/Down through all 10 rows repeatedly.
       Phase C (3 snapshots): close everything → open config → close everything.
  4. Check the log file for candidate addresses.
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

# Phase A/B timing (seconds)
IDLE_DURATION = 12
NAV_DURATION  = 35
SNAP_INTERVAL = 0.10  # 100 ms between poll snapshots

# Phase C settle times (seconds after each voice cue)
SETTLE_C1 = 6   # close everything and stand still in field
SETTLE_C2 = 7   # open config menu and hold still
SETTLE_C3 = 6   # close config and main menu, stand still in field

CONFIG_ROW_NAMES = {
    0: "Window color",
    1: "Sound",
    2: "Controller",
    3: "Cursor",
    4: "ATB",
    5: "Battle speed",
    6: "Battle message",
    7: "Field message",
    8: "Camera angle",
    9: "Magic order",
}

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
PROCESS_VM_ALL   = PROCESS_VM_READ | PROCESS_VM_QUERY

k32 = ctypes.windll.kernel32


# ── I/O helpers ────────────────────────────────────────────────────────────────

class Tee:
    """Mirrors stdout to both the terminal and a log file simultaneously."""
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
    """Speak text synchronously via SAPI so the script waits for completion."""
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=90,
        )
    except Exception:
        pass


def beep(freq=1000, ms=120):
    winsound.Beep(freq, ms)


def countdown(seconds, label):
    for i in range(seconds, 0, -1):
        print(f"  {label}: {i}s …", end='\r', flush=True)
        time.sleep(1)
    print()


# ── Process / memory helpers ───────────────────────────────────────────────────

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
    handle = k32.OpenProcess(PROCESS_VM_ALL, False, pid)
    return handle if handle else None


def read_region(handle, lo, hi):
    """Read [lo, hi) as a bytearray.  Returns None on total failure."""
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


# ── Polling scan (phases A and B) ─────────────────────────────────────────────

def poll_phase(handle, lo, hi, duration_s, phase_label):
    """
    Snapshot [lo, hi) every SNAP_INTERVAL seconds for duration_s seconds.
    Returns:
      changers : dict addr → change_count
      last_val : dict addr → final byte value
    """
    print(f"\n[{phase_label}] Scanning 0x{lo:08X}–0x{hi:08X} "
          f"({(hi-lo)//1024} KB) for {duration_s}s …")

    prev = read_region(handle, lo, hi)
    if prev is None:
        print(f"  ERROR: cannot read region")
        return {}, {}

    changers  = {}
    last_val  = {}
    deadline  = time.time() + duration_s
    snap_num  = 0
    next_snap = time.time() + SNAP_INTERVAL

    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 5:
            beep(800, 40)

        if snap_num % 10 == 0:
            elapsed = duration_s - remaining
            print(f"  {elapsed:5.1f}s  {len(changers)} addrs changed so far …",
                  end='\r', flush=True)

        sleep_for = next_snap - time.time()
        if sleep_for > 0:
            time.sleep(sleep_for)
        next_snap += SNAP_INTERVAL

        curr = read_region(handle, lo, hi)
        if curr is None:
            continue

        compare_len = min(len(prev), len(curr))
        for i in range(compare_len):
            if curr[i] != prev[i]:
                addr = lo + i
                changers[addr] = changers.get(addr, 0) + 1
                last_val[addr] = curr[i]

        prev = curr
        snap_num += 1

    print(f"\n  Done: {snap_num} snapshots in {duration_s:.1f}s, "
          f"{len(changers)} addresses changed.")
    return changers, last_val


# ── Single snapshot (phase C) ─────────────────────────────────────────────────

def take_snapshot(handle, label, settle_s, cue_text):
    """
    Speak cue_text, wait settle_s seconds, take one full snapshot.
    Returns bytearray or None on failure.
    """
    speak_wait(cue_text)
    print()
    print(f"  {cue_text}")
    countdown(settle_s, f"Snapshot {label} in")
    print(f"  Taking snapshot {label} …", end=' ', flush=True)
    data = read_region(handle, STATIC_LO, STATIC_HI)
    if data is None:
        print("FAILED")
        return None
    print(f"OK ({len(data)//1024} KB)")
    beep(880 + 110 * (ord(label) - ord('1')), 120)
    return data


# ── Analysis helpers ───────────────────────────────────────────────────────────

def analyse_row_cursor(idle_changers, nav_changers, nav_last):
    """
    CONFIG_ROW candidates: changed during navigation but NOT during idle,
    with last value in 0–9.
    """
    idle_set = set(idle_changers.keys())
    nav_set  = set(nav_changers.keys())

    nav_only = nav_set - idle_set

    candidates = [
        (addr, nav_changers[addr], nav_last.get(addr, 0xFF))
        for addr in nav_only
        if 0 <= nav_last.get(addr, 0xFF) <= 9
    ]
    candidates.sort(key=lambda t: abs(t[1] - 20))  # closest to expected ~20 presses
    return candidates, nav_only


def analyse_toggle(snap1, snap2, snap3):
    """
    CONFIG_OPEN candidates: changed 1→2 (config opened) AND returned to
    original value in snap3 (config closed → symmetric toggle).
    snap1_value != snap2_value  AND  snap3_value == snap1_value
    """
    length = min(len(snap1), len(snap2), len(snap3))
    results = []
    for i in range(length):
        v1, v2, v3 = snap1[i], snap2[i], snap3[i]
        if v1 == v2:
            continue   # didn't change when config opened
        if v3 != v1:
            continue   # didn't revert when config closed (not a symmetric flag)
        results.append((STATIC_LO + i, v1, v2))
    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"config_menu_{time.strftime('%Y%m%d_%H%M%S')}.log"
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

        fid_buf  = ctypes.create_string_buffer(2)
        fid_read = ctypes.c_size_t(0)
        k32.ReadProcessMemory(handle, ctypes.c_void_p(0x00CC15D0),
                              fid_buf, 2, ctypes.byref(fid_read))
        field_id = (struct.unpack_from('<h', fid_buf.raw)[0]
                    if fid_read.value == 2 else -1)
        print(f"FIELD_ID = {field_id}")
        print()

        # ── Phase A: Config menu idle baseline ────────────────────────────────
        speak_wait(
            "Config menu scan. Phase A. "
            "Open the main menu, navigate to Config, and press Confirm to enter "
            "the Config sub-menu. Once inside, do NOT press any buttons. "
            "Hold the cursor completely still. "
            f"Phase A will run for {IDLE_DURATION} seconds and beep when done."
        )
        print()
        print("=" * 60)
        print(f"  PHASE A — Config idle baseline ({IDLE_DURATION}s)")
        print("  Enter the Config sub-menu and hold cursor STILL.")
        print("  Captures background changers to subtract from Phase B.")
        print("=" * 60)

        idle_changers, idle_last = poll_phase(
            handle, STATIC_LO, STATIC_HI, IDLE_DURATION, "Phase A: Idle")

        beep(880, 200)
        time.sleep(0.2)
        beep(880, 200)

        # ── Phase B: Config row navigation ────────────────────────────────────
        speak_wait(
            "Phase B. Stay inside the Config sub-menu. "
            "Now press Up and Down through all 10 rows repeatedly. "
            f"Keep pressing for about {NAV_DURATION} seconds and cover all rows many times. "
            "I will beep when done."
        )
        print()
        print("=" * 60)
        print(f"  PHASE B — Row navigation ({NAV_DURATION}s)")
        print("  Press Up/Down through ALL 10 Config rows repeatedly.")
        print("=" * 60)

        nav_changers, nav_last = poll_phase(
            handle, STATIC_LO, STATIC_HI, NAV_DURATION, "Phase B: Navigate")

        beep(1100, 300)
        time.sleep(0.3)
        beep(1100, 300)

        # ── Analysis A/B ─────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  ANALYSIS — CONFIG_ROW candidates")
        print("=" * 60)

        row_cands, nav_only = analyse_row_cursor(idle_changers, nav_changers, nav_last)

        idle_set = set(idle_changers.keys())
        nav_set  = set(nav_changers.keys())

        print(f"\n  Idle-only (background noise, excluded): {len(idle_set - nav_set)}")
        print(f"  Both phases (animation/timers):          {len(idle_set & nav_set)}")
        print(f"  Nav-only total:                          {len(nav_only)}")
        print(f"  Nav-only with last value 0–9:            {len(row_cands)}")

        if row_cands:
            print()
            print("  TOP CONFIG_ROW CANDIDATES (sorted by closeness to ~20 presses):")
            print(f"  {'Address':12s}  {'Count':>6}  {'LastVal':>7}  Row name")
            print(f"  {'-'*12}  {'-'*6}  {'-'*7}  {'-'*20}")
            for addr, cnt, val in row_cands[:20]:
                row_name = CONFIG_ROW_NAMES.get(val, f"row {val}")
                print(f"  0x{addr:08X}  {cnt:6d}  {val:7d}  {row_name}")
        else:
            print()
            print("  No nav-only candidates in row range 0–9.")
            print("  Possible causes:")
            print("   — Phase A cursor was not fully stationary (some button presses slipped in)")
            print("   — Row cursor is 16-bit (int16); check addresses ±1 of any close candidates")
            print("   — All row candidates also appeared in idle phase (unlikely but possible)")
            print()
            print("  All nav-only addresses (count 5–35) for manual inspection:")
            fallback = sorted(
                [(addr, nav_changers[addr], nav_last.get(addr, 0xFF))
                 for addr in nav_only
                 if 5 <= nav_changers.get(addr, 0) <= 35],
                key=lambda t: abs(t[1] - 20),
            )
            print(f"  {'Address':12s}  {'Count':>6}  {'LastVal':>7}")
            print(f"  {'-'*12}  {'-'*6}  {'-'*7}")
            for addr, cnt, val in fallback[:40]:
                print(f"  0x{addr:08X}  {cnt:6d}  {val:7d}")

        # ── Phase C: Config-open toggle scan (3 snapshots) ───────────────────
        speak_wait(
            "Phase C. Toggle scan for the Config open flag. "
            "We will take 3 snapshots. "
            "First: close the Config sub-menu and the main menu. "
            "Stand still in the field. "
            "Second: open the Config sub-menu again. "
            "Third: close the Config sub-menu and the main menu again."
        )
        print()
        print("=" * 60)
        print("  PHASE C — Config-open toggle scan (3 snapshots)")
        print("=" * 60)

        s1 = take_snapshot(
            handle, "1", SETTLE_C1,
            "Snap 1. Close Config and main menu. Stand still in the field."
        )
        if s1 is None:
            return

        s2 = take_snapshot(
            handle, "2", SETTLE_C2,
            "Snap 2. Open main menu, navigate to Config, and press Confirm. "
            "Hold cursor still inside Config. Do not press any direction buttons."
        )
        if s2 is None:
            return

        s3 = take_snapshot(
            handle, "3", SETTLE_C3,
            "Snap 3. Press Cancel to close Config, then Cancel to close the main menu. "
            "Stand still in the field."
        )
        if s3 is None:
            return

        # ── Analysis C ───────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  ANALYSIS — CONFIG_OPEN candidates")
        print("=" * 60)

        toggle_cands = analyse_toggle(s1, s2, s3)
        total_12 = sum(1 for i in range(min(len(s1), len(s2))) if s1[i] != s2[i])

        print(f"\n  Total 1→2 changes (when config opened):  {total_12}")
        print(f"  Of those, symmetrically reverted in 3:   {len(toggle_cands)}")

        if toggle_cands:
            clean_flags = [(a, v1, v2) for a, v1, v2 in toggle_cands if v1 == 0]
            other_flags = [(a, v1, v2) for a, v1, v2 in toggle_cands if v1 != 0]

            print()
            print("  CONFIG_OPEN candidates (clean 0→nonzero→0 first):")
            print(f"  {'Address':12s}  {'val(closed)':>11}  {'val(open)':>9}  Notes")
            print(f"  {'-'*12}  {'-'*11}  {'-'*9}  {'-'*30}")

            def note(v1, v2):
                if v1 == 0:
                    return "0→nonzero  (clean flag — PREFERRED)"
                return f"{v1}↔{v2}  (inverted or non-zero base)"

            for addr, v1, v2 in clean_flags[:20]:
                print(f"  0x{addr:08X}  {v1:11d}  {v2:9d}  {note(v1, v2)}")
            for addr, v1, v2 in other_flags[:10]:
                print(f"  0x{addr:08X}  {v1:11d}  {v2:9d}  {note(v1, v2)}")
            if len(toggle_cands) > 30:
                print(f"  … and {len(toggle_cands)-30} more (see full log)")
        else:
            print("  No symmetric-toggle candidates found for CONFIG_OPEN.")
            print("  This can happen if:")
            print("   — Snap 3 was taken while config was not fully closed (cancel needed)")
            print("   — Phase C timing was too tight; re-run with longer settle times")

        # ── Summary ───────────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)

        spoken_parts = []

        if row_cands:
            best_addr, best_cnt, best_val = row_cands[0]
            row_name = CONFIG_ROW_NAMES.get(best_val, f"row {best_val}")
            print(f"\n  Best CONFIG_ROW : 0x{best_addr:08X}")
            print(f"    Change count  : {best_cnt}")
            print(f"    Last value    : {best_val} ({row_name})")
            spoken_parts.append(
                f"Best row cursor: 0x{best_addr:08X}. "
                f"Change count {best_cnt}. Last value {best_val}, {row_name}."
            )
        else:
            print("\n  CONFIG_ROW: no candidates — re-run Phases A and B.")
            spoken_parts.append("No row cursor candidates found.")

        if toggle_cands:
            clean_flags = [(a, v1, v2) for a, v1, v2 in toggle_cands if v1 == 0]
            best_toggle = (clean_flags or toggle_cands)[0]
            addr, v1, v2 = best_toggle
            print(f"\n  Best CONFIG_OPEN: 0x{addr:08X}")
            print(f"    Closed value  : {v1}")
            print(f"    Open value    : {v2}")
            spoken_parts.append(
                f"Best open flag: 0x{addr:08X}. "
                f"Closed equals {v1}, open equals {v2}."
            )
        else:
            print("\n  CONFIG_OPEN: no candidates — re-run Phase C.")
            spoken_parts.append("No config open flag candidates found.")

        print(f"\nLog saved to: {log_path}")
        speak_wait(" ".join(spoken_parts) + " Check the log for full results.")

        print()
        print("NEXT STEPS:")
        print("  1. Verify CONFIG_ROW with a quick verify script (read in a loop,")
        print("     confirm it tracks Up/Down movement in the config sub-menu).")
        print("  2. Verify CONFIG_OPEN: read it inside and outside config sub-menu.")
        print("     Make sure it does NOT fire for the main menu alone (only for")
        print("     the config sub-menu).")
        print("  3. Once confirmed, add both to ff7_addresses.h and implement")
        print("     ConfigMenuThread in proxy.cpp.")
        print("  4. Run ff7_config_values_scan.py (next script) to find the value")
        print("     addresses for each of the 10 config rows (Left/Right changes).")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
