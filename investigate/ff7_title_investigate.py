#!/usr/bin/env python3
"""
ff7_title_investigate.py — Find the title screen cursor address in FF7.

APPROACH: Real-time polling of targeted memory regions (200ms interval).
The previous snapshot-diff approach required holding the cursor still for
10-30 seconds of silent scanning, which made it easy to accidentally move
the cursor back before the scan finished, resulting in 0 changes found.
Polling finds changes the instant they happen — no holding still needed.

Usage:
  1. Start FF7 and reach the title screen (CONTINUE / NEW GAME).
  2. Run this script. It will speak instructions and start polling.
  3. Move the cursor from CONTINUE to NEW GAME. Script beeps on detection.
  4. Move back to CONTINUE. Script beeps again.
  5. Repeat 3-4 times for confidence.
  6. Press Ctrl+C. Summary identifies the cursor byte.

Reading the summary:
  The cursor byte changes exactly once per keypress (a small, even number of
  total changes matching your moves). Background animation counters change
  every poll (dozens to hundreds of changes). Anything in between is noise.
  Filter for offsets with change_count <= 2 * (number of cursor moves).

Watched regions (six candidate areas covering known cursor analogues):
  MENU_STATE   0xDC0000  4KB   — start of DC range (MENU_OBJECTS at +0x0FC0)
  MENU_OBJS    0xDC0F00  256B  — immediately before/at menu_objects struct
  NAME_AREA    0xDD4400  1KB   — around name-entry cursor 0xDD46F8 (confirmed)
  PRE_SAVE     0xDBF000  4KB   — just before savemap (0xDBFD38)
  EARLY_A      0x9F7000  4KB   — early startup data segment (candidate)
  EARLY_B      0xC0F000  4KB   — pre-field module area (candidate)

If 0 changes are detected for cursor moves that the user confirmed with beeps
(no beep = script didn't see it), try expanding to the DD/CB/CC ranges via
the EXTRA_REGIONS list at the bottom of this file.

Frida RPC note: exports_sync lowercases method names before the JS lookup.
All JS export names and Python call names must be fully lowercase.
"""

import frida
import sys
import time
import os
import subprocess
import winsound
from collections import defaultdict

PROCESS_NAME   = "ff7_en.exe"
POLL_INTERVAL  = 0.20          # seconds between polls
CHANGE_BEEP_HZ = 880           # frequency for "change detected" beep
CHANGE_BEEP_MS = 80            # duration for "change detected" beep

# ---------------------------------------------------------------------------
# Watched memory regions: (label, base_address, size_in_bytes)
#
# MENU_STATE: Start of the main game-state DC segment. MENU_OBJECTS lives at
#   0xDC0FC0. The title screen cursor might be earlier in this segment.
#
# MENU_OBJS: 256 bytes centred on the MENU_OBJECTS boundary (0xDC0F00) to
#   catch bytes just before and just after the confirmed anchor address.
#
# NAME_AREA: 1KB around 0xDD46F8, the name-entry column cursor (0-9) confirmed
#   by Echo mod hext patch '01 - Disable Name Change.txt'. The title screen
#   cursor (0/1 for Continue/NewGame) may be nearby in the DD range.
#
# PRE_SAVE: 4KB just before the savemap base (0xDBFD38). Title-screen state
#   might live here since the title screen runs before savemap is populated.
#
# EARLY_A/B: Guesses in the 0x9XXXXX and 0xC0XXXX ranges where FF7's earliest
#   module data tends to live (confirmed by FFNx analysis of startup sequence).
# ---------------------------------------------------------------------------
REGIONS = [
    ("MENU_STATE", 0xDC0000, 0x1000),
    ("MENU_OBJS",  0xDC0F00, 0x0100),
    ("NAME_AREA",  0xDD4400, 0x0400),
    ("PRE_SAVE",   0xDBF000, 0x1000),
    ("EARLY_A",    0x9F7000, 0x1000),
    ("EARLY_B",    0xC0F000, 0x1000),
]

# ---------------------------------------------------------------------------
# Audio helpers
# ---------------------------------------------------------------------------

def speak_wait(text):
    """Speak 'text' via Windows SAPI and block until speech finishes.

    Works regardless of which application has keyboard focus — FF7 can be in
    the foreground and the user still hears instructions through the same
    audio device. Single quotes escaped for PowerShell string literal.
    """
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


def beep_change():
    """Short high beep: a byte change was detected this poll."""
    winsound.Beep(CHANGE_BEEP_HZ, CHANGE_BEEP_MS)


def beep_done():
    """Three ascending tones: investigation finished."""
    winsound.Beep(600, 150)
    winsound.Beep(900, 150)
    winsound.Beep(1200, 300)


# ---------------------------------------------------------------------------
# Tee: Mirror all print() output to both the terminal and a log file.
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Frida JS agent.
# All export names fully lowercase — exports_sync lowercases before lookup.
# ---------------------------------------------------------------------------

JS_CODE = r"""
'use strict';

// safeReadBytes: Read n bytes from integer address. Returns zero array on fault.
// We catch faults so one bad page doesn't abort the whole poll.
function safeReadBytes(addr, n) {
    try { return Array.from(Memory.readByteArray(ptr(addr), n)); }
    catch(e) { return new Array(n).fill(0); }
}

rpc.exports = {
    // snapshot: Read all watched regions in one RPC round-trip.
    // 'regions' is an array of [label, base_int, size_int].
    // Returns array of { label, base, bytes }.
    snapshot: function(regions) {
        return regions.map(function(r) {
            return { label: r[0], base: r[1], bytes: safeReadBytes(r[1], r[2]) };
        });
    }
};
"""

# ---------------------------------------------------------------------------
# Diff helper
# ---------------------------------------------------------------------------

def diff_snaps(prev, curr):
    """
    Compare two snapshot arrays (lists of {label, base, bytes}).
    Returns list of (label, base_addr, offset, old_byte, new_byte).
    """
    changes = []
    for p, c in zip(prev, curr):
        if p['label'] != c['label']:
            continue
        for i, (old, new) in enumerate(zip(p['bytes'], c['bytes'])):
            if old != new:
                changes.append((c['label'], c['base'], i, old, new))
    return changes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"title_investigate_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    session = None
    try:
        print(f"Output saving to: {log_path}")
        print()

        print(f"Attaching to {PROCESS_NAME}...")
        try:
            session = frida.attach(PROCESS_NAME)
        except frida.ProcessNotFoundError:
            speak_wait("Error: F F 7 not found. Start the game first.")
            print(f"ERROR: {PROCESS_NAME} not found. Start FF7 first.")
            sys.exit(1)

        frida_script = session.create_script(JS_CODE)
        frida_script.load()
        print("Attached.")
        print()

        speak_wait(
            "Attached to F F 7. "
            "Make sure you are on the title screen with the cursor on Continue. "
            "When you are ready, press Enter in the terminal."
        )
        input("Press ENTER when you are on the title screen, cursor on CONTINUE...")
        print()

        regions_arg = [[lbl, base, size] for lbl, base, size in REGIONS]

        # Take baseline before polling starts.
        prev_snap    = frida_script.exports_sync.snapshot(regions_arg)
        poll_num     = 0
        change_log   = []     # list of (poll_num, timestamp, changes)
        move_times   = []     # timestamps when we detected a burst of changes

        # Track per-offset change count for the summary.
        # Key: (label, offset) → change_count
        change_count = defaultdict(int)
        last_values  = {}     # (label, offset) → most recent value seen

        # Seed last_values from baseline.
        for region in prev_snap:
            lbl  = region['label']
            for i, b in enumerate(region['bytes']):
                last_values[(lbl, i)] = b

        print("Polling started. Watched regions:")
        for lbl, base, size in REGIONS:
            print(f"  {lbl:<12} 0x{base:08X}  {size} bytes")
        print()
        print("Now move the cursor back and forth between CONTINUE and NEW GAME.")
        print("A beep signals each time the script detects a memory change.")
        print("Repeat 4-6 times, then press Ctrl+C for the summary.")
        print()

        speak_wait(
            "Polling started. "
            "Move the cursor from Continue to New Game, then back, "
            "and repeat. I will beep each time I detect a memory change. "
            "Press Control C when you have moved the cursor at least four times."
        )

        in_burst = False   # True while a burst of changes is ongoing

        try:
            while True:
                time.sleep(POLL_INTERVAL)
                curr_snap = frida_script.exports_sync.snapshot(regions_arg)
                poll_num += 1

                changes = diff_snaps(prev_snap, curr_snap)

                if changes:
                    ts = time.strftime('%H:%M:%S')
                    print(f"[{ts}] POLL#{poll_num:04d} — {len(changes)} byte(s) changed:")
                    for lbl, base, off, old, new in changes:
                        abs_addr = base + off
                        print(f"  {lbl:<12} +0x{off:04X}  (0x{abs_addr:08X})"
                              f"  0x{old:02X}->0x{new:02X}  ({old:3d}->{new:3d})")
                        change_count[(lbl, off)] += 1
                        last_values[(lbl, off)] = new
                    print()
                    change_log.append((poll_num, ts, changes))
                    beep_change()

                prev_snap = curr_snap

        except KeyboardInterrupt:
            print()
            print("=== SUMMARY ===")
            print(f"Total polls: {poll_num}  |  Polls with changes: {len(change_log)}")
            print()

            if not change_count:
                speak_wait(
                    "No changes detected. "
                    "Either the cursor byte is outside the watched regions, "
                    "or the game was not in focus. "
                    "Check the log file for details."
                )
                print("No changes detected in any watched region.")
                print()
                print("Possible causes:")
                print("  - The cursor byte is in a memory region not covered by this script.")
                print("    Try adding more regions (see EXTRA_REGIONS at bottom of this file).")
                print("  - FF7 was not in focus when you moved the cursor.")
                print("  - The title screen cursor is computed per-frame (not stored statically).")
                print()
                print("Next steps: run ff7_menu_investigate.py which covers a broader range,")
                print("or try Cheat Engine attached to ff7_en.exe for a hardware watchpoint.")
            else:
                # Sort by change count. Low count = cursor candidate; high count = animation.
                sorted_offsets = sorted(change_count.items(), key=lambda x: x[1])

                print("Change frequency per byte (sorted by count, lowest first):")
                print("  Cursor byte = small even count matching your # of moves.")
                print("  Animation   = many changes (changes every poll).")
                print()
                print(f"  {'Region':<12} {'Offset':>6}  {'Abs Addr':>10}  "
                      f"{'Count':>5}  {'Last':>4}  Note")
                print(f"  {'-'*12}  {'-'*6}  {'-'*10}  {'-'*5}  {'-'*4}  {'-'*30}")

                base_map = {lbl: base for lbl, base, _ in REGIONS}
                for (lbl, off), count in sorted_offsets[:60]:
                    base     = base_map.get(lbl, 0)
                    abs_addr = base + off
                    last_v   = last_values.get((lbl, off), '?')
                    note     = ""
                    if count <= 8:
                        note = "<--- CURSOR CANDIDATE"
                    elif count <= 20:
                        note = "  (low-frequency)"
                    print(f"  {lbl:<12}  +0x{off:04X}  0x{abs_addr:08X}  "
                          f"{count:5d}  {last_v:>4}  {note}")

                print()
                candidates = [(lbl, off, cnt) for (lbl, off), cnt in sorted_offsets
                              if cnt <= 8]
                if candidates:
                    speak_wait(
                        f"Found {len(candidates)} cursor candidate bytes. "
                        "Check the log for addresses marked CURSOR CANDIDATE."
                    )
                    print(f"=== {len(candidates)} CANDIDATE(S) — count <= 8 ===")
                    for lbl, off, cnt in candidates:
                        base     = base_map.get(lbl, 0)
                        abs_addr = base + off
                        print(f"  0x{abs_addr:08X}  ({lbl}+0x{off:04X})  "
                              f"changed {cnt} time(s)  last=0x{last_values.get((lbl,off),0):02X}")
                else:
                    speak_wait(
                        "No low-frequency candidates found. "
                        "All changes were high-frequency (animation counters). "
                        "The cursor byte may be in a different memory region."
                    )
                    print("No low-frequency candidates (count <= 8).")

            print()
            print("=== IDENTIFICATION GUIDE ===")
            print("The title screen cursor byte:")
            print("  - Changes exactly ONCE per Up/Down keypress")
            print("  - Has value 0 on one option and 1 (or small nonzero) on the other")
            print("  - Is surrounded by zeros or small values in a hex dump")
            print("  - Likely in the 0xDC or 0xDD address range")
            print()
            print(f"Log saved to: {log_path}")
            beep_done()
            speak_wait("Investigation complete. Check the log file.")

    finally:
        if session:
            session.detach()
        sys.stdout = real_stdout
        log_file.close()


# ---------------------------------------------------------------------------
# EXTRA_REGIONS: Add these to REGIONS if the current set finds nothing.
#
# The title screen cursor might be in these areas instead:
#
# ("FIELD_CB",  0xCBF000, 0x1000),   # field module pre-area
# ("FIELD_CC",  0xCC0000, 0x1000),   # field entity/script state
# ("TITLE_DD",  0xDD0000, 0x4800),   # full DD range up to name entry
# ("LATE_DC",   0xDC1000, 0x4000),   # DC range beyond MENU_OBJECTS
# ("SEG_9E",    0x9E0000, 0x1000),   # earlier startup segment
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    main()
