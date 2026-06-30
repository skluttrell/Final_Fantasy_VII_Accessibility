#!/usr/bin/env python3
"""
ff7_menu_investigate.py — Live memory investigation of FF7 menu system.

Run this script WHILE FF7 is running to discover the layout of MENU_OBJECTS
(0xDC0FC0) and nearby menu state variables. We need to find:

  1. Which byte(s) indicate that the main menu is open vs. closed.
  2. Which byte(s) hold the main menu cursor position (0–9 for the top-level
     ITEM/MAGIC/MATERIA/EQUIP/STATUS/ORDER/LIMIT/CONFIG/PHS/SAVE list).
  3. Which byte(s) identify the active submenu (item list, magic list, etc.)
     once you press Enter on a top-level choice.
  4. Whether there is a separate game-mode variable that distinguishes
     "in field menu" from "in field", "in battle", "in world map".

Usage:
    python ff7_menu_investigate.py

What to do during investigation:
  The script prints "=== SNAPSHOT ===" every 200ms. Each snapshot shows
  which bytes in the watched regions changed since the last snapshot.

  Recommended sequence (do each step slowly, wait for a snapshot between steps):
    Step 0: Be in the field (no menu open). Let a few snapshots pass — these
            are the "baseline idle" values. Note the stable byte values.
    Step 1: Press START to open the main menu. Note which bytes change.
            The cursor should be on ITEM (first entry, index 0).
    Step 2: Press DOWN once. Note which bytes change — the cursor moved to MAGIC.
    Step 3: Press DOWN again → MATERIA.
    Step 4: Press DOWN three more times to reach STATUS (index 4).
    Step 5: Press UP once → back to EQUIP (index 3). Cursor went up.
    Step 6: Press Enter on any top-level item to open a submenu.
            Note which bytes change → submenu type indicator.
    Step 7: Press Cancel to close the submenu.
    Step 8: Press Cancel again to close the main menu.
            Note which bytes return to their baseline values.

The output is designed to let you correlate each action with the memory change.
Output is saved automatically to a timestamped log file in the investigate/ directory.

Watched regions:
  MENU_OBJECTS    0xDC0FC0 + 512 bytes  (the primary menu state structure)
  GAME_STATE_1    0xDBAF0C + 16 bytes   (global game state flags — from FFNx
                                          ff7_data.h battle_mode references)
  GAME_STATE_2    0xCBF9D4 + 16 bytes   (field active flag area)
  MENU_EXTRA      0xDC4FE0 + 128 bytes  (extra region just past MENU_OBJECTS)
"""

import frida
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"

# ---------------------------------------------------------------------------
# Tee: Write all print() output to both the terminal and a log file.
#
# Assigned to sys.stdout at the start of main(). The log file captures
# everything that print() emits, including timestamps and change reports.
# input() prompts are also tee'd (they go to stdout before reading stdin).
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

    # Delegate attribute lookups (e.g. .encoding, .isatty) to the terminal
    # so libraries that inspect sys.stdout don't break.
    def __getattr__(self, name):
        return getattr(self._terminal, name)

# ---------------------------------------------------------------------------
# Watched memory regions: (label, address, size_bytes)
#
# MENU_OBJECTS    0xDC0FC0  1024 bytes  — primary menu state (confirmed from
#                                          FFNx externals_102_us.h menu_objects).
#                                          1024 bytes to cover the full struct —
#                                          FF7 has ~10 submenus each with their
#                                          own cursor/flag bytes.
#
# MENU_PRE        0xDC0F00  192 bytes   — 192 bytes BEFORE MENU_OBJECTS. The
#                                          "menu is open" flag might live just
#                                          before the main struct (common pattern).
#                                          Anchored at MENU_OBJECTS - 0xC0.
#
# FIELD_FLAGS     0xCBF5D0  48 bytes    — Region around DIALOG_TEXT_PTRS (confirmed
#                                          at 0xCBF578). Nearby bytes may hold a
#                                          field-vs-menu mode flag. Watching ±40
#                                          bytes around the known anchor.
# ---------------------------------------------------------------------------
REGIONS = [
    ("MENU_OBJECTS", 0xDC0FC0, 1024),
    ("MENU_PRE",     0xDC0F00,  192),
    ("FIELD_FLAGS",  0xCBF5D0,   48),
]

JS_CODE = r"""
'use strict';

// safeReadBytes: Read n bytes from addr, return zero-filled array on fault.
function safeReadBytes(addr, n) {
    try { return Array.from(Memory.readByteArray(ptr(addr), n)); }
    catch(e) { return new Array(n).fill(0); }
}

// Method names must be fully lowercase: exports_sync lowercases names before
// the JS lookup. 'snapshot' has no uppercase so it is safe as-is.
rpc.exports = {
    // snapshot: Return the current bytes of all watched regions.
    // 'regions' is an array of [label, base_int, size] triples.
    // Returns an array of { label, base, bytes } objects.
    snapshot: function(regions) {
        return regions.map(function(r) {
            return {
                label: r[0],
                base:  r[1],
                bytes: safeReadBytes(r[1], r[2])
            };
        });
    }
};
"""

def bytes_to_hex(data, cols=16):
    """Format a byte array as annotated hex rows."""
    lines = []
    for row_start in range(0, len(data), cols):
        chunk = data[row_start:row_start + cols]
        hex_part  = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'  +{row_start:04X}  {hex_part:<{cols*3}}  {ascii_part}')
    return '\n'.join(lines)

def diff_regions(prev, curr):
    """
    Return a list of (label, base, offset, old_val, new_val) for every byte
    that changed between the prev and curr snapshots.
    Prev and curr are both lists of { label, base, bytes } dicts.
    """
    changes = []
    for p, c in zip(prev, curr):
        if p['label'] != c['label']:
            continue
        for i, (old, new) in enumerate(zip(p['bytes'], c['bytes'])):
            if old != new:
                changes.append((c['label'], c['base'], i, old, new))
    return changes

def main():
    # Open log file in the same directory as this script so it's always
    # findable regardless of the working directory the user ran from.
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"menu_investigate_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            print(f"ERROR: {PROCESS_NAME} not found. Start FF7 first.")
            sys.exit(1)

        frida_script = session.create_script(JS_CODE)
        frida_script.load()

        # Convert REGIONS to the format expected by the JS rpc call.
        regions_arg = [[label, base, size] for label, base, size in REGIONS]

        print("Attached. Polling every 200ms.")
        print()
        print("=== INVESTIGATION SEQUENCE ===")
        print("Follow these steps slowly. Wait for a 'CHANGE DETECTED' print")
        print("between each step before doing the next one.")
        print()
        print("  0. Be in the field (no menu). Let 3-4 snapshots pass (IDLE baseline).")
        print("  1. Press START to open the main menu. Cursor on ITEM (position 0).")
        print("  2. Press DOWN → MAGIC (position 1).")
        print("  3. Press DOWN → MATERIA (position 2).")
        print("  4. Press DOWN x3 → STATUS (position 4).")
        print("  5. Press UP → EQUIP (position 3).")
        print("  6. Press Enter → open a submenu (e.g. Item list).")
        print("  7. Press Cancel → close submenu, back to main menu.")
        print("  8. Press Cancel → close main menu entirely.")
        print()
        print("Polling... (Ctrl+C to stop and see summary)")
        print()

        # Take first snapshot as baseline.
        prev_snap   = frida_script.exports_sync.snapshot(regions_arg)
        snapshot_num = 0
        change_log  = []  # list of (snapshot_num, changes)

        try:
            while True:
                time.sleep(0.2)
                curr_snap    = frida_script.exports_sync.snapshot(regions_arg)
                snapshot_num += 1

                changes = diff_regions(prev_snap, curr_snap)
                if changes:
                    ts = time.strftime('%H:%M:%S')
                    print(f"[{ts}] SNAP#{snapshot_num:04d} — {len(changes)} byte(s) changed:")
                    for label, base, offset, old, new in changes:
                        abs_addr = base + offset
                        print(f"  {label}+0x{offset:04X} (0x{abs_addr:08X}):  "
                              f"0x{old:02X} -> 0x{new:02X}  "
                              f"(was {old:3d}, now {new:3d})")
                    print()
                    change_log.append((snapshot_num, changes))

                prev_snap = curr_snap

        except KeyboardInterrupt:
            print("\n\n=== SUMMARY OF ALL CHANGES ===")
            print(f"Total snapshots: {snapshot_num}")
            print(f"Snapshots with changes: {len(change_log)}")
            print()

            # Tally which offsets changed most frequently — likely candidates for
            # cursor positions or animation counters. Cursor positions change exactly
            # once per keypress; animation counters change every poll.
            from collections import Counter
            offset_counts = {}
            for _sn, chg_list in change_log:
                for label, base, offset, old, new in chg_list:
                    key = (label, offset)
                    offset_counts[key] = offset_counts.get(key, 0) + 1

            print("Change frequency per offset (cursor = changes a few times total;")
            print("animation counter = changes every poll):")
            for (label, offset), count in sorted(offset_counts.items(),
                                                  key=lambda x: -x[1])[:40]:
                base     = next(b for l, b, _ in REGIONS if l == label)
                abs_addr = base + offset
                print(f"  {label}+0x{offset:04X} (0x{abs_addr:08X}): changed {count} times")

            print()
            print("The offset that changes exactly once per cursor move (steps 2-5)")
            print("is the cursor position byte.")
            print("The offset that changes on menu open/close (steps 1, 8) but NOT")
            print("on cursor moves is the menu-open indicator.")
            print(f"\nLog saved to: {log_path}")

    finally:
        if session:
            session.detach()
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
