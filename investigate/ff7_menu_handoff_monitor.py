#!/usr/bin/env python3
"""
ff7_menu_handoff_monitor.py — Menu/victory screen-identity investigation
========================================================================

WHY THIS EXISTS (2026-08-03 menu re-assessment):

The mod narrates menus with ~10 independent polling threads, and each one
decides "my screen is live" from a different combination of stale-able
bytes. The victory screens are the worst case: they raise MENU_OPEN=1
while MENU_CURSOR, MENU_DISPATCH_INDEX, and MENU_FOCUS_MODE all stay
STALE at their pre-battle values, so every thread guards against victory
with a different heuristic — a 4-second battle-recency tick window
(MenuCursor/Item/Status), BATTLE_END_MODE != 0 (Materia/Equip/Limit/
Magic — provably wrong during the first victory screen, whose mode is
0), or nothing at all (Save, Order). The v2.30.68 "settle gate" for the
post-battle Item-then-Quit false announce waits ~300ms, but its own
motivating log shows the menu module holding row 0 for ~0.8s — the fix
cannot cover its evidence, and the player reports the menu is still
wrong after victory screens.

One passive play-through of a battle answers every open question at
once. Specifically, this log settles:

 Q1. GAME_MODE during the victory screens. The menu-type dispatcher
     (0x6CDA83) switches on this byte — the offline jump-table decode
     (research doc §14) proved 6=name entry, 7=PHS, 8=shop, 9=main
     menu, and saw further-screen values (14/18/19) it never identified.
     If victory has its own value, that value is the clean POSITIVE
     "victory screens are up" signal, exactly parallel to the shop's
     GAME_MODE==8 gate — and the whole 4-second heuristic plus the
     cross-thread g_victory_active flag can be deleted.

 Q2. Whether MENU_OPEN stays continuously 1 across both results screens
     (EXP/AP -> gil/items) or dips between them. VictoryThread closes
     its window on any single-poll MENU_OPEN!=1; a dip would drop the
     gil announcement and the stale-row suppression mid-victory.

 Q3. What MENU_DISPATCH_INDEX / MENU_DISPATCH_TRANS do across the whole
     sequence: do they park at the last-visited sub-screen after menu
     close (the stale-dispatch false-open class), do they move during
     victory, and does TRANS (the "transition twin") behave like a
     menu-ready signal that could replace the settle gate outright?

 Q4. The anatomy of the 0.8s menu-open transient: what MENU_CURSOR does
     between MENU_OPEN going 1 and the module restoring the remembered
     row, and what TRANS/DISPATCH/GAME_MODE read during that window.
     A positive "menu interactive" signal here kills the settle gate.

 Q5. BATTLE_END_MODE's full lifecycle: its value between battles (if it
     rests at 3, the != 0 suppressor would deadlock the four gear
     threads — they demonstrably work, so something resets it; this log
     shows what and when), and its phase timeline across the screens.

METHOD: read-only ReadProcessMemory polling at 30ms (fast enough for the
~60ms GAME_MODE-blip class of transients), printing ONLY on change with
millisecond timestamps. Every change also prints a derived "EXPOSED:"
line evaluating the DLL's actual per-thread gate expressions against the
raw bytes — the log is self-diagnosing: any gate listed while a victory
screen is on-screen is a thread that would narrate stale UI right there
(modulo the DLL-internal victory suppressors this script exists to
replace). No user cues or keypresses needed — passive observation only;
the transitions themselves mark the phases. Correlate with
ffvii_accessibility.log timestamps (debug_log is on in the test period)
to see which announcements actually fired.

All output tees to a timestamped log file next to this script
(feedback_investigation_scripts rule — never require manual copy-paste).

Addresses: all long-confirmed constants from ff7_addresses.h (§4 of the
research doc); this script adds no new addresses, it samples known ones
in a context (victory) where they were never observed live.
"""

import ctypes
import datetime
import os
import struct
import subprocess
import sys
import time

# name -> (address, struct format). Names carry address+width so the log
# is self-contained even years later.
ADDRS = {
    'game_mode  (0xCC0D89 u8)':  (0x00CC0D89, 'B'),  # Q1: menu-type dispatcher input
    'field_id   (0xCC15D0 i16)': (0x00CC15D0, 'h'),  # stale-nonzero through battle?
    'menu_open  (0xDC12DC u8)':  (0x00DC12DC, 'B'),  # Q2: continuous across results?
    'menu_cursor(0xDC1154 u8)':  (0x00DC1154, 'B'),  # Q4: row-0 transient anatomy
    'dispatch   (0xDC12EC u32)': (0x00DC12EC, 'I'),  # Q3: parks at last sub-screen?
    'disp_trans (0xDC12E8 u32)': (0x00DC12E8, 'I'),  # Q3/Q4: menu-ready candidate
    'battle_end (0xDC1300 u16)': (0x00DC1300, 'H'),  # Q5: lifecycle incl. rest value
    'focus_mode (0xDC1324 u8)':  (0x00DC1324, 'B'),  # Order thread's pane byte
    'quit_cursor(0xDC0FA0 u8)':  (0x00DC0FA0, 'B'),  # stale-speak history; context
}


class Tee:
    """Mirror stdout into the log file — the console stays live for the
    (sighted) operator while the log captures everything for analysis."""
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


k32 = ctypes.windll.kernel32
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def open_ff7(wait=True):
    """Attach to ff7_en.exe; if wait=True, poll every 2s until it appears,
    so the script can be launched BEFORE the game boots."""
    announced = False
    while True:
        out = subprocess.check_output(
            ['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe', '/FO', 'CSV', '/NH'],
            text=True)
        for line in out.strip().splitlines():
            parts = [p.strip('"') for p in line.split(',')]
            if parts[0].lower() == 'ff7_en.exe':
                pid = int(parts[1])
                h = k32.OpenProcess(
                    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
                if not h:
                    raise RuntimeError(f"OpenProcess failed (PID {pid})")
                print(f"FF7 running (PID {pid})")
                return h
        if not wait:
            raise RuntimeError("ff7_en.exe not found — start FF7 first")
        if not announced:
            announced = True
            print("Waiting for ff7_en.exe to start...")
        time.sleep(2.0)


def read_val(h, va, fmt):
    size = struct.calcsize(fmt)
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size,
                               ctypes.byref(read))
    if not ok or read.value < size:
        return None
    return struct.unpack('<' + fmt, buf.raw)[0]


def exposed_gates(v):
    """Evaluate the DLL's per-thread screen gates against the raw bytes.

    These mirror the ACTUAL gate expressions in proxy.cpp (2026-08-03),
    MINUS the DLL-internal victory suppressors (g_victory_active, the
    4s tick window, BATTLE_END_MODE!=0) — deliberately, because this
    investigation exists to find the positive signal that should replace
    those. A thread listed here while a victory screen is visibly on
    screen = a thread whose base gate passes on stale data and is only
    saved (or not) by the heuristic layer.
    """
    fid   = v['field_id   (0xCC15D0 i16)']
    mode  = v['game_mode  (0xCC0D89 u8)']
    mopen = v['menu_open  (0xDC12DC u8)']
    mcur  = v['menu_cursor(0xDC1154 u8)']
    disp  = v['dispatch   (0xDC12EC u32)']
    if None in (fid, mode, mopen, mcur, disp):
        return None
    # MenuModuleForeignScreen(): name entry / PHS / shop stand-down.
    if mode in (6, 7, 8):
        return ['(foreign screen: all main-menu threads stand down)']
    gates = []
    base = (mopen == 1 and fid != 0)
    if base:
        gates.append('MenuCursor(main bar)')
        if mcur == 9:
            gates.append('Save(save_mode)')       # no victory suppressor at all
        if mcur == 7:
            gates.append('Config(cursor==7 proxy)')
        sub = {1: 'Item', 2: 'Magic', 3: 'Materia', 4: 'Equip',
               5: 'Status', 7: 'Limit', 15: 'Equip(dupe 15)'}
        if disp == 0:
            gates.append('Order(dispatch==0)')     # no victory suppressor at all
        elif disp in sub:
            gates.append(f'{sub[disp]}(dispatch=={disp})')
    return gates


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"menu_handoff_monitor_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    real_stdout = sys.stdout
    log_file = open(log_path, 'w', encoding='utf-8')
    sys.stdout = Tee(real_stdout, log_file)
    try:
        print(f"Log: {log_path}")
        print("Menu/victory handoff monitor — passive, read-only, 30ms poll.")
        print("Play sequence: field -> open menu (visit Magic, cancel out, "
              "close) -> win a battle -> pause a few seconds on EACH results "
              "screen before OK -> back on field wait ~5s -> open menu again, "
              "move cursor, close. Ctrl+C here when done.\n")
        h = open_ff7()

        last = None
        dead_polls = 0   # consecutive all-fail polls => process exited
        while True:
            vals = {name: read_val(h, va, fmt)
                    for name, (va, fmt) in ADDRS.items()}
            if all(v is None for v in vals.values()):
                dead_polls += 1
                if dead_polls >= 100:   # ~3s of total failure at 30ms
                    print("\nProcess gone — waiting for restart...")
                    k32.CloseHandle(h)
                    h = open_ff7(wait=True)
                    dead_polls = 0
                    last = None
                    continue
            else:
                dead_polls = 0
            if vals != last:
                stamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                # Print full snapshot but flag which fields CHANGED, so a
                # transition reads at a glance without diffing lines by eye.
                print(f"--- {stamp} ---")
                for name, v in vals.items():
                    changed = (last is not None and last.get(name) != v)
                    mark = ' *' if changed else '  '
                    if v is None:
                        print(f" {mark}{name} = READ FAIL")
                    else:
                        print(f" {mark}{name} = {v} (0x{v:X})")
                gates = exposed_gates(vals)
                if gates is not None:
                    print(f"  EXPOSED: {', '.join(gates) if gates else '(none)'}")
                last = vals
            time.sleep(0.03)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sys.stdout = real_stdout
        log_file.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
