#!/usr/bin/env python3
"""
ff7_menu_cursor_verify.py — Confirm the main-menu cursor address and menu-open flag.

After ff7_menu_cursor_scan.py produces candidate addresses, run this script
to verify which one actually tracks the main-menu cursor in real time.

The script polls each candidate every 100ms and speaks the value when it
changes, so you can hear which address tracks cursor movement in the main menu.

It also watches for the value going to 0 or non-zero when you open/close
the menu, to help identify the "menu is open" flag address.

USAGE:
  Edit CANDIDATES below with the address(es) from the scan log, then run.
  Navigate the main menu with Up/Down. The correct address will speak the
  current position each time you press a direction.

  Without PHS (early game, 3 party members):
    0=Item, 1=Magic, 2=Equip, 3=Status, 4=Order, 5=Limit, 6=Config,
    7=Save, 8=Quit

  With PHS (4+ party members available):
    0=Item, 1=Magic, 2=Equip, 3=Status, 4=Order, 5=Limit, 6=Config,
    7=PHS, 8=Save, 9=Quit

ALSO WATCH:
  Add suspected "menu is open" flag addresses to MENU_FLAG_CANDIDATES.
  They should read non-zero while inside the menu and zero outside.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"
POLL_MS      = 100   # 100ms poll — fast enough to catch cursor moves

# ── Edit these with your scan results ────────────────────────────────────────
# Format: (address_int, "label_string")
CANDIDATES = [
    # From menu_poll_20260701_112615.log — Phase 1 static-BSS hits.
    # 0x00CC1B42: count=17, last=8 (=QUIT). Strong cursor candidate.
    #   0x00CC... is the same region as FIELD_ID (0xCC15D0) — this is stable BSS.
    # 0x00CC1ABA: count=17, last=2. Possibly prior cursor pos or related state.
    (0x00CC1B42, "CURSOR_CC1B42"),  # primary: last=8=QUIT, count matches presses
    (0x00CC1ABA, "STATE_CC1ABA"),   # secondary: last=2, same count — may be related
]

# Potential "menu is open" flag addresses.
# These should read non-zero while inside the menu and zero in the field.
MENU_FLAG_CANDIDATES = [
    # 0x00DC1154: count=20, last=0 in Phase 2. Zero-at-rest is suspicious for
    # a "menu open" flag; leaving this here to observe its behaviour.
    (0x00DC1154, "FLAG_DC1154"),
]

# Menu option labels by cursor index.
# Without PHS (early game): 0–8 (Item through Quit).
# With PHS (4+ party members): 0–9 (Item through Quit, PHS at 7).
# The verify script reports the raw number AND this name, so you can see
# which layout matches your current game state.
# Confirmed from verify run 2026-07-01: Save=9, Quit=10.
# Slots 7 and 8 exist in the cursor range but are hidden/unlockable options
# not yet seen. Likely PHS (party swapping, unlocks when 4+ party members
# are available) and one other. Update this table when they appear in game.
MENU_OPTION_NAMES = {
    0:  "Item",
    1:  "Magic",
    2:  "Equip",
    3:  "Status",
    4:  "Order",
    5:  "Limit",
    6:  "Config",
    7:  "Unknown option 7",   # unlocks later — identify and update
    8:  "Unknown option 8",   # unlocks later — identify and update
    9:  "Save",
    10: "Quit",
}
# ─────────────────────────────────────────────────────────────────────────────

PROCESS_VM_READ = 0x0410   # VM_READ | QUERY_INFORMATION


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


def beep_change():
    winsound.Beep(1100, 60)


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


def main():
    if not CANDIDATES and not MENU_FLAG_CANDIDATES:
        print("ERROR: No candidates configured.")
        print("Edit the CANDIDATES list at the top of this script with")
        print("addresses from ff7_menu_cursor_scan.py, then re-run.")
        return

    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"menu_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            print("ERROR: ff7_en.exe not running.")
            print(f"\nLog saved to: {log_path}")
            return
        print(f"PID: {pid}")

        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            print(f"\nLog saved to: {log_path}")
            return

        all_watched = CANDIDATES + MENU_FLAG_CANDIDATES

        speak_wait(
            "Verifying main menu cursor candidates. "
            "Open the main menu and move the cursor up and down between options. "
            "I will speak the option name each time the value changes. "
            "The correct cursor address will call out Item, Magic, Equip, and so on "
            "each time you press up or down. "
            "Also open and close the menu to test the menu-open flag candidates — "
            "those should change when you open and close the menu overlay. "
            "Press Control C when done."
        )

        print("Watching:")
        last = {}
        for addr, label in all_watched:
            v = read_byte(handle, addr)
            option = MENU_OPTION_NAMES.get(v, f"({v})") if v is not None else "?"
            print(f"  {label:40s}  0x{addr:08X}  current={v}  ({option})")
            last[addr] = v
        print()
        print("Open the main menu and move the cursor. Press Ctrl+C to finish.")
        print()

        try:
            while True:
                time.sleep(POLL_MS / 1000.0)
                now = time.strftime('%H:%M:%S')
                for addr, label in all_watched:
                    v = read_byte(handle, addr)
                    if v is not None and v != last[addr]:
                        option = MENU_OPTION_NAMES.get(v, f"val={v}")
                        print(f"[{now}]  {label} (0x{addr:08X}): "
                              f"{last[addr]} -> {v}  ({option})")
                        beep_change()
                        speak_wait(f"{label}: {option}")
                        last[addr] = v
        except KeyboardInterrupt:
            print()
            print("=== FINAL VALUES ===")
            for addr, label in all_watched:
                v    = read_byte(handle, addr)
                opt  = MENU_OPTION_NAMES.get(v, f"({v})") if v is not None else "?"
                print(f"  {label:40s}  0x{addr:08X}  = {v}  {opt}")
            print()
            print("INTERPRETATION:")
            print("  Correct CURSOR address: spoke a new menu option name each time")
            print("  you pressed Up or Down in the main menu.")
            print("  Correct MENU_OPEN FLAG: non-zero while inside the menu,")
            print("  zero while in the field (outside the menu).")
            print()
            print(f"Log saved to: {log_path}")
            speak_wait("Verification complete. Check the log.")

    finally:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
