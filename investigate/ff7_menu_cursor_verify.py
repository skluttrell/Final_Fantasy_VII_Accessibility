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
    # From menu_isolate_20260701_121926.log — nav-only static candidates.
    #
    # 0x009ADE34: count=22, last=0 (Item). Closest count to ~20 expected presses.
    #   PRIMARY cursor candidate — isolated by subtracting menu-idle changes
    #   from menu-navigation changes, so this address is NOT a field-script
    #   variable; it only changes when the cursor moves in the main menu.
    #
    # 0x009ADE30: count=14, last=0. Four bytes before the primary. Could be the
    #   high word of a WORD-sized cursor field, or a related index.
    #
    # 0x00DC1154: count=37, last=9 (Save). Higher count than expected for ~20
    #   presses; may be a state counter rather than a direct cursor index.
    #   Also appeared in the poll scan (count=20) — watch it in both contexts.
    (0x009ADE34, "CURSOR_9ADE34"),  # primary: count=22, last=0=Item
    (0x009ADE30, "NEAR_9ADE30"),    # nearby:  count=14, last=0
    (0x00DC1154, "STATE_DC1154"),   # secondary: count=37, last=9=Save
]

# Potential "menu is open" flag addresses.
# These should read non-zero while inside the menu and zero in the field.
# The isolate scan found no exclusive menu-open flag in Phase A vs Phase B
# (Phase A was already inside the menu), so this list is empty for now.
# A separate field-vs-menu scan would be needed to find a toggle flag.
MENU_FLAG_CANDIDATES = []

# Menu option labels by cursor index.
# Confirmed layout (no PHS — early game with 3 party members):
#   0=Item  1=Magic  2=Equip  3=Status  4=Order  5=Limit  6=Config
#   7=???   8=???    (unlockable options — identity TBD)
#   9=Save  10=Quit
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
            "Verifying main menu cursor candidates from the isolate scan. "
            "Open the main menu and move the cursor slowly, one step at a time. "
            "I will speak the option name each time a candidate changes. "
            "The correct cursor address will say Item, Magic, Equip, Status, "
            "Order, Limit, Config, Save, Quit — one per button press. "
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
