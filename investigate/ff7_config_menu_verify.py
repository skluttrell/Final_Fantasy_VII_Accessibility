#!/usr/bin/env python3
"""
ff7_config_menu_verify.py — Confirm CONFIG_ROW and CONFIG_OPEN candidates.

Polls the top candidates from ff7_config_menu_scan.py in a live loop, printing
each address's current value every 200 ms and announcing changes via TTS.  The
user navigates inside and outside the Config sub-menu while watching/hearing
which addresses respond correctly.

CANDIDATES UNDER TEST:

  CONFIG_ROW (which row 0–9 is highlighted in the Config sub-menu):
    DC10F0  = 0x00DC10F0   count=33, last=8 (Camera angle) — in DC block near MENU_CURSOR
    DC3D11  = 0x00DC3D11   count=28, last=0 (Window color) — in DC3D block
    DC3D12  = 0x00DC3D12   count=28, last=0 (Window color) — adjacent to DC3D11

  CONFIG_OPEN (set while config sub-menu is visible, 0 otherwise):
    DC3D00  = 0x00DC3D00   0→1 clean flag — DC3D block head
    DC3D04  = 0x00DC3D04   0→1 clean flag — DC3D block +4
    CFFB7C  = 0x00CFFB7C   0→1 clean flag — CFB block
    CFFB8C  = 0x00CFFB8C   0→1 clean flag — CFB block +10

  KNOWN FALSE POSITIVE (do not use):
    ADE34   = 0x009ADE34   button-press toggle — confirmed false in main menu scan

  REFERENCE (already confirmed):
    MENU_OPEN   = 0x00DC12DC  fires for main menu AND config — will appear in both states
    MENU_CURSOR = 0x00DC1154  main menu row (should freeze at 7=Config while config open)

WHAT TO DO:
  1. Run this script.  It prints a header then polls every 200 ms.
  2. Watch the table for changes as you navigate.

  CONFIG_ROW test:
    a. Open the Config sub-menu.
    b. Press Down to move through rows 0→9.  Good CONFIG_ROW address will count up 0→9.
    c. Press Up to move 9→0.  Good address counts back down.
    d. Any address that just toggles 0/1 on every press (regardless of direction)
       is the false-positive button toggle — ignore it.

  CONFIG_OPEN test:
    a. Stand in the field (all menus closed).  CONFIG_OPEN candidates must read 0.
    b. Open the main menu WITHOUT going into Config.  CONFIG_OPEN must remain 0
       (otherwise it is just MENU_OPEN in disguise, which we already have).
    c. Navigate to Config and press Confirm.  CONFIG_OPEN candidate must go non-zero.
    d. Press Cancel to close Config (back to main menu).  CONFIG_OPEN must return to 0.
    e. Press Cancel to close main menu.  CONFIG_OPEN must remain 0.

  Ideal result:
    CONFIG_ROW  — counts 0–9 in sync with Up/Down presses in the config sub-menu
    CONFIG_OPEN — reads 0 in field, 0 in main menu (without config), 1 while config open

Press Ctrl+C to exit.  Results are logged.
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
POLL_MS      = 200   # milliseconds between reads

CANDIDATES = {
    # label          : (address, description)
    "DC10F0"    : (0x00DC10F0, "CONFIG_ROW?  count=33 last=8"),
    "DC3D11"    : (0x00DC3D11, "CONFIG_ROW?  count=28 last=0"),
    "DC3D12"    : (0x00DC3D12, "CONFIG_ROW?  count=28 last=0  adj to DC3D11"),
    "DC3D00"    : (0x00DC3D00, "CONFIG_OPEN? 0→1 clean flag"),
    "DC3D04"    : (0x00DC3D04, "CONFIG_OPEN? 0→1 clean flag"),
    "CFFB7C"    : (0x00CFFB7C, "CONFIG_OPEN? 0→1 clean flag"),
    "CFFB8C"    : (0x00CFFB8C, "CONFIG_OPEN? 0→1 clean flag"),
    # Reference — known
    "ADE34_FP"  : (0x009ADE34, "KNOWN FALSE POSITIVE — button toggle"),
    "MENU_OPEN" : (0x00DC12DC, "MENU_OPEN (ref) — fires for both menu+config"),
    "MENU_CUR"  : (0x00DC1154, "MENU_CURSOR (ref) — should freeze at 7 in config"),
}

CONFIG_ROW_NAMES = {
    0: "Window color",  1: "Sound",       2: "Controller",
    3: "Cursor",        4: "ATB",         5: "Battle speed",
    6: "Battle msg",    7: "Field msg",   8: "Camera angle",
    9: "Magic order",
}

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
PROCESS_VM_ALL   = PROCESS_VM_READ | PROCESS_VM_QUERY

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


def speak_async(text):
    """Fire-and-forget TTS — does not block the poll loop."""
    safe = text.replace("'", "''")
    try:
        subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


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


def read_byte(handle, addr):
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                  buf, 1, ctypes.byref(read))
    return buf.raw[0] if (ok and read.value == 1) else None


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"config_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Config Menu Verify — watching candidates")
        print("Press Ctrl+C to stop.")
        print()

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        # Print header
        print()
        labels = list(CANDIDATES.keys())
        header = "  Time(s)  " + "  ".join(f"{lbl:>8}" for lbl in labels)
        print(header)
        print("  " + "-" * (len(header) - 2))

        # Also print description key
        print()
        print("  ADDRESS KEY:")
        for lbl, (addr, desc) in CANDIDATES.items():
            print(f"    {lbl:>8} = 0x{addr:08X}  {desc}")
        print()
        print("  CONFIG ROW NAMES: 0=Window color  1=Sound  2=Controller  "
              "3=Cursor  4=ATB")
        print("                    5=Battle speed  6=Battle msg  7=Field msg  "
              "8=Camera  9=Magic order")
        print()

        # Poll loop
        prev_vals  = {lbl: None for lbl in labels}
        start_time = time.time()
        line_count = 0

        while True:
            curr_vals = {}
            for lbl, (addr, _) in CANDIDATES.items():
                curr_vals[lbl] = read_byte(handle, addr)

            elapsed = time.time() - start_time

            # Detect changes and build change log
            changes = {}
            for lbl in labels:
                old = prev_vals[lbl]
                new = curr_vals[lbl]
                if old is not None and new is not None and old != new:
                    changes[lbl] = (old, new)

            # Print a row every poll cycle (200ms)
            vals_str = "  ".join(
                f"{curr_vals[lbl]:8d}" if curr_vals[lbl] is not None else "      ??"
                for lbl in labels
            )
            print(f"  {elapsed:7.1f}  {vals_str}")

            # Announce changes
            for lbl, (old, new) in changes.items():
                addr, desc = CANDIDATES[lbl]
                row_note = ""
                # For CONFIG_ROW candidates, annotate with row name
                if "CONFIG_ROW" in desc and 0 <= new <= 9:
                    row_note = f" = {CONFIG_ROW_NAMES[new]}"
                ts = time.strftime("%H:%M:%S")
                change_line = (f"  >>> {ts}  {lbl} (0x{addr:08X})  "
                               f"{old} → {new}{row_note}")
                print(change_line)
                # Speak changes for CONFIG_ROW candidates so user doesn't need
                # to watch the screen
                if "CONFIG_ROW" in desc:
                    name = CONFIG_ROW_NAMES.get(new, str(new))
                    speak_async(f"{lbl} {name}")
                elif "CONFIG_OPEN" in desc:
                    state = "open" if new != 0 else "closed"
                    speak_async(f"{lbl} config {state}")

            # Reprint header every 30 lines for readability
            line_count += 1
            if line_count % 30 == 0:
                print()
                print(header)
                print("  " + "-" * (len(header) - 2))

            prev_vals = curr_vals
            time.sleep(POLL_MS / 1000.0)

    except KeyboardInterrupt:
        print()
        print("  [Stopped by user]")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
