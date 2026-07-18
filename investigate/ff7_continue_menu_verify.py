#!/usr/bin/env python3
"""
ff7_continue_menu_verify.py -- Live-poll the v2.29 SAVEMENU_* addresses on
the TITLE-SCREEN Continue menu (2026-07-17).

WHY:
  v2.29 shipped with the save menu speaking (addresses scanned + grid
  cursor live-verified IN THE FIELD save menu), but the player reports
  the title-screen Continue menu is SILENT. The load-mode design assumed
  the Continue menu reuses the same module state (SAVEMENU_GRID_CURSOR
  0xDC6AE0, SAVEMENU_SLOT_CURSOR 0xDC6B1C, SAVEMENU_PHASE 0xDC1210)
  gated on FIELD_ID==0, with a stand-down range guard (grid>9, slot>14,
  phase>1). Silence has exactly two candidate causes and this script
  separates them with live evidence:
    (a) one of the three bytes holds out-of-range title-module data, so
        the guard mutes everything (fix: guard only the value being
        spoken), or
    (b) the Continue menu keeps its state elsewhere (fix: new scan).
  It also logs FIELD_ID / MENU_OPEN / MENU_CURSOR / GAME_MODE each
  change, so whatever gate the fix needs is captured in the same run.

HOW TO RUN:
  1. Launch FF7, stay on the title screen, choose Continue so the
     "Select a save data file" grid is up. (Or run it first -- it polls
     continuously; everything is spoken.)
  2. Run this script; move around the grid, enter the slot list, move,
     cancel out. It speaks every tracked change and logs raw values.
  3. 90-second window, then a summary.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN = 0x00400000

ADDRS = {
    "grid":        (0x00DC6AE0, 1),
    "slot":        (0x00DC6B1C, 1),
    "phase":       (0x00DC1210, 1),
    "phase_alt":   (0x00DCA028, 1),   # scan runner-up
    "loadptr":     (0x00DD7700, 4),   # scan runner-up (heap ptr, u32)
    "FIELD_ID":    (0x00CC15D0, 2),
    "MENU_OPEN":   (0x00DC12DC, 1),
    "MENU_CURSOR": (0x00DC1154, 1),
    "GAME_MODE":   (0x00CC0D89, 1),
    "TITLE_CURSOR":(0x00DD6F24, 1),
}
SPOKEN = ("grid", "slot", "phase")        # spoken on change; rest log-only

PROCESS_VM_READ = 0x0010
PROCESS_VM_QUERY = 0x0400
k32 = ctypes.windll.kernel32


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak(text, wait=False):
    safe = text.replace("'", "''")
    try:
        p = subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if wait:
            p.wait(timeout=30)
    except Exception:
        pass


def find_pid(exe_name):
    result = subprocess.run(
        ['tasklist', '/FI', f'IMAGENAME eq {exe_name}', '/FO', 'CSV'],
        capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if exe_name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except ValueError:
                    pass
    return None


def read_val(handle, addr, width):
    buf = ctypes.create_string_buffer(width)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf,
                                 width, ctypes.byref(got)):
        return None
    return int.from_bytes(buf.raw[:width], 'little')


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"continue_menu_verify_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("Continue-menu live verify (v2.29 SAVEMENU_* on the title screen)")

        speak("Continue menu verify. Get to the title screen's Continue "
              "save file grid, then move around while I watch. "
              "Starting now.", wait=True)

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("Error. F F 7 not running.")
            print("ERROR: ff7_en.exe not running.")
            return
        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY,
                                 False, pid)
        if not handle:
            speak("Error. Could not open process.")
            print("ERROR: OpenProcess failed.")
            return
        print(f"PID: {pid}\n")

        last = {}
        seen_values = {name: set() for name in ADDRS}
        t_end = time.time() + 90
        while time.time() < t_end:
            row = {}
            for name, (addr, width) in ADDRS.items():
                row[name] = read_val(handle, addr, width)
            changed = [n for n in ADDRS if row[n] != last.get(n)]
            if changed:
                stamp = time.strftime('%H:%M:%S')
                line = ' '.join(f"{n}={row[n]}" for n in ADDRS)
                print(f"  [{stamp}] {line}   (changed: {','.join(changed)})")
                for n in changed:
                    if n in SPOKEN and row[n] is not None:
                        speak(f"{n} {row[n]}")
                last = row
            for n in ADDRS:
                if row[n] is not None:
                    seen_values[n].add(row[n])
            time.sleep(0.1)

        print("\nSUMMARY -- distinct values seen in 90s:")
        for n in ADDRS:
            vals = sorted(seen_values[n])
            shown = ', '.join(str(v) for v in vals[:12])
            print(f"  {n:<12}: {shown}{' ...' if len(vals) > 12 else ''}")
        print("\nREADING THE RESULT:")
        print("  - grid/slot/phase tracking your presses = addresses fine;")
        print("    the mod's range guard or gate is the bug (check which")
        print("    value sat out-of-range above).")
        print("  - grid/slot frozen while you moved = Continue menu keeps")
        print("    its state elsewhere -> new scan needed at the title.")
        speak("Verify window over. Results are in the log.", wait=True)

    except KeyboardInterrupt:
        print("\n  [Stopped by user]")
        speak("Stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
