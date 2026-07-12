#!/usr/bin/env python3
"""
ff7_name_entry_pane_verify.py — Live confirmation of the pane flag found by
ff7_name_entry_pane_flag_scan.py (2026-07-12: 0x921ED4 read 0/1/0 across a
grid -> panel -> grid A/B/A park; sole clean boolean candidate).

Speaks exactly what the mod's panel TTS will speak, from the exact
addresses the mod will read:
  0x00921ED4  pane flag       0 = letter grid, 1 = side panel  (verifying)
  0x00DD4574  panel index     0=Space 1=Delete 2=Select 3=Default
                              (0/1 confirmed by effect; 2/3 by screen order)
The player crosses grid<->panel a few times and moves Up/Down on the panel;
if every spoken word matches what they know they did, both addresses are
confirmed and the mod feature is safe to build.

Runs for 60 seconds. Output teed to name_entry_pane_verify_<timestamp>.log.
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"

PANE_FLAG   = 0x00921ED4
PANEL_INDEX = 0x00DD4574
ROW_ADDR    = 0x00DD453C
COL_ADDR    = 0x00DD4538
ACTIVE      = 0x00DD46FC

PANEL_NAMES = {0: "Space", 1: "Delete", 2: "Select", 3: "Default"}

GRID = [
    list("ABCDEFGHIJ"),
    list("KLMNOPQRST"),
    ["U", "V", "W", "X", "Y", "Z", ",", ".", "+", "-"],
    list("abcdefghij"),
    list("klmnopqrst"),
    ["u", "v", "w", "x", "y", "z", ":", ";", "'", '"'],
    list("0123456789"),
]

DURATION_S = 60

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
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    if ok and read.value == 1:
        return buf.raw[0]
    return None


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"name_entry_pane_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
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

        speak_wait(
            "Pane verify. For one minute: cross between the letter grid and "
            "the side panel a few times, and move Up and Down while on the "
            "panel. I will say grid or the button name as you move. "
            "Starting now."
        )

        last_flag  = read_byte(handle, PANE_FLAG)
        last_panel = read_byte(handle, PANEL_INDEX)
        last_row   = read_byte(handle, ROW_ADDR)
        last_col   = read_byte(handle, COL_ADDR)
        print(f"start: pane_flag={last_flag} panel={last_panel} "
              f"row={last_row} col={last_col}")

        deadline = time.time() + DURATION_S
        while time.time() < deadline:
            time.sleep(0.10)
            flag  = read_byte(handle, PANE_FLAG)
            panel = read_byte(handle, PANEL_INDEX)
            row   = read_byte(handle, ROW_ADDR)
            col   = read_byte(handle, COL_ADDR)
            if None in (flag, panel, row, col):
                continue
            if read_byte(handle, ACTIVE) == 0:
                print("  [ACTIVE=0] naming screen closed — stopping early")
                break

            if flag != last_flag:
                print(f"  [PANE] {last_flag} -> {flag} (panel={panel})")
                if flag == 1:
                    speak_wait(PANEL_NAMES.get(panel, f"panel {panel}"))
                else:
                    cell = (GRID[row][col]
                            if row < 7 and col < 10 else f"row {row} col {col}")
                    speak_wait(f"grid, {cell}")
                last_flag = flag
            elif flag == 1 and panel != last_panel:
                print(f"  [PANEL] {last_panel} -> {panel}")
                speak_wait(PANEL_NAMES.get(panel, f"panel {panel}"))
            elif flag == 0 and (row != last_row or col != last_col):
                cell = (GRID[row][col]
                        if row < 7 and col < 10 else f"row {row} col {col}")
                print(f"  [GRID] row={row} col={col} -> {cell}")
                speak_wait(str(cell))

            last_panel, last_row, last_col = panel, row, col

        speak_wait("Verify finished. Tell Claude whether every word matched "
                   "what you did.")
        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
