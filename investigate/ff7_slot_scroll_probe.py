#!/usr/bin/env python3
"""
ff7_slot_scroll_probe.py -- Find the slot-list SCROLL OFFSET for the
save/continue menus (2026-07-17, v2.29.1 bug report).

THE BUG:
  The 15-slot list shows 3 slots at a time. The scanned "slot cursor"
  bytes (LOADMENU 0xDD6DD4 / SAVEMENU 0xDC6B1C) are the VISIBLE-ROW
  index 0..2, not the absolute slot: both scans only pressed Down/Up
  once from the top, inside the window, where row == absolute slot --
  the two are indistinguishable there. Player-reported symptom confirms
  it: scroll deep, come back up, the mod says "Slot 1" while the real
  slot is scroll+row.

METHOD:
  The scroll offset is a sibling field of the row cursor (both menus'
  structs already echoed each other at +0x3C grid->row). Rather than a
  whole-BSS scan, poll a 0x100-byte WINDOW around each menu's struct at
  50 ms and log every byte change with its offset. The player scrolls
  slowly to the bottom of the list and back: the row byte pins at 2 and
  the scroll byte keeps stepping -- unmistakable in the log. If an
  ABSOLUTE-index byte exists too (steps on every press, 0..14), the same
  log exposes it, and the mod can use it directly instead of adding.

HOW TO RUN:
  1. Open either menu's slot list (title Continue -> a save file, or a
     save point -> SAVE -> a file).
  2. Run this script. Then: slowly press Down until the very bottom of
     the list (slot 15), pause, then Up back to the top. ~90 seconds.
  3. All movement is logged automatically; results analyzed offline.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"

# 0x100-byte windows centred on each menu's known cursor struct.
WINDOWS = {
    "LOAD (title 0xDD6D80)": (0x00DD6D80, 0x100),
    "SAVE (field 0xDC6A80)": (0x00DC6A80, 0x100),
    # The load menu's list-open pointer block, for correlation.
    "LOADPTR (0xDD7700)":    (0x00DD7700, 0x10),
}

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


def read_region(handle, base, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size,
                               ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"slot_scroll_probe_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("Slot-list scroll probe (windows around both menus' structs)")

        speak("Scroll probe running. In the slot list, slowly press Down "
              "to the very bottom of the list, pause, then Up back to "
              "the top. Ninety seconds.", wait=True)

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
        for name, (base, size) in WINDOWS.items():
            last[name] = read_region(handle, base, size)
            if last[name] is None:
                print(f"  WARNING: cannot read {name}")

        t_end = time.time() + 90
        while time.time() < t_end:
            for name, (base, size) in WINDOWS.items():
                snap = read_region(handle, base, size)
                if snap is None or last[name] is None:
                    last[name] = snap
                    continue
                if snap != last[name]:
                    stamp = time.strftime('%H:%M:%S')
                    for i in range(size):
                        if snap[i] != last[name][i]:
                            print(f"  [{stamp}] {name} +0x{i:02X} "
                                  f"(0x{base+i:08X}): "
                                  f"{last[name][i]} -> {snap[i]}")
                    last[name] = snap
            time.sleep(0.05)

        print("\n(window over)")
        speak("Probe complete. Results are in the log.", wait=True)

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
