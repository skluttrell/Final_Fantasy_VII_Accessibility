#!/usr/bin/env python3
"""
ff7_title_verify.py — Confirm which candidate address is the title screen cursor.

Polls specific candidate addresses every 200ms and speaks the value when it
changes, so the user can hear which address tracks their cursor movement.

CANDIDATES from ff7_title_cursor_scan.py run (2026-06-30):
  0x012182D0  Continue=1, NewGame=0   (inverted binary toggle)
  0x012182D4  Continue=1, NewGame=0   (same, 4 bytes away)
  0x012412B4  Continue=0, NewGame=1   (clean binary toggle)

Run this while on the title screen. Move the cursor a few times. The address
that calls out "changed to 0" or "changed to 1" in sync with each cursor move
is the cursor address.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"
POLL_MS      = 200

CANDIDATES = [
    (0x00DD6F24, "TITLE_CURSOR"),   # count=20, last=1 from poll — strong candidate
]

PROCESS_VM_READ = 0x0410   # VM_READ (0x10) | QUERY_INFORMATION (0x400)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress',       ctypes.c_void_p),
        ('AllocationBase',    ctypes.c_void_p),
        ('AllocationProtect', ctypes.c_ulong),
        ('RegionSize',        ctypes.c_size_t),
        ('State',             ctypes.c_ulong),
        ('Protect',           ctypes.c_ulong),
        ('Type',              ctypes.c_ulong),
    ]

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
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"title_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            return
        print(f"PID: {pid}")

        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_VM_READ, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        speak_wait(
            "Verifying title cursor address 0xDD6F24. "
            "Go to the title screen and move the cursor between Continue and New Game. "
            "I will say the new value each time it changes. "
            "It should say 0 on one option and 1 on the other. "
            "Press Control C when done."
        )

        print("Watching:")
        for addr, label in CANDIDATES:
            v = read_byte(handle, addr)
            print(f"  {label}  0x{addr:08X}  current={v}")
        print()
        print("Move cursor back and forth. Press Ctrl+C to finish.")
        print()

        last = {addr: read_byte(handle, addr) for addr, _ in CANDIDATES}

        try:
            while True:
                time.sleep(POLL_MS / 1000.0)
                now = time.strftime('%H:%M:%S')
                for addr, label in CANDIDATES:
                    v = read_byte(handle, addr)
                    if v is not None and v != last[addr]:
                        print(f"[{now}]  {label} (0x{addr:08X}): {last[addr]} -> {v}")
                        beep_change()
                        speak_wait(f"{label} changed to {v}")
                        last[addr] = v
        except KeyboardInterrupt:
            print()
            print("=== FINAL VALUES ===")
            for addr, label in CANDIDATES:
                v = read_byte(handle, addr)
                print(f"  {label}  0x{addr:08X}  = {v}")
            print()
            print("If one label consistently changed to 0 on one option and 1 on "
                  "the other, that is the cursor address.")
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
