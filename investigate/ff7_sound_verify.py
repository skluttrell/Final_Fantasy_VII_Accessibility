#!/usr/bin/env python3
"""
ff7_sound_verify.py — Live monitor for Sound sub-menu slider addresses.

Polls a small set of candidate addresses in the FFNx (AF3DN.P) DLL every 200ms
and speaks/logs any change.  Navigate the Sound sub-menu and press Left/Right on
each slider to confirm which addresses track Music volume and FX volume.

CANDIDATE ADDRESSES (relative to AF3DN.P base):
  Music candidate: +0x1DA2A68  (found by sound_scan_20260703_103217.log)
  FX candidate:    Not yet known.  This script checks a window of ±32 bytes
                   around the Music candidate to find adjacent fields.

HOW TO RUN:
  1. Open FF7, enter the Sound sub-menu (main menu → Config → Sound).
  2. Run this script.  It speaks "ready" when connected.
  3. Stay in FF7.  Move the Music slider with Left/Right and listen.
     The script speaks "<label>: <new_value>" for each address that changes.
  4. Move to the FX slider and repeat.
  5. Press Ctrl+C to stop.

HOW TO INTERPRET:
  - If one address speaks only when Music slider moves → it is the Music address.
  - If another speaks only when FX slider moves → it is the FX address.
  - If the same address speaks for both sliders → sliders share storage (unlikely).
  - If NO address speaks → the real addresses are outside the ±32-byte window;
    widen WINDOW_BYTES and re-run.
  - The before=0/after=236 anomaly from the scan was caused by the slider being
    at minimum — the monitor will show the live value directly, making it obvious.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os

PROCESS_NAME     = "ff7_en.exe"
FFNX_MODULE      = "AF3DN.P"
MUSIC_OFFSET     = 0x1DA2A68   # candidate from scan; may be off by a few bytes
WINDOW_BYTES     = 32          # monitor MUSIC_OFFSET ± this many bytes
POLL_MS          = 200

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

k32 = ctypes.windll.kernel32


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


def speak(text):
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
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
    return handle if handle else None


def find_module_range(pid, module_name):
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize",        ctypes.c_ulong),
            ("th32ModuleID",  ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("GlblcntUsage",  ctypes.c_ulong),
            ("ProccntUsage",  ctypes.c_ulong),
            ("modBaseAddr",   ctypes.c_void_p),
            ("modBaseSize",   ctypes.c_ulong),
            ("hModule",       ctypes.c_void_p),
            ("szModule",      ctypes.c_char * 256),
            ("szExePath",     ctypes.c_char * 260),
        ]

    snap = k32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == ctypes.c_void_p(-1).value:
        return None, 0

    me = MODULEENTRY32()
    me.dwSize = ctypes.sizeof(MODULEENTRY32)
    base, size = None, 0
    if k32.Module32First(snap, ctypes.byref(me)):
        while True:
            if me.szModule.decode('ascii', errors='ignore').lower() == module_name.lower():
                base = me.modBaseAddr
                size = me.modBaseSize
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                  buf, n, ctypes.byref(read))
    if not ok or read.value != n:
        return None
    return list(buf.raw)


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"sound_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Sound Sub-menu Verify")
        print("Polls candidate addresses near Music+0x1DA2A68 in AF3DN.P.")
        print("Move each slider with Left/Right and listen for changes.")
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

        ffnx_base, ffnx_size = find_module_range(pid, FFNX_MODULE)
        if ffnx_base is None:
            print("ERROR: AF3DN.P not found in process.  Is FFNx installed?")
            return
        print(f"AF3DN.P base: 0x{ffnx_base:08X}  size: 0x{ffnx_size:X}")

        # Monitor window: MUSIC_OFFSET ± WINDOW_BYTES, clamped to DLL range
        watch_start = max(0, MUSIC_OFFSET - WINDOW_BYTES)
        watch_end   = min(ffnx_size - 1, MUSIC_OFFSET + WINDOW_BYTES + 3)
        watch_count = watch_end - watch_start + 1
        watch_base  = ffnx_base + watch_start

        print(f"Monitoring {watch_count} bytes: "
              f"AF3DN.P+0x{watch_start:X} … +0x{watch_end:X}")
        print()

        # Print address key
        print("  ADDRESS KEY (offset from AF3DN.P base):")
        for i in range(watch_start, watch_end + 1):
            marker = " ← scan candidate" if i == MUSIC_OFFSET else ""
            print(f"    +0x{i:X}  (0x{ffnx_base + i:08X}){marker}")
        print()

        prev = read_bytes(handle, watch_base, watch_count)
        if prev is None:
            print("ERROR: Could not read watch region.")
            return

        # Print initial values
        print("  Initial values:")
        for i in range(watch_count):
            offset = watch_start + i
            marker = " ← scan candidate" if offset == MUSIC_OFFSET else ""
            print(f"    +0x{offset:X}  {prev[i]:3d}  (0x{prev[i]:02X}){marker}")
        print()

        speak("Sound verify running. Switch to F F 7 and move the sliders.")

        while True:
            time.sleep(POLL_MS / 1000.0)
            curr = read_bytes(handle, watch_base, watch_count)
            if curr is None:
                continue

            for i in range(watch_count):
                if curr[i] != prev[i]:
                    offset = watch_start + i
                    addr   = ffnx_base + offset
                    ts     = time.strftime("%H:%M:%S")
                    label  = f"+0x{offset:X}"
                    print(f"  >>> {ts}  {label} (0x{addr:08X})  "
                          f"{prev[i]} → {curr[i]}")
                    speak(f"{label}: {curr[i]}")

            prev = curr

    except KeyboardInterrupt:
        print()
        print("  [Stopped by user]")
        speak("Verify stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        print(f"\nLog saved to: {log_path}")
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
