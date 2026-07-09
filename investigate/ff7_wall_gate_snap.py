#!/usr/bin/env python3
"""
ff7_wall_gate_snap.py — Diagnose which wall-bump gate is stuck closed
======================================================================

The 2026-07-09 gate fix (game_mode / UC lock / movie word) killed the wall
tone entirely: after adding the three new gates it never fires even during
normal field play. One of the new gate addresses must be reading a blocking
value during ordinary gameplay. This script reads all gate inputs directly
from the running game every 500ms and prints ONLY on change, so the user can
just leave it running while standing on a field — the first snapshot already
answers which gate is wrong, and walking/menuing shows transitions.

No user cues needed — passive observation only.

Gate logic in the DLL (proxy.cpp WallBumpThread):
    tone allowed only if:
      field_id != 0 AND game_mode == 1 AND menu_open == 0
      AND uc_lock == 0 AND NOT (movie_word != 0 AND bgmovie == 0)
"""

import ctypes
import datetime
import os
import struct
import subprocess
import sys
import time

ADDRS = {
    'field_0   (0xCC0D88 u8)':  (0x00CC0D88, 'B'),  # neighbor byte — in case
    'game_mode (0xCC0D89 u8)':  (0x00CC0D89, 'B'),  # game_mode is at +0 not +1
    'uc_lock   (0xCC0DBA u8)':  (0x00CC0DBA, 'B'),
    'bgmovie   (0xCC0DC2 u8)':  (0x00CC0DC2, 'B'),
    'movie_word(0xCC1638 u16)': (0x00CC1638, 'H'),
    'menu_open (0xDC12DC u8)':  (0x00DC12DC, 'B'),
    'field_id  (0xCC15D0 i16)': (0x00CC15D0, 'h'),
    'key_input (0xCC0DF0 u32)': (0x00CC0DF0, 'I'),
}


class Tee:
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
    so the script can be launched BEFORE the game boots and will catch the
    process as soon as it exists (useful for observing boot-time values)."""
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


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"wall_gate_snap_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    real_stdout = sys.stdout
    log_file = open(log_path, 'w', encoding='utf-8')
    sys.stdout = Tee(real_stdout, log_file)
    try:
        print(f"Log: {log_path}")
        h = open_ff7()
        print("Polling every 500ms; printing only on change. Ctrl+C to stop.\n")

        last = None
        dead_polls = 0  # consecutive polls where every read failed
        while True:
            vals = {name: read_val(h, va, fmt)
                    for name, (va, fmt) in ADDRS.items()}
            # If every read fails repeatedly, the process has exited —
            # drop the stale handle and wait for a new ff7_en.exe.
            if all(v is None for v in vals.values()):
                dead_polls += 1
                if dead_polls >= 6:  # ~3 seconds of total failure
                    print("\nProcess gone — waiting for restart...")
                    k32.CloseHandle(h)
                    h = open_ff7(wait=True)
                    dead_polls = 0
                    last = None
                    continue
            else:
                dead_polls = 0
            if vals != last:
                last = vals
                stamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(f"--- {stamp} ---")
                for name, v in vals.items():
                    print(f"  {name} = {v if v is not None else 'READ FAIL'}"
                          + (f" (0x{v:X})" if isinstance(v, int) else ""))
                # Evaluate the DLL's exact gate expression.
                g = vals
                fid  = g['field_id  (0xCC15D0 i16)']
                mode = g['game_mode (0xCC0D89 u8)']
                menu = g['menu_open (0xDC12DC u8)']
                lock = g['uc_lock   (0xCC0DBA u8)']
                mov  = g['movie_word(0xCC1638 u16)']
                bgm  = g['bgmovie   (0xCC0DC2 u8)']
                if None not in (fid, mode, menu, lock, mov, bgm):
                    blockers = []
                    if fid == 0:  blockers.append('field_id==0')
                    if mode != 1: blockers.append(f'game_mode=={mode} (!=1)')
                    if menu != 0: blockers.append('menu_open!=0')
                    if lock != 0: blockers.append(f'uc_lock=={lock} (!=0)')
                    if mov != 0 and bgm == 0: blockers.append('movie_playing')
                    print(f"  => tone {'BLOCKED by: ' + ', '.join(blockers) if blockers else 'ALLOWED'}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sys.stdout = real_stdout
        log_file.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
