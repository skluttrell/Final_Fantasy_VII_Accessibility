#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_fullscan.py -- Enumerate ALL committed, writable memory
regions of the FF7 process (via VirtualQueryEx) instead of guessing a fixed
static/heap range, and delta-scan them for the battle command-menu cursor.

WHY THIS APPROACH (2026-07-07):
  Five earlier approaches (see project memory) scanned only 0x400000-0xDE0000
  (static) and 0xDE0000-0x02000000 (first 32MB of heap), plus the two known
  per-actor structs (G_BATTLE_MODEL_STATE / G_SMALL_BATTLE_MODEL_STATE). All
  came up empty.

  A partial PSX decompile of the original game (PSX_decomps/ff7-decomp)
  revealed the original engine's battle menus are all instances of a generic,
  small (0x240-byte) "widget" struct with a cursorRow/scroll field -- NOT
  part of any per-actor struct, and selected via a single "current widget
  index" global. That means our per-actor scans were the wrong shape of
  search entirely.

  Separately, our 32MB heap cap may simply have been too small: a modern
  FFNx-enhanced process can have several hundred MB of committed heap
  (textures, buffers, etc.), and a small game-logic allocation like a menu
  widget can land anywhere in that space, not just the first 32MB.

  This version walks the process's REAL memory map with VirtualQueryEx and
  scans every committed, writable region under MAX_REGION_SIZE (skipping
  huge asset/texture allocations, which are not where a small UI cursor
  struct would live), covering far more of the address space than any
  previous attempt.

SAFETY: only Up/Down are used. Do NOT press Right (=Confirm) or Left.

PROCEDURE (self-cued, no chat round-trip):
  1. Speaks instructions.
  2. Enumerates memory regions once (logged: count + total bytes).
  3. Phase A (idle, ~20s): do not touch anything.
  4. Phase B (nav, ~20s): press Down repeatedly and steadily.
  5. Reports nav-only candidates. "Clean" candidates (few distinct values
     seen -- looks like a bounded index, not noise) are listed before
     "noisy" ones (many distinct values -- likely audio/animation noise).
"""
import ctypes
import subprocess
import sys
import os
import time
import winsound
import numpy as np

PROCESS_NAME = "ff7_en.exe"

MAX_REGION_SIZE = 4 * 1024 * 1024   # skip huge asset/texture allocations
MIN_REGION_SIZE = 4
IDLE_DURATION = 20   # matches NAV_DURATION so time-only periodic noise
NAV_DURATION = 20     # (e.g. the ~8s animation cycle found earlier) hits both
SNAP_INTERVAL = 0.3
MAX_DISTINCT_VALUES = 10   # more distinct values seen => "noisy", deprioritize
MAX_PRINT = 200

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
WRITABLE_PROTECTS = {PAGE_READWRITE, PAGE_WRITECOPY,
                     PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

USERMODE_CEILING = 0x80000000  # 2GB; FF7 2013 exe is not LARGEADDRESSAWARE

k32 = ctypes.windll.kernel32


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]


k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                                ctypes.c_size_t]
k32.VirtualQueryEx.restype = ctypes.c_size_t


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


def speak(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
    except Exception:
        pass


def beep(freq=1000, ms=100):
    winsound.Beep(freq, ms)


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


def open_process(pid):
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    return handle if handle else None


def enumerate_writable_regions(handle):
    regions = []
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION()
    while addr < USERMODE_CEILING:
        ret = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        if size == 0:
            break
        if (mbi.State == MEM_COMMIT and mbi.Protect in WRITABLE_PROTECTS
                and MIN_REGION_SIZE <= size <= MAX_REGION_SIZE):
            regions.append((base, size))
        next_addr = base + size
        if next_addr <= addr:
            break
        addr = next_addr
    return regions


def read_region(handle, base, size):
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return np.frombuffer(buf, dtype=np.uint8).copy()
    return None


def poll_phase(handle, regions, duration_s, phase_label):
    print(f"\n[{phase_label}] Scanning {len(regions)} regions for {duration_s}s ...")

    prev = {}
    for base, size in regions:
        prev[base] = read_region(handle, base, size)

    changers = {}       # (base, offset) -> count
    last_val = {}
    values_seen = {}     # (base, offset) -> set of values (capped)
    deadline = time.time() + duration_s
    snap_num = 0

    while time.time() < deadline:
        time.sleep(SNAP_INTERVAL)

        for base, size in regions:
            curr = read_region(handle, base, size)
            p = prev.get(base)
            if curr is not None and p is not None and len(curr) == len(p):
                diff_idx = np.nonzero(curr != p)[0]
                if diff_idx.size:
                    curr_list = curr[diff_idx].tolist()
                    for i, v in zip(diff_idx.tolist(), curr_list):
                        key = (base, i)
                        changers[key] = changers.get(key, 0) + 1
                        last_val[key] = v
                        vs = values_seen.setdefault(key, set())
                        if len(vs) < 32:
                            vs.add(v)
            if curr is not None:
                prev[base] = curr

        snap_num += 1

    print(f"  Done: {snap_num} snapshots, {len(changers)} offsets changed.")
    return changers, last_val, values_seen


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, f"battle_menu_fullscan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("FF7 not found. Start the game and get into a battle first.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        speak("Enumerating memory regions. This may take a few seconds.")
        regions = enumerate_writable_regions(handle)
        total_bytes = sum(size for _, size in regions)
        print(f"Regions to scan: {len(regions)}, total bytes: {total_bytes:,} "
              f"({total_bytes / (1024*1024):.1f} MB)")

        speak(
            f"Found {len(regions)} regions, about {int(total_bytes/1024/1024)} megabytes. "
            "Command window should be open, only Up and Down, do not press Right. "
            "Phase A begins now. Do not touch anything for about twenty seconds."
        )

        print("=" * 60)
        print(f"  PHASE A: Idle Baseline ({IDLE_DURATION}s)")
        print("=" * 60)
        idle_changers, idle_last, idle_values = poll_phase(handle, regions, IDLE_DURATION, "Phase A: Idle")

        beep(880, 200); time.sleep(0.2); beep(880, 200)
        speak(
            "Phase B. Now press Down repeatedly and steadily, about once per second, "
            "for the next twenty seconds. I will beep when done."
        )
        print("=" * 60)
        print(f"  PHASE B: Navigation ({NAV_DURATION}s) -- press Down steadily")
        print("=" * 60)
        nav_changers, nav_last, nav_values = poll_phase(handle, regions, NAV_DURATION, "Phase B: Navigate")

        beep(1100, 300); time.sleep(0.3); beep(1100, 300)
        speak("Scan complete. You may act normally now.")

        # ── Analysis ─────────────────────────────────────────────────────
        print("\n" + "=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        idle_set = set(idle_changers.keys())
        nav_set = set(nav_changers.keys())
        nav_only = nav_set - idle_set

        print(f"\n  Idle-only (excluded):  {len(idle_set - nav_set)}")
        print(f"  Both phases (excluded): {len(nav_set & idle_set)}")
        print(f"  Nav-only (candidates):  {len(nav_only)}")

        results = []
        for key in nav_only:
            base, off = key
            abs_addr = base + off
            distinct = len(nav_values.get(key, set()))
            clean = distinct <= MAX_DISTINCT_VALUES
            results.append((clean, nav_changers[key], distinct, abs_addr, base, off, nav_last.get(key, 0xFF)))

        # clean first (sorted by count desc), then noisy (sorted by count desc)
        results.sort(key=lambda t: (not t[0], -t[1]))

        print(f"\n  {'Tag':6}  {'AbsAddr':10}  {'RegionBase':10}  {'Offset':>8}  "
              f"{'Count':>6}  {'Distinct':>8}  {'LastVal':>7}")
        print(f"  {'-'*6}  {'-'*10}  {'-'*10}  {'-'*8}  {'-'*6}  {'-'*8}  {'-'*7}")
        for clean, cnt, distinct, abs_addr, base, off, val in results[:MAX_PRINT]:
            tag = "clean" if clean else "noisy"
            print(f"  {tag:6}  0x{abs_addr:08X}  0x{base:08X}  0x{off:06X}  "
                  f"{cnt:6d}  {distinct:8d}  {val:7d}")

        if len(results) > MAX_PRINT:
            print(f"\n  ... {len(results) - MAX_PRINT} more not printed (see counts above).")

        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
