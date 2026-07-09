#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_edge_scan.py -- Full-heap scan, but edge-correlated
instead of phase-averaged.

WHY (2026-07-07): ff7_battle_menu_cursor_fullscan.py enumerated all 894
committed writable regions (126MB) and diffed idle-vs-continuous-mashing.
It came back with 603,431 "nav-only" candidates -- completely overwhelmed
by background engine churn (audio streaming, particles, animation,
allocator activity) that never truly goes idle in a live 3D battle scene.
Continuous mashing vs continuous idling cannot be separated at this scale.

This version keeps the same full-heap enumeration (the PSX-decomp-inspired
insight that the cursor is a small generic struct that could be ANYWHERE,
not just in the previously-assumed static/32MB-heap range, still holds),
but changes the test signal: instead of "did it change sometime during
a 20s window", it checks "did it change in EVERY single isolated press,
and NEVER during the quiet gaps between presses." That edge-alignment
requirement is far more selective -- background noise is not synchronized
to our press cues, so it will rarely satisfy this for all N presses.

SAFETY: only Up/Down are used. Do NOT press Right (=Confirm) or Left.

PROCEDURE (self-cued, no chat round-trip):
  1. Speaks full instructions once.
  2. Enumerates memory regions once.
  3. For each of N_PRESSES repetitions:
       a. Quiet gap (do not touch anything) -- snapshot at the end, diffed
          against the previous snapshot -> "quiet_changed" set.
       b. Beep cue -> press Down once -> settle gap -- snapshot at the end,
          diffed against the previous snapshot -> "active_changed" set.
  4. Reports addresses that changed in ALL active windows and NONE of the
     quiet windows (strict), plus a looser near-miss list (tolerates one
     mismatch) in case of timing slop.
"""
import ctypes
import subprocess
import sys
import os
import time
import winsound
import numpy as np

PROCESS_NAME = "ff7_en.exe"

MAX_REGION_SIZE = 4 * 1024 * 1024
MIN_REGION_SIZE = 4

N_PRESSES = 6
QUIET_DURATION = 2.2
ACTIVE_DURATION = 2.2
MAX_PRINT = 100

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
WRITABLE_PROTECTS = {PAGE_READWRITE, PAGE_WRITECOPY,
                     PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

USERMODE_CEILING = 0x80000000

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


def snapshot_all(handle, regions):
    return {base: read_region(handle, base, size) for base, size in regions}


def diff_snapshots(prev, curr, regions):
    """Returns dict (base, offset) -> new_value for everything that changed."""
    changed = {}
    for base, size in regions:
        p = prev.get(base)
        c = curr.get(base)
        if p is None or c is None or len(p) != len(c):
            continue
        idx = np.nonzero(c != p)[0]
        if idx.size:
            vals = c[idx].tolist()
            for i, v in zip(idx.tolist(), vals):
                changed[(base, i)] = v
    return changed


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, f"battle_menu_edgescan_{time.strftime('%Y%m%d_%H%M%S')}.log")
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

        speak("Enumerating memory regions.")
        regions = enumerate_writable_regions(handle)
        total_bytes = sum(size for _, size in regions)
        print(f"Regions to scan: {len(regions)}, total bytes: {total_bytes:,} "
              f"({total_bytes / (1024*1024):.1f} MB)")

        speak(
            "Edge-correlated scan starting. Command window should be open. "
            "I will beep low for quiet, then beep high as the cue to press Down once, "
            "exactly one press per high beep. Do not press Right. "
            f"There will be {N_PRESSES} rounds. Starting now."
        )

        prev_snap = snapshot_all(handle, regions)
        print(f"Baseline snapshot taken ({len(prev_snap)} regions).")

        quiet_changed = []   # list of dict per round
        active_changed = []  # list of dict per round

        for i in range(N_PRESSES):
            beep(500, 150)
            time.sleep(QUIET_DURATION)
            curr_snap = snapshot_all(handle, regions)
            qc = diff_snapshots(prev_snap, curr_snap, regions)
            quiet_changed.append(qc)
            prev_snap = curr_snap
            print(f"  Round {i+1}: quiet-gap changed offsets = {len(qc)}")

            beep(1400, 150)
            time.sleep(ACTIVE_DURATION)
            curr_snap = snapshot_all(handle, regions)
            ac = diff_snapshots(prev_snap, curr_snap, regions)
            active_changed.append(ac)
            prev_snap = curr_snap
            print(f"  Round {i+1}: press-window changed offsets = {len(ac)}")

        beep(1100, 300); time.sleep(0.3); beep(1100, 300)
        speak("Scan complete. You may act normally now.")

        # ── Analysis ─────────────────────────────────────────────────────
        print("\n" + "=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        all_keys = set()
        for d in quiet_changed + active_changed:
            all_keys.update(d.keys())
        print(f"\n  Total distinct offsets touched across all rounds: {len(all_keys)}")

        strict = []
        loose = []
        for key in all_keys:
            active_hits = sum(1 for d in active_changed if key in d)
            quiet_hits = sum(1 for d in quiet_changed if key in d)
            last_val = None
            for d in reversed(active_changed):
                if key in d:
                    last_val = d[key]
                    break
            if last_val is None:
                for d in reversed(quiet_changed):
                    if key in d:
                        last_val = d[key]
                        break
            if active_hits == N_PRESSES and quiet_hits == 0:
                strict.append((key, active_hits, quiet_hits, last_val))
            elif active_hits >= N_PRESSES - 1 and quiet_hits <= 1:
                loose.append((key, active_hits, quiet_hits, last_val))

        strict.sort(key=lambda t: (-t[1], t[2]))
        loose.sort(key=lambda t: (-t[1], t[2]))

        print(f"\n  STRICT matches (changed every press, never during quiet): {len(strict)}")
        print(f"  {'AbsAddr':10}  {'RegionBase':10}  {'Offset':>8}  {'ActiveHits':>10}  {'QuietHits':>9}  {'LastVal':>7}")
        print(f"  {'-'*10}  {'-'*10}  {'-'*8}  {'-'*10}  {'-'*9}  {'-'*7}")
        for (base, off), ah, qh, val in strict[:MAX_PRINT]:
            print(f"  0x{base+off:08X}  0x{base:08X}  0x{off:06X}  {ah:10d}  {qh:9d}  {val!s:>7}")

        print(f"\n  LOOSE near-misses (>= {N_PRESSES-1} active hits, <=1 quiet hit): {len(loose)}")
        print(f"  {'AbsAddr':10}  {'RegionBase':10}  {'Offset':>8}  {'ActiveHits':>10}  {'QuietHits':>9}  {'LastVal':>7}")
        print(f"  {'-'*10}  {'-'*10}  {'-'*8}  {'-'*10}  {'-'*9}  {'-'*7}")
        for (base, off), ah, qh, val in loose[:MAX_PRINT]:
            print(f"  0x{base+off:08X}  0x{base:08X}  0x{off:06X}  {ah:10d}  {qh:9d}  {val!s:>7}")

        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
