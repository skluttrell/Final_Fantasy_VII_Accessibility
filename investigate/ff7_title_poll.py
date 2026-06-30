#!/usr/bin/env python3
"""
ff7_title_poll.py — Find the title screen cursor by polling change frequency.

Reads the FF7 game-data range every 200 ms using ReadProcessMemory. After
the user moves the cursor several times and presses Ctrl+C, bytes are ranked
by how many times they changed. The cursor byte changes exactly once per
button press; animation counters change every poll. They are easy to
distinguish.

SCAN RANGE: 0x00400000 – 0x02000000 (28 MB)
  The 0xCC0000–0xDE0000 field-mode range (SAVEMAP, MENU_OBJECTS, etc.) is
  completely absent during the title screen — those pages are not committed
  until the field module loads after game start. The title screen module
  uses its own allocations which appear in the 0x01200000 area (~18 MB).

PROCEDURE:
  1. Reach the title screen.
  2. Run this script — it beeps once when polling starts.
  3. Move the cursor back and forth between CONTINUE and NEW GAME using the
     controller. Do 8–10 moves spaced about 2 seconds apart.
  4. Press Ctrl+C.
  5. The summary shows bytes ranked by change count, lowest first.
     The cursor byte will appear near the top with a count matching your
     number of cursor moves (8–10). Animation counters will have counts
     in the hundreds.

AUDIO:
  SAPI speaks initial instructions and final result count.
  During polling: one beep whenever any byte changes in the range.
  (Background animation will beep continuously — that is expected and normal.)
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound
from collections import defaultdict

PROCESS_NAME = "ff7_en.exe"
SCAN_START   = 0x00400000
SCAN_END     = 0x02000000   # 28 MB; covers early allocations + 0x012xxxxx area
POLL_MS      = 200

PROCESS_VM_READ = 0x0410   # VM_READ (0x10) | QUERY_INFORMATION (0x400) — both needed
MEM_COMMIT      = 0x1000
PAGE_GUARD      = 0x100
PAGE_NOACCESS   = 0x01


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


def beep_start():
    winsound.Beep(900, 200)


def beep_done():
    winsound.Beep(600, 150)
    winsound.Beep(900, 150)
    winsound.Beep(1200, 300)


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


def readable_regions(handle, start, end):
    mbi  = MEMORY_BASIC_INFORMATION()
    addr = start
    k32  = ctypes.windll.kernel32
    while addr < end:
        ret = k32.VirtualQueryEx(
            handle, ctypes.c_void_p(addr),
            ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not ret:
            break
        region_end = addr + mbi.RegionSize
        if (mbi.State == MEM_COMMIT
                and not (mbi.Protect & PAGE_NOACCESS)
                and not (mbi.Protect & PAGE_GUARD)):
            size = min(region_end, end) - addr
            if size > 0:
                yield (addr, size)
        addr = max(region_end, addr + 1)


def read_all(handle):
    """Read entire scan range. Returns dict {base: bytearray}."""
    k32    = ctypes.windll.kernel32
    result = {}
    chunk  = 65536
    buf    = ctypes.create_string_buffer(chunk)
    read   = ctypes.c_size_t(0)
    for base, size in readable_regions(handle, SCAN_START, SCAN_END):
        data   = bytearray()
        offset = 0
        while offset < size:
            n  = min(chunk, size - offset)
            ok = k32.ReadProcessMemory(
                handle, ctypes.c_void_p(base + offset),
                buf, n, ctypes.byref(read))
            got = read.value if ok else 0
            data.extend(buf.raw[:got] if got else b'\x00' * n)
            if got and got < n:
                data.extend(b'\x00' * (n - got))
            offset += n
        result[base] = data
    return result


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"title_poll_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            speak_wait("Cannot open FF7. Try running as Administrator.")
            print("ERROR: OpenProcess failed.")
            return

        speak_wait(
            "Polling the FF7 game data range. "
            "Move the cursor between Continue and New Game at least 20 times. "
            "Space each move about 1 second apart. "
            "Then press Control C. "
            "I will beep once now when polling starts."
        )

        print(f"Scanning 0x{SCAN_START:08X}–0x{SCAN_END:08X} ({(SCAN_END-SCAN_START)//1024//1024} MB) every {POLL_MS} ms.")
        print("Move cursor 20+ times, then Ctrl+C.")
        print()

        beep_start()

        prev       = read_all(handle)
        poll_count = 0

        # change_count[abs_addr] = number of polls on which this byte changed
        change_count = defaultdict(int)
        # last_values[abs_addr]  = most recent value seen
        last_values  = {}
        # Seed last_values
        for base, data in prev.items():
            for i, b in enumerate(data):
                last_values[base + i] = b

        try:
            while True:
                time.sleep(POLL_MS / 1000.0)
                curr       = read_all(handle)
                poll_count += 1
                any_change = False

                for base, data_new in curr.items():
                    data_old = prev.get(base)
                    if data_old is None:
                        continue
                    n = min(len(data_old), len(data_new))
                    for i in range(n):
                        if data_old[i] != data_new[i]:
                            addr = base + i
                            change_count[addr] += 1
                            last_values[addr]   = data_new[i]
                            any_change          = True

                prev = curr

                # Print a period every 10 polls (~2s) as a heartbeat
                if poll_count % 10 == 0:
                    elapsed = poll_count * POLL_MS / 1000
                    print(f"  {elapsed:.0f}s — {len(change_count)} addresses changed so far.",
                          flush=True)

        except KeyboardInterrupt:
            print()
            print(f"=== POLL SUMMARY: {poll_count} polls, "
                  f"{poll_count * POLL_MS / 1000:.1f}s elapsed ===")
            print()

            if not change_count:
                speak_wait("No changes detected at all in the scan range.")
                print("No addresses changed. Is FF7 on the title screen?")
                print(f"\nLog saved to: {log_path}")
                return

            # Sort by change count, lowest first
            ranked = sorted(change_count.items(), key=lambda x: x[1])

            print(f"Total addresses that changed: {len(change_count)}")
            print()

            # Histogram: how many addresses changed exactly N times, N=1..50
            # The cursor byte should form a clear peak matching the move count.
            from collections import Counter
            count_hist = Counter(cnt for _, cnt in ranked)
            print("=== CHANGE-COUNT HISTOGRAM ===")
            print("  Count  Addresses  (cursor byte appears at your # of moves)")
            for n in range(1, 51):
                freq = count_hist.get(n, 0)
                if freq > 0:
                    bar = '#' * min(freq, 60)
                    print(f"  {n:5d}  {freq:8d}  {bar}")
            print()

            # Addresses that changed 2–40 times are the most interesting:
            # count=1 is dominated by one-time memory writes (allocator noise).
            # count>40 is background animation.
            # Cursor = count matching number of moves you made.
            mid = [(addr, cnt) for addr, cnt in ranked if 2 <= cnt <= 40]
            print(f"=== COUNT 2–40 CANDIDATES: {len(mid)} addresses ===")
            print("  (These are most likely to include the cursor byte.)")
            print(f"  {'Address':>10}  {'Count':>5}  {'LastVal':>7}  Note")
            print(f"  {'-'*10}  {'-'*5}  {'-'*7}  {'-'*30}")
            for addr, cnt in mid:
                last_v = last_values.get(addr, '?')
                note   = "<-- LIKELY CURSOR" if isinstance(last_v, int) and last_v <= 1 else ""
                print(f"  0x{addr:08X}  {cnt:5d}  {last_v:7}  {note}")
            print()

            # Also show count=1 with last value of 0 or 1, just in case
            singles_01 = [(addr, cnt) for addr, cnt in ranked
                          if cnt == 1 and isinstance(last_values.get(addr), int)
                          and last_values[addr] <= 1]
            print(f"=== COUNT=1 WITH LAST VALUE 0 OR 1: {len(singles_01)} addresses ===")
            for addr, cnt in singles_01[:60]:
                last_v = last_values.get(addr, '?')
                print(f"  0x{addr:08X}  count={cnt}  last={last_v}")

            n_mid = len(mid)
            speak_wait(
                f"Done. {n_mid} mid-frequency candidates found. "
                "Check the log histogram. The cursor byte count matches "
                "how many times you moved the cursor."
            )
            print()
            print(f"Log saved to: {log_path}")
            beep_done()

    finally:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
