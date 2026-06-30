#!/usr/bin/env python3
"""
ff7_title_cursor_scan.py — Find the FF7 title screen cursor address.

Uses Windows ReadProcessMemory + VirtualQueryEx directly via ctypes.
No Frida involved. Modelled on GrandiaII/tools/43_newgame_diff.py.

THREE-SNAPSHOT DIFF:
  Snap A — cursor on CONTINUE
  Snap B — cursor on NEW GAME
  Snap C — cursor back on CONTINUE

Candidates: bytes that changed A→B AND reverted B→C to the exact A value.

TIMING (user-triggered, no SAPI during snapshots):
  1. SAPI speaks full instructions once at the start.
  2. Press Enter → Snap A taken while cursor is on Continue.
     (FF7 runs in background; controller moves cursor regardless of focus.)
  3. Move cursor to New Game with controller, then press Enter → Snap B.
  4. Move cursor back to Continue, then press Enter → Snap C.
  5. SAPI speaks candidate count; check the log file.

The Enter-triggered approach minimises background noise: the time between
"cursor moved" and "snapshot taken" is only however long it takes the user
to press Enter (~0.5–2 s), vs the old 5-second countdown which captured
many more animation-frame changes.

SCAN RANGE:
  0x00400000 – 0x02000000 (4 MB – 32 MB).
  This covers known FF7 data (BSS/data at 0xDC0FC0 ≈ 14 MB) and the
  candidate area found in the previous run (0x012182D0 ≈ 18 MB) while
  excluding the large heap allocations above 0x10000000 that generate
  hundreds of thousands of false positives per second.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"
SCAN_START   = 0x00400000
SCAN_END     = 0x02000000   # 28 MB of game code+BSS; excludes high heap

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT         = 0x1000
PAGE_GUARD         = 0x100
PAGE_NOACCESS      = 0x01

# ---------------------------------------------------------------------------
# Windows structures
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Tee
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

# ---------------------------------------------------------------------------
# Audio — SAPI only for non-timed steps; beeps for timed cues
# ---------------------------------------------------------------------------

def speak_wait(text):
    """SAPI speech. Only call this when timing is NOT critical."""
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


def beep_snap_ready():
    """Two low tones: script is ready for the next Enter press."""
    winsound.Beep(600, 120)
    winsound.Beep(900, 200)


def beep_snap_taken():
    """Rising two-tone: snapshot captured."""
    winsound.Beep(900, 120)
    winsound.Beep(1400, 200)


def beep_done():
    winsound.Beep(600, 150)
    winsound.Beep(900, 150)
    winsound.Beep(1200, 300)

# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------

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


def open_process(pid):
    h = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise RuntimeError(
            f"OpenProcess failed for PID {pid}. "
            "Try running as Administrator.")
    return h

# ---------------------------------------------------------------------------
# Memory scanning
# ---------------------------------------------------------------------------

def readable_regions(handle, start, end):
    """Yield (base, size) for every committed, readable page in [start, end)."""
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


def read_region(handle, base, size, chunk=65536):
    """Read 'size' bytes from 'base' via ReadProcessMemory."""
    k32    = ctypes.windll.kernel32
    result = bytearray()
    buf    = ctypes.create_string_buffer(chunk)
    read   = ctypes.c_size_t(0)
    offset = 0
    while offset < size:
        n  = min(chunk, size - offset)
        ok = k32.ReadProcessMemory(
            handle, ctypes.c_void_p(base + offset),
            buf, n, ctypes.byref(read))
        got = read.value if ok else 0
        if got == 0:
            result.extend(b'\x00' * n)
        else:
            result.extend(buf.raw[:got])
            if got < n:
                result.extend(b'\x00' * (n - got))
        offset += n
    return result


def snapshot(handle):
    """Return list of (base, bytearray) for all readable regions in scan range."""
    regions = list(readable_regions(handle, SCAN_START, SCAN_END))
    total   = sum(s for _, s in regions)
    print(f"  {len(regions)} region(s), {total // 1024} KB...")
    result  = []
    for base, size in regions:
        data = read_region(handle, base, size)
        result.append((base, data))
    print(f"  Done.", flush=True)
    return result


def diff(snap_a, snap_b):
    """Return (abs_addr, old, new) for every differing byte."""
    b_map   = {base: data for base, data in snap_b}
    changes = []
    for base, data_a in snap_a:
        data_b = b_map.get(base)
        if data_b is None:
            continue
        n = min(len(data_a), len(data_b))
        for i in range(n):
            if data_a[i] != data_b[i]:
                changes.append((base + i, data_a[i], data_b[i]))
    return changes

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"title_cursor_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            speak_wait(f"{PROCESS_NAME} not found. Start FF7 first.")
            print(f"ERROR: {PROCESS_NAME} not running.")
            return
        print(f"Found {PROCESS_NAME}: PID {pid}")

        try:
            handle = open_process(pid)
        except RuntimeError as e:
            speak_wait("Cannot open FF7. Try running as Administrator.")
            print(f"ERROR: {e}")
            return
        print("Process opened.")
        print()

        # ── SAPI instructions (spoken once, before any timing begins) ─────────
        speak_wait(
            "Ready. FF7 can be in the background — it runs normally regardless. "
            "Here is the procedure: "
            "First, make sure the title screen cursor is on Continue, "
            "then press Enter. "
            "Then move the cursor to New Game with the controller and press Enter. "
            "Then move back to Continue and press Enter. "
            "That is all three snapshots. "
            "Do each move quickly after pressing Enter to minimise background noise."
        )

        # ── Snapshot A ────────────────────────────────────────────────────────
        # Two-tone ready beep so user knows the script is waiting for Enter.
        beep_snap_ready()
        input("Cursor on CONTINUE — press ENTER...")
        print("Snapshot A (Continue)...")
        t0     = time.time()
        snap_a = snapshot(handle)
        print(f"  Time: {time.time()-t0:.1f}s")
        beep_snap_taken()
        print()

        # ── Snapshot B ────────────────────────────────────────────────────────
        beep_snap_ready()
        input("Move to NEW GAME, then press ENTER...")
        print("Snapshot B (New Game)...")
        t0     = time.time()
        snap_b = snapshot(handle)
        print(f"  Time: {time.time()-t0:.1f}s")
        beep_snap_taken()

        ab = diff(snap_a, snap_b)
        print(f"  A→B: {len(ab)} byte(s) changed.")
        print()

        if len(ab) == 0:
            speak_wait(
                "No bytes changed between A and B. "
                "Either the cursor did not move, or the address is outside the scan range. "
                "Try the verify script if you have candidates already."
            )
            print("A→B: 0 changes. Was the cursor actually moved between Enter presses?")
            print(f"\nLog saved to: {log_path}")
            return

        # ── Snapshot C ────────────────────────────────────────────────────────
        beep_snap_ready()
        input("Move BACK to CONTINUE, then press ENTER...")
        print("Snapshot C (Continue again)...")
        t0     = time.time()
        snap_c = snapshot(handle)
        print(f"  Time: {time.time()-t0:.1f}s")
        beep_snap_taken()

        bc = diff(snap_b, snap_c)
        print(f"  B→C: {len(bc)} byte(s) changed.")
        print()

        # ── Three-snapshot filter ─────────────────────────────────────────────
        ab_map = {addr: (old, new) for addr, old, new in ab}
        bc_map = {addr: (old, new) for addr, old, new in bc}

        candidates = []
        for addr in sorted(ab_map.keys() & bc_map.keys()):
            a_cont, a_ng   = ab_map[addr]
            b_ng,   b_cont = bc_map[addr]
            if b_cont == a_cont:          # reverted to exact A value
                candidates.append((addr, a_cont, a_ng))

        n = len(candidates)
        print(f"=== CANDIDATES: {n} ===")
        print("(Changed A→B AND reverted B→C to original A value)")
        print()

        if n == 0:
            speak_wait("No candidates passed the revert filter.")
            both = sorted(ab_map.keys() & bc_map.keys())
            print(f"Both-direction changes (revert not clean): {len(both)}")
            for addr in both[:30]:
                ac, ag   = ab_map[addr]
                _,  cc2  = bc_map[addr]
                print(f"  0x{addr:08X}  A={ac}  B={ag}  C={cc2}")

        elif n > 60:
            speak_wait(
                f"{n} candidates — too many background changes matched. "
                "Move the cursor faster after pressing Enter, or re-run. "
                "Small-value candidates are shown first in the log."
            )
            small = [(a, c, g) for a, c, g in candidates if c <= 4 and g <= 4]
            print(f"Small-value candidates (0–4): {len(small)}")
            for addr, cont_val, ng_val in small[:60]:
                print(f"  0x{addr:08X}  Continue={cont_val}  NewGame={ng_val}"
                      + ("  <-- LIKELY CURSOR" if (cont_val <= 1 and ng_val <= 1) else ""))
            if len(candidates) > len(small):
                print(f"\nFull list ({len(candidates)} total):")
                for addr, cont_val, ng_val in candidates:
                    print(f"  0x{addr:08X}  Continue={cont_val}  NewGame={ng_val}")

        else:
            speak_wait(
                f"{n} candidate{'s' if n != 1 else ''} found. "
                "Check the log. Cursor byte will be 0 on one option and 1 on the other."
            )
            for addr, cont_val, ng_val in candidates:
                note = "  <-- LIKELY CURSOR" if cont_val <= 1 and ng_val <= 1 else ""
                print(f"  0x{addr:08X}  Continue={cont_val} (0x{cont_val:02X})"
                      f"  NewGame={ng_val} (0x{ng_val:02X}){note}")

        print()
        print("=== NEXT STEP ===")
        print("Run ff7_title_verify.py with the candidate addresses to confirm.")
        print(f"\nLog saved to: {log_path}")
        beep_done()
        speak_wait("Investigation complete. Check the log file.")

    finally:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
