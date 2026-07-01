#!/usr/bin/env python3
"""
ff7_menu_cursor_scan.py — Find the FF7 main-menu cursor position address.

The "main menu" is the overlay that appears when you press Triangle/Y during
field gameplay. It shows options in a vertical list. The exact set depends on
story progress:

  Early game (3 party members — no PHS option):
    0: ITEM   1: MAGIC   2: EQUIP   3: STATUS   4: ORDER
    5: LIMIT  6: CONFIG  7: SAVE    8: QUIT

  Later (4+ party members available — PHS unlocked):
    0: ITEM   1: MAGIC   2: EQUIP   3: STATUS   4: ORDER
    5: LIMIT  6: CONFIG  7: PHS     8: SAVE     9: QUIT

We want the byte (or word) that holds the highlighted row index so that
TitleCursorThread's sibling — a MenuCursorThread — can announce the current
option by name whenever the cursor moves.

THREE-SNAPSHOT DIFF:
  Snap A — cursor on the FIRST option (ITEM, top of list)
  Snap B — cursor on the LAST option  (SAVE, bottom of list)
  Snap C — cursor back on FIRST option (ITEM again)

Candidates: bytes that changed A→B AND reverted B→C to the exact A value.
The expected values are 0 (ITEM) and 8 (SAVE), but we show all matches so
other encodings (1-indexed, bitmask, etc.) also surface.

A SECOND PASS looks for the "menu is open" flag: bytes that are 0 outside
the menu and non-zero while inside. This flag is needed by the polling thread
to know when it should start and stop watching the cursor.

PROCEDURE:
  1. Start FF7 and load a save into a FIELD MAP (not world map, not battle).
  2. Run this script.
  3. Open the MAIN MENU with Triangle/Y. Make sure the cursor is on ITEM
     (the top option). Press Enter.
  4. Move the cursor to QUIT (the bottom option — press Down until you
     reach the last entry). Press Enter.
  5. Move the cursor back to ITEM (hold Up). Press Enter.
  6. The script reports candidates. Check the log.
  7. Run ff7_menu_cursor_verify.py with the best candidate to confirm.

NOTES:
  - FF7 must be running during the ENTIRE scan; do not alt-tab away until
    Snap C is taken (the game pauses in the menu overlay so scans are fast).
  - The scan covers 0x400000–0x2000000 (28 MB). This includes all BSS,
    savemap, and the game's menu module allocations.
  - Between snaps, move the cursor ONLY between ITEM and QUIT (not into any
    sub-menu). Going into a sub-menu allocates different menu structures and
    will add noise.
  - Early game (no PHS): QUIT is at index 8. Later with PHS: QUIT is at 9.
    The script detects either encoding from the raw values.
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
SCAN_END     = 0x02000000   # 28 MB: covers BSS (0xDBxxxx, 0xDCxxxx), menu allocs

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT         = 0x1000
PAGE_GUARD         = 0x100
PAGE_NOACCESS      = 0x01

# Known address from ff7_addresses.h — we read FIELD_ID to verify the user
# is actually in a field map (not title screen or world map) before scanning.
FIELD_ID_ADDR = 0xCC15D0


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
# Tee: write stdout to both terminal and log file simultaneously
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
# Audio
# ---------------------------------------------------------------------------

def speak_wait(text):
    """SAPI speech — blocking, only call when timing is NOT critical."""
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
    """Two ascending tones: script is waiting for the next Enter press."""
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


def read_byte(handle, addr):
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok   = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    if ok and read.value == 1:
        return buf.raw[0]
    return None


def read_int16(handle, addr):
    buf  = ctypes.create_string_buffer(2)
    read = ctypes.c_size_t(0)
    ok   = ctypes.windll.kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, 2, ctypes.byref(read))
    if ok and read.value == 2:
        import struct
        return struct.unpack_from('<h', buf.raw)[0]
    return None


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
    """Read 'size' bytes starting at 'base' via ReadProcessMemory."""
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
    """Return list of (abs_addr, old_val, new_val) for every differing byte."""
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
    log_name    = f"menu_cursor_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            print(f"\nLog saved to: {log_path}")
            return
        print(f"Found {PROCESS_NAME}: PID {pid}")

        try:
            handle = open_process(pid)
        except RuntimeError as e:
            speak_wait("Cannot open FF7. Try running as Administrator.")
            print(f"ERROR: {e}")
            print(f"\nLog saved to: {log_path}")
            return
        print("Process opened.")

        # Verify the player is in a field map before wasting time on a scan.
        field_id = read_int16(handle, FIELD_ID_ADDR)
        if field_id is None or field_id == 0:
            speak_wait(
                "FF7 is not in a field map. Load a save and enter a field "
                "location before running this script. Title screen and world "
                "map will not work.")
            print(f"ERROR: FIELD_ID = {field_id!r} — must be non-zero (in a field map).")
            print("       Load a save, walk into a field location, then re-run.")
            print(f"\nLog saved to: {log_path}")
            return
        print(f"FIELD_ID = {field_id} (confirmed in field map).")
        print()

        # ── Instructions ─────────────────────────────────────────────────────
        speak_wait(
            "Ready. Here is the procedure. "
            "Open the main menu with Triangle or Y. "
            "Make sure the cursor is on Item, the first option at the top. "
            "Then press Enter. "
            "Next, move the cursor all the way down to Quit, the last option, "
            "and press Enter. "
            "Then move back up to Item and press Enter. "
            "That is all three snapshots. "
            "Do not enter any sub-menu between snapshots — "
            "only move the cursor within the main menu list. "
            "Press Enter for the first snapshot now."
        )

        # ── Snapshot A: cursor on ITEM (first option, expected value 0) ──────
        beep_snap_ready()
        input("Main menu open, cursor on ITEM — press ENTER...")
        print("Snapshot A (cursor on ITEM)...")
        t0     = time.time()
        snap_a = snapshot(handle)
        print(f"  Time: {time.time()-t0:.1f}s")
        beep_snap_taken()
        print()

        # ── Snapshot B: cursor on QUIT (last option, expected value 8 or 9) ──
        beep_snap_ready()
        input("Move cursor DOWN to QUIT (last option) — press ENTER...")
        print("Snapshot B (cursor on QUIT)...")
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
                "Either the cursor did not move, or the menu was closed. "
                "Re-run and keep the main menu open throughout all three snaps.")
            print("A→B: 0 changes. Was the cursor actually moved?")
            print(f"\nLog saved to: {log_path}")
            return

        # ── Snapshot C: cursor back on ITEM ──────────────────────────────────
        beep_snap_ready()
        input("Move cursor back UP to ITEM (first option) — press ENTER...")
        print("Snapshot C (cursor back on ITEM)...")
        t0     = time.time()
        snap_c = snapshot(handle)
        print(f"  Time: {time.time()-t0:.1f}s")
        beep_snap_taken()

        bc = diff(snap_b, snap_c)
        print(f"  B→C: {len(bc)} byte(s) changed.")
        print()

        # ── Three-snapshot filter ─────────────────────────────────────────────
        # A candidate must:
        #   1. Change A→B (cursor moved to SAVE)
        #   2. Revert B→C back to the EXACT A value (cursor returned to ITEM)
        ab_map = {addr: (old, new) for addr, old, new in ab}
        bc_map = {addr: (old, new) for addr, old, new in bc}

        candidates = []
        for addr in sorted(ab_map.keys() & bc_map.keys()):
            a_val, b_val     = ab_map[addr]   # A=ITEM value, B=SAVE value
            b_val2, c_val    = bc_map[addr]   # should match: b_val2==b_val, c_val==a_val
            if c_val == a_val:                # reverted to original A value
                candidates.append((addr, a_val, b_val))

        n = len(candidates)
        print(f"=== CANDIDATES: {n} ===")
        print("(Changed A→B AND reverted B→C to original A value)")
        print("Expected: A_val=0 (ITEM), B_val=8 (QUIT, no PHS) or 9 (QUIT, with PHS)")
        print("          or a different encoding if FF7 uses 1-indexing etc.")
        print()

        if n == 0:
            speak_wait("No candidates found. Try moving the cursor faster after each Enter press.")
            both = sorted(ab_map.keys() & bc_map.keys())
            print(f"Changed in both directions (but did not revert cleanly): {len(both)}")
            for addr in both[:30]:
                av, bv  = ab_map[addr]
                bv2, cv = bc_map[addr]
                print(f"  0x{addr:08X}  A={av}  B={bv}  C={cv}")
            print(f"\nLog saved to: {log_path}")
            return

        elif n > 100:
            speak_wait(
                f"{n} candidates — too many. Move the cursor faster next time. "
                "Small-value candidates (0–15) are shown first.")
            small = [(a, av, bv) for a, av, bv in candidates if av <= 15 and bv <= 15]
            print(f"Small-value candidates (both values 0–15): {len(small)}")
            print(f"  {'Address':>10}  {'ITEM_val':>8}  {'SAVE_val':>8}  Note")
            for addr, av, bv in small[:60]:
                note = "  <-- LIKELY CURSOR" if av == 0 and bv == 8 else (
                       "  <-- POSSIBLE (0-indexed shifted?)" if av <= 1 and 7 <= bv <= 9 else "")
                print(f"  0x{addr:08X}  {av:8}  {bv:8}{note}")
            print()
            if len(candidates) > len(small):
                print(f"(Full list of {len(candidates)} in log — too many to print here)")

        else:
            speak_wait(
                f"{n} candidate{'s' if n != 1 else ''} found. "
                "Check the log. Cursor address will show 0 on Item and 8 on Save, "
                "or similar small values.")
            print(f"  {'Address':>10}  {'ITEM_val':>8}  {'SAVE_val':>8}  Note")
            print(f"  {'-'*10}  {'-'*8}  {'-'*8}  {'-'*35}")
            for addr, av, bv in candidates:
                if av == 0 and bv == 8:
                    note = "  <-- STRONG: 0/8 exact (0-indexed, no PHS, QUIT=8)"
                elif av == 0 and bv == 9:
                    note = "  <-- STRONG: 0/9 exact (0-indexed, PHS present, QUIT=9)"
                elif av == 1 and bv == 9:
                    note = "  <-- STRONG: 1/9 match (1-indexed, no PHS, QUIT=9)"
                elif av == 1 and bv == 10:
                    note = "  <-- STRONG: 1/10 match (1-indexed, PHS present, QUIT=10)"
                elif av <= 2 and 7 <= bv <= 11:
                    note = "  <-- PLAUSIBLE: small values, reasonable range"
                elif av <= 15 and bv <= 15:
                    note = "  <-- low values"
                else:
                    note = ""
                print(f"  0x{addr:08X}  {av:8} (0x{av:02X})  {bv:8} (0x{bv:02X}){note}")

        print()

        # ── Second pass: find "menu is open" flag ────────────────────────────
        # Compare Snap A (inside main menu) against Snap C (inside main menu).
        # We want bytes that were ZERO before the menu was opened. But since we
        # don't have a pre-menu snapshot, we instead look for bytes that were
        # constant across all three snaps (A==C and unchanged A→B) to exclude
        # them, and report which candidate-adjacent bytes are non-zero.
        #
        # Practical approach: re-read current memory NOW (after snap C, still
        # in the menu) vs. what we had in snap A (also in the menu). If both
        # are in-menu, the cursor may have changed but the "menu open" flag
        # should still be set. We report constant non-zero bytes near each
        # candidate as potential "menu open" flags.
        print("=== POTENTIAL 'MENU IS OPEN' INDICATORS ===")
        print("Bytes that were CONSTANT and NON-ZERO across all three snaps,")
        print("within ±64 bytes of each cursor candidate.")
        print("These are the most likely 'menu active' flags.")
        print()

        # Build a map of bytes that did NOT change across A→B and B→C
        changed_in_ab = {addr for addr, _, _ in ab}
        changed_in_bc = {addr for addr, _, _ in bc}
        stable_addrs  = set()
        for base, data in snap_a:
            for i, b in enumerate(data):
                addr = base + i
                if addr not in changed_in_ab and addr not in changed_in_bc and b != 0:
                    stable_addrs.add(addr)

        snap_a_map = {}
        for base, data in snap_a:
            for i, b in enumerate(data):
                snap_a_map[base + i] = b

        for cand_addr, av, bv in candidates[:10]:  # limit to first 10 candidates
            nearby = []
            for delta in range(-64, 65):
                chk = cand_addr + delta
                if chk in stable_addrs:
                    v = snap_a_map.get(chk, 0)
                    if v != 0:
                        nearby.append((chk, v, delta))
            if nearby:
                print(f"  Near 0x{cand_addr:08X} (ITEM={av},SAVE={bv}):")
                for addr, v, delta in nearby[:10]:
                    print(f"    0x{addr:08X}  (+{delta:+d})  value={v} (0x{v:02X})")
            else:
                print(f"  Near 0x{cand_addr:08X}: no stable non-zero bytes found in ±64.")

        print()
        print("=== NEXT STEP ===")
        print("Run ff7_menu_cursor_verify.py with the best candidate address to confirm.")
        print(f"\nLog saved to: {log_path}")
        beep_done()
        speak_wait("Scan complete. Check the log file.")

    finally:
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    main()
