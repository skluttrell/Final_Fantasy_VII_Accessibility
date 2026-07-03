#!/usr/bin/env python3
"""
ff7_sound_cursor_scan.py — Find the Sound sub-menu cursor address.

Two-pass delta scan on FF7's BSS (0x00400000–0x00DE0000):

  Pass A  (Down):  Music slider highlighted → press Down → FX highlighted.
                   Looks for bytes that changed by exactly +1.
  Pass B  (Up):    FX highlighted → press Up → Music highlighted.
                   Looks for bytes that changed by exactly -1.

  Confident candidates = addresses that appeared in BOTH passes with
  the expected delta (±1) — consistent with a 0=Music / 1=FX cursor byte.

  The scan runs TWO full rounds (A→B→A→B) and only keeps addresses that
  responded correctly in all four transitions.

HOW TO RUN:
  1. Open FF7.  Enter the Sound sub-menu:
       Main menu → Config (row 7) → Sound (row 1) → press Confirm.
     The Music slider should be highlighted at the top.
  2. Run this script.  All instructions are spoken aloud; stay in FF7.
  3. Press the indicated key (Down or Up) once when you hear the countdown
     reach "press now".
  4. Press Ctrl+C to stop early if needed.  Log is always saved.
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"
BSS_MIN      = 0x00400000
BSS_MAX      = 0x00DE0000
BSS_SIZE     = BSS_MAX - BSS_MIN
DC_LO        = 0x00DC0000    # DC block — most likely home for menu state bytes
DC_HI        = 0x00DCFFFF
ROUNDS       = 2             # repeat the Down/Up pair this many times

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

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


def read_bss(handle):
    buf  = ctypes.create_string_buffer(BSS_SIZE)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(BSS_MIN),
                                  buf, BSS_SIZE, ctypes.byref(read))
    if not ok or read.value != BSS_SIZE:
        return None
    return bytes(buf)


def countdown_to_press(direction):
    """
    Synchronous beep countdown so snapshot timing is deterministic.

    Pattern: three 800 Hz warning beeps (one per second) then one 1400 Hz
    'press' beep.  winsound.Beep() blocks until the tone finishes, so the
    snapshot taken after this function returns is always the same distance
    from the final beep regardless of SAPI latency.

    User presses the key ON the high beep (or immediately after hearing it).
    We then sleep SETTLE_S seconds for FF7 to process the input before
    snapshotting.
    """
    SETTLE_S = 1.5   # seconds between end of high beep and snapshot

    print(f"  Beep countdown for {direction}: .", end="", flush=True)
    for _ in range(3):
        winsound.Beep(800, 200)     # low warning tone (200 ms)
        time.sleep(0.8)             # total period = 1 s per beat
        print(".", end="", flush=True)

    # High 'press' beep — user presses ON this tone
    winsound.Beep(1400, 400)
    print("  PRESS!", flush=True)

    time.sleep(SETTLE_S)            # wait for FF7 to update state


def do_transition(handle, label, direction, expected_delta):
    """
    Snapshot BSS, prompt user to press the key, snapshot again.
    Returns a set of addresses whose byte changed by exactly expected_delta.
    expected_delta: +1 for Down (Music→FX), -1 for Up (FX→Music)
    """
    print(f"\n  --- {label} ---")

    snap_before = read_bss(handle)
    if snap_before is None:
        print("  ERROR: Could not read BSS before press.")
        return set()

    countdown_to_press(direction)

    snap_after = read_bss(handle)
    if snap_after is None:
        print("  ERROR: Could not read BSS after press.")
        return set()

    # Find every byte that changed by exactly expected_delta (signed)
    hits = set()
    for i in range(BSS_SIZE):
        b = snap_before[i]
        a = snap_after[i]
        # Signed-byte delta: interpret unsigned bytes as signed
        diff = a - b
        if diff > 127:
            diff -= 256
        elif diff < -128:
            diff += 256
        if diff == expected_delta:
            hits.add(BSS_MIN + i)

    print(f"  Bytes changed by {'+' if expected_delta > 0 else ''}{expected_delta}: {len(hits)}")
    return hits


def format_candidates(addrs):
    """Sort and print candidate addresses, prioritising DC block and small values."""
    if not addrs:
        print("  (none)")
        return

    # Build annotated list
    items = []
    for addr in sorted(addrs):
        i = addr - BSS_MIN
        dc = DC_LO <= addr <= DC_HI
        items.append((addr, dc))

    # DC block first, then others; within each group sort by address
    dc_items    = [(a, True)  for a, dc in items if dc]
    other_items = [(a, False) for a, dc in items if not dc]

    all_sorted = dc_items + other_items

    if len(all_sorted) > 20:
        print(f"  (showing first 20 of {len(all_sorted)})")
        all_sorted = all_sorted[:20]

    print(f"  {'Address':<14}  {'Notes'}")
    print(f"  {'-'*13}  -----")
    for addr, dc in all_sorted:
        dc_flag = "← DC block" if dc else ""
        print(f"  0x{addr:08X}    {dc_flag}")


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"sound_cursor_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Sound Sub-menu Cursor Scan")
        print("Finds the byte that tracks which slider is highlighted (0=Music, 1=FX).")
        print()
        print("SETUP:")
        print("  Open the Sound sub-menu (Config → Sound → Confirm).")
        print("  Music slider should be highlighted.  Stay in FF7.")
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
        print(f"BSS scan range: 0x{BSS_MIN:08X}–0x{BSS_MAX:08X}  ({BSS_SIZE // 1024} KB)")
        print()

        print("  Press Enter when you are in FF7 with the Music slider highlighted,")
        print("  then immediately switch back to FF7 — the beep countdown starts at once.")
        input("  → ")
        print("  Switching to FF7 … beep countdown begins in 3 seconds.")
        time.sleep(3)

        # Each set holds addresses that passed ALL transitions of that type so far.
        # We start with None (meaning "not yet constrained") and intersect each round.
        down_hits = None   # addresses that change by +1 on every Down press
        up_hits   = None   # addresses that change by -1 on every Up press

        for rnd in range(1, ROUNDS + 1):
            print()
            print(f"{'=' * 62}")
            print(f"  ROUND {rnd} of {ROUNDS}")
            print(f"{'=' * 62}")

            # ── Down: Music → FX ──────────────────────────────────────────
            d = do_transition(
                handle,
                f"Round {rnd} Pass A — Down (Music → FX cursor)",
                direction="Down",
                expected_delta=+1,
            )
            down_hits = d if down_hits is None else (down_hits & d)
            print(f"  Running total (Down, +1):  {len(down_hits)} addresses")

            # Give the user a moment to confirm the cursor moved to FX
            time.sleep(1)

            # ── Up: FX → Music ────────────────────────────────────────────
            u = do_transition(
                handle,
                f"Round {rnd} Pass B — Up (FX → Music cursor)",
                direction="Up",
                expected_delta=-1,
            )
            up_hits = u if up_hits is None else (up_hits & u)
            print(f"  Running total (Up,   -1):  {len(up_hits)} addresses")

            time.sleep(1)

        # ── Results ───────────────────────────────────────────────────────
        print()
        print(f"{'=' * 62}")
        print("  RESULTS")
        print(f"{'=' * 62}")
        print()

        # Confident candidates: responded correctly to EVERY Down AND every Up
        confident = down_hits & up_hits if (down_hits and up_hits) else set()

        print(f"  Confident (correct delta in all {ROUNDS * 2} transitions): "
              f"{len(confident)} addresses")
        format_candidates(confident)

        # Fallback A: correct on all Downs only
        down_only = down_hits - up_hits if up_hits else down_hits
        if down_only:
            print(f"\n  Down-only (correct on all Down presses, missed Up): "
                  f"{len(down_only)} addresses")
            format_candidates(down_only)

        # Fallback B: correct on all Ups only
        up_only = up_hits - down_hits if down_hits else up_hits
        if up_only:
            print(f"\n  Up-only (correct on all Up presses, missed Down): "
                  f"{len(up_only)} addresses")
            format_candidates(up_only)

        # Highlight DC-block winners
        dc_confident = sorted(a for a in confident if DC_LO <= a <= DC_HI)
        if dc_confident:
            print()
            print("  BEST CANDIDATES (DC block):")
            for addr in dc_confident:
                print(f"    0x{addr:08X}")
        elif confident:
            print()
            print("  BEST CANDIDATES (non-DC block — may be different menu struct):")
            for addr in sorted(confident)[:5]:
                print(f"    0x{addr:08X}")
        else:
            print()
            print("  No confident candidates found.")
            print("  Try: widen ROUNDS, check cursor is actually moving, or run again")
            print("       with the Sound sub-menu freshly opened.")

        print()
        print("NEXT STEPS:")
        print("  1. Run ff7_sound_cursor_verify.py (or add address to ff7_addresses.h")
        print("     and confirm by watching live in the mod log).")
        print("  2. Implement Sound sub-menu cursor TTS:")
        print("     - Detect Sound sub-menu open (CONFIG_ROW==1 + sub-menu flag)")
        print("     - On cursor change: announce 'Music volume, <val>' or 'FX volume, <val>'")
        print("     - On Left/Right: announce new value via dotemuRegSetValueExA IAT hook")

        speak("Cursor scan complete. Check the log for results.")

    except KeyboardInterrupt:
        print()
        print("  [Stopped by user]")
        speak("Scan stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
