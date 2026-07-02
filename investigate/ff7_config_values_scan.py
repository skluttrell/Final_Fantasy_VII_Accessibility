#!/usr/bin/env python3
"""
ff7_config_values_scan.py — Find memory addresses for per-row config setting values.

For each config row that has a left/right scannable value, runs an isolate scan:
  Phase A (idle):  Cursor stationary on the row, value not changing  (8s)
  Phase B (nav):   Left/Right presses change the value               (20s)
  Candidates = nav_changers − idle_changers

Also scans the two sliders inside the Sound sub-menu (row 1).

ROWS COVERED:
  Row 3 — Cursor:         Initial / Memory              (2 options, expect 0–1)
  Row 4 — ATB:            Active / Recommended / Wait   (3 options, expect 0–2)
  Row 5 — Battle speed:   Fast ←slider→ Slow            (numeric, expect 0–255)
  Row 6 — Battle message: Fast ←slider→ Slow            (numeric, expect 0–255)
  Row 7 — Field message:  Fast ←slider→ Slow            (numeric, expect 0–255)
  Row 8 — Camera angle:   Auto / Fixed                  (2 options, expect 0–1)
  Row 9 — Magic order:    No.1 / restore / attack / indirect  (4 options, expect 0–3)
  Sound sub-menu Music volume                           (numeric, screenshot: 060)
  Sound sub-menu FX volume                             (numeric, screenshot: 100)

SKIPPED (complex sub-screens, very low priority):
  Row 0 — Window color:  Opens color picker overlay
  Row 2 — Controller:    Opens button rebinding screen

HOW TO RUN:
  1. Start FF7 and get into a field map.
  2. Open the main menu, navigate to Config (row 7), press Confirm to enter.
  3. Run this script. It speaks all instructions aloud — keep FF7 in focus
     and Alt+Tab to the terminal only when you hear "press Enter to continue".
  4. Results are saved to a timestamped log file automatically.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os

PROCESS_NAME  = "ff7_en.exe"
SCAN_MIN      = 0x00400000
SCAN_MAX      = 0x00DE0000
POLL_INTERVAL = 0.25   # seconds between memory snapshots
IDLE_TIME     = 8      # seconds of idle baseline per phase
NAV_TIME      = 20     # seconds of left/right navigation per phase
TOP_N         = 8      # candidates to display per row

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400

k32 = ctypes.windll.kernel32


# ---------------------------------------------------------------------------
# Tee: mirrors stdout to the log file simultaneously so no manual copy-paste
# is ever needed.
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
# TTS helper — fire-and-forget so it never blocks the scan loop
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Process / memory helpers
# ---------------------------------------------------------------------------
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


def read_region(handle, base, size):
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                  buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


# ---------------------------------------------------------------------------
# Scan engine
# ---------------------------------------------------------------------------
def countdown(seconds, start_message):
    """Speak the start message, then count down aloud (3, 2, 1, go)."""
    speak(start_message)
    print(f"  {start_message}")
    time.sleep(max(0, seconds - 3))
    for n in (3, 2, 1):
        speak(str(n))
        print(f"\r  {n} …", end="", flush=True)
        time.sleep(1)
    speak("Go")
    print()


def scan_phase(handle, duration_s, phase_label):
    """
    Poll BSS memory for duration_s seconds.
    Returns dict: addr → [change_count, last_value].
    """
    scan_size = SCAN_MAX - SCAN_MIN
    prev = read_region(handle, SCAN_MIN, scan_size)
    if prev is None:
        print("  ERROR: Could not read BSS region.")
        return {}

    changers   = {}
    snap_count = 1
    start      = time.time()
    last_sec   = -1

    while True:
        elapsed = time.time() - start
        if elapsed >= duration_s:
            break
        time.sleep(POLL_INTERVAL)

        curr = read_region(handle, SCAN_MIN, scan_size)
        if curr is None:
            continue
        snap_count += 1

        for i in range(scan_size):
            if curr[i] != prev[i]:
                addr = SCAN_MIN + i
                if addr not in changers:
                    changers[addr] = [0, curr[i]]
                changers[addr][0] += 1
                changers[addr][1] = curr[i]
        prev = curr

        sec = int(elapsed)
        if sec != last_sec:
            last_sec = sec
            print(f"\r  [{phase_label}] {sec:2d}s / {duration_s}s — "
                  f"{len(changers)} addresses changed …", end="", flush=True)

    print(f"\r  [{phase_label}] Done: {snap_count} snapshots, "
          f"{len(changers)} addresses changed.{' ' * 20}")
    return changers


def analyze_and_print(idle_changers, nav_changers, label):
    """Subtract idle noise from nav results, print top candidates, return them."""
    candidates = {
        addr: info
        for addr, info in nav_changers.items()
        if addr not in idle_changers
    }
    sorted_cands = sorted(candidates.items(), key=lambda x: x[1][0], reverse=True)
    top = sorted_cands[:TOP_N]

    print(f"\n  CANDIDATES — {label} ({len(candidates)} nav-only, showing top {TOP_N}):")
    print(f"  {'Address':<14} {'Count':>6}  {'LastVal':>8}  Notes")
    print(f"  {'-'*13}  {'------'}  {'-------'}  -----")
    if not top:
        print("  (none found — check that you were pressing Left/Right during Phase B)")
    for addr, (count, last_val) in top:
        dc_note = "← DC block" if 0x00DC0000 <= addr <= 0x00DCFFFF else ""
        print(f"  0x{addr:08X}  {count:6d}  {last_val:8d}  {dc_note}")

    return top


def run_one_scan(handle, label, setup_instruction, nav_instruction, expected_note):
    """
    Run one complete idle→nav isolate scan for a single config value.

    setup_instruction  — spoken/printed before the idle countdown; tells the
                         player which row to be on and to hold still.
    nav_instruction    — spoken/printed before the nav countdown; tells the
                         player what to press.
    """
    print()
    print("=" * 62)
    print(f"  {label}")
    print(f"  {expected_note}")
    print("=" * 62)

    # ── Idle phase ────────────────────────────────────────────────────────
    print()
    print(f"  SETUP: {setup_instruction}")
    speak(setup_instruction)
    print()

    countdown(5, "Idle scan starting. Hold cursor still.")
    idle = scan_phase(handle, IDLE_TIME, "idle")
    speak("Idle scan complete.")

    # ── Nav phase ─────────────────────────────────────────────────────────
    print()
    print(f"  NAV: {nav_instruction}")
    speak(nav_instruction)
    print()

    countdown(5, "Navigation scan starting.")
    nav = scan_phase(handle, NAV_TIME, "nav")
    speak(f"{label} scan complete.")

    return analyze_and_print(idle, nav, label)


# ---------------------------------------------------------------------------
# Scan definitions
# ---------------------------------------------------------------------------
ROW_SCANS = [
    # (config_row_index, row_name, setup_instruction, nav_instruction, expected_note)
    (3, "Cursor",
     "Navigate to row 3, Cursor. Options are Initial and Memory. Hold still.",
     "Press Left and Right repeatedly to toggle between Initial and Memory.",
     "Toggle: 0=Initial  1=Memory"),

    (4, "ATB",
     "Navigate to row 4, ATB. Options are Active, Recommended, and Wait. Hold still.",
     "Press Left and Right repeatedly to cycle through Active, Recommended, and Wait.",
     "Toggle: 0=Active  1=Recommended  2=Wait"),

    (5, "Battle speed",
     "Navigate to row 5, Battle speed. The slider goes from Fast to Slow. Hold still.",
     "Press Left and Right repeatedly to sweep the slider across its full range.",
     "Slider: numeric, Fast to Slow  (0–255 expected)"),

    (6, "Battle message",
     "Navigate to row 6, Battle message speed. The slider goes from Fast to Slow. Hold still.",
     "Press Left and Right repeatedly to sweep the slider across its full range.",
     "Slider: numeric, Fast to Slow  (0–255 expected)"),

    (7, "Field message",
     "Navigate to row 7, Field message speed. The slider goes from Fast to Slow. Hold still.",
     "Press Left and Right repeatedly to sweep the slider across its full range.",
     "Slider: numeric, Fast to Slow  (0–255 expected)"),

    (8, "Camera angle",
     "Navigate to row 8, Camera angle. Options are Auto and Fixed. Hold still.",
     "Press Left and Right repeatedly to toggle between Auto and Fixed.",
     "Toggle: 0=Auto  1=Fixed"),

    (9, "Magic order",
     "Navigate to row 9, Magic order. Options are No.1, restore, attack, and indirect. Hold still.",
     "Press Left and Right repeatedly to cycle through all four options.",
     "Toggle: 0=No.1  1=restore  2=attack  3=indirect"),
]

SOUND_SCANS = [
    # (label, setup_instruction, nav_instruction, expected_note)
    ("Sound sub-menu — Music volume",
     "Press Cancel to return to the config list. Navigate to row 1, Sound, "
     "and press Confirm to open the Sound sub-menu. Move to the Music slider at the top. Hold still.",
     "Press Left and Right repeatedly to sweep the Music volume across its full range.",
     "Slider: 0–127  (screenshot value: 060)"),

    ("Sound sub-menu — FX volume",
     "Navigate down to the FX slider. Hold still.",
     "Press Left and Right repeatedly to sweep the FX volume across its full range.",
     "Slider: 0–127  (screenshot value: 100)"),
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"config_values_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Config Values Scan")
        print("Identifies memory addresses for each config setting.")
        print()
        print("SETUP:")
        print("  1. FF7 must be running in a field map.")
        print("  2. Open the main menu, go to Config (row 7), press Confirm.")
        print("  3. Keep FF7 in focus — the script speaks all instructions aloud.")
        print("     Alt+Tab to this terminal only when you hear 'press Enter to continue'.")
        print()

        speak("Config values scan ready. Alt Tab to the terminal and press Enter to begin.")
        input("  Press Enter when the Config sub-menu is open …")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("Error. F F 7 is not running.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak("Error. Could not open process.")
            print("ERROR: OpenProcess failed.")
            return

        speak("Connected. Switch to F F 7 now.")
        print("Connected. Switch to FF7 now.")
        all_results = {}

        # ── Per-row scans (rows 3–9) ──────────────────────────────────────
        for row_idx, row_name, setup_instr, nav_instr, expected in ROW_SCANS:
            speak(f"Ready to scan row {row_idx}, {row_name}. "
                  f"Alt Tab to terminal and press Enter to start.")
            print()
            input(f"  Press Enter to start row {row_idx} ({row_name}) scan …")
            speak("Starting. Switch back to F F 7.")

            candidates = run_one_scan(
                handle,
                f"Row {row_idx} — {row_name}",
                setup_instr,
                nav_instr,
                expected,
            )
            all_results[f"Row {row_idx} — {row_name}"] = candidates

        # ── Sound sub-menu scans ──────────────────────────────────────────
        speak("Row scans complete. Now scanning the Sound sub-menu. "
              "Alt Tab to terminal and press Enter to continue.")
        print()
        print("=" * 62)
        print("  SOUND SUB-MENU")
        print("  Two sliders: Music volume and FX volume.")
        print("=" * 62)

        for label, setup_instr, nav_instr, expected in SOUND_SCANS:
            input(f"\n  Press Enter to start '{label}' scan …")
            speak("Starting. Switch back to F F 7.")
            candidates = run_one_scan(handle, label, setup_instr, nav_instr, expected)
            all_results[label] = candidates

        # ── Final summary ─────────────────────────────────────────────────
        print()
        print("=" * 62)
        print("  SUMMARY — BEST CANDIDATE PER TARGET")
        print("=" * 62)
        for label, candidates in all_results.items():
            if candidates:
                best_addr, (best_count, best_val) = candidates[0]
                dc_flag = " ← DC block" if 0x00DC0000 <= best_addr <= 0x00DCFFFF else ""
                print(f"  {label}")
                print(f"    0x{best_addr:08X}  count={best_count}  last={best_val}{dc_flag}")
            else:
                print(f"  {label}")
                print(f"    (no candidates)")
            print()

        print("NEXT STEPS:")
        print("  1. Note the best address for each row.")
        print("  2. Run ff7_config_values_verify.py to confirm each address tracks")
        print("     the correct value live.")
        print("  3. Once confirmed, add to ff7_addresses.h and implement per-row")
        print("     value TTS in ConfigMenuThread.")

        speak("Scan complete. Check the terminal for results.")

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
