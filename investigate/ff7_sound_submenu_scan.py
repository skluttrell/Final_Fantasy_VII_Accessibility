#!/usr/bin/env python3
"""
ff7_sound_submenu_scan.py — Find memory addresses for Sound sub-menu sliders.

The standard isolate scan (used in ff7_config_values_scan.py) fails for the
Sound sub-menu because opening that sub-menu activates the audio subsystem,
flooding memory with constantly-changing timer and buffer state.  The idle
baseline becomes contaminated and subtraction produces ~47 false candidates.

This script uses a DELTA SCAN instead:
  1. User is already inside the Sound sub-menu.
  2. Script takes a baseline snapshot.
  3. User presses Left exactly N times (announced via TTS).
  4. Script takes a second snapshot.
  5. Candidates = addresses whose byte value decreased by exactly N.

Because audio timers increment randomly, they will not decrease by exactly N
on cue.  The slider value will.

Runs the delta scan twice:
  Pass A — Music volume slider
  Pass B — FX volume slider

HOW TO RUN:
  1. In FF7, open the main menu → Config → Sound.
     The Sound sub-menu should be open with the Music slider highlighted.
  2. Run this script.  Keep FF7 in focus — all instructions are spoken.
  3. When prompted, press Left exactly the number of times announced.
     Press at a normal pace (roughly one press per second).

From the config screenshot:
  Music volume displayed as 060.
  FX volume displayed as 100.
The delta scan presses Left 20 times, so we look for a decrease of 20.
If the displayed value is near the bottom already, press Right instead and
the script will look for an increase — follow the spoken instruction.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
SCAN_MIN     = 0x00400000
SCAN_MAX     = 0x00DE0000
DELTA_PRESSES = 20       # how many times to press Left (or Right)
PRESS_INTERVAL = 0.8     # seconds between each prompted press (spoken countdown)

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
    """Fire-and-forget TTS — never blocks."""
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


def read_region(handle, base, size):
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                  buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def countdown(seconds, message):
    speak(message)
    print(f"  {message}")
    time.sleep(max(0, seconds - 3))
    for n in (3, 2, 1):
        speak(str(n))
        print(f"\r  {n} …", end="", flush=True)
        time.sleep(1)
    speak("Go")
    print()


def guided_press_countdown(n_presses, direction):
    """
    Count down each individual press so the user knows exactly when to press.
    Speaks "press" N times with a fixed interval between each.
    """
    print(f"  Press {direction} once for each 'press' call — {n_presses} total.")
    time.sleep(1.5)
    for i in range(1, n_presses + 1):
        speak("press")
        print(f"\r  Press {i} of {n_presses} …", end="", flush=True)
        time.sleep(PRESS_INTERVAL)
    print()
    speak("Done. Hold still.")
    print("  Done. Hold still.")


def delta_scan(handle, label, direction, n):
    """
    Take snapshot A, guide user through N presses of direction, take snapshot B.
    Return list of (address, old_val, new_val) where the change = ±n.
    """
    scan_size = SCAN_MAX - SCAN_MIN

    print()
    print(f"  Taking baseline snapshot for {label} …")
    snap_a = read_region(handle, SCAN_MIN, scan_size)
    if snap_a is None:
        print("  ERROR: Could not read memory.")
        return []
    print("  Baseline taken.")
    print()

    # Guide the user through the presses
    msg = (f"Press {direction} exactly {n} times on the {label} slider. "
           f"I will count each press.")
    speak(msg)
    print(f"  {msg}")
    time.sleep(2)
    guided_press_countdown(n, direction)

    # Brief pause so the game can commit the writes
    time.sleep(0.5)

    print()
    print(f"  Taking post-press snapshot …")
    snap_b = read_region(handle, SCAN_MIN, scan_size)
    if snap_b is None:
        print("  ERROR: Could not read memory.")
        return []
    print("  Snapshot taken.")

    # Find addresses where byte changed by exactly ±n
    expected_signed = -n if direction.lower() == "left" else n
    results = []
    for i in range(scan_size):
        a = snap_a[i]
        b = snap_b[i]
        # Signed byte difference (handles wrap-around for 8-bit values)
        diff = b - a
        if diff > 127:
            diff -= 256
        elif diff < -128:
            diff += 256
        if diff == expected_signed:
            results.append((SCAN_MIN + i, a, b))

    return results


def print_delta_results(results, label, direction, n):
    dc_results = [(a, old, new) for a, old, new in results
                  if 0x00DC0000 <= a <= 0x00DCFFFF]
    other      = [(a, old, new) for a, old, new in results
                  if not (0x00DC0000 <= a <= 0x00DCFFFF)]

    print()
    print(f"  DELTA RESULTS — {label} (press {direction} ×{n})")
    print(f"  Total addresses that changed by exactly {'-' if direction.lower()=='left' else '+'}{n}: {len(results)}")
    print()

    if dc_results:
        print(f"  DC block candidates ({len(dc_results)}) — PREFERRED:")
        print(f"  {'Address':<14} {'Before':>8}  {'After':>8}")
        print(f"  {'-'*13}  {'------'}  {'------'}")
        for addr, old, new in dc_results:
            print(f"  0x{addr:08X}  {old:8d}  {new:8d}")
    else:
        print("  (no DC block candidates)")

    print()
    if other:
        print(f"  Other candidates ({len(other)}):")
        print(f"  {'Address':<14} {'Before':>8}  {'After':>8}")
        print(f"  {'-'*13}  {'------'}  {'------'}")
        for addr, old, new in other[:10]:
            print(f"  0x{addr:08X}  {old:8d}  {new:8d}")
        if len(other) > 10:
            print(f"  … and {len(other) - 10} more")
    else:
        print("  (no non-DC candidates)")

    return dc_results if dc_results else other


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"sound_scan_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Sound Sub-menu Scan (delta method)")
        print(f"Presses Left ×{DELTA_PRESSES} and searches for addresses that decreased by exactly {DELTA_PRESSES}.")
        print()
        print("SETUP:")
        print("  Open main menu → Config (row 7) → Sound (row 1, press Confirm).")
        print("  The Sound sub-menu should be open with the Music slider highlighted.")
        print(f"  Make sure the Music volume is at least {DELTA_PRESSES} above minimum")
        print(f"  (screenshot showed 060, so current value needs to be ≥{DELTA_PRESSES}).")
        print()

        speak("Sound sub-menu scan ready. "
              "Open the Sound sub-menu and navigate to the Music slider. "
              "Then Alt Tab to terminal and press Enter.")
        input("  Press Enter when the Music slider is highlighted and value is stable …")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("Error. F F 7 not running.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak("Error. Could not open process.")
            print("ERROR: OpenProcess failed.")
            return

        speak("Connected. Switch to F F 7 now. Hold the Music slider still.")
        print("Connected. Switch to FF7. Hold Music slider still.")
        time.sleep(2)

        # ── Pass A: Music volume ──────────────────────────────────────────
        print()
        print("=" * 60)
        print("  PASS A — Music volume slider")
        print("=" * 60)
        music_results = delta_scan(handle, "Music volume", "Left", DELTA_PRESSES)
        music_best    = print_delta_results(music_results, "Music volume", "Left", DELTA_PRESSES)

        # ── Pass B: FX volume ─────────────────────────────────────────────
        speak("Music scan complete. Now navigate down to the FX slider. "
              "Alt Tab to terminal and press Enter when ready.")
        print()
        input("  Press Enter when the FX slider is highlighted and value is stable …")
        speak("Starting FX scan. Switch back to F F 7. Hold FX slider still.")
        time.sleep(2)

        print()
        print("=" * 60)
        print("  PASS B — FX volume slider")
        print("=" * 60)
        fx_results = delta_scan(handle, "FX volume", "Left", DELTA_PRESSES)
        fx_best    = print_delta_results(fx_results, "FX volume", "Left", DELTA_PRESSES)

        # ── Summary ───────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)

        def best_addr(candidates):
            return f"0x{candidates[0][0]:08X}" if candidates else "(not found)"

        print(f"  Music volume best candidate: {best_addr(music_best)}")
        print(f"  FX volume best candidate:    {best_addr(fx_best)}")
        print()

        # Check if they match (some games store both in the same byte or adjacent bytes)
        if music_best and fx_best:
            ma = music_best[0][0]
            fa = fx_best[0][0]
            print(f"  Address distance: 0x{abs(ma - fa):X} bytes apart")
            if abs(ma - fa) <= 4:
                print("  (adjacent — likely same config struct)")
        print()
        print("NEXT STEPS:")
        print("  1. Verify these addresses with ff7_sound_verify.py (optional).")
        print("  2. Add confirmed addresses to ff7_addresses.h as SOUND_MUSIC and SOUND_FX.")
        print("  3. Implement Sound sub-menu TTS in a SoundMenuThread or extend ConfigMenuThread.")

        speak("Sound scan complete. Check terminal for results.")

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
