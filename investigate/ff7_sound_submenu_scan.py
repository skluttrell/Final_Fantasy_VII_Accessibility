#!/usr/bin/env python3
"""
ff7_sound_submenu_scan.py — Find memory addresses for Sound sub-menu sliders.

WHY THE STANDARD BSS SCAN FAILS (and why this script scans FFNx DLL memory):

  The standard isolate scan fails for the Sound sub-menu because opening it
  activates the audio subsystem, flooding BSS memory with constantly-changing
  timer and buffer state (~47 false candidates for Music).

  The first delta-scan attempt (sound_scan_20260703_101953.log) returned zero
  results despite pressing Left ×20.  Root cause: FF7's Sound config values are
  NOT stored in the FF7 BSS (0x00400000–0x00DE0000).

  When FF7 adjusts Music or FX volume it calls RegSetValueExA("MusicVolume",
  value).  FFNx intercepts this (dotemuRegSetValueExA in common.cpp) and stores
  the value in `external_music_volume` / `external_sfx_volume` — global long
  variables in FFNx's AF3DN.P DLL, which loads at an address above 0x9FFFFF,
  outside the FF7 BSS scan range.

  This script finds AF3DN.P's loaded base address via module enumeration, then
  runs the delta scan over both the FF7 BSS AND the FFNx DLL range.

DELTA SCAN METHOD:
  1. User is inside the Sound sub-menu with Music slider highlighted.
  2. Script takes a baseline snapshot of both memory ranges.
  3. User presses Left exactly N times (announced via TTS).
  4. Script takes a second snapshot and searches for addresses whose byte value
     decreased by exactly N.

  Audio timers change by random amounts — they will not match exactly N.
  The slider value will.  Values stored as longs (4 bytes): the low byte
  changes by N, the upper bytes stay at 0 — caught by the byte-level scan.

ENCODING:
  `external_music_volume` and `external_sfx_volume` are C `long` (4 bytes,
  little-endian).  Both use a 0–100 scale (FFNx caps incoming writes at
  0x64 = 100 in dotemuRegSetValueExA).  The Sound menu displays the value
  directly (060 = stored byte 60, 100 = stored byte 100).

HOW TO RUN:
  1. In FF7, open main menu → Config → Sound sub-menu (Music slider highlighted).
  2. Run this script.  Keep FF7 in focus — all instructions are spoken.
  3. When prompted, press Left exactly the number of times announced.
     Press at a normal pace (roughly one press per second).
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os

PROCESS_NAME   = "ff7_en.exe"
FFNX_MODULE    = "AF3DN.P"
BSS_MIN        = 0x00400000
BSS_MAX        = 0x00DE0000
DELTA_PRESSES  = 20       # how many times to press Left
PRESS_INTERVAL = 0.8      # seconds between each prompted press

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


def find_module_range(pid, module_name):
    """
    Find a loaded DLL's base address and size in a remote process via
    CreateToolhelp32Snapshot + Module32First/Next.
    Returns (base_addr: int, size: int) or (None, 0) if not found.
    """
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
            name = me.szModule.decode('ascii', errors='ignore')
            if name.lower() == module_name.lower():
                base = me.modBaseAddr
                size = me.modBaseSize
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break

    k32.CloseHandle(snap)
    return base, size


def read_region(handle, base, size):
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(base),
                                  buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def guided_press_countdown(n_presses, direction):
    """Speak 'press' N times so the user presses in sync."""
    print(f"  Press {direction} once for each 'press' call — {n_presses} total.")
    time.sleep(1.5)
    for i in range(1, n_presses + 1):
        speak("press")
        print(f"\r  Press {i} of {n_presses} …", end="", flush=True)
        time.sleep(PRESS_INTERVAL)
    print()
    speak("Done. Hold still.")
    print("  Done. Hold still.")


def delta_scan_ranges(handle, ranges, label, direction, n):
    """
    Run the delta scan over a list of (base, size) memory ranges.
    Returns (results, failed_bases) where:
      results      = list of (address, old_val, new_val) where byte changed by ±n
      failed_bases = set of range base addresses where ReadProcessMemory failed
                     (either snapshot A or B); these ranges are absent from results
                     and must be distinguished from "scanned clean" in the output.
    """
    expected = -n if direction.lower() == "left" else n
    failed_bases = set()

    # Snapshot A
    print()
    print(f"  Taking baseline snapshots for {label} …")
    snaps_a = []
    for base, size in ranges:
        snap = read_region(handle, base, size)
        if snap is None:
            print(f"  WARNING: could not read range 0x{base:08X}–0x{base+size:08X}")
            failed_bases.add(base)
        snaps_a.append(snap)
    print("  Baselines taken.")
    print()

    # Guide presses
    msg = (f"Press {direction} exactly {n} times on the {label} slider. "
           f"I will count each press.")
    speak(msg)
    print(f"  {msg}")
    time.sleep(2)
    guided_press_countdown(n, direction)
    time.sleep(0.5)

    # Snapshot B
    print()
    print(f"  Taking post-press snapshots …")
    snaps_b = []
    for base, size in ranges:
        snap = read_region(handle, base, size)
        if snap is None:
            print(f"  WARNING: could not read range 0x{base:08X}–0x{base+size:08X}")
            failed_bases.add(base)
        snaps_b.append(snap)
    print("  Snapshots taken.")

    # Find addresses where byte changed by exactly ±n
    results = []
    for (base, size), snap_a, snap_b in zip(ranges, snaps_a, snaps_b):
        if snap_a is None or snap_b is None:
            continue
        for i in range(size):
            a = snap_a[i]
            b = snap_b[i]
            diff = b - a
            if diff > 127:
                diff -= 256
            elif diff < -128:
                diff += 256
            if diff == expected:
                results.append((base + i, a, b))

    return results, failed_bases


def print_delta_results(results, label, direction, n, ffnx_base, ffnx_size,
                        failed_bases=None):
    ffnx_end = (ffnx_base or 0) + (ffnx_size or 0)
    if failed_bases is None:
        failed_bases = set()

    def in_ffnx(a):
        return ffnx_base is not None and ffnx_base <= a < ffnx_end

    def in_dc(a):
        return 0x00DC0000 <= a <= 0x00DCFFFF

    ffnx_cands = [(a, o, nv) for a, o, nv in results if in_ffnx(a)]
    dc_cands   = [(a, o, nv) for a, o, nv in results if in_dc(a)]
    other      = [(a, o, nv) for a, o, nv in results
                  if not in_ffnx(a) and not in_dc(a)]

    print()
    print(f"  DELTA RESULTS — {label} (press {direction} ×{n})")
    print(f"  Total addresses that changed by exactly "
          f"{'-' if direction.lower()=='left' else '+'}{n}: {len(results)}")
    print()

    hdr = f"  {'Address':<14} {'Before':>8}  {'After':>8}"
    sep = f"  {'-'*13}  {'------'}  {'------'}"

    if ffnx_cands:
        print(f"  FFNx (AF3DN.P) candidates ({len(ffnx_cands)}) — PREFERRED:")
        print(hdr); print(sep)
        for addr, old, new in ffnx_cands:
            offset = addr - ffnx_base
            print(f"  0x{addr:08X}  {old:8d}  {new:8d}  (+0x{offset:X} from AF3DN.P base)")
    elif ffnx_base is not None and ffnx_base in failed_bases:
        print("  (FFNx range read failed — not scanned; see WARNING above)")
    else:
        print("  (no FFNx candidates)")

    print()
    if dc_cands:
        print(f"  DC-block BSS candidates ({len(dc_cands)}):")
        print(hdr); print(sep)
        for addr, old, new in dc_cands:
            print(f"  0x{addr:08X}  {old:8d}  {new:8d}")
    else:
        print("  (no DC-block BSS candidates)")

    print()
    if other:
        print(f"  Other candidates ({len(other)}):")
        print(hdr); print(sep)
        for addr, old, new in other[:10]:
            print(f"  0x{addr:08X}  {old:8d}  {new:8d}")
        if len(other) > 10:
            print(f"  … and {len(other) - 10} more")
    else:
        print("  (no other candidates)")

    # Best = FFNx first, then DC, then other
    return ffnx_cands or dc_cands or other


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
        print("FF7 Sound Sub-menu Scan (delta method — FF7 BSS + FFNx DLL range)")
        print(f"Presses Left ×{DELTA_PRESSES} and searches for byte change of "
              f"exactly −{DELTA_PRESSES}.")
        print()
        print("SETUP:")
        print("  Open main menu → Config (row 7) → Sound (row 1, press Confirm).")
        print("  The Sound sub-menu should be open with the Music slider highlighted.")
        print(f"  Make sure the Music volume is at least {DELTA_PRESSES} above minimum.")
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

        # Locate FFNx DLL in the FF7 process
        ffnx_base, ffnx_size = find_module_range(pid, FFNX_MODULE)
        if ffnx_base is not None:
            print(f"FFNx (AF3DN.P): base=0x{ffnx_base:08X}  size=0x{ffnx_size:X} "
                  f"({ffnx_size // 1024} KB)")
        else:
            print("WARNING: AF3DN.P not found in process — scanning BSS only.")
            print("         (FFNx may not be installed; the slider might be in BSS.)")

        # Build list of scan ranges: BSS + FFNx DLL (if found)
        ranges = [(BSS_MIN, BSS_MAX - BSS_MIN)]
        if ffnx_base is not None:
            ranges.append((ffnx_base, ffnx_size))

        print()
        print("Scan ranges:")
        for base, size in ranges:
            print(f"  0x{base:08X}–0x{base+size:08X}  ({size // 1024} KB)")
        print()

        speak("Connected. Switch to F F 7 now. Hold the Music slider still.")
        print("Connected. Switch to FF7. Hold Music slider still.")
        time.sleep(2)

        # ── Pass A: Music volume ──────────────────────────────────────────
        print()
        print("=" * 60)
        print("  PASS A — Music volume slider")
        print("=" * 60)
        music_results, music_failed = delta_scan_ranges(
            handle, ranges, "Music volume", "Left", DELTA_PRESSES)
        music_best = print_delta_results(
            music_results, "Music volume", "Left", DELTA_PRESSES,
            ffnx_base, ffnx_size, failed_bases=music_failed)

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
        fx_results, fx_failed = delta_scan_ranges(
            handle, ranges, "FX volume", "Left", DELTA_PRESSES)
        fx_best = print_delta_results(
            fx_results, "FX volume", "Left", DELTA_PRESSES,
            ffnx_base, ffnx_size, failed_bases=fx_failed)

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

        if music_best and fx_best:
            ma = music_best[0][0]
            fa = fx_best[0][0]
            dist = abs(ma - fa)
            print(f"  Address distance: 0x{dist:X} bytes apart")
            if dist <= 8:
                print("  (adjacent — likely same config struct)")
        print()

        if ffnx_base is not None:
            print("NOTE: If candidates are in FFNx range, their addresses are dynamic")
            print("  (AF3DN.P can relocate between launches).  The mod will need to")
            print("  find the FFNx base at runtime and apply the offset.")

        print()
        print("NEXT STEPS:")
        print("  1. Run ff7_sound_verify.py to confirm addresses track correctly.")
        print("  2. If in FFNx range: record +offset from AF3DN.P base.")
        print("     Resolve at DLL init time via GetModuleHandleA(\"AF3DN.P\") + offset.")
        print("  3. Add to ff7_addresses.h as SOUND_MUSIC_VOL and SOUND_FX_VOL.")
        print("  4. Extend ConfigMenuThread to speak volume on Sound sub-menu navigation.")

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
