#!/usr/bin/env python3
"""
ff7_continue_menu_scan.py -- Find the TITLE-SCREEN Continue (load) menu's
own state addresses: file-grid cursor, grid<->slot-list phase, slot cursor.
(2026-07-17, follow-up to the v2.29 silence report.)

WHY A SECOND SCAN:
  v2.29's save-menu addresses (SAVEMENU_* 0xDC6AE0/0xDC6B1C/0xDC1210,
  found in the IN-FIELD save menu) were assumed shared with the title
  Continue menu. LIVE-DISPROVED 2026-07-17 by
  ff7_continue_menu_verify.py (log continue_menu_verify_20260717_120914):
  while the player navigated the Continue grid for 90 seconds, all three
  bytes sat FROZEN (grid=0 slot=0, phase=16 = title-module data). The
  Continue menu is a separate implementation with its own state -- this
  scan finds it with the exact method that solved the save menu:
  press-and-revert rounds (wrap-immune, start-position-independent),
  A/B/A phase toggle, and a speak-back verify pass in the same session.

  Scan ranges include FFNx's AF3DN.P module as well as the FF7 BSS (the
  SOUND_CURSOR lesson: not everything lives in the exe's BSS). If BOTH
  come up empty the state is heap-allocated and will need a pointer
  chase instead.

HOW TO RUN (all instructions spoken):
  1. Launch to the title screen, choose Continue so the "Select a save
     data file" grid is up.
  2. Run this script and follow the voice prompts (Right/Left twice,
     Confirm into the slot list, Cancel back, Down/Up twice, then a
     20-second free-movement verify window).
  Read-only -- never writes game memory.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
FFNX_MODULE  = "AF3DN.P"
BSS_MIN      = 0x00400000
BSS_MAX      = 0x00DE0000

KNOWN = {
    "MENU_OPEN":    0x00DC12DC,
    "MENU_CURSOR":  0x00DC1154,
    "TITLE_CURSOR": 0x00DD6F24,
    "GAME_MODE":    0x00CC0D89,
}

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
k32 = ctypes.windll.kernel32


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


def speak(text, wait=False):
    safe = text.replace("'", "''")
    try:
        p = subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        if wait:
            p.wait(timeout=30)
    except Exception:
        pass


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


def find_module_range(pid, module_name):
    class MODULEENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong), ("th32ModuleID", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong), ("GlblcntUsage", ctypes.c_ulong),
            ("ProccntUsage", ctypes.c_ulong), ("modBaseAddr", ctypes.c_void_p),
            ("modBaseSize", ctypes.c_ulong), ("hModule", ctypes.c_void_p),
            ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260),
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
                base, size = me.modBaseAddr, me.modBaseSize
                break
            if not k32.Module32Next(snap, ctypes.byref(me)):
                break
    k32.CloseHandle(snap)
    return base, size


def read_region(handle, base, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size,
                               ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def read_u8(handle, addr):
    buf = ctypes.create_string_buffer(1)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, 1,
                                 ctypes.byref(got)):
        return None
    return buf.raw[0]


def snapshot_all(handle, ranges, label):
    time.sleep(1.2)
    snaps = []
    for base, size in ranges:
        snaps.append(read_region(handle, base, size))
    vals = ', '.join(f"{n}={read_u8(handle, a)}" for n, a in KNOWN.items())
    print(f"  [{label}] {vals}")
    return snaps


def prompted(handle, ranges, instruction):
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(2.5)
    return snapshot_all(handle, ranges, instruction)


def signed_diff(a, b):
    d = b - a
    if d > 127:
        d -= 256
    elif d < -128:
        d += 256
    return d


def round_candidates(ranges, base_s, fwd_s, back_s):
    out = set()
    for (rb, rs), sa, sf, sk in zip(ranges, base_s, fwd_s, back_s):
        if sa is None or sf is None or sk is None:
            continue
        for i in range(rs):
            if (signed_diff(sa[i], sf[i]) == 1 and
                    sf[i] != sk[i] and sk[i] == sa[i]):
                out.add(rb + i)
    return out


def toggle_candidates(ranges, s_a, s_b, s_c):
    out = []
    for (rb, rs), sa, sb, sc in zip(ranges, s_a, s_b, s_c):
        if sa is None or sb is None or sc is None:
            continue
        for i in range(rs):
            if sa[i] != sb[i] and sc[i] == sa[i]:
                out.append((rb + i, sa[i], sb[i]))
    return out


def show(items, title, limit=25):
    print(f"\n  {title}: {len(items)}")
    for item in sorted(items)[:limit]:
        if isinstance(item, tuple):
            a, va, vb = item
            print(f"    0x{a:08X}  {va} -> {vb}")
        else:
            print(f"    0x{item:08X}")
    if len(items) > limit:
        print(f"    ... and {len(items) - limit} more")


def cursor_pass(handle, ranges, what, fwd, back):
    inter = None
    for rnd in (1, 2):
        print(f"\n  -- {what}: round {rnd} --")
        base = snapshot_all(handle, ranges, f"{what} r{rnd} baseline")
        f = prompted(handle, ranges, f"Press {fwd} once, then hold still.")
        b = prompted(handle, ranges, f"Press {back} once, then hold still.")
        cands = round_candidates(ranges, base, f, b)
        print(f"  round {rnd}: {len(cands)} candidates")
        inter = cands if inter is None else (inter & cands)
    show(inter, f"{what} INTERSECTED candidates")
    return sorted(inter)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"continue_menu_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("TITLE Continue-menu state scan (grid / phase / slot)")

        speak("Continue menu scan ready. At the title screen choose "
              "Continue, so the save file grid is on screen. Then come "
              "back to the terminal and press Enter.", wait=True)
        input("  Press Enter when the Continue file grid is on screen ...")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("Error. F F 7 not running.")
            print("ERROR: ff7_en.exe not running.")
            return
        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY,
                                 False, pid)
        if not handle:
            speak("Error. Could not open process.")
            print("ERROR: OpenProcess failed.")
            return
        print(f"PID: {pid}")

        ranges = [(BSS_MIN, BSS_MAX - BSS_MIN)]
        ffnx_base, ffnx_size = find_module_range(pid, FFNX_MODULE)
        if ffnx_base is not None:
            print(f"FFNx (AF3DN.P): base=0x{ffnx_base:08X} size=0x{ffnx_size:X}")
            ranges.append((ffnx_base, ffnx_size))
        else:
            print("WARNING: AF3DN.P not found -- scanning FF7 BSS only.")

        speak("Connected. Switch back to the game. Ten seconds.", wait=True)
        time.sleep(10)

        print("\n" + "=" * 60)
        print("  PASS A -- file grid cursor (Right then Left, twice)")
        print("=" * 60)
        grid = cursor_pass(handle, ranges, "grid cursor", "Right", "Left")

        print("\n" + "=" * 60)
        print("  PASS B -- phase (enter slot list, then cancel out)")
        print("=" * 60)
        s_a = snapshot_all(handle, ranges, "phase A: grid")
        speak("Press Confirm once to open the file's slot list, then "
              "hold still.", wait=True)
        time.sleep(3.0)
        s_b = snapshot_all(handle, ranges, "phase B: slot list")
        speak("Press Cancel once to go back to the file grid, then "
              "hold still.", wait=True)
        time.sleep(3.0)
        s_c = snapshot_all(handle, ranges, "phase C: grid again")
        phase = toggle_candidates(ranges, s_a, s_b, s_c)
        show(phase, "phase toggle candidates")

        print("\n" + "=" * 60)
        print("  PASS C -- slot list cursor (Down then Up, twice)")
        print("=" * 60)
        speak("Press Confirm once to open the slot list again, then come "
              "back and press Enter in the terminal.", wait=True)
        input("  Press Enter when the slot list is on screen ...")
        speak("Switch back to the game. Ten seconds.", wait=True)
        time.sleep(10)
        slots = cursor_pass(handle, ranges, "slot cursor", "Down", "Up")

        print("\n" + "=" * 60)
        print("  PASS D -- live verify (speaks the grid candidate)")
        print("=" * 60)
        if grid:
            top = grid[0]
            speak("Verify pass. Press Cancel to return to the file grid, "
                  "then move the cursor around slowly for twenty "
                  "seconds.", wait=True)
            last = None
            t_end = time.time() + 20
            while time.time() < t_end:
                v = read_u8(handle, top)
                if v is not None and v != last:
                    print(f"  grid 0x{top:08X} = {v}")
                    speak(str(v))
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")
        else:
            print("  (no grid candidates -- state is likely heap-allocated;")
            print("   next step would be a pointer chase, not a rescan)")

        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  grid cursor candidates : {[hex(a) for a in grid[:8]]}")
        print(f"  slot cursor candidates : {[hex(a) for a in slots[:8]]}")
        print(f"  phase candidates       : {len(phase)}")
        if ffnx_base is not None:
            print(f"  (FFNx base this run: 0x{ffnx_base:08X} -- any candidate "
                  f"inside it must be stored as an OFFSET from the module base)")
        speak("Scan complete. Results are in the log.", wait=True)

    except KeyboardInterrupt:
        print("\n  [Stopped by user]")
        speak("Scan stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
