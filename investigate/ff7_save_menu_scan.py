#!/usr/bin/env python3
"""
ff7_save_menu_scan.py -- Find the SAVE/LOAD menu's state addresses:
  (1) the 10-file grid cursor ("Save 1".."Save 10"),
  (2) the grid<->slot-list phase indicator,
  (3) the 15-slot list cursor.
(2026-07-17, for the save/continue menu TTS feature.)

WHY THESE THREE AND NOTHING MORE:
  The slot PREVIEW data (lead name, level, time, gil, location) does NOT
  need memory addresses at all -- it lives in the save files on disk,
  whose layout was derived from the player's own save00.ff7 against
  screenshot ground truth (ff7_savefile_preview_derive.py, log
  savefile_preview_derive_20260717_113941: slot base 9+n*0x10F4,
  +0x04 level, +0x05..07 portraits, +0x08 name, +0x20 gil u32,
  +0x24 seconds u32, +0x28 location, empty slot = all zero). The mod
  will read the files itself; only CURSOR/PHASE state must come from
  memory. Save-vs-load MODE also needs no scan: in FF7 PC the save menu
  is only reachable in-field (main menu SAVE row) and the load menu only
  from the title screen -- context the mod already tracks.

METHOD (proven patterns from Section 9 of the research doc):
  - Cursors: symmetric press-and-revert rounds (Right then Left; Down
    then Up), TWO rounds intersected -- candidates must move +1 on the
    forward press and back on the reverse, both times. Immune to wrap
    and to not knowing the starting index (the SOUND_CURSOR lesson).
  - Phase: A/B/A toggle (grid -> OK into slot list -> Cancel back);
    candidates changed A->B and reverted B->C.
  - Each snapshot also logs the known menu addresses (MENU_OPEN,
    MENU_CURSOR, QUIT_CURSOR, TITLE_CURSOR) so we learn how the save
    menu relates to the machinery the mod already has.
  - Final optional pass: live-poll the top candidates and SPEAK the
    grid cursor value while the player moves freely -- scan and verify
    in one session.

HOW TO RUN (all instructions are spoken):
  1. Stand on the save point, open the main menu, choose SAVE.
     The 10-file grid should be showing.
  2. Run this script and follow the voice prompts.
     It never writes game memory -- read-only snapshots.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN      = 0x00400000
BSS_MAX      = 0x00DE0000

# Known menu-machinery addresses (ff7_addresses.h) logged with every
# snapshot for correlation:
KNOWN = {
    "MENU_OPEN":    0x00DC12DC,
    "MENU_CURSOR":  0x00DC1154,
    "QUIT_CURSOR":  0x00DC0FA0,
    "TITLE_CURSOR": 0x00DD6F24,
}

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
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
    """TTS via PowerShell System.Speech (the v2.24 lesson: pywin32 is
    absent on the system python; SAPI COM via powershell always works).
    wait=True blocks until spoken -- used before timed press prompts."""
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


def read_bss(handle):
    size = BSS_MAX - BSS_MIN
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(BSS_MIN),
                               buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def log_known(snap, label):
    vals = ', '.join(
        f"{name}={snap[addr - BSS_MIN]}" for name, addr in KNOWN.items())
    print(f"  [{label}] {vals}")


def wait_snapshot(handle, label):
    """Give the user a moment to settle, then snapshot."""
    time.sleep(1.2)
    snap = read_bss(handle)
    if snap is None:
        print("  ERROR: snapshot failed")
        speak("Snapshot failed.")
        sys.exit(1)
    log_known(snap, label)
    return snap


def prompted_press(handle, instruction):
    """Speak an instruction, give the user time to do ONE press, snapshot."""
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(2.5)                      # time for one unhurried press
    return wait_snapshot(handle, instruction)


def signed_diff(a, b):
    d = b - a
    if d > 127:
        d -= 256
    elif d < -128:
        d += 256
    return d


def round_candidates(base_snap, fwd_snap, back_snap):
    """Addresses that moved +1 on the forward press and reverted on the
    reverse press."""
    out = set()
    for i in range(len(base_snap)):
        if (signed_diff(base_snap[i], fwd_snap[i]) == 1 and
                fwd_snap[i] != back_snap[i] and
                back_snap[i] == base_snap[i]):
            out.add(BSS_MIN + i)
    return out


def toggle_candidates(snap_a, snap_b, snap_c):
    """Addresses that changed A->B and reverted B->C (symmetric toggle)."""
    out = []
    for i in range(len(snap_a)):
        if snap_a[i] != snap_b[i] and snap_c[i] == snap_a[i]:
            out.append((BSS_MIN + i, snap_a[i], snap_b[i]))
    return out


def show(addrs_vals, title, limit=25):
    print(f"\n  {title}: {len(addrs_vals)}")
    for item in sorted(addrs_vals)[:limit]:
        if isinstance(item, tuple):
            a, va, vb = item
            print(f"    0x{a:08X}  {va} -> {vb}")
        else:
            print(f"    0x{item:08X}")
    if len(addrs_vals) > limit:
        print(f"    ... and {len(addrs_vals) - limit} more")


def cursor_pass(handle, what, fwd, back):
    """Two intersected forward/revert rounds for one cursor."""
    inter = None
    for rnd in (1, 2):
        print(f"\n  -- {what}: round {rnd} --")
        base = wait_snapshot(handle, f"{what} r{rnd} baseline")
        f = prompted_press(handle, f"Press {fwd} once, then hold still.")
        b = prompted_press(handle, f"Press {back} once, then hold still.")
        cands = round_candidates(base, f, b)
        print(f"  round {rnd}: {len(cands)} candidates")
        inter = cands if inter is None else (inter & cands)
    show(inter, f"{what} INTERSECTED candidates")
    return sorted(inter)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir, f"save_menu_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("FF7 SAVE-MENU state scan (grid cursor / phase / slot cursor)")

        speak("Save menu scan ready. In the game, stand on the save "
              "point, open the main menu, choose Save. The Save 1 to "
              "Save 10 file grid should be on screen. Then come back "
              "to the terminal and press Enter.", wait=True)
        input("  Press Enter when the file grid is on screen ...")

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
        speak("Connected. Switch back to the game now. Leave the cursor "
              "wherever it is. Ten seconds.", wait=True)
        time.sleep(10)

        # -- PASS A: file-grid cursor (Right/Left, two rounds) ------------
        print("\n" + "=" * 60)
        print("  PASS A -- file grid cursor (Right then Left, twice)")
        print("=" * 60)
        grid = cursor_pass(handle, "grid cursor", "Right", "Left")

        # -- PASS B: phase toggle (grid -> slot list -> grid) -------------
        print("\n" + "=" * 60)
        print("  PASS B -- phase (enter slot list, then cancel out)")
        print("=" * 60)
        snap_a = wait_snapshot(handle, "phase A: grid")
        speak("Press Confirm once to open the save file's slot list, "
              "then hold still.", wait=True)
        time.sleep(3.0)
        snap_b = wait_snapshot(handle, "phase B: slot list")
        speak("Press Cancel once to go back to the file grid, "
              "then hold still.", wait=True)
        time.sleep(3.0)
        snap_c = wait_snapshot(handle, "phase C: grid again")
        phase = toggle_candidates(snap_a, snap_b, snap_c)
        show(phase, "phase toggle candidates (changed then reverted)")

        # -- PASS C: slot-list cursor (Down/Up, two rounds) ---------------
        print("\n" + "=" * 60)
        print("  PASS C -- slot list cursor (Down then Up, twice)")
        print("=" * 60)
        speak("Press Confirm once to open the slot list again, then "
              "come back and press Enter in the terminal.", wait=True)
        input("  Press Enter when the slot list is on screen ...")
        speak("Switch back to the game. Ten seconds.", wait=True)
        time.sleep(10)
        slots = cursor_pass(handle, "slot cursor", "Down", "Up")

        # -- PASS D: live tracking check on the grid cursor ---------------
        print("\n" + "=" * 60)
        print("  PASS D -- live verify (speaks the candidate values)")
        print("=" * 60)
        if grid:
            top = grid[0]
            speak("Verify pass. Press Cancel to return to the file "
                  "grid, then move the cursor around slowly for "
                  "twenty seconds. I will call out the tracked "
                  "value on every change.", wait=True)
            last = None
            t_end = time.time() + 20
            while time.time() < t_end:
                snap = read_bss(handle)
                if snap is None:
                    break
                v = snap[top - BSS_MIN]
                if v != last:
                    print(f"  grid 0x{top:08X} = {v}")
                    speak(str(v + 1))
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")
        else:
            print("  (no grid candidates to verify)")

        # -- summary ------------------------------------------------------
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  grid cursor candidates : {[hex(a) for a in grid[:8]]}")
        print(f"  slot cursor candidates : {[hex(a) for a in slots[:8]]}")
        print(f"  phase candidates       : {len(phase)} "
              f"(prefer one in the DC menu block that also appears in "
              f"neither cursor list)")
        print()
        print("NEXT: wire the confirmed addresses into ff7_addresses.h")
        print("  (SAVEMENU_* constants) and add the SaveMenu speaker to")
        print("  proxy.cpp reading previews from the save files on disk.")
        speak("Scan complete. Results are in the log. You can close "
              "the menu.", wait=True)

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
