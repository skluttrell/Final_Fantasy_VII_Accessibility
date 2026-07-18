#!/usr/bin/env python3
"""
ff7_item_menu_scan.py -- Find the ITEM menu's cursor/state addresses:
  (1) the top-bar cursor (Use / Arrange / Key Items),
  (2) the top-bar <-> item-list phase indicator,
  (3) the item-list cursor,
  (4) the use-on-whom target pane: open flag + party cursor.
(2026-07-18, for the Item menu TTS feature; screenshots
Screenshots/Menus/items_menu_1.png / items_menu_2.png are ground truth.)

WHAT NEEDS NO SCAN (established statically the same morning,
ff7_item_menu_static.py + ff7_menu_dispatch_disasm.py):
  - Inventory data: savemap items[320] at 0xDC0234 (= savemap+0x4FC,
    word = id | qty<<9, EMPTY = 0xFFFF per FFNx menu.cpp), key-item
    bitmask at 0xDC0894. Item names: the mod's existing kernel2 item
    section. So only CURSOR/PHASE state must come from memory.
  - Which sub-screen is open: the dispatcher (menu_sub_6CB56A) indexes
    menu_subs_call_table[16] with u32 [0xDC12E8] (transition frames) /
    u32 [0xDC12EC] (steady state) — ITEM MENU = INDEX 3 (caption-string
    + items-array evidence). Both are logged with every snapshot here;
    the scan doubles as their live verify.

METHOD (same proven passes as ff7_save_menu_scan.py):
  - Cursors: symmetric press-and-revert rounds, two rounds intersected.
  - Phases: A/B/A toggle (enter, cancel out).
  - Save-menu SCAN LESSONS applied: lists must be exercised PAST their
    window to split window-row from absolute index — the player's
    inventory is only 3 items today, so the list cannot scroll and the
    window/absolute question CANNOT be settled in this session. The
    summary flags it as a mandatory follow-up once inventory > visible
    rows (the mod ships with the same-address assumption until then).

HOW TO RUN (all instructions are spoken):
  1. Open the main menu, choose ITEM. The Use/Arrange/Key Items bar
     should be at the top with the item list on the right.
  2. Run this script and follow the voice prompts.
     It never writes game memory -- read-only snapshots.

RESULT (run 2026-07-18, log item_menu_scan_20260718_114427): every pass
a SINGLE candidate — MODE 0xDD19C8 (0 top bar/1 list/2 target; both
toggles landed on it), TOPBAR 0xDD1A18, LIST 0xDD1A54 (speak-back
verified), TARGET 0xDD1A8C; dispatch index 0xDC12EC read 1 throughout.
FLOW CORRECTION from the player: the item menu OPENS in the ITEM LIST
and Cancel goes UP to the top bar — this docstring's step 1 (and the
spoken prompts) had it backwards; the passes still worked because the
player adapted, but a rerun should enter the list first, Cancel to the
bar for PASS A, and expect mode to start at 1.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN      = 0x00400000
BSS_MAX      = 0x00DE0000

# Known/static addresses logged with every snapshot for correlation:
# the DC12xx dispatcher block (this scan is also their live verify) and
# the item menu's exclusive static block found by ff7_item_menu_static.py.
KNOWN = {
    "MENU_OPEN":   0x00DC12DC,
    "MENU_CURSOR": 0x00DC1154,
    "SUBMENU_CUR": 0x00DC12EC,   # dispatcher steady-state index (want 3)
    "SUBMENU_TRN": 0x00DC12E8,   # dispatcher transition index
    "ITM_A7F8":    0x00DCA7F8,   # item-menu exclusive block (static find)
    "ITM_A814":    0x00DCA814,
    "SAVE_WIDGET": 0x00DCA028,   # save menu's widget state, for contrast
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
    absent on the system python; SAPI COM via powershell always works)."""
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
    time.sleep(1.2)
    snap = read_bss(handle)
    if snap is None:
        print("  ERROR: snapshot failed")
        speak("Snapshot failed.")
        sys.exit(1)
    log_known(snap, label)
    return snap


def prompted_press(handle, instruction):
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(2.5)
    return wait_snapshot(handle, instruction)


def signed_diff(a, b):
    d = b - a
    if d > 127:
        d -= 256
    elif d < -128:
        d += 256
    return d


def round_candidates(base_snap, fwd_snap, back_snap):
    out = set()
    for i in range(len(base_snap)):
        if (signed_diff(base_snap[i], fwd_snap[i]) == 1 and
                fwd_snap[i] != back_snap[i] and
                back_snap[i] == base_snap[i]):
            out.add(BSS_MIN + i)
    return out


def toggle_candidates(snap_a, snap_b, snap_c):
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
        script_dir, f"item_menu_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("FF7 ITEM-MENU state scan (top bar / phase / list / target)")

        speak("Item menu scan ready. In the game, open the main menu and "
              "choose Item. The cursor should be on Use at the top. "
              "Then come back to the terminal and press Enter.", wait=True)
        input("  Press Enter when the item menu is on screen ...")

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
              "on Use. Ten seconds.", wait=True)
        time.sleep(10)

        # -- PASS A: top-bar cursor (Right/Left, two rounds) --------------
        print("\n" + "=" * 60)
        print("  PASS A -- top bar cursor (Right then Left, twice)")
        print("=" * 60)
        topbar = cursor_pass(handle, "top bar cursor", "Right", "Left")

        # -- PASS B: phase toggle (top bar -> item list -> top bar) -------
        print("\n" + "=" * 60)
        print("  PASS B -- phase (Confirm into the item list, Cancel out)")
        print("=" * 60)
        speak("Make sure the top cursor is back on Use. Hold still.",
              wait=True)
        time.sleep(2.5)
        snap_a = wait_snapshot(handle, "phase A: top bar")
        speak("Press Confirm once to move down into the item list, "
              "then hold still.", wait=True)
        time.sleep(3.0)
        snap_b = wait_snapshot(handle, "phase B: item list")
        speak("Press Cancel once to go back to the top bar, "
              "then hold still.", wait=True)
        time.sleep(3.0)
        snap_c = wait_snapshot(handle, "phase C: top bar again")
        phase = toggle_candidates(snap_a, snap_b, snap_c)
        show(phase, "phase toggle candidates (changed then reverted)")

        # -- PASS C: item-list cursor (Down/Up, two rounds) ---------------
        print("\n" + "=" * 60)
        print("  PASS C -- item list cursor (Down then Up, twice)")
        print("=" * 60)
        speak("Press Confirm once to enter the item list again. The "
              "cursor should be on the first item. Then hold still.",
              wait=True)
        time.sleep(3.0)
        items = cursor_pass(handle, "item cursor", "Down", "Up")

        # -- PASS D: target pane (open toggle, then party cursor) ---------
        print("\n" + "=" * 60)
        print("  PASS D -- use-on-whom target pane")
        print("=" * 60)
        speak("Move the item cursor to a usable item like Potion, "
              "then hold still.", wait=True)
        time.sleep(3.5)
        snap_a = wait_snapshot(handle, "target A: list")
        speak("Press Confirm once. The hand should move to Cloud on the "
              "left. Hold still.", wait=True)
        time.sleep(3.0)
        snap_b = wait_snapshot(handle, "target B: pane open")
        speak("Press Cancel once to go back to the item list. "
              "Hold still.", wait=True)
        time.sleep(3.0)
        snap_c = wait_snapshot(handle, "target C: list again")
        tgt_open = toggle_candidates(snap_a, snap_b, snap_c)
        show(tgt_open, "target-pane-open candidates (changed then reverted)")

        speak("Press Confirm once more to open the target pane again, "
              "with the hand on Cloud. Then hold still.", wait=True)
        time.sleep(3.0)
        target = cursor_pass(handle, "target cursor", "Down", "Up")
        speak("Press Cancel to close the target pane.", wait=True)
        time.sleep(2.0)

        # -- PASS E: live speak-back verify on the item-list cursor -------
        print("\n" + "=" * 60)
        print("  PASS E -- live verify (speaks tracked values on change)")
        print("=" * 60)
        if items:
            top = items[0]
            speak("Verify pass. Move up and down the item list slowly "
                  "for twenty seconds. I will call out the tracked row "
                  "number on every change.", wait=True)
            last = None
            t_end = time.time() + 20
            while time.time() < t_end:
                snap = read_bss(handle)
                if snap is None:
                    break
                v = snap[top - BSS_MIN]
                if v != last:
                    print(f"  item cursor 0x{top:08X} = {v}")
                    speak(str(v + 1))
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")
        else:
            print("  (no item-cursor candidates to verify)")

        # -- summary ------------------------------------------------------
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  top bar cursor candidates : {[hex(a) for a in topbar[:8]]}")
        print(f"  item cursor candidates    : {[hex(a) for a in items[:8]]}")
        print(f"  target cursor candidates  : {[hex(a) for a in target[:8]]}")
        print(f"  phase candidates          : {len(phase)}")
        print(f"  target-open candidates    : {len(tgt_open)}")
        print()
        print("  RESIDUAL (mandatory follow-up): with only 3 items the list")
        print("  cannot scroll, so 'item cursor' may be the WINDOW row, not")
        print("  the absolute row (the save-menu lesson). Re-verify with a")
        print("  scroll probe once inventory exceeds the visible rows; a")
        print("  nearby scroll word (save menu: cursor+~0x10) is expected.")
        print()
        print("NEXT: wire confirmed addresses into ff7_addresses.h")
        print("  (ITEMMENU_* constants) and add the ItemMenu speaker to")
        print("  proxy.cpp reading inventory from savemap items[320].")
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
