#!/usr/bin/env python3
"""
ff7_order_menu_scan.py -- Find the ORDER menu's state addresses:
  (1) the party cursor (which member the hand is on),
  (2) the "first member selected" latch (the flashing second cursor),
  (3) LIVE-confirm the row byte (savemap char record +0x1F: expected
      0xFF = front row, 0xFE = back row) by toggling a row,
  (4) LIVE-observe the dispatcher index (0xDC12EC) for the Order screen
      (logged with every snapshot — no scanning needed for it),
  (5) LIVE-observe that swapping two members rewrites SAVEMAP_PARTY_IDS
      (logged with every snapshot).
(2026-07-18, for the Order menu TTS feature; screenshot
Screenshots/Menus/order_menu_1.jpg. Same guided-scan recipe as
ff7_item_menu_scan.py / ff7_save_menu_scan.py.)

ORDER SCREEN MECHANICS (drives what the mod will speak):
  Confirm on one member, then Confirm on another = swap their positions.
  Confirm twice on the SAME member = toggle that member's front/back row.
  Cancel = back out (clears a pending first selection).

HOW TO RUN (all instructions are spoken):
  1. Open the main menu, move to ORDER (row 5), press Confirm so the
     Order screen's hand cursor is on the top party member.
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

SAVEMAP_CHAR_RECORDS = 0xDBFD8C
CHAR_REC_SIZE        = 0x84
CHAR_ROW_OFF         = 0x1F      # FFNx savemap_char 'flags'; community: 0xFF front / 0xFE back
SAVEMAP_PARTY_IDS    = 0xDC0230

# Logged with every snapshot. SUBMENU_CUR: the item session proved this
# is the dispatcher's screen index (item=1); this session captures the
# ORDER screen's value — and, before Confirm, the PLAIN MAIN MENU's
# value, closing the §4 "never observed" caveat.
KNOWN = {
    "MENU_OPEN":   0x00DC12DC,
    "MENU_CURSOR": 0x00DC1154,
    "SUBMENU_CUR": 0x00DC12EC,
    "SUBMENU_TRN": 0x00DC12E8,
    "ITEM_MODE":   0x00DD19C8,   # item screen's mode var — contrast only
    "PARTY0":      SAVEMAP_PARTY_IDS,
    "PARTY1":      SAVEMAP_PARTY_IDS + 1,
    "PARTY2":      SAVEMAP_PARTY_IDS + 2,
    "ROW_REC0":    SAVEMAP_CHAR_RECORDS + 0 * CHAR_REC_SIZE + CHAR_ROW_OFF,  # Cloud (id 0)
    "ROW_REC1":    SAVEMAP_CHAR_RECORDS + 1 * CHAR_REC_SIZE + CHAR_ROW_OFF,  # Barret (id 1)
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
    """TTS via PowerShell System.Speech (pywin2 absent on system python —
    the v2.24 lesson; SAPI COM via powershell always works)."""
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


def prompted_press(handle, instruction, settle=2.5):
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(settle)
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
        script_dir, f"order_menu_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("FF7 ORDER-MENU state scan (cursor / selection latch / row byte)")

        speak("Order menu scan ready. In the game, open the main menu and "
              "move the cursor to Order, but do NOT press Confirm yet. "
              "Then come back to the terminal and press Enter.", wait=True)
        input("  Press Enter with the MAIN menu open, cursor on Order ...")

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

        # -- PASS 0: plain-main-menu dispatch value (closes a §4 caveat),
        #    then the Order screen's own value.
        print("\n" + "=" * 60)
        print("  PASS 0 -- dispatch index: main menu vs Order screen")
        print("=" * 60)
        wait_snapshot(handle, "PLAIN MAIN MENU, cursor on Order")
        snap = prompted_press(
            handle, "Press Confirm once to enter the Order screen, "
                    "then hold still.", settle=3.0)
        order_screen_snap = snap

        # -- PASS A: party cursor (Down/Up, two rounds) -------------------
        print("\n" + "=" * 60)
        print("  PASS A -- party cursor (Down then Up, twice)")
        print("=" * 60)
        cursor = cursor_pass(handle, "party cursor", "Down", "Up")

        # -- PASS B: first-selection latch (Confirm then Cancel, A/B/A) ---
        print("\n" + "=" * 60)
        print("  PASS B -- selection latch (Confirm a member, Cancel out)")
        print("=" * 60)
        speak("Make sure the cursor is on the top member. Hold still.",
              wait=True)
        time.sleep(2.5)
        snap_a = wait_snapshot(handle, "latch A: nothing selected")
        speak("Press Confirm once to select the top member. A second "
              "cursor should start flashing there. Hold still.", wait=True)
        time.sleep(3.0)
        snap_b = wait_snapshot(handle, "latch B: member selected")
        speak("Press Cancel once to clear the selection. Hold still.",
              wait=True)
        time.sleep(3.0)
        snap_c = wait_snapshot(handle, "latch C: cleared")
        latch = toggle_candidates(snap_a, snap_b, snap_c)
        show(latch, "selection-latch candidates (changed then reverted)")

        # -- PASS C: row toggle (Confirm same member twice, twice) --------
        print("\n" + "=" * 60)
        print("  PASS C -- row toggle (watch the savemap row bytes)")
        print("=" * 60)
        speak("Now press Confirm twice on the top member to switch their "
              "row, then hold still.", wait=True)
        time.sleep(4.0)
        snap_tog = wait_snapshot(handle, "row toggled")
        speak("Press Confirm twice on the same member again to switch "
              "them back. Hold still.", wait=True)
        time.sleep(4.0)
        snap_back = wait_snapshot(handle, "row restored")
        row_cands = toggle_candidates(snap_a, snap_tog, snap_back)
        show(row_cands, "row-toggle candidates (changed then reverted)")
        r0 = KNOWN["ROW_REC0"] - BSS_MIN
        print(f"  ROW_REC0 (Cloud +0x1F): {snap_a[r0]:#04x} -> "
              f"{snap_tog[r0]:#04x} -> {snap_back[r0]:#04x} "
              f"(expected 0xff <-> 0xfe if +0x1F is the row byte)")

        # -- PASS D: swap the two members and swap back -------------------
        print("\n" + "=" * 60)
        print("  PASS D -- swap (party IDs array should swap)")
        print("=" * 60)
        speak("Now swap the two members: Confirm on the top member, then "
              "Confirm on the second member. Hold still.", wait=True)
        time.sleep(5.0)
        snap_swapped = wait_snapshot(handle, "after swap")
        speak("Swap them back the same way. Hold still.", wait=True)
        time.sleep(5.0)
        wait_snapshot(handle, "after swap back")

        # -- PASS E: live speak-back verify on the party cursor -----------
        print("\n" + "=" * 60)
        print("  PASS E -- live verify (speaks tracked cursor on change)")
        print("=" * 60)
        if cursor:
            top = cursor[0]
            speak("Verify pass. Move up and down the member list slowly "
                  "for fifteen seconds. I will call out the tracked "
                  "position on every change.", wait=True)
            last = None
            t_end = time.time() + 15
            while time.time() < t_end:
                snap = read_bss(handle)
                if snap is None:
                    break
                v = snap[top - BSS_MIN]
                if v != last:
                    print(f"  party cursor 0x{top:08X} = {v}")
                    speak(str(v + 1))
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")
        else:
            print("  (no cursor candidates to verify)")

        # -- summary ------------------------------------------------------
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  party cursor candidates : {[hex(a) for a in cursor[:8]]}")
        print(f"  latch candidates        : {len(latch)}")
        print(f"  row-toggle candidates   : {len(row_cands)}")
        print("  Dispatch index: compare SUBMENU_CUR in the PASS 0 lines")
        print("  (main menu vs Order screen). Party-IDs swap: compare the")
        print("  PARTY0/1/2 bytes across the PASS D lines.")
        print()
        print("NEXT: wire confirmed addresses into ff7_addresses.h")
        print("  (ORDERMENU_*) and add the OrderMenu speaker to proxy.cpp.")
        speak("Scan complete. Results are in the log. You can leave the "
              "menu.", wait=True)

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
