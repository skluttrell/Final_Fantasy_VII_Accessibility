#!/usr/bin/env python3
"""
ff7_name_entry_verify.py — Confirm the corrected name-entry addresses live,
decode the side panel, and hunt the screen-active gate flag.

CONTEXT (results of ff7_name_entry_scan.py, 2026-07-12):
  ROW cursor    0x00DD453C  CONFIRMED live (rows matched typed letters)
  COLUMN cursor 0x00DD4538  found by scan but never spoken from live —
                            the scan's live phase mistakenly polled the old
                            Echo-mod anchor 0xDD46F8, which turned out to be
                            DEAD (never changed once during Left/Right).
  NAME buffer   0x00DD45F5  CONFIRMED live (position 0: full delete emptied
                            it, first re-added letter landed at F5)
  Caret         none found  (candidates were 0->32->0 press pulses, likely
                            SFX triggers; length comes from the 0xFF-
                            terminated buffer instead)

THIS SCRIPT'S THREE JOBS:
  1. LIVE GRID TEST with the corrected column address — the spoken letter
     should now match the actual cursor cell in BOTH axes.
  2. SIDE PANEL DECODE — while the player navigates to Space/Delete/Select/
     Default, every byte change in the DD4400-DD4800 window is logged with
     a timestamp.  Whatever byte tracks the panel (maybe the mislabeled
     0xDD46F8?) will reveal itself.  Row/col values while "outside" the 7x10
     grid are spoken raw so the player can narrate afterwards.
  3. GATE FLAG HUNT — after the player confirms the name and returns to
     gameplay, diff the DD window (and GAME_MODE) against the on-screen
     snapshot.  A byte that flips when leaving the naming screen is our
     "name entry active" gate candidate for the eventual mod thread.

AUDIO CUES: same protocol as the scan — SAPI instructions first, double
high beep = start, triple low beep = phase over.

OUTPUT: teed to name_entry_verify_<timestamp>.log next to this script.
"""

import ctypes
import subprocess
import sys
import time
import os
import winsound

PROCESS_NAME = "ff7_en.exe"

ROW_ADDR    = 0x00DD453C   # confirmed
COL_ADDR    = 0x00DD4538   # to verify now
BUF_ADDR    = 0x00DD45F5   # confirmed, 0xFF-terminated, max 12ish
OLD_ANCHOR  = 0x00DD46F8   # dead during grid nav — side-panel suspect
GAME_MODE   = 0x00CC0D89   # u8: 0=field 2=battle 9=menu (live-observed)

# Whole name-entry state window — every byte change here gets logged.
WIN_LO = 0x00DD4400
WIN_HI = 0x00DD4800

LIVE_DURATION = 120        # grid + side-panel exploration
EXIT_WAIT     = 40         # time for the player to confirm name + return

GRID = [
    list("ABCDEFGHIJ"),
    list("KLMNOPQRST"),
    ["U", "V", "W", "X", "Y", "Z", ",", ".", "+", "-"],
    list("abcdefghij"),
    list("klmnopqrst"),
    ["u", "v", "w", "x", "y", "z", ":", ";", "'", '"'],   # cols 8-9 uncertain
    list("0123456789"),
]

CHAR_SPOKEN = {
    ",": "comma", ".": "period", "+": "plus", "-": "minus",
    ":": "colon", ";": "semicolon", "'": "apostrophe", '"': "quote",
}


def spoken_char(ch):
    if ch in CHAR_SPOKEN:
        return CHAR_SPOKEN[ch]
    if ch.isupper():
        return f"capital {ch}"
    return ch


def decode_ff7_name(raw):
    out = []
    for b in raw:
        if b == 0xFF:
            break
        c = b + 0x20
        out.append(chr(c) if 0x20 <= c <= 0x7E else "?")
    return "".join(out)


k32 = ctypes.windll.kernel32


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


def speak_wait(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=90
        )
    except Exception:
        pass


def beep_start():
    winsound.Beep(1200, 120); time.sleep(0.08); winsound.Beep(1200, 120)


def beep_stop():
    for _ in range(3):
        winsound.Beep(600, 100); time.sleep(0.06)


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


def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(addr), buf, n, ctypes.byref(read))
    if ok and read.value == n:
        return buf.raw
    return None


def read_byte(handle, addr):
    raw = read_bytes(handle, addr, 1)
    return raw[0] if raw is not None else None


def snapshot_window(handle):
    return read_bytes(handle, WIN_LO, WIN_HI - WIN_LO)


def diff_window(label, prev, curr, t0):
    """Log every changed byte in the DD window: addr, old -> new.
    Cursor/buffer addresses are annotated so the log reads itself."""
    known = {ROW_ADDR: "ROW", COL_ADDR: "COL", OLD_ANCHOR: "OLD_ANCHOR"}
    changes = []
    for i in range(len(curr)):
        if curr[i] != prev[i]:
            addr = WIN_LO + i
            tag = known.get(addr, "")
            if BUF_ADDR <= addr < BUF_ADDR + 16:
                tag = f"BUF+{addr - BUF_ADDR}"
            changes.append((addr, prev[i], curr[i], tag))
    for addr, old, new, tag in changes:
        print(f"  [{time.time()-t0:7.2f}s {label}] 0x{addr:08X}: "
              f"{old:3d} -> {new:3d}  {tag}")
    return changes


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"name_entry_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak_wait("FF7 not found.")
            print("ERROR: ff7_en.exe not running.")
            return

        handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        gm = read_byte(handle, GAME_MODE)
        print(f"GAME_MODE on naming screen = {gm}   "
              f"(known: 0=field 2=battle 9=menu)")
        print(f"row={read_byte(handle, ROW_ADDR)} "
              f"col={read_byte(handle, COL_ADDR)} "
              f"old_anchor={read_byte(handle, OLD_ANCHOR)}")

        # ---- Phase 1+2: live grid + side panel -----------------------------
        speak_wait(
            "Verify test. Move around the letter grid; I will speak each "
            "letter, and this time columns should be correct. After roaming "
            "a bit, move right past the last grid column to reach the side "
            "panel with Space, Delete, Select and Default, and press Up and "
            "Down there a few times. Remember what you hear. Two minutes, "
            "starting at the double beep."
        )
        beep_start()

        t0        = time.time()
        prev_win  = snapshot_window(handle)
        last_row  = read_byte(handle, ROW_ADDR)
        last_col  = read_byte(handle, COL_ADDR)
        last_name = None
        deadline  = time.time() + LIVE_DURATION

        while time.time() < deadline:
            time.sleep(0.10)
            curr_win = snapshot_window(handle)
            if curr_win is None or prev_win is None:
                prev_win = curr_win
                continue

            diff_window("live", prev_win, curr_win, t0)
            prev_win = curr_win

            row = read_byte(handle, ROW_ADDR)
            col = read_byte(handle, COL_ADDR)
            raw = read_bytes(handle, BUF_ADDR, 16)
            name = decode_ff7_name(raw) if raw is not None else None

            if row is not None and col is not None and \
               (row != last_row or col != last_col):
                if row < len(GRID) and col < len(GRID[row]):
                    msg = spoken_char(GRID[row][col])
                else:
                    msg = f"row {row}, column {col}, outside grid"
                print(f"  [CURSOR] row={row} col={col} -> {msg}")
                speak_wait(msg)
                last_row, last_col = row, col

            if name is not None and name != last_name:
                if last_name is not None:
                    print(f"  [NAME] '{name}'")
                    speak_wait(f"Name is now "
                               f"{' '.join(name) if name else 'empty'}")
                last_name = name

        beep_stop()

        # ---- Phase 3: exit diff (gate flag hunt) ----------------------------
        on_screen = snapshot_window(handle)
        gm_on     = read_byte(handle, GAME_MODE)

        speak_wait(
            "Now finish the naming screen for real. Delete any junk letters, "
            "enter the name you want, then choose Select to confirm and "
            "continue into the game. I will check memory again in about "
            "forty seconds."
        )
        print(f"\n[EXIT] waiting {EXIT_WAIT}s for the player to confirm "
              f"and leave the naming screen ...")
        time.sleep(EXIT_WAIT)

        off_screen = snapshot_window(handle)
        gm_off     = read_byte(handle, GAME_MODE)

        print(f"\nGAME_MODE: on-screen={gm_on}  after-exit={gm_off}")
        print("DD-window bytes that changed between naming screen and after "
              "exit (gate flag candidates):")
        if on_screen and off_screen:
            n = diff_window("exit-diff", on_screen, off_screen, t0)
            if not n:
                print("  (none — gate must live outside the DD window; "
                      "GAME_MODE comparison above may be enough)")

        speak_wait("All done. Results are in the log. You can keep playing "
                   "or quit, whichever you like.")
        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
