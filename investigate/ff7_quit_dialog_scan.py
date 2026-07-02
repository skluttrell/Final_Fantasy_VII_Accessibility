#!/usr/bin/env python3
"""
ff7_quit_dialog_scan.py — Find the Yes/No cursor and dialog-open flag for
                          the Quit confirmation dialog.

The Quit confirmation ("Do you want to quit playing Final Fantasy VII and
return to Windows?  Yes / No") is a horizontal 2-option cursor driven by
the menu system, independent of field opcodes.  We need:

  QUIT_CURSOR  — byte that changes between Yes and No as the cursor moves
  QUIT_OPEN    — byte that is set when the dialog is visible and cleared
                 when it is dismissed (used to announce the dialog text and
                 default "No" position when the dialog first appears)

APPROACH — 4-snapshot differential:

  Snap A  Main menu open, cursor on Quit row, NOT yet confirmed
  Snap B  Quit dialog open, cursor on No  (default position)
  Snap C  Quit dialog open, cursor moved to Yes
  Snap D  Quit dialog open, cursor moved back to No

  QUIT_CURSOR candidates : changed B→C AND reverted C→D (symmetric toggle)
  QUIT_OPEN   candidates : changed A→B AND stable across B, C, D
                           (set when dialog opened, constant while open)

USAGE:
  1. Start FF7, load a save, enter the field.
  2. Open the main menu and navigate to Quit.  Rest the cursor on Quit.
     Do NOT press Confirm yet.
  3. Run this script.  It will guide you with voice and countdown cues.

  Snap A: Script tells you to hold still on the main-menu Quit row.
  Snap B: Script tells you to confirm Quit (open the dialog) and rest on No.
  Snap C: Script tells you to press Left to move to Yes.
  Snap D: Script tells you to press Right to move back to No.

  Results are logged and spoken.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os
import winsound
import struct

PROCESS_NAME = "ff7_en.exe"

STATIC_LO = 0x00400000
STATIC_HI = 0x00DE0000   # ~10 MB stable BSS/data region

# Seconds of settling time after each voice cue before the snapshot is taken.
SETTLE_A = 5   # just standing still on Quit — very fast
SETTLE_B = 6   # time to press Confirm and let dialog animation finish
SETTLE_C = 5   # time to press Left once and hold
SETTLE_D = 5   # time to press Right once and hold

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
PROCESS_VM_ALL   = PROCESS_VM_READ | PROCESS_VM_QUERY

k32 = ctypes.windll.kernel32


# ── I/O helpers ───────────────────────────────────────────────────────────────

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


def beep(freq=1000, ms=120):
    winsound.Beep(freq, ms)


def countdown(seconds, label):
    for i in range(seconds, 0, -1):
        print(f"  {label}: {i}s …", end='\r', flush=True)
        time.sleep(1)
    print()


# ── Process / memory helpers ──────────────────────────────────────────────────

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
    handle = k32.OpenProcess(PROCESS_VM_ALL, False, pid)
    return handle if handle else None


def read_region(handle, lo, hi):
    size = hi - lo
    buf  = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(
        handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytearray(buf.raw)
    if read.value > 0:
        return bytearray(buf.raw[:read.value])
    return None


def snap(handle, label, settle, cue):
    speak_wait(cue)
    print()
    print(f"  {cue}")
    countdown(settle, f"Snapshot {label} in")
    print(f"  Taking snapshot {label} …", end=' ', flush=True)
    data = read_region(handle, STATIC_LO, STATIC_HI)
    if data is None:
        print("FAILED")
        return None
    print(f"OK ({len(data)//1024} KB)")
    beep(880 + 110 * (ord(label) - ord('A')), 120)
    return data


# ── Analysis ──────────────────────────────────────────────────────────────────

def find_cursor_candidates(snap_b, snap_c, snap_d):
    """
    QUIT_CURSOR: changed B→C (No→Yes) AND reverted C→D (Yes→No).
    Returns list of (addr, val_no, val_yes) sorted by address.
    """
    length = min(len(snap_b), len(snap_c), len(snap_d))
    results = []
    for i in range(length):
        b, c, d = snap_b[i], snap_c[i], snap_d[i]
        if b == c:
            continue         # didn't change when cursor moved to Yes
        if d != b:
            continue         # didn't revert when cursor moved back to No
        results.append((STATIC_LO + i, b, c))
    return results


def find_open_candidates(snap_a, snap_b, snap_c, snap_d):
    """
    QUIT_OPEN: changed A→B (dialog appeared) AND held the same value
    in B, C, and D (stable while dialog is open regardless of cursor).
    Returns list of (addr, val_field, val_dialog).
    """
    length = min(len(snap_a), len(snap_b), len(snap_c), len(snap_d))
    results = []
    for i in range(length):
        a = snap_a[i]
        b = snap_b[i]
        c = snap_c[i]
        d = snap_d[i]
        if a == b:
            continue         # didn't change when dialog opened
        if b != c or b != d:
            continue         # changed while dialog was open (not a stable flag)
        results.append((STATIC_LO + i, a, b))
    return results


def print_table(rows, col_a, col_b, col_c, note_fn=None):
    print(f"  {'Address':12s}  {col_a:>10}  {col_b:>10}  {col_c}")
    print(f"  {'-'*12}  {'-'*10}  {'-'*10}  {'-'*30}")
    for row in rows[:30]:
        addr = row[0]
        v1   = row[1]
        v2   = row[2]
        note = note_fn(addr, v1, v2) if note_fn else ""
        print(f"  0x{addr:08X}  {v1:10d}  {v2:10d}  {note}")
    if len(rows) > 30:
        print(f"  … and {len(rows)-30} more (see log)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"quit_dialog_{time.strftime('%Y%m%d_%H%M%S')}.log"
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
            speak_wait("FF7 not found. Start the game and load a save file first.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak_wait("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        fid_buf  = ctypes.create_string_buffer(2)
        fid_read = ctypes.c_size_t(0)
        k32.ReadProcessMemory(handle, ctypes.c_void_p(0x00CC15D0),
                              fid_buf, 2, ctypes.byref(fid_read))
        field_id = struct.unpack_from('<h', fid_buf.raw)[0] if fid_read.value == 2 else -1
        print(f"FIELD_ID = {field_id}")
        print()

        speak_wait(
            "Quit dialog scan. "
            "Open the main menu and move the cursor to Quit. "
            "Rest on Quit but do NOT press Confirm yet. "
            "We will take 4 snapshots with voice guidance for each one."
        )

        print("=" * 60)
        print("  4-SNAPSHOT QUIT DIALOG SCAN")
        print("=" * 60)

        # ── Snap A: main menu on Quit, dialog not yet open ────────────────
        sa = snap(handle, "A", SETTLE_A,
                  "Snap A. Rest on Quit in the main menu. Do not press Confirm.")
        if sa is None:
            return

        # ── Snap B: dialog open, cursor on No ─────────────────────────────
        sb = snap(handle, "B", SETTLE_B,
                  "Snap B. Press Confirm now to open the Quit dialog. "
                  "Rest with the cursor on No. Do not move left or right.")
        if sb is None:
            return

        # ── Snap C: dialog open, cursor on Yes ────────────────────────────
        sc = snap(handle, "C", SETTLE_C,
                  "Snap C. Press Left once to move the cursor to Yes. Hold still.")
        if sc is None:
            return

        # ── Snap D: dialog open, cursor back on No ────────────────────────
        sd = snap(handle, "D", SETTLE_D,
                  "Snap D. Press Right once to move back to No. Hold still.")
        if sd is None:
            return

        # ── Analysis ──────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        cursor_cands = find_cursor_candidates(sb, sc, sd)
        open_cands   = find_open_candidates(sa, sb, sc, sd)

        # ── Cursor results ─────────────────────────────────────────────────
        print()
        print(f"  QUIT_CURSOR candidates (toggled B↔C↔D with cursor): "
              f"{len(cursor_cands)}")
        if cursor_cands:
            def cursor_note(addr, v_no, v_yes):
                notes = []
                if v_no == 1 and v_yes == 0:
                    notes.append("1=No / 0=Yes  (typical)")
                elif v_no == 0 and v_yes == 1:
                    notes.append("0=No / 1=Yes")
                else:
                    notes.append(f"{v_no}=No / {v_yes}=Yes")
                return ";  ".join(notes)
            print_table(cursor_cands, "val(No)", "val(Yes)", "Notes", cursor_note)
        else:
            print("  None found.")

        # ── Dialog-open results ────────────────────────────────────────────
        print()
        print(f"  QUIT_OPEN candidates (set A→B, stable B/C/D): "
              f"{len(open_cands)}")
        if open_cands:
            def open_note(addr, v_field, v_dialog):
                if v_field == 0:
                    return "0→nonzero  (clean flag)"
                elif v_dialog == 0:
                    return "nonzero→0  (inverted flag)"
                return ""
            print_table(open_cands, "val(field)", "val(dialog)", "Notes", open_note)
        else:
            print("  None found.")

        # ── A→B noise floor ───────────────────────────────────────────────
        ab = sum(1 for i in range(min(len(sa), len(sb))) if sa[i] != sb[i])
        print()
        print(f"  Total A→B changes (noise floor when dialog opened): {ab}")
        print(f"  Of those, stable through dialog (open flag cands):   {len(open_cands)}")
        print(f"  Cursor-toggle candidates:                             {len(cursor_cands)}")

        # ── Summary ───────────────────────────────────────────────────────
        print()
        print("=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        spoken = []
        if cursor_cands:
            addr, v_no, v_yes = cursor_cands[0]
            print(f"\n  Best QUIT_CURSOR: 0x{addr:08X}  No={v_no}  Yes={v_yes}")
            spoken.append(f"Best cursor: 0x{addr:08X}. No equals {v_no}, Yes equals {v_yes}.")
        if open_cands:
            addr, v_f, v_d = open_cands[0]
            print(f"  Best QUIT_OPEN:   0x{addr:08X}  field={v_f}  dialog={v_d}")
            spoken.append(f"Best open flag: 0x{addr:08X}. Field value {v_f}, dialog value {v_d}.")
        if not spoken:
            spoken.append("No candidates found. Check the log and re-run.")

        print(f"\nLog saved to: {log_path}")
        speak_wait(" ".join(spoken) + " Check the log.")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
