#!/usr/bin/env python3
"""
ff7_save_confirm_scan.py -- Find the save menu's "Are you sure you want
to save?" Yes/No dialog state: an OPEN flag and the Yes/No cursor.
(2026-07-17, save/continue menu TTS follow-up.)

WHY A FULL-BSS SCAN:
  The windowed probe run (slot_scroll_probe_20260717_200802) captured the
  player opening/toggling/closing this dialog and saw NO dedicated bytes
  move in the DC6Axx save-menu struct or the DD77xx pointer block -- the
  only movement was the slot-row byte flipping 0/1, which is ambiguous
  (it could be the dialog reusing the slot cursor, or ordinary slot
  moves). Without an open flag the mod cannot distinguish "toggling
  Yes/No" from "moving between slots 1 and 2", so this scan sweeps the
  whole FF7 BSS for:
    PASS A: dialog-open flag -- A/B/A toggle (closed -> open -> closed
            via Cancel), candidates changed then reverted.
    PASS B: Yes/No cursor -- two press-and-revert rounds (Down then Up)
            with the dialog open, intersected (the SOUND_CURSOR method).
    PASS C: live speak-back of the best cursor candidate.
  Every snapshot also logs the known save-menu bytes (slot row/scroll,
  grid col/row, list pointer) so the shared-cursor hypothesis is settled
  by the same log.

HOW TO RUN (all instructions spoken):
  Stand at a save point, open the save menu, enter a file's slot list,
  put the cursor on any slot, leave the dialog CLOSED. Run this script
  and follow the prompts. It ends by telling you to answer No, so
  nothing is written to your save file.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN = 0x00400000
BSS_MAX = 0x00DE0000

KNOWN = {
    "grid_col":  0x00DC6AE0,
    "grid_row":  0x00DC6AE4,
    "slot_row":  0x00DC6B1C,
    "slot_scr":  0x00DC6B2C,
    "list_ptr":  0x00DD7700,
}

PROCESS_VM_READ = 0x0010
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
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(BSS_MIN), buf, size,
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


def snapshot(handle, label):
    time.sleep(1.2)
    snap = read_bss(handle)
    if snap is None:
        print("  ERROR: snapshot failed")
        speak("Snapshot failed.")
        sys.exit(1)
    vals = ', '.join(f"{n}={snap[a - BSS_MIN]}" for n, a in KNOWN.items())
    print(f"  [{label}] {vals}")
    return snap


def prompted(handle, instruction):
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(2.5)
    return snapshot(handle, instruction)


def signed_diff(a, b):
    d = b - a
    if d > 127:
        d -= 256
    elif d < -128:
        d += 256
    return d


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"save_confirm_scan_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("Save-confirm dialog scan (open flag + Yes/No cursor)")

        speak("Save confirm scan ready. Be in the save menu's slot "
              "list with the cursor on a slot and the dialog closed. "
              "Then press Enter in the terminal.", wait=True)
        input("  Press Enter when ready (slot list showing, no dialog) ...")

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
        speak("Connected. Switch back to the game. Ten seconds.", wait=True)
        time.sleep(10)

        # -- PASS A: dialog open flag (A/B/A) -----------------------------
        print("\n" + "=" * 60)
        print("  PASS A -- dialog open flag (open, then Cancel closed)")
        print("=" * 60)
        s_a = snapshot(handle, "A: dialog closed")
        s_b = prompted(handle,
                       "Press Confirm once to open the are-you-sure "
                       "dialog, then hold still.")
        s_c = prompted(handle,
                       "Press Cancel once to close the dialog, then "
                       "hold still.")
        toggles = []
        for i in range(len(s_a)):
            if s_a[i] != s_b[i] and s_c[i] == s_a[i]:
                toggles.append((BSS_MIN + i, s_a[i], s_b[i]))
        print(f"\n  open-flag candidates (changed then reverted): "
              f"{len(toggles)}")
        for a, va, vb in toggles[:30]:
            print(f"    0x{a:08X}  {va} -> {vb}")
        if len(toggles) > 30:
            print(f"    ... and {len(toggles) - 30} more")

        # -- PASS B: Yes/No cursor (two press-revert rounds) --------------
        print("\n" + "=" * 60)
        print("  PASS B -- Yes/No cursor (Down then Up, twice)")
        print("=" * 60)
        speak("Press Confirm once to open the dialog again, then hold "
              "still.", wait=True)
        time.sleep(3.0)
        inter = None
        for rnd in (1, 2):
            print(f"\n  -- cursor round {rnd} --")
            base = snapshot(handle, f"cursor r{rnd} baseline (on Yes)")
            f = prompted(handle, "Press Down once, to No. Hold still.")
            b = prompted(handle, "Press Up once, back to Yes. Hold still.")
            cands = set()
            for i in range(len(base)):
                if (signed_diff(base[i], f[i]) == 1 and
                        f[i] != b[i] and b[i] == base[i]):
                    cands.add(BSS_MIN + i)
            print(f"  round {rnd}: {len(cands)} candidates")
            inter = cands if inter is None else (inter & cands)
        cursor = sorted(inter)
        print(f"\n  cursor INTERSECTED candidates: {len(cursor)}")
        for a in cursor[:20]:
            print(f"    0x{a:08X}")

        # -- PASS C: live speak-back --------------------------------------
        print("\n" + "=" * 60)
        print("  PASS C -- live verify (speaks the cursor candidate)")
        print("=" * 60)
        if cursor:
            top = cursor[0]
            speak("Verify pass. Move between Yes and No slowly for "
                  "fifteen seconds. I will call out the tracked value.",
                  wait=True)
            last = None
            t_end = time.time() + 15
            while time.time() < t_end:
                v = read_u8(handle, top)
                if v is not None and v != last:
                    print(f"  cursor 0x{top:08X} = {v}")
                    speak("no" if v else "yes")
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")
        else:
            print("  (no cursor candidates)")

        speak("Scan done. Now answer No so nothing is saved. Results "
              "are in the log.", wait=True)

        # -- summary ------------------------------------------------------
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        print(f"  open-flag candidates : {len(toggles)} "
              f"(prefer a small-value byte in the DC/DD menu blocks)")
        print(f"  cursor candidates    : {[hex(a) for a in cursor[:8]]}")
        print("  If the cursor list contains 0xDC6B1C, the dialog REUSES")
        print("  the slot-row byte and the open flag is what gates it.")

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
