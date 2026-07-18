#!/usr/bin/env python3
"""
ff7_order_entry_probe.py -- One missing piece after the main Order scan
(order_menu_scan_20260718_152825): an "Order screen is OPEN" flag.

WHY: that scan proved the Order screen is NOT a separate dispatched
sub-screen — the dispatcher index 0xDC12EC reads 0 on the plain main
menu AND inside Order (the main-menu screen handles Order inline). So
the mod cannot tell "cursor parked on the Order row" from "Order screen
entered" with what we have, and the entry announcement (instructions)
needs that transition.

METHOD: A/B/A toggle (main menu, cursor on Order -> Confirm into the
Order screen -> Cancel back out), TWO rounds intersected, then a live
speak-back pass while the player enters/leaves repeatedly. Read-only.

HOW TO RUN: main menu open, cursor on Order, NOT confirmed yet. Then
run and follow the voice prompts.
"""

import ctypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
BSS_MIN      = 0x00400000
BSS_MAX      = 0x00DE0000

PROCESS_VM_READ  = 0x0010
PROCESS_VM_QUERY = 0x0400
k32 = ctypes.windll.kernel32

# Known noise / already-identified state to auto-drop from candidates:
DROP = {
    0x00DC1210,   # dispatcher frame-parity XOR (toggles every tick)
    0x00DC1138,   # menu frame counter
    0x00DC11C4,   # ORDERMENU party cursor (found; may reset on entry)
    0x00DC1320,   # ORDERMENU selection latch (found)
}


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
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(BSS_MIN),
                               buf, size, ctypes.byref(read))
    if not ok or read.value != size:
        return None
    return bytes(buf)


def snapshot(handle, label):
    time.sleep(1.2)
    snap = read_bss(handle)
    if snap is None:
        print("  ERROR: snapshot failed")
        speak("Snapshot failed.")
        sys.exit(1)
    print(f"  [{label}] snapshot taken")
    return snap


def prompted(handle, instruction, settle=3.0):
    speak(instruction, wait=True)
    print(f"  >> {instruction}")
    time.sleep(settle)
    return snapshot(handle, instruction)


def toggle_candidates(a, b, c):
    out = set()
    for i in range(len(a)):
        if a[i] != b[i] and c[i] == a[i]:
            va = BSS_MIN + i
            if va not in DROP:
                out.add(va)
    return out


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir, f"order_entry_probe_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")
        print("FF7 ORDER-SCREEN entry flag probe (A/B/A x2 + speak-back)")

        speak("Order entry probe ready. Main menu open, cursor on Order, "
              "not confirmed. Come back to the terminal and press Enter.",
              wait=True)
        input("  Press Enter when ready ...")

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
        speak("Connected. Switch to the game. Ten seconds.", wait=True)
        time.sleep(10)

        inter = None
        for rnd in (1, 2):
            print(f"\n  -- round {rnd} --")
            a = snapshot(handle, f"r{rnd} A: main menu, on Order row")
            b = prompted(handle,
                         "Press Confirm once to enter the Order screen, "
                         "then hold still.")
            c = prompted(handle,
                         "Press Cancel once to leave the Order screen, "
                         "then hold still.")
            cands = toggle_candidates(a, b, c)
            print(f"  round {rnd}: {len(cands)} candidates")
            inter = cands if inter is None else (inter & cands)
            if rnd == 1:
                speak("Round two, same thing.", wait=True)

        cands = sorted(inter)
        print(f"\n  INTERSECTED candidates: {len(cands)}")
        for va in cands[:25]:
            print(f"    0x{va:08X}")
        if len(cands) > 25:
            print(f"    ... and {len(cands) - 25} more")

        if cands:
            top = cands[0]
            speak("Verify pass. Enter and leave the Order screen a few "
                  "times over fifteen seconds. I will call out the "
                  "tracked value on every change.", wait=True)
            last = None
            t_end = time.time() + 15
            while time.time() < t_end:
                snap = read_bss(handle)
                if snap is None:
                    break
                v = snap[top - BSS_MIN]
                if v != last:
                    print(f"  0x{top:08X} = {v}")
                    speak(str(v))
                    last = v
                time.sleep(0.1)
            print("  (verify window over)")

        print("\nNEXT: the surviving address is ORDERMENU_ACTIVE; wire it")
        print("  with the 152825 scan finds into ff7_addresses.h.")
        speak("Probe complete. Results are in the log.", wait=True)

    except KeyboardInterrupt:
        print("\n  [Stopped by user]")
        speak("Probe stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
