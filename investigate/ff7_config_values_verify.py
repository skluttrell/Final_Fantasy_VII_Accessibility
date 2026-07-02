#!/usr/bin/env python3
"""
ff7_config_values_verify.py — Confirm config row value addresses live.

Monitors the DC0E candidate block found by ff7_config_values_scan.py and
speaks each address's current value whenever it changes.  Navigate through
the config sub-menu (change settings with Left/Right) and listen to confirm
which address tracks which row and what encoding is used.

CANDIDATES UNDER TEST (from config_values_20260702_152936.log):

  SLIDERS (high confidence — unique address, sensible last value):
    DC0E10  = 0x00DC0E10   Row 5  Battle speed       last=119  (0–255 slider)
    DC0E11  = 0x00DC0E11   Row 6  Battle message spd  last=153  (0–255 slider)
    DC0E24  = 0x00DC0E24   Row 7  Field message spd   last=55   (0–255 slider)

  TOGGLES (ambiguous — same address appeared for multiple rows; need verification):
    DC0E12  = 0x00DC0E12   Row 3 Cursor AND Row 4 ATB top candidate
                           Could be packed byte or display noise.
                           Row 3 last=85, Row 4 last=149.
    DC0E13  = 0x00DC0E13   Row 8 Camera AND Row 9 Magic top candidate
                           Row 8 last=1 (plausible: 0=Auto 1=Fixed).
                           Row 9 last=4 (out of expected 0–3 range — suspicious).

WHAT TO DO:
  1. Run this script.
  2. In FF7, open the Config sub-menu.
  3. Navigate to each row in turn and press Left/Right.
     Listen for which address speaks and what values it reports.

  For each toggle row, confirm:
    a. DC0E12 or DC0E13 changes and reports the correct option index
       (or a packed byte that encodes the option).
    b. If neither changes, the real address is buried below top-8 in the scan.

  For each slider row, confirm:
    a. The nominated slider address increases going Right (Slow) and
       decreases going Left (Fast).
    b. Range: probably 0–255 but confirm the actual min/max.

  For REFERENCE, also monitors:
    CONFIG_ROW = 0x00DC10F0  (already confirmed — tracks which row is selected)

Press Ctrl+C to exit.  All output is saved to a timestamped log.
"""

import ctypes
import ctypes.wintypes
import subprocess
import sys
import time
import os

PROCESS_NAME = "ff7_en.exe"
POLL_MS      = 200   # milliseconds between reads

# Candidates to monitor.  Label → (address, description)
CANDIDATES = {
    # Confirmed from earlier work — used as reference
    "CONFIG_ROW": (0x00DC10F0, "Config sub-menu row cursor (confirmed)"),

    # Slider candidates — high confidence
    "DC0E10":     (0x00DC0E10, "Row 5  Battle speed       (slider, last=119)"),
    "DC0E11":     (0x00DC0E11, "Row 6  Battle message spd  (slider, last=153)"),
    "DC0E24":     (0x00DC0E24, "Row 7  Field message spd   (slider, last=55)"),

    # Toggle candidates — ambiguous, need verification
    "DC0E12":     (0x00DC0E12, "Row 3+4  Cursor/ATB?  (packed or noise, last=85/149)"),
    "DC0E13":     (0x00DC0E13, "Row 8+9  Camera/Magic? (packed or noise, last=1/4)"),

    # Immediate neighbors — included in case the real address is ±1 off
    "DC0E0F":     (0x00DC0E0F, "DC0E10-1  (neighbor)"),
    "DC0E14":     (0x00DC0E14, "DC0E13+1  (neighbor)"),
    "DC0E15":     (0x00DC0E15, "DC0E13+2  (neighbor)"),
}

# Human-readable labels for CONFIG_ROW values
CONFIG_ROW_NAMES = {
    0: "Window color", 1: "Sound",       2: "Controller",
    3: "Cursor",       4: "ATB",         5: "Battle speed",
    6: "Battle msg",   7: "Field msg",   8: "Camera angle",
    9: "Magic order",
}

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


def read_byte(handle, addr):
    buf  = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok   = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                  buf, 1, ctypes.byref(read))
    return buf.raw[0] if (ok and read.value == 1) else None


def main():
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    log_name    = f"config_verify_{time.strftime('%Y%m%d_%H%M%S')}.log"
    log_path    = os.path.join(script_dir, log_name)
    log_file    = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout  = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}")
        print()
        print("FF7 Config Values Verify")
        print("Monitoring DC0E candidate block. Navigate config rows with Left/Right.")
        print("Press Ctrl+C to stop.")
        print()

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            print("ERROR: OpenProcess failed.")
            return

        # Print address key
        print()
        print("  ADDRESS KEY:")
        for lbl, (addr, desc) in CANDIDATES.items():
            print(f"    {lbl:>10} = 0x{addr:08X}  {desc}")
        print()

        # Print header
        labels = list(CANDIDATES.keys())
        header = "  Time(s)  " + "  ".join(f"{lbl:>10}" for lbl in labels)
        print(header)
        print("  " + "-" * (len(header) - 2))

        prev_vals  = {lbl: None for lbl in labels}
        start_time = time.time()
        line_count = 0

        speak("Config verify running. Switch to F F 7 and navigate the config menu.")

        while True:
            curr_vals = {}
            for lbl, (addr, _) in CANDIDATES.items():
                curr_vals[lbl] = read_byte(handle, addr)

            elapsed = time.time() - start_time

            # Detect and log changes
            for lbl in labels:
                old = prev_vals[lbl]
                new = curr_vals[lbl]
                if old is not None and new is not None and old != new:
                    addr, desc = CANDIDATES[lbl]
                    ts = time.strftime("%H:%M:%S")

                    # Annotate CONFIG_ROW with the row name
                    note = ""
                    if lbl == "CONFIG_ROW":
                        note = f" = {CONFIG_ROW_NAMES.get(new, '?')}"
                        speak(f"Row {new}, {CONFIG_ROW_NAMES.get(new, 'unknown')}")
                    else:
                        # For all other candidates, speak label and new value
                        speak(f"{lbl}: {new}")
                        note = f"  {old} → {new}"

                    print(f"  >>> {ts}  {lbl} (0x{addr:08X})  {old} → {new}{note}")

            # Print table row
            vals_str = "  ".join(
                f"{curr_vals[lbl]:>10d}" if curr_vals[lbl] is not None else "        ??"
                for lbl in labels
            )
            print(f"  {elapsed:7.1f}  {vals_str}")

            # Reprint header every 30 lines
            line_count += 1
            if line_count % 30 == 0:
                print()
                print(header)
                print("  " + "-" * (len(header) - 2))

            prev_vals = curr_vals
            time.sleep(POLL_MS / 1000.0)

    except KeyboardInterrupt:
        print()
        print("  [Stopped by user]")
        speak("Verify stopped.")
    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
