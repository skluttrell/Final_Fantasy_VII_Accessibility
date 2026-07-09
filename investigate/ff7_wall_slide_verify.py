#!/usr/bin/env python3
"""
ff7_wall_slide_verify.py — Measure wall-slide displacement for the slide tone
==============================================================================

PURPOSE
-------
Live testing of the v2.6 wall-bump tone (2026-07-09) confirmed full stops
beep correctly, but ANGLED wall contact stays silent: FF7's walkmesh slides
the player along the wall, so the position keeps changing and the frozen-
position predicate never fires. The chosen fix is a SECOND tone for sliding:
"direction held AND moving much slower than free movement".

This script measures the numbers that design needs:

  1. Per-poll displacement magnitude (ground-plane x/y, 20 Hz polls) during:
       Phase A: free WALKING            (expected: full walk displacement)
       Phase B: free RUNNING            (expected: ~2x walk displacement)
       Phase C: sliding along a wall    (expected: fraction of free walking)
       Phase D: pushing straight into a wall (expected: ~0 — sanity check)

  2. The player model's movement_speed field (field_event_data +0x76, u16)
     in each phase. IF displacement scales linearly with movement_speed,
     the DLL can detect sliding as
         displacement < K * movement_speed      (single constant K)
     which works at any speed without tracking a rolling baseline. If the
     field turns out not to reflect walk-vs-run, fall back to a threshold
     relative to observed-recent-maximum displacement.

Addresses: same provenance as ff7_wall_nav_verify.py (static resolution
2026-07-09 + live confirmation). All cues are audible (SAPI + beeps); the
player never needs to read the screen after pressing Enter.

USAGE
-----
    python ff7_wall_slide_verify.py

Stand on a field with a long wall you can approach at an angle (a corridor
edge works). Press Enter, focus FF7, follow the spoken instructions.
"""

import ctypes
import datetime
import math
import os
import struct
import subprocess
import sys
import time
import winsound

FIELD_EVENT_DATA_PTR   = 0x00CC0B60
FIELD_PLAYER_MODEL_ID  = 0x00CC162C
FIELD_N_MODELS         = 0x00CFF73E
KEY_INPUT_STATUS       = 0x00CC0DF0
FIELD_ID               = 0x00CC15D0

EVENT_DATA_STRIDE      = 0x88
OFF_MODEL_POS          = 0x0C
OFF_MOVEMENT_SPEED     = 0x76   # WORD movement_speed (FFNx ff7.h)

DIR_ANY  = 0xF000
POLL_HZ  = 20


class Tee:
    def __init__(self, terminal, log_file):
        self._terminal = terminal
        self._log      = log_file
    def write(self, data):
        self._terminal.write(data)
        self._log.write(data)
        self._log.flush()
    def flush(self):
        self._terminal.flush()
        self._log.flush()
    def __getattr__(self, name):
        return getattr(self._terminal, name)


def speak_wait(text):
    print(f"[SPEAK] {text}")
    safe = text.replace("'", "''")
    subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         f"Add-Type -AssemblyName System.Speech; "
         f"(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{safe}')"],
        check=False)


def countdown_go():
    for _ in range(3):
        winsound.Beep(800, 200)
        time.sleep(0.8)
    winsound.Beep(1400, 400)


def phase_end_beep():
    winsound.Beep(600, 300)


k32 = ctypes.windll.kernel32
PROCESS_VM_READ           = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400


def open_ff7():
    out = subprocess.check_output(
        ['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe', '/FO', 'CSV', '/NH'],
        text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == 'ff7_en.exe':
            pid = int(parts[1])
            h = k32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not h:
                raise RuntimeError(f"OpenProcess failed (PID {pid})")
            print(f"FF7 running (PID {pid})")
            return h
    raise RuntimeError("ff7_en.exe not found — start FF7 first")


def read_mem(h, va, size):
    buf  = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size,
                               ctypes.byref(read))
    if not ok or read.value < size:
        return None
    return buf.raw


def read_u16(h, va):
    b = read_mem(h, va, 2)
    return struct.unpack_from('<H', b)[0] if b else None


def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None


def sample(h):
    arr  = read_u32(h, FIELD_EVENT_DATA_PTR)
    pmid = read_u16(h, FIELD_PLAYER_MODEL_ID)
    keys = read_u32(h, KEY_INPUT_STATUS)
    if arr is None or pmid is None or keys is None or arr < 0x10000 or pmid > 0x20:
        return None
    elem = arr + pmid * EVENT_DATA_STRIDE
    blob = read_mem(h, elem + OFF_MODEL_POS, 12)
    spd  = read_u16(h, elem + OFF_MOVEMENT_SPEED)
    if blob is None or spd is None:
        return None
    x, y, z = struct.unpack('<iii', blob)
    return {'x': x, 'y': y, 'keys': keys, 'speed': spd}


def run_phase(h, seconds):
    samples = []
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        t0 = time.perf_counter()
        s = sample(h)
        if s is not None:
            samples.append(s)
        time.sleep(max(0.0, (1.0 / POLL_HZ) - (time.perf_counter() - t0)))
    return samples


def analyze(name, samples):
    """Per-poll ground-plane displacement stats over dir-held samples."""
    print(f"\n--- Phase {name}: {len(samples)} samples ---")
    disps = []
    speeds = {}
    prev = None
    for s in samples:
        if prev is not None and (s['keys'] & DIR_ANY):
            d = math.hypot(s['x'] - prev['x'], s['y'] - prev['y'])
            disps.append(d)
            speeds[s['speed']] = speeds.get(s['speed'], 0) + 1
        prev = s
    if not disps:
        print("  no direction-held samples!")
        return None
    disps.sort()
    n = len(disps)
    med = disps[n // 2]
    p10, p90 = disps[n // 10], disps[(9 * n) // 10]
    print(f"  dir-held samples   : {n}")
    print(f"  displacement/poll  : median={med:.0f}  p10={p10:.0f}  p90={p90:.0f}")
    print(f"  movement_speed dist: {sorted(speeds.items())}")
    med_speed = max(speeds.items(), key=lambda kv: kv[1])[0] if speeds else 0
    if med_speed:
        print(f"  disp/speed ratio   : median={med / med_speed:.3f}")
    return {'median': med, 'speed': med_speed}


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"wall_slide_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    real_stdout = sys.stdout
    log_file = open(log_path, 'w', encoding='utf-8')
    sys.stdout = Tee(real_stdout, log_file)
    try:
        print(f"Log: {log_path}")
        print("=" * 70)
        print("FF7 wall-slide displacement measurement")
        print("=" * 70)
        h = open_ff7()

        s = sample(h)
        if s is None:
            speak_wait("Pre-flight memory read failed. Cannot continue.")
            return 1
        print(f"Pre-flight sample OK: {s}")

        input("Press Enter, then switch focus to FF7. Stand near a long "
              "wall you can slide along...")
        time.sleep(3.0)

        speak_wait("Phase A. After the high beep, WALK around freely in open "
                   "space for eight seconds. Do not hold the run button.")
        countdown_go()
        a = run_phase(h, 8.0)
        phase_end_beep()

        speak_wait("Phase B. After the high beep, RUN around freely in open "
                   "space for eight seconds, holding the run button.")
        countdown_go()
        b = run_phase(h, 8.0)
        phase_end_beep()

        speak_wait("Phase C. After the high beep, walk into the wall at an "
                   "angle and keep sliding along it for eight seconds. Keep "
                   "the direction held even as you scrape along the wall.")
        countdown_go()
        c = run_phase(h, 8.0)
        phase_end_beep()

        speak_wait("Phase D. After the high beep, push straight into the "
                   "wall and hold for five seconds.")
        countdown_go()
        d = run_phase(h, 5.0)
        phase_end_beep()

        ra = analyze('A (walking free)', a)
        rb = analyze('B (running free)', b)
        rc = analyze('C (sliding along wall)', c)
        rd = analyze('D (dead stop)', d)

        print("\n" + "=" * 70)
        verdict = "Measurement complete. Check the log for numbers."
        if ra and rc and ra['median'] > 0:
            frac = rc['median'] / ra['median']
            print(f"slide displacement = {frac:.2f} x free-walk displacement")
            verdict = (f"Done. Sliding moved at {frac:.0%} of free walking "
                       f"speed. Full analysis is in the log.")
        print(f"Log saved to: {log_path}")
        speak_wait(verdict)
        return 0
    finally:
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    sys.exit(main())
