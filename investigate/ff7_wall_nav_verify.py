#!/usr/bin/env python3
"""
ff7_wall_nav_verify.py — Live verification of the wall-bump detection signal
=============================================================================

PURPOSE
-------
Verify, in a running game, the three ingredients of the planned wall-bump
navigation tone before any C++ is written:

    1. FIELD_PLAYER_MODEL_ID (0x00CC162C, u16) really indexes the player's
       element in the field_event_data array (pointer at 0x00CC0B60,
       stride 0x88) — i.e. model_pos at element+0x0C changes when the
       player walks and only then.

    2. current_key_input_status (0x00CC0DF0, u32) really carries the
       directional input bits while walking:
           UP = 0x1000, RIGHT = 0x2000, DOWN = 0x4000, LEFT = 0x8000
       (FFNx ff7::world::input_key enum — same digested-input global is
       consumed by the field module, so the format should be identical.)

    3. The wall predicate — "a direction bit is held AND model_pos has not
       changed for N consecutive polls" — actually discriminates the three
       situations a player can be in:
           walking freely      → direction held, position changing
           pushing into a wall → direction held, position frozen
           standing still      → no direction,   position frozen

All three addresses were resolved statically from the exe on disk by
ff7_wall_nav_static.py (2026-07-09) via FFNx's own discovery chains, with
two independent FFNx-source-comment cross-checks passing exactly.

METHOD (fully self-cued — the player never needs to read the screen)
--------------------------------------------------------------------
Three timed phases, each announced via SAPI speech and started with the
standard beep countdown (three 800 Hz warning tones, one second apart,
then a single high 1400 Hz "go" tone):

    Phase A (8s): walk around FREELY — keep moving the whole time.
    Phase B (8s): walk INTO A WALL and keep pushing against it.
    Phase C (6s): stand STILL — touch nothing.

While each phase runs, the script polls at 20 Hz:
    - field_event_data_ptr (re-read every poll — the array is reallocated
      on every field load, so caching the pointer across polls is unsafe)
    - player model element: model_pos x/y/z (int32 ×3 at +0x0C),
      triangle_id (u16 at +0x78), movement_type (u8 at +0x63)
    - current_key_input_status (u32)

Afterwards it reports, per phase:
    - % of samples with any direction bit held
    - % of samples where position changed vs the previous sample
    - % of samples where the wall predicate fired
      (direction held AND position unchanged for >= 3 consecutive samples)
    - movement_type value distribution (a possible cleaner future signal)

EXPECTED RESULT if everything is correct:
    Phase A: direction ~100%, movement ~100%, predicate ~0%
    Phase B: direction ~100%, movement ~0%,   predicate ~90%+
    Phase C: direction ~0%,   movement ~0%,   predicate 0%

USAGE
-----
    python ff7_wall_nav_verify.py

Start FF7 first and stand on a field map near a wall (any room works —
e.g. a corner of the starting reactor bridge). Press Enter, switch focus
to FF7, and follow the spoken instructions.
"""

import ctypes
import datetime
import os
import struct
import subprocess
import sys
import time
import winsound

# ---------------------------------------------------------------------------
# Addresses (2013 Steam / 1.02 US exe; confirmed identical in 2026 rerelease).
# Resolution provenance: ff7_wall_nav_static.py 2026-07-09, chains lifted
# from FFNx/src/ff7_data.h with ff7.h-comment cross-checks.
# ---------------------------------------------------------------------------
FIELD_EVENT_DATA_PTR   = 0x00CC0B60  # field_event_data** (array realloc'd per field)
FIELD_PLAYER_MODEL_ID  = 0x00CC162C  # u16 index of player model in that array
FIELD_N_MODELS         = 0x00CFF73E  # u16 model count on current field
KEY_INPUT_STATUS       = 0x00CC0DF0  # u32 digested input (modules_global_object+0x68)
FIELD_ID               = 0x00CC15D0  # s16, non-zero on named field maps (known-good)

EVENT_DATA_STRIDE      = 0x88        # sizeof(field_event_data), from FFNx ff7.h
OFF_MODEL_POS          = 0x0C        # vector3<int> model_pos
OFF_MOVEMENT_TYPE      = 0x63        # char movement_type (1 = walk/run per FFNx)
OFF_TRIANGLE_ID        = 0x78        # short field_triangle_id

DIR_UP    = 0x1000
DIR_RIGHT = 0x2000
DIR_DOWN  = 0x4000
DIR_LEFT  = 0x8000
DIR_ANY   = DIR_UP | DIR_RIGHT | DIR_DOWN | DIR_LEFT

POLL_HZ        = 20
CONSEC_BLOCKED = 3    # samples in a row (150ms) before the predicate fires


# ---------------------------------------------------------------------------
# Tee logging (project rule: every investigation script logs automatically).
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Audible cues (project rule: the player cannot read the terminal while the
# game has focus — every instruction must be spoken, every timing cue beeped).
# ---------------------------------------------------------------------------
def speak_wait(text):
    """SAPI speech, BLOCKING until finished (subprocess exit = speech done).
    Used for instructions/results. Never used for precise timing — SAPI
    startup latency varies; beeps handle timing."""
    print(f"[SPEAK] {text}")
    safe = text.replace("'", "''")
    subprocess.run(
        ['powershell', '-NoProfile', '-Command',
         f"Add-Type -AssemblyName System.Speech; "
         f"(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak('{safe}')"],
        check=False)


def countdown_go():
    """Standard cue: three synchronous 800 Hz warning tones one second
    apart, then one 1400 Hz 'go' tone. winsound.Beep blocks for the tone
    duration, making the moment after the high beep deterministic."""
    for _ in range(3):
        winsound.Beep(800, 200)
        time.sleep(0.8)
    winsound.Beep(1400, 400)


def phase_end_beep():
    winsound.Beep(600, 300)


# ---------------------------------------------------------------------------
# Process attach + memory reads.
# ---------------------------------------------------------------------------
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


def read_i16(h, va):
    b = read_mem(h, va, 2)
    return struct.unpack_from('<h', b)[0] if b else None


def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None


def sample_player(h):
    """One poll: returns dict or None if any read failed (e.g. mid field
    transition while the event array is being reallocated)."""
    arr = read_u32(h, FIELD_EVENT_DATA_PTR)
    pmid = read_u16(h, FIELD_PLAYER_MODEL_ID)
    nmod = read_u16(h, FIELD_N_MODELS)
    keys = read_u32(h, KEY_INPUT_STATUS)
    if arr is None or pmid is None or nmod is None or keys is None:
        return None
    if arr < 0x10000 or pmid >= max(nmod, 1) or pmid > 0x20:
        return None  # array not allocated / model id implausible
    elem = arr + pmid * EVENT_DATA_STRIDE
    blob = read_mem(h, elem + OFF_MODEL_POS, 12)
    mtyp = read_mem(h, elem + OFF_MOVEMENT_TYPE, 1)
    tri  = read_i16(h, elem + OFF_TRIANGLE_ID)
    if blob is None or mtyp is None or tri is None:
        return None
    x, y, z = struct.unpack('<iii', blob)
    return {
        'keys': keys, 'x': x, 'y': y, 'z': z,
        'tri': tri, 'mtype': mtyp[0], 'pmid': pmid, 'arr': arr,
    }


def run_phase(h, name, seconds):
    """Poll for `seconds` at POLL_HZ; returns the list of samples."""
    samples = []
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        t0 = time.perf_counter()
        s = sample_player(h)
        if s is not None:
            s['t'] = t0
            samples.append(s)
        time.sleep(max(0.0, (1.0 / POLL_HZ) - (time.perf_counter() - t0)))
    return samples


def analyze_phase(name, samples):
    """Compute and print the per-phase stats; returns predicate-fire %."""
    print(f"\n--- Phase {name}: {len(samples)} samples ---")
    if len(samples) < 2:
        print("  TOO FEW SAMPLES — reads failing?")
        return None

    n_dir = 0          # samples with any direction bit
    n_moved = 0        # samples whose position differs from previous
    n_pred = 0         # samples where the wall predicate fired
    blocked_run = 0    # consecutive (dir held AND not moved) samples
    mtype_counts = {}
    keys_seen = {}     # distinct raw key values → count; if the assumed
                       # direction-bit layout is wrong, this is enough to
                       # recover the real layout from one run of the script
    prev = samples[0]
    first, last = samples[0], samples[-1]

    for s in samples[1:]:
        dir_held = bool(s['keys'] & DIR_ANY)
        moved = (s['x'], s['y'], s['z']) != (prev['x'], prev['y'], prev['z'])
        if dir_held:
            n_dir += 1
        if moved:
            n_moved += 1
        if dir_held and not moved:
            blocked_run += 1
        else:
            blocked_run = 0
        if blocked_run >= CONSEC_BLOCKED:
            n_pred += 1
        mtype_counts[s['mtype']] = mtype_counts.get(s['mtype'], 0) + 1
        keys_seen[s['keys']] = keys_seen.get(s['keys'], 0) + 1
        prev = s

    n = len(samples) - 1
    pct_dir   = 100.0 * n_dir / n
    pct_moved = 100.0 * n_moved / n
    pct_pred  = 100.0 * n_pred / n
    print(f"  direction bit held : {pct_dir:5.1f}%")
    print(f"  position changed   : {pct_moved:5.1f}%")
    print(f"  wall predicate     : {pct_pred:5.1f}%")
    print(f"  movement_type dist : {sorted(mtype_counts.items())}")
    print(f"  pos first→last     : ({first['x']},{first['y']},{first['z']}) → "
          f"({last['x']},{last['y']},{last['z']})  tri {first['tri']}→{last['tri']}")
    top_keys = sorted(keys_seen.items(), key=lambda kv: -kv[1])[:8]
    print(f"  distinct raw keys  : "
          + ", ".join(f"{k:#010x}×{c}" for k, c in top_keys))
    print(f"  player model id    : {first['pmid']}   event array @ {first['arr']:#010x}")
    return pct_pred


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(
        script_dir,
        f"wall_nav_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    real_stdout = sys.stdout
    log_file = open(log_path, 'w', encoding='utf-8')
    sys.stdout = Tee(real_stdout, log_file)
    try:
        print(f"Log: {log_path}")
        print("=" * 70)
        print("FF7 wall-bump signal live verification")
        print("=" * 70)

        h = open_ff7()

        fid = read_i16(h, FIELD_ID)
        print(f"FIELD_ID = {fid}")
        if not fid:
            speak_wait("You are not on a field map. Load a field, then run "
                       "this script again.")
            return 1

        # Pre-flight: one sample must succeed before wasting the user's time.
        s = sample_player(h)
        if s is None:
            speak_wait("Pre-flight memory read failed. Cannot continue. "
                       "Check the log.")
            print("PRE-FLIGHT FAILED: sample_player returned None.")
            # Print each raw read separately — any of them may be None and
            # knowing WHICH one failed identifies the broken address.
            print(f"  raw: arr={read_u32(h, FIELD_EVENT_DATA_PTR)} "
                  f"pmid={read_u16(h, FIELD_PLAYER_MODEL_ID)} "
                  f"nmod={read_u16(h, FIELD_N_MODELS)} "
                  f"keys={read_u32(h, KEY_INPUT_STATUS)}")
            return 1
        print(f"Pre-flight sample OK: {s}")

        input("Press Enter, then switch focus to FF7. Stand somewhere with "
              "a reachable wall...")
        time.sleep(3.0)

        speak_wait("Phase A. After the high beep, walk around freely for "
                   "eight seconds. Keep moving the whole time.")
        countdown_go()
        samples_a = run_phase(h, 'A', 8.0)
        phase_end_beep()

        speak_wait("Phase B. After the high beep, walk into a wall and keep "
                   "pushing against it for eight seconds. Do not let go.")
        countdown_go()
        samples_b = run_phase(h, 'B', 8.0)
        phase_end_beep()

        speak_wait("Phase C. After the high beep, stand completely still "
                   "for six seconds. Touch nothing.")
        countdown_go()
        samples_c = run_phase(h, 'C', 6.0)
        phase_end_beep()

        pred_a = analyze_phase('A (walking freely)', samples_a)
        pred_b = analyze_phase('B (pushing wall)',   samples_b)
        pred_c = analyze_phase('C (standing still)', samples_c)

        print("\n" + "=" * 70)
        ok = (pred_a is not None and pred_b is not None and pred_c is not None
              and pred_a < 10.0 and pred_b > 50.0 and pred_c < 5.0)
        if ok:
            verdict = ("Verification passed. Wall detection signal is clean. "
                       f"Predicate fired {pred_b:.0f} percent while pushing "
                       f"the wall, {pred_a:.0f} percent while walking, and "
                       f"{pred_c:.0f} percent while idle.")
        else:
            verdict = ("Verification FAILED or ambiguous. Check the log for "
                       "per-phase numbers before writing any C plus plus.")
        print(f"RESULT: {'OK' if ok else 'FAILED'}")
        print(f"Log saved to: {log_path}")
        speak_wait(verdict)
        return 0 if ok else 1
    finally:
        sys.stdout = real_stdout
        log_file.close()


if __name__ == '__main__':
    sys.exit(main())
