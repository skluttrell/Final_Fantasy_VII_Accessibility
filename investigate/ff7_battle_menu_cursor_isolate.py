#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_isolate.py (v3) -- Targeted scan of the ALREADY-KNOWN
per-actor battle structs for the command-cursor field, 2026-07-06.

WHY V3:
  v1 (static-only delta scan) and v2 (static+heap delta scan) both scanned
  huge, unstructured memory regions and found nothing but event pulses,
  animation noise, and SFX buffer churn. A separate FFNx-internal-pointer
  heuristic also came up empty.

  This version scans a MUCH smaller, already-understood search space: the
  two per-actor structs we already have confirmed offsets in:
    G_BATTLE_MODEL_STATE       (0x00BE1178, stride 0x1AEC) -- commandID @ +0x23
    G_SMALL_BATTLE_MODEL_STATE (0x00BF23B8, stride 0x74)   -- actionIdx @ +0x3E (bogus)

  If there's a "currently highlighted command, before confirm" field, it is
  far more likely to be a sibling field inside one of these already-known
  per-actor structs than scattered somewhere else in 34MB of memory. This
  scan is tiny (~7KB total) so it can poll very fast with no numpy needed,
  and it automatically follows G_ACTIVE_ACTOR_ID so it always looks at the
  correct actor's struct.

SAFETY: only Up/Down are used. Do NOT press Right (=Confirm) or Left.

PROCEDURE (self-cued, no chat round-trip):
  1. Speaks instructions, identifies the active actor.
  2. Phase A (idle, ~8s): do not touch anything.
  3. Phase B (nav, ~20s): press Down repeatedly and steadily.
  4. Reports nav-only byte offsets within the two structs.
"""
import ctypes
import subprocess
import sys
import os
import time
import winsound
import struct

PROCESS_NAME = "ff7_en.exe"

G_ACTIVE_ACTOR_ID = 0x00BE1170
G_BATTLE_MODEL_STATE = 0x00BE1178
BATTLE_MODEL_STATE_STRIDE = 0x1AEC
G_SMALL_BATTLE_MODEL_STATE = 0x00BF23B8
BATTLE_SMALL_MODEL_STRIDE = 0x74

IDLE_DURATION = 8
NAV_DURATION = 20
SNAP_INTERVAL = 0.05   # tiny region, can poll fast

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


def speak(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW, timeout=90)
    except Exception:
        pass


def beep(freq=1000, ms=100):
    winsound.Beep(freq, ms)


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


def open_process(pid):
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_VM_QUERY, False, pid)
    return handle if handle else None


def read_region(handle, lo, size):
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(lo), buf, size, ctypes.byref(read))
    if ok and read.value == size:
        return bytearray(buf.raw)
    if read.value > 0:
        return bytearray(buf.raw[:read.value])
    return None


def read_u8(handle, addr):
    buf = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, 1, ctypes.byref(read))
    return buf.raw[0] if ok and read.value == 1 else None


def poll_phase(handle, actor_bases, duration_s, phase_label):
    """
    actor_bases: list of (actor_id, base_large, base_small) tuples --
    we watch all of them at once since we don't know in advance which
    party slot actually has its command menu open.
    """
    print(f"\n[{phase_label}] Scanning {len(actor_bases)} actor structs for {duration_s}s ...")

    prev = {}
    for actor_id, base_large, base_small in actor_bases:
        prev[actor_id] = (
            read_region(handle, base_large, BATTLE_MODEL_STATE_STRIDE),
            read_region(handle, base_small, BATTLE_SMALL_MODEL_STRIDE),
        )

    changers = {}   # (actor_id, 'large'/'small', offset) -> count
    last_val = {}
    deadline = time.time() + duration_s
    snap_num = 0

    while time.time() < deadline:
        time.sleep(SNAP_INTERVAL)

        for actor_id, base_large, base_small in actor_bases:
            prev_large, prev_small = prev[actor_id]

            curr_large = read_region(handle, base_large, BATTLE_MODEL_STATE_STRIDE)
            if curr_large is not None and prev_large is not None:
                n = min(len(curr_large), len(prev_large))
                for i in range(n):
                    if curr_large[i] != prev_large[i]:
                        key = (actor_id, 'large', i)
                        changers[key] = changers.get(key, 0) + 1
                        last_val[key] = curr_large[i]

            curr_small = read_region(handle, base_small, BATTLE_SMALL_MODEL_STRIDE)
            if curr_small is not None and prev_small is not None:
                n = min(len(curr_small), len(prev_small))
                for i in range(n):
                    if curr_small[i] != prev_small[i]:
                        key = (actor_id, 'small', i)
                        changers[key] = changers.get(key, 0) + 1
                        last_val[key] = curr_small[i]

            prev[actor_id] = (curr_large if curr_large is not None else prev_large,
                              curr_small if curr_small is not None else prev_small)

        snap_num += 1

    print(f"  Done: {snap_num} snapshots, {len(changers)} offsets changed.")
    return changers, last_val


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(script_dir, f"battle_menu_isolate3_{time.strftime('%Y%m%d_%H%M%S')}.log")
    log_file = open(log_path, 'w', encoding='utf-8')
    real_stdout = sys.stdout
    sys.stdout = Tee(real_stdout, log_file)

    handle = None
    try:
        print(f"Output saving to: {log_path}\n")

        pid = find_pid(PROCESS_NAME)
        if pid is None:
            speak("FF7 not found. Start the game and get into a battle first.")
            print("ERROR: ff7_en.exe not running.")
            return
        print(f"PID: {pid}")

        handle = open_process(pid)
        if not handle:
            speak("Cannot open FF7 process.")
            print("ERROR: OpenProcess failed.")
            return

        active_actor_id = read_u8(handle, G_ACTIVE_ACTOR_ID)
        print(f"G_ACTIVE_ACTOR_ID (last actor to ACT, may not be whose menu is "
              f"open) = {active_actor_id}")

        # Watch all three party slots at once -- we don't trust
        # G_ACTIVE_ACTOR_ID to tell us whose command menu is actually open
        # (2026-07-06 finding: it tracked an enemy while the player's menu
        # was open, i.e. it reflects last-actor-to-act, not current chooser).
        party_slots = [0, 1, 2]
        actor_bases = []
        for pid_slot in party_slots:
            base_large = G_BATTLE_MODEL_STATE + pid_slot * BATTLE_MODEL_STATE_STRIDE
            base_small = G_SMALL_BATTLE_MODEL_STATE + pid_slot * BATTLE_SMALL_MODEL_STRIDE
            actor_bases.append((pid_slot, base_large, base_small))
            print(f"  slot {pid_slot}: large=0x{base_large:08X}  small=0x{base_small:08X}")

        speak(
            "Targeted actor struct scan starting, watching all three party slots. "
            "Command window open, only Up and Down, do not press Right. "
            "Phase A begins now. Do not touch anything for about eight seconds."
        )

        print("=" * 60)
        print(f"  PHASE A: Idle Baseline ({IDLE_DURATION}s)")
        print("=" * 60)
        idle_changers, idle_last = poll_phase(handle, actor_bases, IDLE_DURATION, "Phase A: Idle")

        beep(880, 200); time.sleep(0.2); beep(880, 200)
        speak(
            "Phase B. Now press Down repeatedly and steadily, about once per second, "
            "for the next twenty seconds. I will beep when done."
        )
        print("=" * 60)
        print(f"  PHASE B: Navigation ({NAV_DURATION}s) -- press Down steadily")
        print("=" * 60)
        nav_changers, nav_last = poll_phase(handle, actor_bases, NAV_DURATION, "Phase B: Navigate")

        beep(1100, 300); time.sleep(0.3); beep(1100, 300)
        speak("Scan complete. You may act normally now.")

        # ── Analysis ─────────────────────────────────────────────────────
        print("\n" + "=" * 60)
        print("  ANALYSIS")
        print("=" * 60)

        idle_set = set(idle_changers.keys())
        nav_set = set(nav_changers.keys())
        nav_only = nav_set - idle_set

        print(f"\n  Idle-only (excluded):  {len(idle_set - nav_set)}")
        print(f"  Both phases (excluded): {len(nav_set & idle_set)}")
        print(f"  Nav-only (candidates):  {len(nav_only)}")

        print(f"\n  {'Slot':4}  {'Struct':6}  {'Offset':>7}  {'AbsAddr':10}  {'Count':>6}  {'LastVal':>7}")
        print(f"  {'-'*4}  {'-'*6}  {'-'*7}  {'-'*10}  {'-'*6}  {'-'*7}")
        base_lookup = {slot: (bl, bs) for slot, bl, bs in actor_bases}
        results = []
        for key in nav_only:
            actor_id, struct_name, off = key
            base_large, base_small = base_lookup[actor_id]
            base = base_large if struct_name == 'large' else base_small
            abs_addr = base + off
            results.append((actor_id, struct_name, off, abs_addr, nav_changers[key], nav_last.get(key, 0xFF)))
        results.sort(key=lambda t: -t[4])
        for actor_id, struct_name, off, abs_addr, cnt, val in results:
            print(f"  {actor_id:4d}  {struct_name:6}  0x{off:04X}   0x{abs_addr:08X}  {cnt:6d}  {val:7d}")

        print(f"\nLog saved to: {log_path}")

    finally:
        if handle:
            k32.CloseHandle(handle)
        sys.stdout = real_stdout
        log_file.close()
        print(f"\nLog saved to: {log_path}")


if __name__ == '__main__':
    main()
