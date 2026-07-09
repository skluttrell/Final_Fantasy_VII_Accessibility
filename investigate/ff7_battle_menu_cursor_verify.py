#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_cued.py -- Self-cued (voice+beep) live verification of
battle command-cursor candidates, 2026-07-06.

WHY SELF-CUED:
  Earlier live tests required the player (who is blind) to alt-tab to read
  chat prompts telling them when to press a button, then reply in chat when
  done. That round-trip introduced timing slop and, worse, an accidental
  Right D-pad press (which doubles as Confirm in the battle menu) during one
  test likely confirmed a command mid-scan. This script instead speaks its
  own cues via SAPI and beeps, with precise internal timestamps for each cue,
  so there is no chat round-trip and no guessing about exact timing.

CANDIDATES:
  Two groups, loaded from ffnx_pointer_scan_20260706_111122.log (widened
  scan, 0x00400000-0x02000000, writable .data section of AF3DN.P only):

  1. MULTI-REF: target addresses referenced by 2+ distinct AF3DN.P code
     sites -- a real global is naturally referenced from several places in
     compiled code, whereas a coincidental immediate value showing up as a
     "pointer" by chance is very unlikely to repeat across multiple sites.
  2. PROXIMITY: a few single-reference hits near the kernel2 table
     (0x9A9484) / earlier event-pulse cluster (0x9ADE30-34) that are
     plausible but unconfirmed.

  The known-noise 0xBE0000-0xE00000 animation cluster (confirmed periodic,
  unrelated to input, 2026-07-06) is excluded.

PROCEDURE (fully automatic once started):
  1. Speaks instructions once.
  2. CUE SEQUENCE A: 6 isolated "press Down" cues, ~3s apart (beep + speech).
  3. CUE SEQUENCE B: 6 isolated "press Up" cues, ~3s apart.
  4. Analysis: for each candidate, checks how many of its value-changes fall
     within a 1.5s window after each cue. A real cursor should show exactly
     one change per cue (in both sequences) and otherwise stay silent.

SAFETY NOTE:
  This script only ever asks for Up/Down. Do not press Right (=Confirm on
  this control scheme) or Left during the test.

Run while your battle command window is open; the script runs for about
70 seconds and stops on its own (or Ctrl+C early).
"""
import ctypes, struct, subprocess, sys, os, datetime, time, winsound

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_cursor_cued_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

k32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

MULTI_REF = [
    0x00410040, 0x00610045, 0x00610064, 0x00770064, 0x006A90A1,
    0x00989680, 0x00A8008E, 0x00C80280, 0x00C06200, 0x00C06328,
    0x00CC16E8, 0x00E800C6, 0x0128BDA8, 0x01220121, 0x01330132,
    0x01CE3F06,
]
PROXIMITY = [
    0x009A8750, 0x009AB0A0, 0x009AD1AC, 0x009ADBE4, 0x009ADE28,
    0x0041BDE8,
]
CANDIDATES = MULTI_REF + PROXIMITY

N_CUES = 6
CUE_SPACING = 3.0     # seconds between cues
MATCH_WINDOW = 1.5    # seconds after a cue counted as "response"


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


def find_pid(exe_name="ff7_en.exe"):
    out = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {exe_name}',
                                    '/FO', 'CSV', '/NH'], text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == exe_name.lower():
            return int(parts[1])
    return None


def read_u8(h, va):
    buf = ctypes.create_string_buffer(1)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, 1, ctypes.byref(read))
    return buf.raw[0] if ok and read.value == 1 else None


def poll_window(h, seconds, events):
    """Poll all candidates for `seconds`, appending (t, addr, old, new) to events."""
    last = {addr: read_u8(h, addr) for addr in CANDIDATES}
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(0.05)
        now = time.time()
        for addr in CANDIDATES:
            val = read_u8(h, addr)
            if val is not None and val != last[addr]:
                events.append((now, addr, last[addr], val))
                last[addr] = val
    return last


def main():
    pid = find_pid()
    if not pid:
        print("ff7_en.exe not found -- start FF7 first")
        speak("F F 7 not found.")
        return
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    print(f"FF7 running (PID {pid})")
    print(f"Watching {len(CANDIDATES)} candidates.\n")

    speak("Battle cursor test starting. Make sure your command window is open. "
          "Do not press Right or Left, only Up and Down. "
          f"I will beep {N_CUES} times, once every 3 seconds. "
          "Press Down once, right after each beep.")
    time.sleep(2)

    events = []  # (timestamp, addr, old, new)
    cue_times_down = []
    cue_times_up = []

    print("=" * 60)
    print("  CUE SEQUENCE A: press DOWN once after each beep")
    print("=" * 60)
    for i in range(N_CUES):
        beep(1200, 120)
        t = time.time()
        cue_times_down.append(t)
        print(f"  cue {i+1}/{N_CUES} (Down) at {time.strftime('%H:%M:%S', time.localtime(t))}")
        poll_window(h, CUE_SPACING, events)

    beep(700, 300)
    speak(f"Now I will beep {N_CUES} more times. Press Up once, right after each beep.")
    time.sleep(2)

    print("=" * 60)
    print("  CUE SEQUENCE B: press UP once after each beep")
    print("=" * 60)
    for i in range(N_CUES):
        beep(1200, 120)
        t = time.time()
        cue_times_up.append(t)
        print(f"  cue {i+1}/{N_CUES} (Up) at {time.strftime('%H:%M:%S', time.localtime(t))}")
        poll_window(h, CUE_SPACING, events)

    beep(1600, 300); time.sleep(0.2); beep(1600, 300)
    speak("Test complete. You may act normally now.")

    # ── Analysis ──────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("  RAW EVENTS")
    print("=" * 60)
    for t, addr, old, new in events:
        print(f"  {time.strftime('%H:%M:%S', time.localtime(t))}  0x{addr:08X}  {old!s:>4} -> {new!s:<4}")

    print("\n" + "=" * 60)
    print("  ANALYSIS: matches per candidate")
    print("=" * 60)
    print(f"  (a 'match' = a value change within {MATCH_WINDOW}s after a cue)\n")

    all_cues = [('D', t) for t in cue_times_down] + [('U', t) for t in cue_times_up]

    per_addr_matches = {addr: [] for addr in CANDIDATES}
    for t, addr, old, new in events:
        for label, cue_t in all_cues:
            if cue_t <= t <= cue_t + MATCH_WINDOW:
                per_addr_matches[addr].append((label, old, new))

    print(f"  {'addr':12}  {'D-matches':>9}  {'U-matches':>9}  {'total events':>13}")
    print(f"  {'-'*12}  {'-'*9}  {'-'*9}  {'-'*13}")
    total_events_by_addr = {addr: sum(1 for e in events if e[1] == addr) for addr in CANDIDATES}
    ranked = []
    for addr in CANDIDATES:
        matches = per_addr_matches[addr]
        d_count = sum(1 for l, o, n in matches if l == 'D')
        u_count = sum(1 for l, o, n in matches if l == 'U')
        total = total_events_by_addr[addr]
        ranked.append((addr, d_count, u_count, total))

    ranked.sort(key=lambda r: -(min(r[1], N_CUES) + min(r[2], N_CUES)))
    for addr, d_count, u_count, total in ranked:
        print(f"  0x{addr:08X}  {d_count:9d}  {u_count:9d}  {total:13d}")

    print(f"\n  Ideal real cursor: D-matches=={N_CUES}, U-matches=={N_CUES}, "
          f"total events=={2*N_CUES} (no extra noise).")
    print(f"\nLog saved to: {_log_path}")

    k32.CloseHandle(h)


if __name__ == '__main__':
    main()
