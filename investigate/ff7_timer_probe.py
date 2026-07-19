#!/usr/bin/env python3
"""
ff7_timer_probe.py -- Live-verify the countdown timer address during an
actual timed escape (2026-07-19; Shift+T freeze reported not working on
the timer's first live run).

Two checks, read-only, run WHILE the escape clock is counting down:
  1. Sample the static-derived COUNTDOWN_TIMER_SECONDS (0xDC08BC) and the
     ms accumulator (0xDC08C0) several times over ~5s and print the trail
     — proves whether that address is the live ticking timer.
  2. If it is NOT obviously counting, scan a wide region for any u32 that
     decreases by ~1 per second (a countdown's signature) and report the
     candidates — finds the REAL timer address if the static one is wrong.

Speaks a spoken summary at the end (System.Speech) so you don't have to
read the terminal.
"""
import ctypes, struct, subprocess, sys, time, os

TIMER_SECS = 0x00DC08BC
TIMER_MS   = 0x00DC08C0
# Wide scan window: savemap + menu region (where savemap-persisted state
# lives) plus a margin. Countdown is savemap+0xB84, so this brackets it.
SCAN_LO, SCAN_HI = 0x00DBF000, 0x00DC3000

k32 = ctypes.windll.kernel32

def speak(text):
    safe = text.replace("'", "''")
    try:
        subprocess.Popen(
            ['powershell', '-WindowStyle', 'Hidden', '-Command',
             f"(New-Object -ComObject SAPI.SpVoice).Speak('{safe}')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass

def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                          '/FO', 'CSV'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if 'ff7_en.exe' in line.lower():
            try:
                return int(line.strip('"').split('","')[1])
            except (IndexError, ValueError):
                pass
    return None

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"timer_probe_{time.strftime('%Y%m%d_%H%M%S')}.log")
_log = open(_log_path, 'w', encoding='utf-8')
def out(s):
    print(s)
    _log.write(s + "\n"); _log.flush()

out(f"Output saving to: {_log_path}\n")
pid = find_pid()
if pid is None:
    out("ERROR: ff7_en.exe not running")
    speak("F F 7 is not running.")
    sys.exit(1)
h = k32.OpenProcess(0x0410, False, pid)

def read(addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                             ctypes.byref(got)) and got.value == n:
        return bytes(buf)
    return None

def u32(addr):
    b = read(addr, 4)
    return struct.unpack('<I', b)[0] if b else None

# ── Check 1: the static-derived address ────────────────────────────────
out("Sampling 0xDC08BC (timer seconds) and 0xDC08C0 (ms) over 5 seconds:")
speak("Sampling the timer address for five seconds. Let the clock run.")
trail = []
for i in range(6):
    s, m = u32(TIMER_SECS), u32(TIMER_MS)
    trail.append(s)
    out(f"  t={i}s  seconds=0x{TIMER_SECS:X} -> {s}    ms=0x{TIMER_MS:X} -> {m}")
    time.sleep(1.0)

ticking = (trail[0] is not None and trail[-1] is not None and
           trail[-1] < trail[0] and (trail[0] - trail[-1]) <= 8)
if ticking:
    out(f"\n==> 0xDC08BC IS the live timer (went {trail[0]} -> {trail[-1]}).")
    out("    The address is correct; the freeze/key handling is the issue.")
    speak(f"The timer address is correct. It went from {trail[0]} to "
          f"{trail[-1]} seconds. The problem is in the freeze or key "
          f"handling, not the address.")
else:
    out(f"\n==> 0xDC08BC did NOT count down cleanly ({trail}).")
    out("    Scanning for the real countdown (a u32 dropping ~1/sec)...")
    speak("The expected address is not counting. Scanning for the real "
          "timer. This takes about six seconds.")

    size = SCAN_HI - SCAN_LO
    a = read(SCAN_LO, size)
    time.sleep(5.0)
    b = read(SCAN_LO, size)
    if a is None or b is None:
        out("    scan read failed")
        speak("Scan failed.")
    else:
        cands = []
        for off in range(0, size - 3, 4):
            va = SCAN_LO + off
            xa = struct.unpack_from('<I', a, off)[0]
            xb = struct.unpack_from('<I', b, off)[0]
            # a countdown: dropped by 3..7 over 5s, plausible remaining range
            if 0 < xa <= 24 * 3600 and xb < xa and 3 <= (xa - xb) <= 7:
                cands.append((va, xa, xb))
        out(f"    {len(cands)} countdown-like u32 candidates:")
        for va, xa, xb in cands[:20]:
            out(f"      0x{va:08X}: {xa} -> {xb}  (savemap+0x{va-0xDBFD38:X})")
        if cands:
            speak(f"Found {len(cands)} candidate. "
                  f"The first is at offset {cands[0][0]-0xDBFD38} in the "
                  f"savemap. Results are in the log.")
        else:
            speak("No countdown-like value found in the scanned region. "
                  "The timer may be paused or already finished.")

k32.CloseHandle(h)
out(f"\nLog: {_log_path}")
