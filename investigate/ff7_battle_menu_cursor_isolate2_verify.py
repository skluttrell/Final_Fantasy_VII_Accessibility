#!/usr/bin/env python3
"""
ff7_battle_menu_cursor_isolate2_verify.py -- Targeted single-press check of
the 0xD8F5xx/0xD8F6xx cluster found by the v2 static+heap delta-scan
(2026-07-06), which held small distinct values (3,8,8,8,5,9) rather than
pulsing to 0 like the earlier event-flag candidates.

Self-cued: speaks each cue, no chat round-trip needed. Does 8 STRICTLY
isolated single Down presses (long gaps) so we can see whether values shift
predictably (real cursor) or jump randomly / snap back to a fixed value
(something else).

SAFETY: only Down is used. Do NOT press Right (=Confirm) or Left.
"""
import ctypes, subprocess, sys, os, datetime, time, winsound

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_isolate2_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

CANDIDATES = [0x00D8F5FE, 0x00D8F600, 0x00D8F61C, 0x00D8F628, 0x00D8F632, 0x00D8F636,
              0x009A85D5, 0x009A85D6]

N_PRESSES = 8
GAP = 3.5  # seconds between presses -- generous, strictly isolated


def speak(text):
    safe = text.replace("'", "''")
    try:
        subprocess.run(['powershell', '-WindowStyle', 'Hidden', '-Command',
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


def snapshot(h):
    return {addr: read_u8(h, addr) for addr in CANDIDATES}


def main():
    pid = find_pid()
    if not pid:
        print("ff7_en.exe not found"); speak("F F 7 not found."); return
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    print(f"FF7 running (PID {pid})\n")

    speak("Targeted cursor check. Command window open, only Down, no Right. "
          f"I will beep {N_PRESSES} times, about {GAP:.0f} seconds apart. "
          "Press Down once after each beep, then wait.")
    time.sleep(2)

    baseline = snapshot(h)
    print("Baseline:")
    for addr, val in baseline.items():
        print(f"  0x{addr:08X} = {val}")
    print()

    history = {addr: [baseline[addr]] for addr in CANDIDATES}

    for i in range(N_PRESSES):
        beep(1200, 120)
        cue_t = time.strftime('%H:%M:%S')
        time.sleep(GAP)
        snap = snapshot(h)
        print(f"After press {i+1}/{N_PRESSES} (cue at {cue_t}):")
        for addr in CANDIDATES:
            old = history[addr][-1]
            new = snap[addr]
            changed = "  <-- changed" if new != old else ""
            print(f"  0x{addr:08X}: {old} -> {new}{changed}")
            history[addr].append(new)
        print()

    beep(1600, 300); time.sleep(0.2); beep(1600, 300)
    speak("Test complete.")

    print("=" * 60)
    print("  SUMMARY: value sequence per candidate")
    print("=" * 60)
    for addr in CANDIDATES:
        seq = history[addr]
        changed_count = sum(1 for a, b in zip(seq, seq[1:]) if a != b)
        print(f"  0x{addr:08X}: {seq}  (changed {changed_count}/{N_PRESSES} times)")

    print(f"\nLog saved to: {_log_path}")
    k32.CloseHandle(h)


if __name__ == '__main__':
    main()
