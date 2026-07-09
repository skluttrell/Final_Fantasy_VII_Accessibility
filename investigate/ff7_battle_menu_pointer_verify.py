#!/usr/bin/env python3
"""
ff7_battle_menu_pointer_verify.py -- Live-monitor every battle-state-region
candidate found by ff7_ffnx_pointer_scan.py (2026-07-06), watching for one
that changes in lockstep with Up/Down presses in the battle command menu
and holds a small, PERSISTENT value (unlike the fleeting cand_B/C/D/F event
pulses found earlier, or the free-running cand_E animation counter).

Candidates below are every 0x00BE0000-0x00C10000-range pointer target from
ffnx_pointer_scan_20260706_110226.log, excluding ones already identified as
something else (G_ACTIVE_ACTOR_ID, G_BATTLE_MODEL_STATE,
G_SMALL_BATTLE_MODEL_STATE).

Run while in battle with your command window open; press Ctrl+C to stop.
"""
import ctypes, struct, subprocess, sys, os, datetime, time

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"battle_menu_pointer_verify_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

# Known/already-identified -- excluded.
KNOWN = {0x00BE1170, 0x00BE1178, 0x00BF23B8}

CANDIDATES = [
    0x00BE00A6, 0x00BE10B4, 0x00BE10B8, 0x00BE10C0, 0x00BE10E8, 0x00BE10F0,
    0x00BE1130, 0x00BF1EB8, 0x00BF2032, 0x00BF211C, 0x00BF2158, 0x00BF2378,
    0x00BF23C0, 0x00BF2858, 0x00BF2A30, 0x00BF2A38, 0x00BF2DF4, 0x00BF2DF8,
    0x00BF2E08, 0x00BF2E1C, 0x00BF2E70, 0x00BFB1A0, 0x00BFB1B0, 0x00BFB2DC,
    0x00BFB2E0, 0x00BFB718, 0x00BFC3A0, 0x00BFCB28, 0x00BFCDE0, 0x00BFCE08,
    0x00BFD098, 0x00BFD0E8, 0x00BFD0F0, 0x00BFD0F4, 0x00C05EBC, 0x00C05EC0,
    0x00C05F78, 0x00C05FE8, 0x00C06200, 0x00C06328, 0x00C06A00,
]
CANDIDATES = [c for c in CANDIDATES if c not in KNOWN]


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


pid = find_pid()
if not pid:
    print("ff7_en.exe not found -- start FF7 first")
    sys.exit(1)
h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
print(f"FF7 running (PID {pid})")
print(f"Watching {len(CANDIDATES)} candidates. Polling every 100ms. Ctrl+C to stop.\n")
print(f"{'time':>8}  {'addr':10}  {'old':>4} -> {'new':<4}")

last = {addr: read_u8(h, addr) for addr in CANDIDATES}
try:
    while True:
        time.sleep(0.1)
        for addr in CANDIDATES:
            val = read_u8(h, addr)
            if val is not None and val != last[addr]:
                ts = time.strftime('%H:%M:%S')
                print(f"{ts:>8}  0x{addr:08X}  {last[addr]!s:>4} -> {val!s:<4}")
                last[addr] = val
except KeyboardInterrupt:
    pass

print(f"\nLog saved to: {_log_path}")
_log_file.close()
