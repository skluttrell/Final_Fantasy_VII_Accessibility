#!/usr/bin/env python3
"""
ff7_status_stats_hunt.py -- Hunt the menu's COMPUTED character stats
(2026-07-18, for the v2.33 status reader).

WHY: the savemap char record holds BASE stats (live-proven minutes ago:
record str=22/mag=20 vs screen 20/24 — materia modifiers applied at
display time; status_record_verify log). Screen parity needs the
menu's computed numbers, which must exist in memory while the status
screen draws them.

METHOD: pattern-scan BSS for the screenshot's exact value runs (Cloud,
status_screen_1.jpg):
  effective base stats  20,16,24,17,9,17   (str,vit,mag,spr,dex,luck -
                        internal savemap order) and the display order
                        20,9,16,24,17,17   (str,dex,vit,mag,spr,luck)
  derived combat block  38,96,24,2,24,17,0 (atk,atk%,def,def%,
                        matk,mdef,mdef%)
as u8 runs AND little-endian u16 runs. Read-only; ideally run while
the status screen is (or was recently) open so the block is populated.
"""
import ctypes, struct, subprocess, sys, time, os

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"status_stats_hunt_{time.strftime('%Y%m%d_%H%M%S')}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

BSS_MIN, BSS_MAX = 0x00400000, 0x00DE0000
k32 = ctypes.windll.kernel32

def find_pid():
    out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                          '/FO', 'CSV'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if 'ff7_en.exe' in line.lower():
            parts = line.strip('"').split('","')
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                pass
    return None

pid = find_pid()
if pid is None:
    print("ERROR: ff7_en.exe not running")
    sys.exit(1)
print(f"PID: {pid}")
h = k32.OpenProcess(0x0410, False, pid)
size = BSS_MAX - BSS_MIN
buf = ctypes.create_string_buffer(size)
got = ctypes.c_size_t(0)
if not k32.ReadProcessMemory(h, ctypes.c_void_p(BSS_MIN), buf, size,
                             ctypes.byref(got)) or got.value != size:
    print("ERROR: BSS read failed")
    sys.exit(1)
mem = bytes(buf)
k32.CloseHandle(h)

PATTERNS = {
    "base internal order u8":  bytes([20, 16, 24, 17, 9, 17]),
    "base display order u8":   bytes([20, 9, 16, 24, 17, 17]),
    "derived u8":              bytes([38, 96, 24, 2, 24, 17, 0]),
    "base internal order u16": struct.pack('<6H', 20, 16, 24, 17, 9, 17),
    "base display order u16":  struct.pack('<6H', 20, 9, 16, 24, 17, 17),
    "derived u16":             struct.pack('<7H', 38, 96, 24, 2, 24, 17, 0),
}

for label, pat in PATTERNS.items():
    hits = []
    start = 0
    while len(hits) < 40:
        idx = mem.find(pat, start)
        if idx < 0:
            break
        hits.append(BSS_MIN + idx)
        start = idx + 1
    print(f"{label:26}: {len(hits):2} hits " +
          " ".join(f"0x{a:08X}" for a in hits[:12]))

print("\nContext dump around each derived/base-display hit (the status")
print("screen block should show base AND derived near each other):")
seen = set()
for label in ("derived u16", "derived u8",
              "base display order u16", "base display order u8"):
    pat = PATTERNS[label]
    start = 0
    while True:
        idx = mem.find(pat, start)
        if idx < 0:
            break
        start = idx + 1
        va = BSS_MIN + idx
        key = va & ~0x3F
        if key in seen:
            continue
        seen.add(key)
        ctx_start = max(0, idx - 0x20)
        ctx = mem[ctx_start:idx + 0x40]
        hexes = " ".join(f"{b:02x}" for b in ctx)
        print(f"\n  {label} @ 0x{va:08X} (ctx from 0x{BSS_MIN+ctx_start:08X}):")
        print(f"    {hexes}")
