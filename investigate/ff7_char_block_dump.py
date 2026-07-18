#!/usr/bin/env python3
"""
ff7_char_block_dump.py -- Dump party slot 0's 0xDBA498 char-data block
(first 0x100 bytes) and annotate every byte/word matching the status
screen's ground-truth values (status_screen_1.jpg + the record dump):
eff str 20, vit 16, mag 24, spr 17, dex 9, luck 17; atk 38, atk% 96,
def 24, def% 2, matk 24, mdef 17, mdef% 0; LV 7, HP 222/311, MP 54/57,
limit level 1. The stats hunt just proved +0x02..+0x07 = effective
base stats (menu-populated, materia applied); this locates the derived
combat stats in the same struct for the v2.33 status reader.
"""
import ctypes, struct, subprocess, sys, time, os

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"char_block_dump_{time.strftime('%Y%m%d_%H%M%S')}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

BASE = 0xDBA498
N    = 0x100
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
buf = ctypes.create_string_buffer(N)
got = ctypes.c_size_t(0)
if not k32.ReadProcessMemory(h, ctypes.c_void_p(BASE), buf, N,
                             ctypes.byref(got)) or got.value != N:
    print("ERROR: read failed")
    sys.exit(1)
b = bytes(buf)
k32.CloseHandle(h)

INTEREST = {20: "str", 16: "vit", 24: "mag/matk/def?", 17: "spr/luck/mdef",
            9: "dex", 38: "atk", 96: "atk%", 2: "def%", 7: "LV",
            222: "HP", 311: "maxHP", 54: "MP", 57: "maxMP", 1: "limitlvl/1"}

print(f"0xDBA498 block, first {N:#x} bytes (u8 grid):")
for row in range(0, N, 16):
    hexes = " ".join(f"{b[row+i]:02x}" for i in range(16))
    print(f"  +{row:03x}: {hexes}")

print("\nu16 interpretation with ground-truth matches:")
for off in range(0, N - 1, 2):
    v = struct.unpack_from('<H', b, off)[0]
    if v in (222, 311, 54, 57, 38, 96, 24, 2, 17, 20, 16, 9, 7, 856, 93):
        print(f"  +{off:03x}: u16 = {v}")
