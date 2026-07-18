#!/usr/bin/env python3
"""
ff7_status_record_verify.py -- Read-only live dump of party slot 0's
savemap char record, interpreted against the STATUS screen ground truth
(Screenshots/Menus/status_screen_1.jpg, captured 2026-07-18 16:00:
Cloud LV7, HP 222/311, MP 54/57, EXP 856p, next level 93p, Limit lvl 1,
Str 20 Dex 9 Vit 16 Mag 24 Spr 17 Luck 17, Wpn Buster Sword,
Arm Bronze Bangle, Acc empty).

WHY: the v2.33 status reader needs the base-stat offsets +0x02..+0x07
and equipment ids +0x1C/+0x1D/+0x1E. Only dex (+0x06) is FFNx-named;
the rest are community savemap doc — the SAME source whose +0x1F row
byte was just proven one byte off (v2.32). Every offset gets checked
against the screenshot before anything ships. No user interaction; the
player can be anywhere in-game.
"""
import ctypes, struct, subprocess, sys, time, os

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"status_record_verify_{time.strftime('%Y%m%d_%H%M%S')}.log")
_log = open(_log_path, 'w', encoding='utf-8')
_orig = sys.stdout.write
def _tee(s):
    _orig(s)
    _log.write(s)
    _log.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

CHAR_RECORDS = 0xDBFD8C
REC_SIZE     = 0x84
PARTY_IDS    = 0xDC0230

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

def read(addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n,
                                 ctypes.byref(got)) or got.value != n:
        print(f"ERROR: read failed @{addr:#x}")
        sys.exit(1)
    return bytes(buf)

party = read(PARTY_IDS, 3)
print(f"party ids: {[hex(b) for b in party]}")
char_id = party[0]
rec = char_id
if char_id == 9:  rec = 6
if char_id == 10: rec = 7
base = CHAR_RECORDS + rec * REC_SIZE
b = read(base, REC_SIZE)

def u16(o): return struct.unpack_from('<H', b, o)[0]
def u32(o): return struct.unpack_from('<I', b, o)[0]

name = ''.join(chr(c + 0x20) for c in b[0x10:0x1C] if c != 0xFF).rstrip()
print(f"\nrecord {rec} (char id {char_id}) @ {base:#x}")
print(f"  +0x00 id        = {b[0]}      (expect {char_id})")
print(f"  +0x01 level     = {b[1]}      (screenshot: 7)")
print(f"  +0x02 strength? = {b[2]}      (screenshot: 20)")
print(f"  +0x03 vitality? = {b[3]}      (screenshot: 16)")
print(f"  +0x04 magic?    = {b[4]}      (screenshot: 24)")
print(f"  +0x05 spirit?   = {b[5]}      (screenshot: 17)")
print(f"  +0x06 dex       = {b[6]}      (screenshot: 9, FFNx-named)")
print(f"  +0x07 luck?     = {b[7]}      (screenshot: 17)")
print(f"  +0x0E limitlvl  = {b[0x0E]}   (screenshot: 1)")
print(f"  +0x10 name      = '{name}'")
print(f"  +0x1C weapon id = {b[0x1C]}   (Buster Sword = 0)")
print(f"  +0x1D armor id  = {b[0x1D]}   (Bronze Bangle = 0)")
print(f"  +0x1E acc id?   = {b[0x1E]:#x} (empty slot expect 0xff)")
print(f"  +0x1F (flags)   = {b[0x1F]:#x}")
print(f"  +0x20 row byte  = {b[0x20]:#x} (0xff front / 0xfe back)")
print(f"  +0x2C HP        = {u16(0x2C)}  (screenshot: 222; may have changed)")
print(f"  +0x38 maxHP     = {u16(0x38)}  (screenshot: 311)")
print(f"  +0x30 MP        = {u16(0x30)}  (screenshot: 54)")
print(f"  +0x3A maxMP     = {u16(0x3A)}  (screenshot: 57)")
print(f"  +0x3C exp       = {u32(0x3C)}  (screenshot: 856; may have grown)")
print(f"  +0x80 exp2next  = {u32(0x80)}  (screenshot: 93; may have shrunk)")
k32.CloseHandle(h)
print("\nAll offsets matching screenshot values = layout confirmed for v2.33.")
