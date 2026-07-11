#!/usr/bin/env python3
"""
ff7_kernel2_table_probe.py -- One-shot live probe of the kernel2 text region
(2026-07-11), diagnosing why the file-table path of the name replication
returns blanks while the section-9 enemy table works.

Dumps:
  1. The u16 offset table at 0x9A7FC8 (entries 0-19) and each computed
     section base (0x9A13C8 + off), with a 32-byte hexdump + FF7 decode of
     the first entry of each section.
  2. A raw search for FF7-encoded 'Potion' (30 4F 54 49 4F 4E) and 'Cure'
     (23 55 52 45) across 0x9A0000-0x9B4000 to locate the REAL item/magic
     name storage.
  3. 64 bytes around whatever the file-10 computation points at, to see what
     is actually there.
"""
import sys, os, struct, ctypes, datetime, subprocess

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_table_probe_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
def open_ff7():
    out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                                    '/FO', 'CSV', '/NH'], text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == 'ff7_en.exe':
            pid = int(parts[1])
            h = k32.OpenProcess(0x0410, False, pid)
            if not h:
                raise RuntimeError(f"OpenProcess failed (PID {pid})")
            print(f"FF7 running (PID {pid})")
            return h
    raise RuntimeError("ff7_en.exe not found")

def read_mem(h, va, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(read))
    if not ok or read.value < size:
        return None
    return buf.raw

def ff7_decode(data, max_bytes=32):
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        out.append(chr(b + 0x20) if b <= 0x5E else f'[{b:02X}]')
    return ''.join(out)

K2_OFFSET_TABLE = 0x009A7FC8
K2_TEXT_BASE    = 0x009A13C8

h = open_ff7()

print("=" * 80)
print("1. offset table u16[0x9A7FC8 + i*2], section base, first entry")
print("=" * 80)
tbl = read_mem(h, K2_OFFSET_TABLE, 40)
for i in range(20):
    off = struct.unpack_from('<H', tbl, i * 2)[0]
    base = K2_TEXT_BASE + off
    head = read_mem(h, base, 36)
    if head is None:
        print(f"  [{i:2d}] off=0x{off:04X} base=0x{base:08X}  (unreadable)")
        continue
    e0 = struct.unpack_from('<H', head, 0)[0]
    entry = read_mem(h, base + e0, 24)
    dec = ff7_decode(entry) if entry else '(unreadable)'
    print(f"  [{i:2d}] off=0x{off:04X} base=0x{base:08X}  e0_off=0x{e0:04X}  first='{dec}'")

print()
print("=" * 80)
print("2. raw search for encoded 'Potion' / 'Cure' / 'Bolt' in 0x9A0000-0x9B4000")
print("=" * 80)
def encode(s):
    return bytes(ord(c) - 0x20 for c in s)
region = read_mem(h, 0x9A0000, 0x14000)
if region:
    for label, pat in [('Potion', encode('Potion')), ('Cure', encode('Cure')),
                       ('Bolt', encode('Bolt')), ('Fire', encode('Fire')),
                       ('Grenade', encode('Grenade'))]:
        pos, hits = 0, []
        while len(hits) < 8:
            p = region.find(pat, pos)
            if p < 0:
                break
            hits.append(0x9A0000 + p)
            pos = p + 1
        print(f"  {label:8s}: " + (', '.join(f'0x{a:08X}' for a in hits) if hits else '(not found)'))
else:
    print("  region unreadable")

print()
print("=" * 80)
print("3. file-10 computation detail (item names path)")
print("=" * 80)
off10 = struct.unpack_from('<H', tbl, 10 * 2)[0]
base10 = K2_TEXT_BASE + off10
print(f"  u16[0x9A7FC8+20] = 0x{off10:04X} -> base = 0x{base10:08X}")
dump = read_mem(h, base10, 96)
if dump:
    for row in range(6):
        chunk = dump[row*16:(row+1)*16]
        hexs = ' '.join(f'{b:02X}' for b in chunk)
        print(f"    0x{base10+row*16:08X}: {hexs}   '{ff7_decode(chunk, 16)}'")

print(f"\nLog saved to: {_log_path}")
_log_file.close()
