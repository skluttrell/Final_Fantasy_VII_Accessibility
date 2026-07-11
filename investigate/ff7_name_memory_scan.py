#!/usr/bin/env python3
"""
ff7_name_memory_scan.py -- Full-process scan for FF7-encoded item/magic name
strings during battle (2026-07-11).

WHY: kernel2_table_probe (today) showed the kernel2 text file table
(0x9A7FC8 -> 0x9A13C8) is ALL ZEROS during battle -- that scratch region is
only populated when another module loads kernel text (likely main menu).
Yet the battle Magic/Item menus display real names, so the strings must be
resident somewhere else while in battle. This scan finds every copy.

WHAT: walks the whole address space with VirtualQueryEx, reads committed
readable regions, and searches for the FF7-encoded bytes of several known
names ('Potion', 'Cure', 'Bolt', 'Fire', 'Tent', 'Phoenix Down'). Prints
every hit address grouped by name, plus a short decode of the surrounding
64 bytes for the first few hits so the containing table layout is visible.

Run while IN BATTLE (ideally after having opened the battle Item and Magic
menus at least once, so any lazily-built battle menu tables exist).
"""
import sys, os, struct, ctypes, datetime, subprocess
from ctypes import wintypes

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"name_memory_scan_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

MEM_COMMIT = 0x1000
PAGE_READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # R, RW, WC, X+R, X+RW, X+WC

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
    if not ok:
        return None
    return buf.raw[:read.value]

def ff7_decode(data, max_bytes=48):
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            out.append('|')
            continue
        out.append(chr(b + 0x20) if b <= 0x5E else f'[{b:02X}]')
    return ''.join(out)

def encode(s):
    return bytes(ord(c) - 0x20 for c in s)

NAMES = ['Potion', 'Cure', 'Bolt', 'Fire', 'Tent', 'Phoenix Down', 'Grenade']

h = open_ff7()
patterns = {n: encode(n) for n in NAMES}
hits = {n: [] for n in NAMES}

addr = 0
mbi = MEMORY_BASIC_INFORMATION()
total_scanned = 0
while addr < 0x7FFF0000:
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr),
                              ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in PAGE_READABLE \
       and not (mbi.Protect & 0x100):  # skip PAGE_GUARD
        blob = read_mem(h, base, min(size, 0x1000000))
        if blob:
            total_scanned += len(blob)
            for n, pat in patterns.items():
                pos = 0
                while len(hits[n]) < 40:
                    p = blob.find(pat, pos)
                    if p < 0:
                        break
                    hits[n].append(base + p)
                    pos = p + 1
    addr = base + size

print(f"Scanned {total_scanned/1048576:.0f} MB of committed readable memory\n")
for n in NAMES:
    lst = hits[n]
    print(f"{n}: {len(lst)} hit(s)")
    for a in lst[:12]:
        ctx = read_mem(h, a - 8, 72)
        print(f"  0x{a:08X}   ...{ff7_decode(ctx) if ctx else ''}")
    print()

print(f"Log saved to: {_log_path}")
_log_file.close()
