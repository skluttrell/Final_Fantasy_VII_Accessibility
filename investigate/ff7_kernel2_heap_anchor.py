#!/usr/bin/env python3
"""
ff7_kernel2_heap_anchor.py -- Find the static anchor pointer(s) to the heap
block holding the decompressed kernel2 text, and map its section layout
(2026-07-11).

Context: name_memory_scan (today) located the real kernel2 text in heap
around 0x22EE0000-0x22F00000 (magic names, item names, descriptions -- all
resident during battle). The static scratch at 0x9A13C8 used by
kernel2_get_text is empty in battle, so the game must reach this text some
other way. The research doc lists 0x9ADF0C as an unverified 'kernel2 data
pointer candidate' from v2.5.

WHAT THIS DOES:
  1. Reads u32[0x9ADF0C] and prints where it points.
  2. Scans the static data ranges 0x900000-0xA10000 and 0xDB0000-0xDE0000
     for every 4-aligned DWORD pointing into the heap text block (bounds
     taken from today's hits, padded: 0x22E00000-0x22F80000). These are the
     candidate anchors the DLL can use.
  3. For each anchor found, dumps the first 64 bytes at the target and, if
     it looks like a u16 offset table, decodes the first 8 entries -- so we
     can tell WHICH kernel2 section each anchor points to.
  4. Bonus: dumps u32 values AROUND the best anchor (+/- 0x40) -- FF7 often
     keeps an array of per-section pointers, and if 18 consecutive DWORDs
     all point into the block, that array replaces all offset math.

NOTE: heap addresses change between runs; only the STATIC anchor addresses
found here are usable in the DLL. Bounds are re-derived each run by
searching for the encoded 'Potion|Hi-Potion' item-name run first.
"""
import sys, os, struct, ctypes, datetime, subprocess
from ctypes import wintypes

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_heap_anchor_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b and len(b) == 4 else None

def ff7_decode(data, max_bytes=48):
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            out.append('|')
        else:
            out.append(chr(b + 0x20) if b <= 0x5E else f'[{b:02X}]')
    return ''.join(out)

def encode(s):
    return bytes(ord(c) - 0x20 for c in s)

h = open_ff7()

# -- 0. re-locate the heap text block this run -----------------------------------
pattern = encode('Potion') + b'\xff' + encode('Hi-Potion') + b'\xff'
block_hit = None
addr = 0
mbi = MEMORY_BASIC_INFORMATION()
while addr < 0x7FFF0000:
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x20, 0x40} \
       and not (mbi.Protect & 0x100):
        blob = read_mem(h, base, min(size, 0x1000000))
        if blob:
            p = blob.find(pattern)
            if p >= 0 and base > 0xA00000:   # skip static copies; we want heap
                block_hit = base + p
                # remember the containing allocation for bounds
                alloc_base = mbi.AllocationBase
                region_base, region_size = base, size
                break
    addr = base + size

if block_hit is None:
    print("ERROR: item-name run not found in heap -- is the game past kernel load?")
    sys.exit(1)

LO = block_hit - 0x40000
HI = block_hit + 0x40000
print(f"Item-name run ('Potion|Hi-Potion|') found at 0x{block_hit:08X}")
print(f"Anchor search target range: 0x{LO:08X} - 0x{HI:08X}\n")

# -- 1. the documented candidate --------------------------------------------------
v = read_u32(h, 0x9ADF0C)
print(f"u32[0x9ADF0C] = 0x{v:08X}" + ("  <-- IN RANGE" if v and LO <= v <= HI else ""))
print()

# -- 2. static-range scan for pointers into the block ------------------------------
print("=" * 80)
print("Static DWORDs pointing into the heap text block:")
print("=" * 80)
anchors = []
for lo, hi in [(0x900000, 0xA10000), (0xDB0000, 0xDE0000)]:
    blob = read_mem(h, lo, hi - lo)
    if not blob:
        continue
    for off in range(0, len(blob) - 3, 4):
        val = struct.unpack_from('<I', blob, off)[0]
        if LO <= val <= HI:
            anchors.append((lo + off, val))

for slot, val in anchors:
    target_head = read_mem(h, val, 16)
    words = struct.unpack_from('<8H', target_head) if target_head and len(target_head) == 16 else ()
    # Heuristic: does the target start with a plausible u16 offset table
    # (monotonic, small)?
    is_offtab = len(words) == 8 and all(words[i] < words[i+1] for i in range(7)) and words[0] < 0x400
    print(f"  static 0x{slot:08X} -> 0x{val:08X}  head={ff7_decode(target_head, 16) if target_head else '?'}"
          + ("   <== looks like u16 offset table" if is_offtab else ""))

# -- 3. decode first entries through each offset-table-looking anchor -------------
print()
print("=" * 80)
print("Entry decode through each offset-table anchor (first 6 entries):")
print("=" * 80)
for slot, val in anchors:
    head = read_mem(h, val, 0x40)
    if not head or len(head) < 0x40:
        continue
    words = struct.unpack_from('<16H', head, 0)
    if not all(words[i] <= words[i+1] for i in range(10)):
        continue
    print(f"  anchor 0x{slot:08X} -> base 0x{val:08X}:")
    for i in range(6):
        e = read_mem(h, val + words[i], 24)
        print(f"    [{i}] +0x{words[i]:04X}: '{ff7_decode(e) if e else '?'}'")
    print()

print(f"Log saved to: {_log_path}")
_log_file.close()
