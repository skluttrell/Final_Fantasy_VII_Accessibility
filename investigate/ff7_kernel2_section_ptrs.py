#!/usr/bin/env python3
"""
ff7_kernel2_section_ptrs.py -- Find pointers (especially static ones, or
per-section pointer ARRAYS) into the kernel2 text area itself (2026-07-11).

Refinement of ff7_kernel2_anchor_chain.py: the containing 'allocation' turned
out to be a whole heap segment, so pointers to its base are just heap
bookkeeping. What the v2.7 DLL actually needs is a deterministic route to
each text SECTION (magic names, item names, ...). FF7 or FFNx very likely
keeps an array of 18 per-section pointers -- consecutive ascending DWORDs all
landing inside the text area. This script:

  1. Re-locates the text area bounds from known strings:
     start probe = 'Cures' descriptions block, end probe = item names run.
     Pads generously: [item_run - 0x28000, item_run + 0x8000].
  2. Scans all committed readable memory for 4-aligned DWORDs in that range.
  3. Prints every STATIC holder (inside any module image) with module+offset.
  4. Detects runs of >= 4 consecutive in-range ascending DWORDs anywhere
     (pointer arrays), prints each with what its entries point at (decoded),
     and reports the holder's location class.
"""
import sys, os, struct, ctypes, datetime, subprocess
from ctypes import wintypes

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_section_ptrs_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
psapi = ctypes.windll.psapi

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD), ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD), ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD)]

class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p), ("SizeOfImage", wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p)]

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
    n = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(n))
    return buf.raw[:n.value] if ok else None

def ff7_decode(data, max_bytes=28):
    out = []
    for b in data[:max_bytes]:
        out.append('|' if b == 0xFF else (chr(b + 0x20) if b <= 0x5E else f'[{b:02X}]'))
    return ''.join(out)

def encode(s):
    return bytes(ord(c) - 0x20 for c in s)

h = open_ff7()

psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p),
                                     wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.GetModuleInformation.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                       ctypes.POINTER(MODULEINFO), wintypes.DWORD]
psapi.GetModuleBaseNameA.argtypes = [wintypes.HANDLE, ctypes.c_void_p,
                                     ctypes.c_char_p, wintypes.DWORD]
mods = (ctypes.c_void_p * 1024)()
needed = wintypes.DWORD(0)
psapi.EnumProcessModules(h, mods, ctypes.sizeof(mods), ctypes.byref(needed))
module_ranges = []
for i in range(needed.value // ctypes.sizeof(ctypes.c_void_p)):
    mi = MODULEINFO()
    hmod = ctypes.c_void_p(mods[i])
    psapi.GetModuleInformation(h, hmod, ctypes.byref(mi), ctypes.sizeof(mi))
    namebuf = ctypes.create_string_buffer(260)
    psapi.GetModuleBaseNameA(h, hmod, namebuf, 260)
    module_ranges.append((mi.lpBaseOfDll or 0, (mi.lpBaseOfDll or 0) + mi.SizeOfImage,
                          namebuf.value.decode('ascii', 'replace')))

def classify(addr):
    for lo, hi, name in module_ranges:
        if lo <= addr < hi:
            return f"{name}+0x{addr-lo:X}"
    return None

# -- 1. locate text area ----------------------------------------------------------
pattern = encode('Potion') + b'\xff' + encode('Hi-Potion') + b'\xff'
mbi = MEMORY_BASIC_INFORMATION()
item_run = None
regions = []
addr = 0
while addr < 0x7FFF0000:
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x20, 0x40} \
       and not (mbi.Protect & 0x100):
        regions.append((base, size))
        if item_run is None and classify(base) is None:
            blob = read_mem(h, base, min(size, 0x1000000))
            if blob:
                p = blob.find(pattern)
                if p >= 0:
                    item_run = base + p
    addr = base + size

if item_run is None:
    print("ERROR: item-name run not found")
    sys.exit(1)

LO = item_run - 0x28000
HI = item_run + 0x8000
print(f"Item-name run at 0x{item_run:08X}; scanning for pointers into "
      f"[0x{LO:08X}, 0x{HI:08X})\n")

# -- 2/3/4. scan ------------------------------------------------------------------
static_holders = []
arrays = []
for base, size in regions:
    blob = read_mem(h, base, min(size, 0x1000000))
    if not blob:
        continue
    in_range_flags = []
    n = len(blob) // 4
    vals = struct.unpack_from(f'<{n}I', blob, 0)
    run_start = None
    prev_in = False
    for i in range(n):
        v = vals[i]
        inr = LO <= v < HI
        if inr:
            holder = base + i * 4
            cls = classify(holder)
            if cls:
                static_holders.append((holder, v, cls))
            if run_start is None:
                run_start = i
        else:
            if run_start is not None and i - run_start >= 4:
                seq = vals[run_start:i]
                if all(seq[j] <= seq[j+1] for j in range(len(seq)-1)):
                    arrays.append((base + run_start * 4, list(seq)))
            run_start = None
    if run_start is not None and n - run_start >= 4:
        seq = vals[run_start:n]
        if all(seq[j] <= seq[j+1] for j in range(len(seq)-1)):
            arrays.append((base + run_start * 4, list(seq)))

print("=" * 80)
print(f"STATIC holders ({len(static_holders)}):")
print("=" * 80)
for holder, v, cls in static_holders[:30]:
    head = read_mem(h, v, 28)
    print(f"  0x{holder:08X} ({cls}) -> 0x{v:08X}  '{ff7_decode(head) if head else '?'}'")

print()
print("=" * 80)
print(f"Ascending pointer ARRAYS of >=4 entries ({len(arrays)}):")
print("=" * 80)
for arr_addr, seq in arrays[:10]:
    cls = classify(arr_addr) or 'HEAP'
    print(f"  array at 0x{arr_addr:08X} ({cls}), {len(seq)} entries:")
    for j, v in enumerate(seq[:20]):
        head = read_mem(h, v, 28)
        print(f"    [{j:2d}] 0x{v:08X}  '{ff7_decode(head) if head else '?'}'")
    print()

print(f"Log saved to: {_log_path}")
_log_file.close()
