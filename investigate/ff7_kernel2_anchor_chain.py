#!/usr/bin/env python3
"""
ff7_kernel2_anchor_chain.py -- Find a STABLE pointer chain from static memory
to the heap block holding decompressed kernel2 text (2026-07-11).

Context: the kernel2 text (magic/item/all names) lives in heap (found near
0x22EF0000 this run; address changes per run). The static scratch tables the
game's get_kernel_text uses are empty during battle, and the only direct
static pointer into the block's vicinity (0x9A8128) points mid-data, not at
a section base. The v2.7 DLL needs a deterministic way to reach this block
every run, so: walk pointer chains backward.

METHOD:
  1. Locate the item-name run ('Potion|Hi-Potion|') in heap; VirtualQueryEx
     gives the containing allocation base A.
  2. Scan ALL committed readable memory for 4-aligned DWORDs whose value is
     in [A, A + 0x1000) -- pointers to (near) the block start. Classify each
     holder: STATIC (exe image 0x400000-0xE00000), DLL (module ranges via
     EnumProcessModules + GetModuleInformation), or HEAP.
  3. For each HEAP holder, recurse once: find pointers to ITS allocation
     base, again classifying. Two levels is usually enough for
     static -> container -> buffer chains.
  4. Report every static/DLL-rooted chain found, with module name + offset
     for DLL roots (module base changes with ASLR; module-relative offset is
     what the DLL implementation would use).

Also prints the offset of the item-name run within the allocation, so any
found root can be turned into 'name table = *root + fixed_offset'.
"""
import sys, os, struct, ctypes, datetime, subprocess
from ctypes import wintypes

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_anchor_chain_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
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
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", wintypes.DWORD),
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
    if not ok:
        return None
    return buf.raw[:n.value]

def encode(s):
    return bytes(ord(c) - 0x20 for c in s)

h = open_ff7()

# -- module map for holder classification -----------------------------------------
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
    module_ranges.append((mi.lpBaseOfDll or 0,
                          (mi.lpBaseOfDll or 0) + mi.SizeOfImage,
                          namebuf.value.decode('ascii', 'replace')))

def classify(addr):
    for lo, hi, name in module_ranges:
        if lo <= addr < hi:
            return f"{name}+0x{addr-lo:X}"
    return None   # heap/other

# -- 1. locate block --------------------------------------------------------------
pattern = encode('Potion') + b'\xff' + encode('Hi-Potion') + b'\xff'
mbi = MEMORY_BASIC_INFORMATION()
block_addr = None
addr = 0
regions = []   # cache the region list for reuse
while addr < 0x7FFF0000:
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize
    if mbi.State == 0x1000 and (mbi.Protect & 0xFF) in {0x02, 0x04, 0x20, 0x40} \
       and not (mbi.Protect & 0x100):
        regions.append((base, size, mbi.AllocationBase or 0))
        if block_addr is None and classify(base) is None:  # heap only
            blob = read_mem(h, base, min(size, 0x1000000))
            if blob:
                p = blob.find(pattern)
                if p >= 0:
                    block_addr = base + p
                    block_alloc = mbi.AllocationBase or 0
    addr = base + size

if block_addr is None:
    print("ERROR: item-name run not found in heap")
    sys.exit(1)

print(f"Item names at 0x{block_addr:08X}; allocation base 0x{block_alloc:08X}; "
      f"offset within allocation 0x{block_addr - block_alloc:X}\n")

def find_pointers_to(target_lo, target_hi, label):
    """Scan every cached region for DWORDs in [target_lo, target_hi)."""
    found = []
    for base, size, alloc in regions:
        blob = read_mem(h, base, min(size, 0x1000000))
        if not blob:
            continue
        for off in range(0, len(blob) - 3, 4):
            v = struct.unpack_from('<I', blob, off)[0]
            if target_lo <= v < target_hi:
                holder = base + off
                found.append((holder, v, classify(holder)))
    print(f"Pointers into {label} [0x{target_lo:08X}-0x{target_hi:08X}): {len(found)}")
    for holder, v, cls in found[:25]:
        print(f"  0x{holder:08X} -> 0x{v:08X}   holder is {cls or 'HEAP'}")
    print()
    return found

# -- 2. level 1: who points at the block start? -----------------------------------
lvl1 = find_pointers_to(block_alloc, block_alloc + 0x1000, "text allocation start")

# -- 3. level 2: for heap holders, who points at THEM? ----------------------------
seen_allocs = set()
for holder, v, cls in lvl1:
    if cls is not None:
        continue
    # find holder's allocation base
    mbi2 = MEMORY_BASIC_INFORMATION()
    if not k32.VirtualQueryEx(h, ctypes.c_void_p(holder), ctypes.byref(mbi2), ctypes.sizeof(mbi2)):
        continue
    ab = mbi2.AllocationBase or 0
    if ab in seen_allocs:
        continue
    seen_allocs.add(ab)
    find_pointers_to(ab, ab + 0x200, f"container alloc of holder 0x{holder:08X}")

print(f"Log saved to: {_log_path}")
_log_file.close()
