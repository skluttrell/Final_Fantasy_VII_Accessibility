#!/usr/bin/env python3
"""
ff7_kernel2_section_table.py -- Read 0x00DC3630 (kernel2 section table pointer)
in live FF7 memory, then walk the 0x98-byte section entries to find the actual
string data for section 0 (command names) and section 1 (magic names).

Run with FF7 past the title screen, preferably in battle.
"""
import sys, os, struct, ctypes, datetime

# -- tee logging ---------------------------------------------------------------
_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"kernel2_section_table_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
print(f"Output saving to: {_log_path}\n")

# -- win32 memory reading -------------------------------------------------------
k32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

def open_ff7():
    import subprocess
    out = subprocess.check_output(['tasklist', '/FI', 'IMAGENAME eq ff7_en.exe',
                                   '/FO', 'CSV', '/NH'], text=True)
    for line in out.strip().splitlines():
        parts = [p.strip('"') for p in line.split(',')]
        if parts[0].lower() == 'ff7_en.exe':
            pid = int(parts[1])
            h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
            if not h:
                raise RuntimeError(f"OpenProcess failed (PID {pid})")
            print(f"FF7 running (PID {pid})")
            return h
    raise RuntimeError("ff7_en.exe not found -- start FF7 first")

def read_mem(h, va, size):
    buf = ctypes.create_string_buffer(size)
    read = ctypes.c_size_t(0)
    ok = k32.ReadProcessMemory(h, ctypes.c_void_p(va), buf, size, ctypes.byref(read))
    if not ok or read.value < size:
        return None
    return buf.raw

def read_u32(h, va):
    b = read_mem(h, va, 4)
    return struct.unpack_from('<I', b)[0] if b else None

def hexdump(data, base_va=0, indent="  "):
    for row in range(0, len(data), 16):
        chunk = data[row:row+16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        asc_part = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)
        print(f"{indent}0x{base_va+row:08X}  {hex_part:<48}  {asc_part}")

# -- FF7 text decode -----------------------------------------------------------
def ff7_decode(data, max_bytes=64):
    extra = {
        0x60: '{', 0x61: '}', 0x62: '|', 0x63: '~', 0x64: '`',
        0xE0: '\n', 0xFF: '[END]',
        0xEA: '[Cloud]', 0xEB: '[Barret]', 0xEC: '[Tifa]',
        0xED: '[Aeris]', 0xEE: '[Red XIII]', 0xEF: '[Yuffie]',
        0xF0: '[Cait Sith]', 0xF1: '[Vincent]', 0xF2: '[Cid]',
    }
    out = []
    for b in data[:max_bytes]:
        if b == 0xFF:
            break
        if b <= 0x5E:
            out.append(chr(b + 0x20))
        elif b in extra:
            out.append(extra[b])
        else:
            out.append(f'[{b:02X}]')
    return ''.join(out)

# -- main ----------------------------------------------------------------------
h = open_ff7()

# 1. Read the section table pointer at 0x00DC3630
SECTION_TABLE_PTR_VA = 0x00DC3630
ptr_val = read_u32(h, SECTION_TABLE_PTR_VA)
print(f"\n[0x{SECTION_TABLE_PTR_VA:08X}] = 0x{ptr_val:08X}  (kernel2 section table base)")

if ptr_val is None or ptr_val < 0x00400000:
    print("  INVALID -- kernel2 not loaded yet. Load a save file first.")
    sys.exit(1)

SECTION_STRIDE = 0x98  # from disasm: IMUL reg, 0x98

# 2. Dump first 3 section entries
for sec in range(3):
    entry_va = ptr_val + sec * SECTION_STRIDE
    entry = read_mem(h, entry_va, SECTION_STRIDE)
    if entry is None:
        print(f"\nSection {sec}: read failed at 0x{entry_va:08X}")
        continue

    print(f"\n{'='*72}")
    print(f"Section {sec} entry at 0x{entry_va:08X}:")
    hexdump(entry, entry_va)
    print()

    # Annotate interesting fields
    for i in range(0, SECTION_STRIDE, 4):
        dw = struct.unpack_from('<I', entry, i)[0]
        if 0x00700000 <= dw <= 0x00EF0000:
            print(f"  +{i:02X}  0x{dw:08X}  <- pointer")
        elif 1 <= dw <= 512 and i < 16:
            print(f"  +{i:02X}  {dw:5d}       <- count/index")

# 3. Direct search: scan each section entry's pointer fields for FF7 string data
ATTACK = bytes([0x21, 0x54, 0x54, 0x41, 0x43, 0x4B, 0xFF])  # "Attack"
FIRE   = bytes([0x26, 0x49, 0x52, 0x45, 0xFF])               # "Fire"
MAGIC  = bytes([0x2D, 0x41, 0x47, 0x49, 0x43, 0xFF])         # "Magic"

print(f"\n{'='*72}")
print("Scanning for 'Attack' / 'Magic' / 'Fire' near each pointer in entries")
print("=" * 72)

for sec in range(3):
    entry_va = ptr_val + sec * SECTION_STRIDE
    entry = read_mem(h, entry_va, SECTION_STRIDE)
    if entry is None:
        continue
    for i in range(0, SECTION_STRIDE, 4):
        candidate = struct.unpack_from('<I', entry, i)[0]
        if not (0x00700000 <= candidate <= 0x00EF0000):
            continue
        region = read_mem(h, candidate, 4096)
        if region is None:
            continue
        found = []
        for pat, name in [(ATTACK, 'Attack'), (MAGIC, 'Magic'), (FIRE, 'Fire')]:
            pos = region.find(pat)
            if pos >= 0:
                found.append(f"{name}@+{pos}")
        if not found:
            continue
        print(f"\n  sec={sec} entry+{i:02X}: ptr=0x{candidate:08X}  {', '.join(found)}")
        # Walk back looking for uint16 offset table header
        for back in range(0, 512, 2):
            base = candidate - back
            hdr = read_mem(h, base, 128)
            if hdr is None:
                break
            u16s = [struct.unpack_from('<H', hdr, j)[0] for j in range(0, 64, 2)]
            n = u16s[0] // 2
            if n < 2 or n > 256:
                continue
            # Check ascending
            if not all(u16s[k] <= u16s[k+1] for k in range(n-1) if k+1 < 32):
                continue
            print(f"  Offset table found at 0x{base:08X}, n={n}")
            for idx in range(min(n, 36)):
                off2 = u16s[idx]
                if base + off2 < candidate + 4096:
                    sd = read_mem(h, base + off2, 48)
                    if sd:
                        decoded = ff7_decode(sd)
                        print(f"    [{idx:3d}] 0x{base+off2:08X}  '{decoded}'")
            break

print(f"\nLog saved to: {_log_path}")
_log_file.close()