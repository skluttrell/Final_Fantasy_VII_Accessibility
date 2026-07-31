#!/usr/bin/env python3
"""
ff7_char_handler_disasm.py -- does the CHAR opcode (0xA1) initialize the
visibility byte (+0x62) found by ff7_visi_handler_disasm.py?
(2026-07-31, task-2 follow-up)

WHY IT MATTERS: the pickup filter wants "visibility byte == 0 => hidden".
That is only safe if models the scripts never VISI (Cloud, most NPCs —
they demonstrably render) START with a nonzero byte. CHAR is the opcode
that binds an entity to a model at init; if its handler (or the code it
tail-calls) stores 1 to [array + model*0x88 + 0x62], the default is
proven visible and ==0 is a trustworthy hidden test.
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"char_handler_disasm_{datetime.datetime.now():%Y%m%d_%H%M%S}.log"
)
_log_file = open(_log_path, 'w', encoding='utf-8')
_orig_write = sys.stdout.write
def _tee(s):
    _orig_write(s)
    _log_file.write(s)
    _log_file.flush()
sys.stdout.write = _tee
import atexit
def _restore_stdout():
    sys.stdout.write = _orig_write
    try:
        _log_file.close()
    except Exception:
        pass
atexit.register(_restore_stdout)
print(f"Output saving to: {_log_path}\n")

import capstone

EXE_CANDIDATES = [
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
img = open(exe_path, 'rb').read()

pe = struct.unpack_from('<I', img, 0x3C)[0]
n_sec = struct.unpack_from('<H', img, pe + 6)[0]
opt_sz = struct.unpack_from('<H', img, pe + 20)[0]
image_base = struct.unpack_from('<I', img, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + opt_sz + i * 40
    vsz, va, rsz, ro = struct.unpack_from('<4I', img, s + 8)
    secs.append((va, vsz, ro, rsz))

def va_to_off(va):
    rva = va - image_base
    for sva, vsz, ro, rsz in secs:
        if sva <= rva < sva + max(vsz, rsz):
            return ro + (rva - sva)
    return None

def off_to_va(off):
    for sva, vsz, ro, rsz in secs:
        if ro <= off < ro + rsz:
            return image_base + sva + (off - ro)
    return None

IDLCK_HANDLER = 0x0061E29F
needle = struct.pack('<I', IDLCK_HANDLER)
pos, t_off = -1, None
while True:
    pos = img.find(needle, pos + 1)
    if pos < 0:
        break
    cand = pos - 0x6D * 4
    if cand < 0:
        continue
    if all(image_base <= struct.unpack_from('<I', img, cand + k * 4)[0]
           < image_base + 0x00A00000 for k in range(256)):
        t_off = cand
        break
h_char = struct.unpack_from('<I', img, t_off + 0xA1 * 4)[0]
print(f"CHAR handler @ 0x{h_char:08X}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# Disassemble the handler AND one level of direct calls, hunting +0x62
# stores and 0x88-stride math. Restart past bad bytes (capstone lesson).
def dump(va, budget, label):
    print(f"\n--- {label} @ 0x{va:08X} ---")
    addr, end = va, va + budget
    calls, hits = [], []
    while addr < end:
        off = va_to_off(addr)
        progressed = False
        for ins in md.disasm(img[off:off + (end - addr)], addr):
            progressed = True
            text = f"{ins.mnemonic} {ins.op_str}"
            mark = ""
            if '0x62' in ins.op_str and '[' in ins.op_str:
                hits.append((ins.address, text))
                mark = "   <<< +0x62"
            if '0x88' in text:
                mark += "   <<< 0x88 stride"
            print(f"  0x{ins.address:08X}: {text}{mark}")
            if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
                calls.append(int(ins.op_str, 16))
            if ins.mnemonic == 'ret':
                addr = end
                break
            addr = ins.address + ins.size
        if addr >= end:
            break
        if not progressed:
            addr += 1
    return calls, hits

calls, hits = dump(h_char, 0x180, "CHAR handler")
all_hits = list(hits)
for c in dict.fromkeys(calls):
    if image_base <= c < image_base + 0x00A00000:
        _, h2 = dump(c, 0x300, f"callee 0x{c:08X}")
        all_hits.extend(h2)

print("\n=== +0x62 STORES FOUND ===")
for a, t in all_hits:
    print(f"  0x{a:08X}: {t}")
if not all_hits:
    print("  none in CHAR or its direct callees -- default may be set by")
    print("  the field loader memset/init path instead; check a live log")
    print("  (NAV vis= column) before trusting ==0.")
