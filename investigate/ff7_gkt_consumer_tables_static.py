#!/usr/bin/env python3
"""
ff7_gkt_consumer_tables_static.py -- confirm the flash-text consumer's
get_kernel_text call signature + dump the GKT remap tables, 2026-08-09.

FOLLOW-UP to ff7_kernel2_battle_source_static.py (same session): that
script proved get_kernel_text (0x41963C) is the game's authoritative
name source in battle -- under FFNx the callee kernel2_get_text is
REPLACED (FFNx/src/ff7/kernel.cpp) to read FFNx's own per-file
external_malloc blocks, which is why the on-screen flash/limit window
always shows correct text while the mod's scavenged heap copy rotted.

BEFORE the mod switches ResolveActionName to call 0x41963C directly,
two things must be byte-verified from the exe:

  1. The REAL flash consumer (research S4: dispatcher 0x6D1CC0,
     actual CALL to 0x41963C at 0x6D72C6, consumer fn ~0x6D72E9):
     does it pass the cmd->branch byte (table 0x6D70A8) DIRECTLY as
     the section argument, with arg3 = 8?  If yes, the mod's
     ResolveActionName branch numbers ARE GKT section numbers and the
     forwarding call is a drop-in.
  2. The remap tables GKT reads for sections < 6 (all file-backed
     .data -- dump initial values):
       0x7B74A0  u8 bias per section 0..3   (expect bias[3] = 0x80 --
                 the +128 limit-name bias applied INSIDE the game)
       0x7B74A8  u8 section->file map 0..5  (file + caller arg3=8 =
                 kernel2 file index fed to kernel2_get_text)
       0x7B7488 / 0x7B748A / 0x7B7498  the section-4 item-id remap
                 (thresholds + target sections)
       0x7C0AE8  the default/empty return string bytes
       0x6D70A8  the cmd->branch byte table (re-confirm the mod's copy)

USAGE
-----
    investigate/venv/Scripts/python.exe investigate/ff7_gkt_consumer_tables_static.py
"""
import sys, os, struct, datetime

_log_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    f"gkt_consumer_tables_static_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
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
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII\ff7_en.exe",
    r"C:\Program Files (x86)\Steam\steamapps\common\FINAL FANTASY VII Steam Edition\ff7\workingdir\ff7_en.exe",
]
exe_path = next((c for c in EXE_CANDIDATES if os.path.isfile(c)), None)
if exe_path is None:
    print("ERROR: ff7_en.exe not found")
    sys.exit(1)
data = open(exe_path, 'rb').read()
print(f"Loaded exe: {exe_path} ({len(data)} bytes)")

pe = struct.unpack_from('<I', data, 0x3C)[0]
n_sec = struct.unpack_from('<H', data, pe + 6)[0]
osz = struct.unpack_from('<H', data, pe + 20)[0]
image_base = struct.unpack_from('<I', data, pe + 0x34)[0]
secs = []
for i in range(n_sec):
    s = pe + 24 + osz + i * 40
    name = data[s:s+8].rstrip(b'\0').decode('ascii', 'replace')
    vs, va, rs, ro = struct.unpack_from('<4I', data, s + 8)
    secs.append((name, va, vs, rs, ro))

def v2o(va):
    r = va - image_base
    for _, sva, svs, srs, sro in secs:
        if sva <= r < sva + max(svs, srs):
            fo = sro + (r - sva)
            return fo if fo < len(data) else None
    return None

KNOWN = {
    0x41963C: "get_kernel_text",
    0x419457: "kernel2_get_text",
    0x6D70A8: "cmd->branch byte table",
    0x6D7080: "dispatch jump table",
    0xDC3640: "composed-name buffer (branch 4)",
    0xDC38E0: "battle_actor_data (flash struct)",
    0xDC208C: "GKT_result_ptr",
}
def annotate(insn):
    notes = []
    for op in insn.operands:
        vals = []
        if op.type == capstone.x86.X86_OP_IMM:
            vals.append(op.imm & 0xFFFFFFFF)
        elif op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
            vals.append(op.mem.disp & 0xFFFFFFFF)
        for v in vals:
            if v in KNOWN:
                notes.append(KNOWN[v])
            elif 0xDC38E0 <= v < 0xDC38E0 + 0x20:
                notes.append(f"battle_actor_data+0x{v-0xDC38E0:X}")
    return ("   ; " + ", ".join(notes)) if notes else ""

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
md.skipdata = True

def disasm_range(start, end, label=""):
    off = v2o(start)
    if off is None:
        print(f"!! cannot map 0x{start:X}")
        return
    print()
    print("=" * 76)
    print(f"===== 0x{start:08X}..0x{end:08X}  {label}")
    print("=" * 76)
    for insn in md.disasm(data[off:off + (end - start)], start):
        if insn.id == 0:
            continue
        print(f"  0x{insn.address:08X}  {insn.mnemonic:<8s} {insn.op_str}"
              f"{annotate(insn)}")

# 1. the consumer around the real GKT call at 0x6D72C6.  Start well
#    before so the argument setup (branch byte fetch, idx fetch) shows.
disasm_range(0x6D7200, 0x6D7340, "flash-text consumer around CALL 0x41963C @0x6D72C6")

# 2. dispatcher head (how cmd indexes the branch byte table) -- context
disasm_range(0x6D1CC0, 0x6D1D40, "dispatcher sub_6D1CC0 head (cmd -> branch)")

# 3. .data tables
def dump_bytes(va, n, label, fmt="u8"):
    off = v2o(va)
    print(f"\n-- {label} @0x{va:08X}:")
    if off is None:
        print("   (not file-backed / BSS)")
        return None
    if fmt == "u8":
        vals = data[off:off+n]
        print("   " + " ".join(f"{b:02X}" for b in vals))
        return vals
    else:
        vals = struct.unpack_from(f'<{n}H', data, off)
        print("   " + " ".join(f"{v:04X}" for v in vals))
        return vals

dump_bytes(0x7B74A0, 8,  "GKT idx-bias per section 0..3 (u8)")
dump_bytes(0x7B74A8, 8,  "GKT section->file map 0..5 (u8; +caller arg3)")
dump_bytes(0x7B7488, 8,  "section-4 remap thresholds A (u16 x4)", fmt="u16")
dump_bytes(0x7B748A, 8,  "section-4 remap thresholds B (u16 x4)", fmt="u16")
dump_bytes(0x7B7498, 8,  "section-4 remap target sections (u8)")
dump_bytes(0x7C0AE8, 16, "GKT default/empty string bytes")
dump_bytes(0x6D70A8, 33, "cmd->branch byte table (cmd 0x00..0x20)")

print("\nDone.")
