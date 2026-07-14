#!/usr/bin/env python3
"""
ff7_field_models_verify.py -- Verify the v2.16 FieldModelLabel walk against
live memory (2026-07-13). Mirrors proxy.cpp's parser EXACTLY (same bounds,
same skips: name, u16, 8-byte HRC, 4-byte scale, u16 nAnim, 30-byte light
block, nAnim x (u16 len + name + u16)) and prints every model index -> label
so any walk-arithmetic bug shows up as garbled labels immediately.
One-shot; game running with a field loaded.
"""
import ctypes, subprocess, sys, time, os, struct

FIELD_FILE_BUFFER = 0x00CFF594
FIELD_N_MODELS    = 0x00CFF73E
TRIGGERS_HDR_PTR  = 0x00CFF454
PROCESS_VM_READ   = 0x0410

class Tee:
    def __init__(self, t, l): self.t, self.l = t, l
    def write(self, d): self.t.write(d); self.l.write(d)
    def flush(self): self.t.flush(); self.l.flush()
    def __getattr__(self, n): return getattr(self.t, n)

def find_pid(name):
    out = subprocess.run(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV'],
                         capture_output=True, text=True).stdout
    for line in out.splitlines():
        if name.lower() in line.lower():
            parts = line.strip('"').split('","')
            if len(parts) >= 2:
                try: return int(parts[1])
                except ValueError: pass
    return None

def rmem(h, addr, size):
    buf = ctypes.create_string_buffer(size); n = ctypes.c_size_t(0)
    ok = ctypes.windll.kernel32.ReadProcessMemory(
        h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw if ok and n.value == size else None

def main():
    d = os.path.dirname(os.path.abspath(__file__))
    lp = os.path.join(d, f"field_models_verify_{time.strftime('%Y%m%d_%H%M%S')}.log")
    sys.stdout = Tee(sys.__stdout__, open(lp, 'w', encoding='utf-8'))
    print(f"Output saving to: {lp}\n")

    pid = find_pid("ff7_en.exe")
    if not pid:
        print("ERROR: game not running"); return
    h = ctypes.windll.kernel32.OpenProcess(PROCESS_VM_READ, False, pid)

    buf = struct.unpack('<I', rmem(h, FIELD_FILE_BUFFER, 4))[0]
    hdrp = struct.unpack('<I', rmem(h, TRIGGERS_HDR_PTR, 4))[0]
    fname = (rmem(h, hdrp, 9) or b'').split(b'\0')[0].decode('ascii', 'replace').lower()
    nmod_live = struct.unpack('<H', rmem(h, FIELD_N_MODELS, 2))[0]
    print(f"buf=0x{buf:08X} field='{fname}' live n_models={nmod_live}")

    sec_off = struct.unpack('<I', rmem(h, buf + 6 + 2 * 4, 4))[0]
    sec_size = struct.unpack('<I', rmem(h, buf + sec_off, 4))[0]
    data = rmem(h, buf + sec_off + 4, sec_size)
    print(f"section2 off=0x{sec_off:X} size={sec_size}\n")

    n_models = struct.unpack_from('<H', data, 2)[0]
    print(f"section n_models={n_models} (match={'YES' if n_models == nmod_live else 'NO'})")
    p = 6
    for m in range(n_models):
        nlen = struct.unpack_from('<H', data, p)[0]; p += 2
        raw = data[p:p+nlen].decode('ascii', 'replace').lower(); p += nlen
        label = raw[:-5] if raw.endswith('.char') else raw
        if fname and label.startswith(fname):
            label = label[len(fname):]
        label = label.replace('_', ' ').strip()
        p += 2 + 8 + 4                      # unknown, HRC, scale
        nanim = struct.unpack_from('<H', data, p)[0]; p += 2
        p += 30                              # light block
        anims = []
        for _ in range(nanim):
            alen = struct.unpack_from('<H', data, p)[0]; p += 2
            anims.append(data[p:p+alen].decode('ascii', 'replace')); p += alen + 2
        print(f"  model {m}: label='{label}'  (raw='{raw}', {nanim} anims, "
              f"first={anims[0] if anims else '-'})")
    print(f"\nwalk ended at +0x{p:X} of {sec_size} "
          f"({'CLEAN' if abs(sec_size - p) <= 4 else 'MISMATCH — check format'})")
    ctypes.windll.kernel32.CloseHandle(h)

if __name__ == '__main__':
    main()
