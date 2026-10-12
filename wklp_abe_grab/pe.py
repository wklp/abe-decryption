import struct

from wklp_abe_grab.memory import read_mem
from wklp_abe_grab.winapi import OSCRYPT_MARKER


def find_section(h_proc, base, name):
    dos = read_mem(h_proc, base, 0x40)
    if len(dos) < 0x40 or dos[:2] != b"MZ":
        return None
    lfanew = struct.unpack_from("<I", dos, 0x3C)[0]
    if lfanew == 0 or lfanew > 0x1000:
        return None
    nt = read_mem(h_proc, base + lfanew, 0x108)
    if len(nt) < 0x18 or nt[:2] != b"PE":
        return None
    nsec = struct.unpack_from("<H", nt, 6)[0]
    optsz = struct.unpack_from("<H", nt, 20)[0]
    secoff = lfanew + 24 + optsz
    for i in range(min(nsec, 32)):
        s = read_mem(h_proc, base + secoff + i * 40, 40)
        if len(s) < 40:
            continue
        if s[:8].rstrip(b"\x00") == name:
            return (base + struct.unpack_from("<I", s, 12)[0],
                    struct.unpack_from("<I", s, 16)[0])
    return None


def _find_marker_va(h_proc, base):
    for sec in (b".rdata", b".data"):
        r = find_section(h_proc, base, sec)
        if not r:
            continue
        sa, ss = r
        off = 0
        while off < ss:
            chunk = read_mem(h_proc, sa + off, min(4 * 1024 * 1024, ss - off))
            if not chunk:
                break
            p = chunk.find(OSCRYPT_MARKER)
            if p != -1:
                return sa + off + p
            off += max(1, len(chunk) - len(OSCRYPT_MARKER) + 1)
    return None


def find_all_leas(h_proc, base):
    sva = _find_marker_va(h_proc, base)
    if not sva:
        return []
    text = find_section(h_proc, base, b".text")
    if not text:
        return []
    ta, ts = text
    leas = []
    off = 0
    while off < ts:
        chunk = read_mem(h_proc, ta + off, min(4 * 1024 * 1024, ts - off))
        if not chunk:
            break
        for i in range(len(chunk) - 7):
            if chunk[i] == 0x48 and chunk[i + 1] == 0x8D:
                modrm = chunk[i + 2]
                if (modrm & 0xC7) != 0x05:
                    continue
                d = struct.unpack_from("<i", chunk, i + 3)[0]
                va = ta + off + i
                if (va + 7 + d) & 0xFFFFFFFFFFFFFFFF == sva:
                    leas.append(va)
        off += max(1, len(chunk) - 7)
    return leas