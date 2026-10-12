import ctypes

from wklp_abe_grab.winapi import CONTEXT_FULL, Context64, k32


def set_hwbps(h_thread, addrs):
    ctx = Context64()
    ctx.Flags = CONTEXT_FULL
    if not k32.GetThreadContext(h_thread, ctypes.byref(ctx)):
        return False
    ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0
    ctx.Dr7 = 0
    for i, addr in enumerate(addrs[:4]):
        if i == 0:
            ctx.Dr0 = addr
        elif i == 1:
            ctx.Dr1 = addr
        elif i == 2:
            ctx.Dr2 = addr
        elif i == 3:
            ctx.Dr3 = addr
        ctx.Dr7 |= (1 << (i * 2))
    return bool(k32.SetThreadContext(h_thread, ctypes.byref(ctx)))


def set_hwbp(h_thread, addr):
    return set_hwbps(h_thread, [addr])