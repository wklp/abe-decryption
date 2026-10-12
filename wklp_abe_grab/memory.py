import ctypes

from wklp_abe_grab.winapi import (
    PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
    k32,
    psapi,
)


def read_mem(h_proc, addr, size):
    if not addr or size <= 0:
        return b""
    buf = ctypes.create_string_buffer(size)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h_proc, ctypes.c_void_p(addr), buf,
                                 size, ctypes.byref(got)):
        return b""
    return buf.raw[:got.value]


def enum_modules(h_proc):
    close_after = False
    if not h_proc or h_proc == ctypes.c_void_p(-1).value:
        h_proc = k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False,
            k32.GetCurrentProcessId())
        if not h_proc:
            return {}
        close_after = True

    mods = (ctypes.c_void_p * 4096)()
    needed = ctypes.c_uint32(0)
    ok = psapi.EnumProcessModulesEx(h_proc, mods, ctypes.sizeof(mods),
                                    ctypes.byref(needed), 0x03)
    if not ok:
        ok = psapi.EnumProcessModules(h_proc, mods, ctypes.sizeof(mods),
                                      ctypes.byref(needed))
    out = {}
    if ok:
        count = needed.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(min(count, 4096)):
            base = mods[i]
            if not base:
                continue
            buf = ctypes.create_unicode_buffer(260)
            if psapi.GetModuleBaseNameW(h_proc, ctypes.c_void_p(base),
                                        buf, 260):
                out[buf.value.lower()] = base
    if close_after:
        k32.CloseHandle(h_proc)
    return out