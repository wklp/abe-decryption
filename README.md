# wklp-abe-grab

Chromium credential extraction on Windows via the OSCrypt App-Bound decrypt path.

## Browsers

| Browser  | v20 | Method        |
|----------|-----|---------------|
| Chrome   | yes | OSCrypt hwbp  |
| Edge     | yes | OSCrypt hwbp  |
| Opera    | no  | DPAPI         |
| Opera GX | no  | DPAPI         |

## Requirements

Windows 10/11 x64, Python 3.10+, `pycryptodome`, `pywin32`.

**UAC must be disabled.** The debugger needs SeDebugPrivilege to attach to the browser process, and the elevation service must accept the caller without an interactive prompt. With UAC enabled, some browsers refuse the attach and the app-bound path returns nothing.

Disable UAC:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
```

Then reboot. To re-enable later, set `EnableLUA` back to `1` and reboot.

The CLI also self-elevates via `ShellExecuteW runas` when launched from a non-admin shell. If UAC is disabled, that call runs silently. If UAC is enabled, you get a prompt — but the debugger will still likely fail to attach.

## Install

```
git clone https://github.com/wklp/wklp-abe-grab
cd wklp-abe-grab
python -m pip install -e .
```

## Usage

```
wklp-abe-grab
wklp-abe-grab --browser chrome
wklp-abe-grab --browser chrome --browser edge
wklp-abe-grab --out ./results
```

Output goes to `./grabbed/<browser>.json`.

## Author

wklp