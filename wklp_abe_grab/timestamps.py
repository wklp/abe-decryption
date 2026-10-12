import datetime

from wklp_abe_grab.winapi import WEBKIT_EPOCH, WIN_EPOCH


def ts_chromium(ts):
    try:
        u = (ts - WIN_EPOCH) // 1000000
        if u <= 0:
            return "session"
        return datetime.datetime.fromtimestamp(
            u, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "?"


def ts_webkit(ts):
    try:
        u = ts / 1000000 + WEBKIT_EPOCH
        return datetime.datetime.fromtimestamp(
            u, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return "?"