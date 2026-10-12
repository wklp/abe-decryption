import ctypes

CONTEXT_AMD64 = 0x00100000
CONTEXT_CONTROL = 0x00000001
CONTEXT_INTEGER = 0x00000002
CONTEXT_DEBUG = 0x00000010
CONTEXT_FULL = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG

THREAD_ALL = 0x0008 | 0x0010 | 0x0002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
DEBUG_ONLY_THIS = 0x00000002
CREATE_NO_WINDOW = 0x08000000

PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_TERMINATE = 0x0001
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

EVENT_EXCEPTION = 1
EVENT_CREATE_THREAD = 2
EVENT_CREATE_PROCESS = 3
EVENT_EXIT_THREAD = 4
EVENT_EXIT_PROCESS = 5
EVENT_LOAD_DLL = 6

EXCEPTION_SINGLE_STEP = 0x80000004

IGNORED_EXCEPTIONS = frozenset({
    0x406D1388, 0x80000003, 0x80000004,
    0xC0000139, 0xC0000135, 0xE06D7363,
    0x80000026, 0x40010006, 0xC0000005,
    0xC000001D, 0xC0000094, 0x40080201,
})

GENERIC_READ = 0x80000000
SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
OPEN_EXISTING = 3
FILE_ATTR_NORMAL = 0x80
INVALID_HANDLE = ctypes.c_void_p(-1).value

WIN_EPOCH = 11644473600000000
WEBKIT_EPOCH = 978307200

OSCRYPT_MARKER = b"OSCrypt.AppBoundProvider.Decrypt.ResultCode"

k32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

k32.LoadLibraryW.argtypes = [ctypes.c_wchar_p]
k32.LoadLibraryW.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
k32.GetModuleHandleW.restype = ctypes.c_void_p
k32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
k32.OpenProcess.restype = ctypes.c_void_p
k32.GetCurrentProcessId.restype = ctypes.c_uint32
k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.c_void_p]
k32.ReadProcessMemory.restype = ctypes.c_int

psapi.EnumProcessModulesEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_uint32, ctypes.c_void_p,
                                       ctypes.c_uint32]
psapi.EnumProcessModulesEx.restype = ctypes.c_int
psapi.EnumProcessModules.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_uint32, ctypes.c_void_p]
psapi.EnumProcessModules.restype = ctypes.c_int
psapi.GetModuleBaseNameW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                     ctypes.c_wchar_p, ctypes.c_uint32]
psapi.GetModuleBaseNameW.restype = ctypes.c_uint32


class Context64(ctypes.Structure):
    _fields_ = [
        ("P1", ctypes.c_uint64), ("P2", ctypes.c_uint64),
        ("P3", ctypes.c_uint64), ("P4", ctypes.c_uint64),
        ("P5", ctypes.c_uint64), ("P6", ctypes.c_uint64),
        ("Flags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
        ("Xmm", ctypes.c_uint8 * (16 * 16)),
        ("Vec", ctypes.c_uint8 * 416),
        ("VecCtl", ctypes.c_uint64),
        ("DbgCtl", ctypes.c_uint64),
        ("LbTo", ctypes.c_uint64), ("LbFrom", ctypes.c_uint64),
        ("ExTo", ctypes.c_uint64), ("ExFrom", ctypes.c_uint64),
    ]


class ExcRecord(ctypes.Structure):
    _fields_ = [
        ("Code", ctypes.c_uint32), ("Flags", ctypes.c_uint32),
        ("Record", ctypes.c_void_p), ("Address", ctypes.c_void_p),
        ("NParam", ctypes.c_uint32), ("Info", ctypes.c_uint64 * 15),
    ]


class DllInfo(ctypes.Structure):
    _fields_ = [
        ("hFile", ctypes.c_void_p), ("Base", ctypes.c_void_p),
        ("InfoOff", ctypes.c_uint32), ("InfoSize", ctypes.c_uint32),
        ("ImageName", ctypes.c_void_p), ("Unicode", ctypes.c_uint16),
    ]


class ThreadInfo(ctypes.Structure):
    _fields_ = [
        ("hThread", ctypes.c_void_p), ("TlsBase", ctypes.c_void_p),
        ("Start", ctypes.c_void_p),
    ]


class DebugUnion(ctypes.Union):
    _fields_ = [
        ("Exc", ExcRecord), ("Dll", DllInfo),
        ("Thread", ThreadInfo), ("Raw", ctypes.c_byte * 160),
    ]


class DebugEvent(ctypes.Structure):
    _fields_ = [
        ("Code", ctypes.c_uint32), ("Pid", ctypes.c_uint32),
        ("Tid", ctypes.c_uint32), ("u", DebugUnion),
    ]


class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32), ("reserved", ctypes.c_wchar_p),
        ("desktop", ctypes.c_wchar_p), ("title", ctypes.c_wchar_p),
        ("x", ctypes.c_uint32), ("y", ctypes.c_uint32),
        ("xs", ctypes.c_uint32), ("ys", ctypes.c_uint32),
        ("xc", ctypes.c_uint32), ("yc", ctypes.c_uint32),
        ("fill", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("show", ctypes.c_uint16), ("r2", ctypes.c_uint16),
        ("r2p", ctypes.c_void_p),
        ("stdin", ctypes.c_void_p), ("stdout", ctypes.c_void_p),
        ("stderr", ctypes.c_void_p),
    ]


class ProcInfo(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
        ("Pid", ctypes.c_uint32), ("Tid", ctypes.c_uint32),
    ]