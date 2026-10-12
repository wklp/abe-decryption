import ctypes
import os
import shutil
import sqlite3
import tempfile

from wklp_abe_grab.winapi import (
    FILE_ATTR_NORMAL,
    GENERIC_READ,
    INVALID_HANDLE,
    OPEN_EXISTING,
    SHARE_ALL,
    k32,
)


def copy_locked(src, dst):
    h = k32.CreateFileW(str(src), GENERIC_READ, SHARE_ALL,
                        None, OPEN_EXISTING, FILE_ATTR_NORMAL, None)
    if h == INVALID_HANDLE:
        return False
    try:
        with open(dst, "wb") as out:
            buf = ctypes.create_string_buffer(1024 * 1024)
            got = ctypes.c_uint32(0)
            while True:
                if not k32.ReadFile(h, buf, len(buf), ctypes.byref(got), None):
                    break
                if got.value == 0:
                    break
                out.write(buf.raw[:got.value])
        return True
    finally:
        k32.CloseHandle(h)


def safe_copy(src, dst):
    try:
        shutil.copy2(src, dst)
        return True
    except PermissionError:
        return copy_locked(src, dst)
    except Exception:
        return False


def query(db, sql):
    tmp = tempfile.mktemp(suffix=".db")
    if not safe_copy(db, tmp):
        return []
    rows = []
    try:
        con = sqlite3.connect(tmp)
        con.row_factory = sqlite3.Row
        try:
            cur = con.cursor()
            cur.execute(sql)
            rows = [dict(r) for r in cur.fetchall()]
        except sqlite3.OperationalError:
            pass
        con.close()
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass
    return rows


def has_table(db, name):
    r = query(db, "SELECT name FROM sqlite_master "
                  "WHERE type='table' AND name='" + name + "'")
    return len(r) > 0