from wklp_abe_grab.keycheck import is_valid_key


def test_rejects_short():
    assert not is_valid_key(b"a" * 16)


def test_rejects_v10_prefix():
    assert not is_valid_key(b"v10" + b"A" * 29)


def test_rejects_repetitive():
    assert not is_valid_key(b"A" * 32)


def test_accepts_high_entropy():
    key = bytes(range(32))
    assert is_valid_key(key)