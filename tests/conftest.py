def pytest_configure(config):
    for marker in ("first", "last", "second_to_last"):
        config.addinivalue_line("markers", marker)


def pytest_pycollect_makeitem(collector, name, obj):
    if name == "testpwnproc" and getattr(obj, "__module__", "") == "pwnlib.ui":
        return []
    return None
