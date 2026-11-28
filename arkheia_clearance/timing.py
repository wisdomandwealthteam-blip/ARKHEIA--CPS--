"""ARKHEIA Clearance — fixed response-latency floor, integer nanoseconds only.

Copyright (c) Eric A. Scott / ARKHEIA GROUP. All rights reserved.

``time.sleep`` takes a float, so the floor sleeps through libc ``nanosleep``
with an integer ``struct timespec`` instead. Every response on the clearance
endpoints (CLEARED and REJECTED alike) is held until ``floor_ns`` has elapsed
since the request arrived, so timing cannot separate rejection reasons, or
rejections from approvals, below that floor.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import time

_NS_PER_S = 1_000_000_000


class _Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


def _load_libc() -> ctypes.CDLL:
    name = ctypes.util.find_library("c")
    return ctypes.CDLL(name, use_errno=True) if name else ctypes.CDLL(None, use_errno=True)


_libc = _load_libc()
_nanosleep = _libc.nanosleep
_nanosleep.argtypes = [ctypes.POINTER(_Timespec), ctypes.POINTER(_Timespec)]
_nanosleep.restype = ctypes.c_int


def sleep_ns(ns: int) -> None:
    if type(ns) is not int or ns <= 0:
        return
    req = _Timespec(ns // _NS_PER_S, ns % _NS_PER_S)
    rem = _Timespec(0, 0)
    while _nanosleep(ctypes.byref(req), ctypes.byref(rem)) != 0:
        if ctypes.get_errno() != errno.EINTR:
            raise OSError(ctypes.get_errno(), "nanosleep failed")
        req = _Timespec(rem.tv_sec, rem.tv_nsec)


def now_ns() -> int:
    return time.monotonic_ns()


def hold_until(start_ns: int, floor_ns: int) -> None:
    remaining = floor_ns - (time.monotonic_ns() - start_ns)
    if remaining > 0:
        sleep_ns(remaining)
