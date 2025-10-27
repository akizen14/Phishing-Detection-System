# ncd.py
# LZMA compression helpers and NCD computation with simple caching for compressed sizes.

import lzma
from typing import Dict


def compress_size(data: bytes) -> int:
    """
    Return compressed size using LZMA.
    """
    if not isinstance(data, (bytes, bytearray)):
        data = str(data).encode("utf-8")
    return len(lzma.compress(data))


class NCDCache:
    """
    Simple in-memory cache for compressed sizes to avoid recompressing identical prototypes.
    Key is bytes object (hashed via id) or explicit string keys.
    """
    def __init__(self):
        self._csize_cache: Dict[bytes, int] = {}

    def csize(self, data: bytes) -> int:
        # bytes are hashed by their value: use small key to avoid big memory overhead
        key = data  # bytes are hashable
        if key in self._csize_cache:
            return self._csize_cache[key]
        c = compress_size(data)
        self._csize_cache[key] = c
        return c

    def ncd(self, x: bytes, y: bytes, cx: int = None, cy: int = None) -> float:
        if cx is None:
            cx = self.csize(x)
        if cy is None:
            cy = self.csize(y)
        cxy = compress_size(x + y)
        return (cxy - min(cx, cy)) / max(cx, cy)
