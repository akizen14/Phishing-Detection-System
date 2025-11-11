"""
Normalized Compression Distance (NCD) computation using LZMA compression.

NCD measures similarity between two byte sequences by comparing their compressed sizes.
Lower NCD values indicate higher similarity.
"""
import lzma
from functools import lru_cache


@lru_cache(maxsize=10000)
def C(x: bytes) -> int:
    """
    Compute compressed size of bytes using LZMA compression.
    Results are cached for performance.
    
    Args:
        x: Bytes to compress
        
    Returns:
        Compressed size in bytes
    """
    return len(lzma.compress(x))


def ncd(x: bytes, y: bytes) -> float:
    """
    Compute Normalized Compression Distance between two byte sequences.
    
    NCD(x,y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))
    
    Where:
    - C(x) is the compressed size of x
    - C(xy) is the compressed size of concatenated x and y
    
    Args:
        x: First byte sequence
        y: Second byte sequence
        
    Returns:
        NCD value between 0 and 1+ (lower = more similar)
    """
    cx = C(x)
    cy = C(y)
    cxy = C(x + y)
    return (cxy - min(cx, cy)) / max(cx, cy)
