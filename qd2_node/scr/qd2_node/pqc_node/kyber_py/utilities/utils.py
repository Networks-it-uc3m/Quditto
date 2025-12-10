"""
Three functions:
- Bit_count: if compatible version of Python is installed, it counts 
the number of bits which value is 1 in a number.

- Xor_bytes: application the XOR gate between two byte arrays 
of the same length.

- Select_bytes: conditional selection between two byte arrays used in
the "implicit rejection" mechanism in the "decaps_internal"algorithm.
This function avoids explicit conditional branches, which is resistant
to timing attacks in cryptography.
"""
import sys

# int.bit_count() was only made available in 3.10
if sys.version_info >= (3, 10):

    def bit_count(x: int) -> int:
        """
        Count the number of bits in x
        """
        return x.bit_count()

else:

    def bit_count(x: int) -> int:
        """
        Count the number of bits in x
        """
        return bin(x).count("1")


def xor_bytes(a, b):
    """
    XOR two byte arrays, assume that they are
    of the same length
    """
    assert len(a) == len(b)
    return bytes(a ^ b for a, b in zip(a, b))


def select_bytes(a, b, cond):
    """
    Select between the bytes a or b depending
    on whether cond is False or True
    """
    assert len(a) == len(b)
    out = [0] * len(a)
    cw = -cond % 256
    for i in range(len(a)):
        out[i] = a[i] ^ (cw & (a[i] ^ b[i]))
    return bytes(out)
