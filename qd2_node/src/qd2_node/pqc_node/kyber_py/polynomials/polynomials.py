"""
The mathematical structure of the Number-Theoretic
Transform (NTT) used in the "ML-KEM" is described 
in the section 4.3 of the FIPS 203 (page 24). This
version of the discrete Fourier transform is used to
improve the efficiency of multiplication in the ring.
"""
from ..utilities.utils import bit_count
from .polynomials_generic import PolynomialRing, Polynomial

class PolynomialRingKyber(PolynomialRing):
    """
    This function initialises the polynomial ring "Rq":
        R = GF(q) / (X^n + 1) = GF(3329) / (X^256 + 1)

    Informal description: it defines two important constants
    for the ML-KEM scheme, "q" and "n", and two polynomial
    elements, one being a polynomial (f E Rq) and the other
    being an alternative representation in the NTT domain.
    Also, the root of unity "zeta" is defined. In order to
    calculate the polynomial X^256 + 1 factors into 128 of
    degree 2 modulo "q", the following value is calculated
    and stored in the variable "ntt_zetas":
        ntt_zetas = zeta^(2*BitRev7(i))

    NOTE:  
        As specified in the document, there are two constants:
        q = 3329 = (2^8)*13 + 1 and n = 256. Also, there are 128
        primitives 256-th roots of unity and no primitive 512-th
        roots of unity in "Zq". This root of  unity, denoted by
        "zeta" with value 17 (zeta = 17 E Zq), is a primitive
        256-th root of unity modulo "q".

        The variable "ntt_f" is used in "fromNTT" function and
        it is defined in step 14 of algorithm 10 (page 26):
            ntt_f = (128^-1) mod q = 3303
    """
    def __init__(self):
        self.q = 3329
        self.n = 256
        self.element = PolynomialKyber
        self.element_ntt = PolynomialKyberNTT

        root_of_unity = 17
        self.ntt_zetas = [
            pow(root_of_unity, self._br(i, 7), 3329) for i in range(128)
        ]

        self.ntt_f = pow(128, -1, 3329)

    """
    This function does a bit reversal of an unsigned k-bit integer.
    Specifically, it is used to obtain the integer represented by
    bit-reversing the unsigned 7-bit value that corresponds to the
    input integer i E {0,...,127}.

    NOTE:
        BitRev7(i) does a bit reversal of a seven bit-integer "k".
        Specifically, if k = k0 + 2*k1 + 4*k2+...+ 64*k6 with
        ki E {0,1}, the BitRev7(k) = k6 + 2*k5 + 4*k4 +...+ 64*k0.
    """
    @staticmethod
    def _br(i, k):
        bin_i = bin(i & (2**k - 1))[2:].zfill(k)
        return int(bin_i[::-1], 2)

    """
    The function "SampleNTT" is described in algorithm 7 of section
    4.2.2 from FIPS 203 (page 23) and in algorithm 1 of section 1.1
    from CRYSTALS-KYBER's algorithm specifications and supporting
    documentation version 3.02 (page 6):
        https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf

    This function converts a 32-byte seed together with two indexing
    bytes into a pseudorandom element or polynomial in the NTT domain.
    If the seed is uniformly random, the resulting polynomial will be
    drawn from a distribution that is computationally indistinguishable
    from the uniform distribution on "Tq". Therefore, the output of
    this function is an array in  "Zq^256" that contains the coefficients
    of the sampled element of "Tq".

    NOTE:
        The algorithm implemented is the second mentioned before. This
        function uses a deterministic approach to sample elements in "Rq"
        that are statistically close to a uniformly random  distribution.
        For this sampling we use a function Parse: B* -> Rq, which 
        receives as input a byte stream B = b0,b2,b2,... and computes the
        NTT-representation a = a0 + a1*X +...+ an-1*X^n-1 E Rq of a E Rq.

        This function probably should be substituted with the algorithm
        described in the FIPS 203 standard [!].

        I changed "3329" for "self.q" in lines 106 and 111.
    """
    def ntt_sample(self, input_bytes):
        
        # Definition of two indexing bytes (Steps 1-2)
        i, j = 0, 0

        # Definition of the NTT-representation output (Step 2.5)
        coefficients = [0 for _ in range(self.n)]

        # While loop (Step 3)
        while j < self.n:

            # (Steps 4-5)
            d1 = input_bytes[i] + 256 * (input_bytes[i + 1] % 16)
            d2 = (input_bytes[i + 1] // 16) + 16 * input_bytes[i + 2]

            # (Steps 6-9)
            if d1 < self.q:
                coefficients[j] = d1
                j = j + 1

            # (Steps 10-13)
            if d2 < self.q and j < self.n:
                coefficients[j] = d2
                j = j + 1

            # (Steps 14)
            i = i + 3

        # Outputs the NTT-representantion "a_hat" (Steps 15)
        return self(coefficients, is_ntt=True)

    """
    The function "SamplePolyCBD" is described in algorithm 8 of section
    4.2.2 from FIPS 203 (page 23) and in algorithm 2 of section 1.1
    from CRYSTALS-KYBER's algorithm specifications and supporting
    documentation version 3.02 (page 7).

    This function takes a seed as input and outputs a pseudorandom
    sample from the distribution "D_eta(Rq)" by the coefficient array
    of a polynomial f E Rq.
    
    For sampling from the centered binomial distribution, this scheme
    use a special distribution "D_eta(Rq)" of polynomials in Rq with
    small coefficients, which are referred to as "errors" or "noise".
    This distribution is parametrized by an integer "eta" E{2,3}. To
    sample a polynomial from "D_eta(Rq)", each of its coefficients is
    independently sampled from a certain centered binomial distribution.
    
    NOTE:
        It expects a byte array of length (eta * deg/4). For Kyber,
        this is 64 eta.

        This function probably should be substituted with the algorithm
        described in the FIPS 203 standard [!].
    """
    def cbd(self, input_bytes, eta, is_ntt=False):
        # Byte array B length checking (Step 0)
        assert 64 * eta == len(input_bytes)

        # Definition of the coefficients of the sampled polynomial output (Step 0.5)
        coefficients = [0 for _ in range(256)]

        # Turn of bytes to bits (Step 1):
        # The line (1 << eta) is equivalent to 2^eta.
        b_int = int.from_bytes(input_bytes, "little")
        mask1 = (1 << eta) - 1
        mask2 = (1 << 2 * eta) - 1

        # Loop to optain the coefficients (Steps 2-6)
        for i in range(256):
            x = b_int & mask2
            a = bit_count(x & mask1)
            b = bit_count((x >> eta) & mask1)
            b_int >>= 2 * eta

            # Obtain the correspondent coefficient with modulo "q" (Step 5)
            coefficients[i] = (a - b) % 3329

        # Output the coefficients of the sampled polynomial (Step 7)
        return self(coefficients, is_ntt=is_ntt)

    """
    The function "ByteDecode" is described in algorithm 6 of section
    4.2.1 from FIPS 203 (page 22) and in algorithm 3 of section 1.1
    from CRYSTALS-KYBER's algorithm specifications and supporting
    documentation version 3.02 (page 7).
    
    This function converts an array of bytes into an array of integers
    modulo "m". In other words, it decodes a byte array into an array
    of d-bit integers for 1 <= d <= 12.

    The operations are performed in two different ways, depending on
    the value of "d":
        - For 1 <= d <= 11, the conversion is one-to-one, thereby
        converting each d-bit segment of its input into one integer
        modulo "2^d".
        - For d = 12, this function produces integers modulo "q" as
        output, converting each 12-bit segment of its input into an
        integer modulo 2^12 = 4096 and then reduces the result modulo
        "q". Then, this is no longer a one-on-one operation. Indeed,
        some 12-bit segments could correspond to an integer greater
        than q-1 = 3328 but less than 4096.
    """
    def decode(self, input_bytes, d, is_ntt=False):
        # Ensure the value d is set correctly (Step 0)
        if 256 * d != len(input_bytes) * 8:
            raise ValueError(
                f"input bytes must be a multiple of (polynomial degree) / 8,"+
                f" {256*d = }, {len(input_bytes)*8 = }"
            )

        # Set the modulus depending on "d" (Step 0.1)
        if d == 12:
            m = 3329
        else:
            m = 1 << d

        # Definition of the integer array output (Step 0.2)
        coeffs = [0 for _ in range(256)]

        # Turn of bytes to bits (Step 1)
        b_int = int.from_bytes(input_bytes, "little")
        mask = (1 << d) - 1

        # Obtain the coefficients of the integer array (Steps 2-4)
        for i in range(256):
            coeffs[i] = (b_int & mask) % m
            b_int >>= d

        # Outputs the integer array output (Step 5)
        return self(coeffs, is_ntt=is_ntt)

    def __call__(self, coefficients, is_ntt=False):
        if not is_ntt:
            element = self.element
        else:
            element = self.element_ntt

        if isinstance(coefficients, int):
            return element(self, [coefficients])
        if not isinstance(coefficients, list):
            raise TypeError(
                f"Polynomials should be constructed from a list of integers, of length at most n = {256}"
            )
        return element(self, coefficients)


class PolynomialKyber(Polynomial):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    """
    The function "ByteEncode" is described in algorithm 5 of section
    4.2.1 from FIPS 203 (page 22) and in algorithm 3 of section 1.1
    from CRYSTALS-KYBER's algorithm specifications and supporting
    documentation version 3.02 (page 7), in its reverse version.

    This function conver an array of n=256 integers modulo "m" into
    a corresponding array of bytes. In other words, it encodes an
    array of d-bit integers into a byte array for 1 <= d <= 12.

    The operations are performed in two different ways, depending on
    the value of "d":
        - For 1 <= d <= 11, the conversion is one-to-one, thereby
        converting each d-integer modulo "q" into one bit segment.
        - For d = 12, this function receives integers modulo "q"
        as input.

    NOTE:
        This function probably should be substituted with the algorithm
        described in the FIPS 203 standard [!].
    """
    def encode(self, d):
        t = 0
        for i in range(255):
            t |= self.coeffs[256 - i - 1]
            t <<= d
        t |= self.coeffs[0]

        # Outputs the byte array after converting it (Step 9)
        return t.to_bytes(32 * d, "little")

    """
    This function computes round((2^d / q) * x) % 2^d
    """
    def _compress_ele(self, x, d):
        t = 1 << d
        y = (t * x + 1664) // 3329  # 1664 = 3329 // 2
        return y % t

    """
    This function computes round((q / 2^d) * x)
    """
    def _decompress_ele(self, x, d):
        t = 1 << (d - 1)
        y = (3329 * x + t) >> d
        return y

    """
    This function compresses the polynomial by compressing
    each coefficient.

    NOTE:
        This is lossy compression
    """
    def compress(self, d):
        self.coeffs = [self._compress_ele(c, d) for c in self.coeffs]
        return self

    """
    This function decompresses the polynomial by decompressing
    each coefficient.

    NOTE: 
        This as compression is lossy, we have 
        x' = decompress(compress(x)), which
        x' != x, but is close in magnitude.
    """
    def decompress(self, d):
        self.coeffs = [self._decompress_ele(c, d) for c in self.coeffs]
        return self

    """
    This function converts a polynomial to number-theoretic transform (NTT)
    form described in algorithm 9 of section 4.3 from FIPS 203 (page 26).
    The input is in standard order, the output is in bit-reversed order.

    This function computes the NTT representation "f_hat" of the given
    polynomial f E Rq. Therefore, it is used to transform elements "Rq"
    to elements "Tq". In other words, this function maps matrices or
    vectors with entries in "Rq" to matrices or vectors with entries in "Tq".
    """
    def to_ntt(self):
        # Compute in place on a copy of input array (Step 1):
        # The values of "zetas" is precomputed into an array.
        coeffs = self.coeffs
        zetas = self.parent.ntt_zetas

        # Define variables "i" and "len" for the first loop (Step 2)
        i, len = 1, 128

        # First loop of the code (Step 3)
        while len >= 2:
            start = 0

            # Second loop of the code (Steps 4-6)
            while start < 256:
                zeta = zetas[i]
                i = i + 1

                # Third loop of the code (Step 7 - 11)
                for j in range(start, start + len):
                    t = zeta * coeffs[j + len]
                    coeffs[j + len] = coeffs[j] - t
                    coeffs[j] = coeffs[j] + t
                start = len + (j + 1)
            len = len >> 1

        # Coefficients modulo "q"
        for j in range(256):
            coeffs[j] = coeffs[j] % 3329

        # Return the coefficients of the NTT of the input polynomial (Step 14)
        return self.parent(coeffs, is_ntt=True)

    """
    This function is not supported, raises a "TypeError".
    """
    def from_ntt(self):
        raise TypeError(f"Polynomial not in the NTT domain: {type(self) = }")


class PolynomialKyberNTT(PolynomialKyber):
    def __init__(self, parent, coefficients):
        self.parent = parent
        self.coeffs = self._parse_coefficients(coefficients)

    """
    This function is not supported, raises a "TypeError".
    """
    def to_ntt(self):
        raise TypeError(
            f"Polynomial is already in the NTT domain: {type(self) = }"
        )

    """
    This function converts a polynomial from number-theoretic transform (NTT)
    form described in algorithm 10 of section 4.3 from FIPS 203 (page 26).
    The input is in bit-reversed order, the output is in standard order.

    This function computes the polynomial f E Rq that corresponds to the
    given NTT representation f_hat E Tq. Therefore, it is used to transform
    elements "Tq" to elements "Rq".  In other words, this function maps
    matrices or vectors with entries in "Tq" to matrices or vectors with
    entries in "Rq".

    This function computes the NTT representation "f_hat" of the given
    polynomial f E Rq. Therefore, it is used to transform elements "Rq"
    to elements "Tq". In other words, this function maps matrices or
    vectors with entries in "Rq" to matrices or vectors with entries in "Tq".

    NOTE:
        This function should be checked in order to ensure its correct
        functionality. I have some doubts about the third loop (steps 8-10)
        and with how the variable "start" is managed (line 426).
    """
    def from_ntt(self):
        # Compute in place on a copy of input array (Step 1):
        # The values of "zetas" is precomputed into an array.
        coeffs = self.coeffs
        zetas = self.parent.ntt_zetas

        # Define variables "i" and "len" for the first loop (Step 2)
        len, len_upper = 2, 128
        i = len_upper - 1
        
        # First loop of the code (Step 3)
        while len <= 128:
            start = 0

            # Second loop of the code (Step 4)
            while start < 256:
                zeta = zetas[i]
                i = i - 1
                
                # Third loop of the code (Step 7)
                for j in range(start, start + len):
                    t = coeffs[j]
                    coeffs[j] = t + coeffs[j + len]
                    coeffs[j + len] = coeffs[j + len] - t
                    coeffs[j + len] = zeta * coeffs[j + len]

                # This line should be equivalent to (start + 2*len)
                start = j + len + 1
            len = len << 1

        # Multiple every entry by "ntt_f" and apply modulo "q" (Step 14)
        f = self.parent.ntt_f
        for j in range(256):
            coeffs[j] = (coeffs[j] * f) % 3329

        # Return the coefficients of the inverse NTT of the input (Step 15)
        return self.parent(coeffs, is_ntt=False)

    """
    This algorithm, which has two different coefficients
    as input and ouputs the modulus "X^2-zeta" is described
    in algorithm 12 of section 4.3.1 from FIPS 203 (page 27).

    This function computes the product of two degree-one
    polynomials with respect to a quadratic modulus.
    """
    @staticmethod
    def _ntt_base_multiplication(a0, a1, b0, b1, zeta):
        # The coefficients of the product of the two polynomials (Steps 1-2)
        r0 = (a0 * b0 + zeta * a1 * b1) % 3329
        r1 = (a1 * b0 + a0 * b1) % 3329

        # Output the coefficients in modulo "q" (Step 3)
        return r0, r1

    """
    This function is described in algorithm 11 of section 4.3.1
    from FIPS 203 (page 27).

    The multiplication in the ring "Rq" consists of independent
    multiplication in each of the 128 coordinates with respect
    to the quadratic modulus of that coordinate. Specifically,
    the i-th coordinate in "Tq" of the product:
        h_hat = f x {Tq}g_hat
    This product is determined by the calculation:
        h[2i]+h[2i+1]X = (f[2i]+f[2i+1]X)(g[2i]+g[2i+1]X) mod (X^2 - zeta^(2BitRev7(i)+1))
    """
    def _ntt_coefficient_multiplication(self, f_coeffs, g_coeffs):
        # Definition of coefficients for outputs and zeta coefficients (Step 0)
        new_coeffs = []
        zetas = self.parent.ntt_zetas

        # Calculation of the multiplication in the ring "tq" (Steps 1-3)
        for i in range(64):
            r0, r1 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 0],
                f_coeffs[4 * i + 1],
                g_coeffs[4 * i + 0],
                g_coeffs[4 * i + 1],
                zetas[64 + i],
            )
            r2, r3 = self._ntt_base_multiplication(
                f_coeffs[4 * i + 2],
                f_coeffs[4 * i + 3],
                g_coeffs[4 * i + 2],
                g_coeffs[4 * i + 3],
                -zetas[64 + i],
            )
            new_coeffs += [r0, r1, r2, r3]

        # Outputs the coefficients of the product of the inputs (Step 4)
        return new_coeffs

    """
    Number-Theoretic Transform (NTT) multiplication using the
    two previous functions defined "_ntt_base_multiplication"
    and "_ntt_coefficient_multiplication".
    """
    def _ntt_multiplication(self, other):
        new_coeffs = self._ntt_coefficient_multiplication(
            self.coeffs, other.coeffs
        )
        return new_coeffs

    def __add__(self, other):
        new_coeffs = self._add_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __sub__(self, other):
        new_coeffs = self._sub_(other)
        return self.parent(new_coeffs, is_ntt=True)

    def __mul__(self, other):
        if isinstance(other, type(self)):
            new_coeffs = self._ntt_multiplication(other)
        elif isinstance(other, int):
            new_coeffs = [(c * other) % 3329 for c in self.coeffs]
        else:
            raise NotImplementedError(
                f"Polynomials can only be multiplied by each other, or scaled by integers, {type(other) = }, {type(self) = }"
            )
        return self.parent(new_coeffs, is_ntt=True)
