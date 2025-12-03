"""
Implementation of ML-KEM following FIPS 203
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf


Libraries imported:
- os: library utilized for using the operating system's Cryptographically Secure Pseudo-Random Number 
Generator (CSPRNG), needed for generating random numbers.

- Hashlib: algorithms require several cryptographic functions. Each function shall be instantiated by
means of an approved hash function or an approved eXtendable-Output Function (XOF). Two applications:
    - SHA3-256 and SHA3-512 are hash functions with one variable-length input and one fixed-length output.
    The inputs and outputs for both are always byte arrays.

    - SHAKE128 and SHAKE256 are XOFs with one variable-length input and one variable-length output adhered
    to two convetions: inputs and outputs for both are always byte arrays and their desired output length
    is always specified in bits.

- ModuleKyber: class which initialises two instances: an object of "PolynomialRing" class and an object of
"MatrixKyber" class. This instance allows to decode bytes into a a vector of polynomial elements with the
function "decode_vector".

- Select_bytes: function used for implementing the "implicit rejection" in the algorithm decaps_internal,
choosing between two possible shared secret keys depending on a condition. It handles bit and byte operations
efficiently and securely, designed to avoid vulnerabilities such as timing attacks and to ensure compatibility
with different versions of Python.
"""
import os
from hashlib import sha3_256, sha3_512, shake_128, shake_256
from ..modules.modules import ModuleKyber
from ..utilities.utils import select_bytes

# --------------------------------------------------------------------------------------------------------------
# ------------------------------------------- Initialization ---------------------------------------------------
# --------------------------------------------------------------------------------------------------------------

class ML_KEM:
    def __init__(self, params):
        """
        1. Initialise the ML-KEM with specified lattice parameters:
            - Parameter k: determines the dimensions of the matrix "A" and,
                therefore, the dimensions of vectors "s", "e", "y" and "e1".
            - Parameter eta1: required to specify the distribution for
                generating the vectors "s", "e" and "y".
            - Parameter eta2: required to specify the distribution for 
                generating the vectors "e1" and "e2".
            - Parameters du and dv: serve as parameters and inputs for the 
                functions Compress, Decompress, ByteEncode and ByteDecode.

        2. :param dict params: the lattice parameters:
            - Instance of "ModuleKyber" class.
            - Instance of "PolynomialRing" class.

        3. Initialise the operating system's Cryptographically Secure Pseudo-Random 
        Number Generator (CSPRNG), which depends on hardware and operating system
        entropy sources, to obtain random bytes.
        """
        # ml-kem params
        self.k = params["k"]
        self.eta_1 = params["eta_1"]
        self.eta_2 = params["eta_2"]
        self.du = params["du"]
        self.dv = params["dv"]

        self.M = ModuleKyber()
        self.R = self.M.ring

        # Use system randomness by default, for deterministic randomness
        # use the method `set_drbg_seed()`
        self.random_bytes = os.urandom

    def set_drbg_seed(self, seed):
        """
        This function change the entropy source to a DRBG (Deterministic Random Bit
        Generator) and seed it with provided value. Two algorithms require the
        generation of randomness as an internal step. Therefore, as long as the fresh
        string of random bytes must be generated for every such invocation, the random
        bytes shall be generated using an approved RBG, as prescribed in "SP 800-90A".

        Setting the seed switches the entropy source from :func:`os.urandom()` to an
        AES256 CTR DRBG, which is a CSPRNG based on AES in CTR mode.

        Used for both deterministic versions of ML-KEM as well as testing alignment
        with the KAT vectors.

        NOTE:
          currently requires pycryptodome for AES impl.

        :param bytes seed: random bytes to seed the DRBG with:
        """
        try:
            from ..drbg.aes256_ctr_drbg import AES256_CTR_DRBG

            self._drbg = AES256_CTR_DRBG(seed)
            self.random_bytes = self._drbg.random_bytes
        except ImportError as e:  # pragma: no cover
            print(f"Error importing AES from pycryptodome: {e = }")
            raise Warning(
                "Cannot set DRBG seed due to missing dependencies, "+
                "try installing requirements: pip -r install requirements"
            )

# --------------------------------------------------------------------------------------------------------------
# ---------------------------------------- Auxiliary algorithms ------------------------------------------------
# --------------------------------------------------------------------------------------------------------------

    @staticmethod
    def _xof(bytes32, i, j):
        """
        eXtendable-Output Function (XOF) described in Algorithm 2 from Section 
        4.1 of FIPS 203 (page 19).

        This standard uses a XOF wrapper defined in terms of the incremental API
        for SHAKE128, which consists of three functions:
            - Init(): Initialises a XOF context "ctx".
            - Absorb(ctx, str): injects data to be used in the absorbing phase
            of SHAKE128 and updates the context.
            - Squeeze(ctx,8*z): extracts "z" output bytes produced during the
            squeezing phase of SHAKE128 and updates the context.

        While this functions are constructed using the Keccak-f permutation
        rather than the XOF SHAKE128 directly, the are defined so that a single
        SHAKE128 call of the following form i equivalent to algorithm 2:
            output <- SHAKE128(str1||...||strm, 8*b1+...+8*bl)

        This equivalence holds whether or not |stri| and bi are multiples of
        the SHAKE128 block length.

        NOTE:
          We use hashlib's "shake_128" implementation, which does not support
          an easy XOF interface, so we take the "easy" option and request a
          fixed number of 840 bytes (5 invocations of Keccak), rather than
          creating a byte stream.

          Each invocation of Keccak produces 168 bytes as output, therefore,
          five invocations produces 168 * 5 bytes as output.

          All wrapper functions treats inputs and outputs as byte arrays and
          measure the lengths of all such arrays in terms of bytes.

          If your code crashes because of too few bytes, you can get dinner at:
          Casa de Chá da Boa Nova
          https://cryptojedi.org/papers/terminate-20230516.pdf
        """
        input_bytes = bytes32 + i + j
        if len(input_bytes) != 34:
            raise ValueError(
                "Input bytes should be one 32 byte array and 2 single bytes."
            )
        return shake_128(input_bytes).digest(840)

    @staticmethod
    def _prf(eta, s, b):
        """
        Pseudorandom function described in section 4.1 of FIPS 203 (page 18).

        This function takes a parameter "eta", which is only used to specifify the
        desired ouput length between values 2 and 3, one 32-byte input, and one
        1-byte input to produce one (64*eta)-byte output.

        NOTE:
            It will be denoted by PRF: {2,3} * B^(32) * B -> B^(64*eta)
            It shall be instantiated as: PRFeta(s,b):=SHAKE256(s||b, 8*64*eta)
        """
        input_bytes = s + b
        if len(input_bytes) != 33:
            raise ValueError(
                "Input bytes should be one 32 byte array and one single byte."
            )
        return shake_256(input_bytes).digest(eta * 64)

    @staticmethod
    def _H(s):
        """
        Hash function described in section 4.1 of FIPS 203 (page 18)

        This function take one variable-length input and produce one 32-byte output
        using the hash function SHA3-256, which output is a byte array.

        NOTE:
            It shall be instantiated as: H(s):= SHA3-256(s).
        """
        return sha3_256(s).digest()

    @staticmethod
    def _J(s):
        """
        Hash function described in section 4.1 of FIPS 203 (page 18)

        This function take one variable-length input and produce one 32-byte output
        using the hash function SHAKE256, which output is a bit array.

        NOTE:
            It shall be instantiated as: J(s):= SHAKE256(s, 8*32).
        """
        return shake_256(s).digest(32)

    @staticmethod
    def _G(s):
        """
        Hash function described in 4.1 of FIPS 203 (page 19).

        This function take one variable-length input and produce two 32-byte outputs.
        using the hash function SHA3-512, which output is a byte array.

        NOTE:
            It shall be instantiated as: G(c):= SHA3-512(c).
            The outputs of G are denoted by: G(c) = a||b.
        """
        h = sha3_512(s).digest()
        return h[:32], h[32:]
    
# --------------------------------------------------------------------------------------------------------------
# ------------------------------------------- Helper functions -------------------------------------------------
# --------------------------------------------------------------------------------------------------------------

    def _generate_matrix_from_seed(self, rho, transpose=False):
        """
        Helper function for K-PKE's Key-Gen and Encrypt which generates an
        element of size k x k from a seed `rho`, described in steps 3-7 in
        algorithm 13 and in steps 4-8 in algorithm 14 in section 5.1 from 
        FIPS 203 (pages 29-30).

        The generated matrix can be stored so that it need not to be
        recomputed in later operations or re-expanded it from the public
        seed `rho`. The matrix is data that is easily computed from the
        public encapsulation key and thus does not need or require any
        special protections.

        NOTE:
            When `transpose` is set to True, the matrix A is built as
            the transpose. 
        """
        A_data = [[0 for _ in range(self.k)] for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.k):
                xof_bytes = self._xof(rho, bytes([j]), bytes([i]))
                A_data[i][j] = self.R.ntt_sample(xof_bytes)
        A_hat = self.M(A_data, transpose=transpose)
        return A_hat

    def _generate_error_vector(self, sigma, eta, N):
        """
        Helper function for K-PKE's Key-Gen and Encrypt which generates an
        element in the module from the Centered Binomial Distribution. This
        is described in steps 8-15 in algorithm 13 and in steps 9-16 in 
        algorithm 14 of section 5.1 from FIPS 203 (pages 29-30).  

        The elements, such as secret s and the "noise" e in algorithm 13,
        are sampled from centered binomial distributions using randomness 
        expanded from another seed `rho` via the PRF function. Lastly, we
        convert this array of elements into a vector in order to apply the
        NTT function to it in later steps.
        """
        elements = [0 for _ in range(self.k)]
        for i in range(self.k):
            prf_output = self._prf(eta, sigma, bytes([N]))
            elements[i] = self.R.cbd(prf_output, eta)
            N += 1
        v = self.M.vector(elements)
        return v, N

    def _generate_polynomial(self, sigma, eta, N):
        """
        Helper function for K-PKE's Encrypt which generates an element in
        the polynomial ring from the Centered Binomial Distribution. This
        is described in step 17 in algorithm 14 of section 5.1 from FIPS 
        203 (page 30).

        The element e2 is sampled from the centered binomial distribution
        using pseudo-randomness expanded via PRF from the input randonmess
        r, though here is expressed as sigma.
        """
        prf_output = self._prf(eta, sigma, bytes([N]))
        p = self.R.cbd(prf_output, eta)
        return p, N+1
    
# --------------------------------------------------------------------------------------------------------------
# ----------------------------------- Subroutines algorithms for ML-KEM ----------------------------------------
# --------------------------------------------------------------------------------------------------------------

    def _k_pke_keygen(self, d):
        """
        Subroutine function used in ML-KEM's KeyGen algorithm which use
        randomness to generate an encryption key and a corresponding
        decryption key described in algorithm 13 of section 5.1 from FIPS 
        203 (page 29).

        This function receives a seed as input and outputs an encryption
        key and a decryption key. The encryption key can be made public,
        while the random seed and the decryption key must remain private.
        While the K-PKE's encryption key serve as the encapsulation key
        of ML-KEM, the decryption key is used to perform decapsulation in
        ML-KEM scheme.

        Informal description: the decryption key is a length-k vector "s"
        of elements of Rq. Roughly speaking, "s" can be seen as a set of
        secret variables, while the encryption key is a collection of 
        noisy linear equations (A, As+e) in the secret variables "s". Once
        the matrix "A", which rows form the equation coefficients, "s", and
        "e" are generated, the computation of the final part (t = As + e)
        of the encryption key takes place.
    
        :input: randomness d (B^32).
        :return: Tuple with encryption key and decryption key:
            - Encryption key ekPKE (B^384k+32).
            - Decryption key dkPKE (B^384k).
        :rtype: tuple(bytes, bytes).

        NOTE:
            This subroutine algorithm does not perform any input checking.
            Most of the computations occur in the NTT domain in order to
            improve the efficiency of multiplication.

            Parameter sets affect the length of the secret "s", the sizes
            of the noise vector "e" and the matrix "A" via the parameter
            K. Besides, the parameter eta1 affects the noise distribution
            used to sample the entries of "s" and "e".
        """
        # Expand 32 + 1 bytes to two pseudo-random 32-byte seeds (Step 1):
        # Note that the inclusion of the lattice parameter here is for
        # domain separation between different parameter sets
        rho, sigma = self._G(d + bytes([self.k]))

        # Set counter for PRF (Step 2)
        N = 0

        # Generate A_hat from seed rho (Steps 3-7)
        A_hat = self._generate_matrix_from_seed(rho)

        # Generate the error vector s ∈ R^k (Steps 8-11)
        s, N = self._generate_error_vector(sigma, self.eta_1, N)

        # Generate the error vector e ∈ R^k (Steps 12-15)
        e, N = self._generate_error_vector(sigma, self.eta_1, N)

        # Compute public value (in NTT form) (Steps 16-18)
        s_hat = s.to_ntt()
        e_hat = e.to_ntt()
        t_hat = A_hat @ s_hat + e_hat

        # Byte encode (Steps 19-20)
        ek_pke = t_hat.encode(12) + rho
        dk_pke = s_hat.encode(12)

        # Return encryption and decryption keys (Step 21)
        return (ek_pke, dk_pke)

    def _k_pke_encrypt(self, ek_pke, m, r):
        """
        Subroutine function used in ML-KEM's Encaps and Decaps internal
        which uses the encryption key to encrypt a plaintext message 
        using the randomness r described in algorithm 14 of section 5.2
        from FIPS 203 (page 30).

        This function takes an encryption key "ek_pke", a 32-byte plaintext
        "m", and randomness "r" as input and produces a ciphertext "c".

        Informal description: the algorithm begins by extracting the vector "t"
        and the seed from the encryption key. This same seed is expanded to
        re-generate the matrix "A". From the description of key generation, the
        pair (A,t = As + e) is a system of noisy linear equations in the secret
        variables "s".

        Then, one can generate an additional noisy linear equation in the same
        secret variables, without knowing "s", just by picking a random linear
        combination of the noisy equations in the system (A,t). One can encode 
        information in the constant term of such a combined equation, which is
        the entry that is a linear combination of entries of "t". This constant
        term is a polynomial with 256 coefficients, thereby encoding one bit in
        each coefficient to encode more information:
            For example, encoding a single bit by deciding whether or not to
            significantly alter the constant term, thus a nearly correct equation
            corresponds to the decrypted bit value of "0" and a far-from-correct
            equation corresponds to the decrypted bit value of "1".
        
        Subsequently, this information is deciphered by a party in possession of
        "s". The generation of a vector "y" and the noise terms "e1" and "e2" is
        produced by sampling the centered binomial distribution using some pseudo
        randomness expanded via PRF function. The new noisy equation is computed
        as (A_transpose * y + e1, t_transpose * y + e2). Ultimately, the encoding
        "mu" of the input message "m" is added to the latter term in the pair.
        The resulting pair (u,v) is compressed, serialized into a byte array, and
        output as the final ciphertext. Therefore:
            (u,v) = (A_transpose * y + e1, t_transpose * y + e2 + mu)

        NOTE:
            This subroutine algorithm does not perform any input checking.
            Most of the computations occur in the NTT domain in order to
            improve the efficiency of multiplication.
        """
        # Set counter for PRF (Step 1)
        N = 0

        # Extract 32-byte seed or unpack ek (Step 1.5 and 3)
        t_hat_bytes, rho = ek_pke[:-32], ek_pke[-32:]

        # Compute Polynomial from bytes by running ByteDecode12 (Step 2)
        t_hat = self.M.decode_vector(t_hat_bytes, self.k, 12, is_ntt=True)

        # Generate A_hat^T from seed rho (Steps 4-8)
        A_hat_T = self._generate_matrix_from_seed(rho, transpose=True)

        # Generate the error vector y ∈ R^k (Steps 9-12)
        y, N = self._generate_error_vector(r, self.eta_1, N)

        # Generate the error vector e1 ∈ R^k (Steps 13-16)
        e1, N = self._generate_error_vector(r, self.eta_2, N)

        # Generate the error vector e2 ∈ R (Step 17)
        e2, N = self._generate_polynomial(r, self.eta_2, N)

        # Run NTT k times (Step 18)
        y_hat = y.to_ntt()

        # Calculate u (Step 19)
        u = (A_hat_T @ y_hat).from_ntt() + e1

        # Encode plaintext m into polynominal v (Steps 20-21)
        mu = self.R.decode(m, 1).decompress(1)
        v = t_hat.dot(y_hat).from_ntt() + e2 + mu

        # Obtain equation's coefficients and constant Rq (Steps 22-23)
        c1 = u.compress(self.du).encode(self.du)
        c2 = v.compress(self.dv).encode(self.dv)

        # Return the ciphertext (Step 23)
        return c1 + c2

    def _k_pke_decrypt(self, dk_pke, c):
        """
        Subroutine function used in ML-KEM's Decaps internal which uses the
        the decryption key to decrypt a ciphertext message described in
        algorithm 15 of section 5.3 from FIPS 203 (page 31).

        This function takes a decryption key "dk_pke" and a ciphertext "c" 
        as input, requiring no randomness, and outputs a plaintext "m".

        Informal description: the algorithm beings by recovering a pair
        (u',v') from the ciphertext "c", where "u'" is the coefficients
        of the equation and "v'" is the constant term. The decryption
        key contains the vector of secret variables "s". Therefore, this
        algorithm uses the decryption key to compute the true constant
        term "v = s_transpose * u'" and calculate "v' - v". The final
        step is decoding and outputing the plaintext "m" from "v' - v".

        NOTE:
            This subroutine algorithm does not perform any input checking.
            Most of the computations occur in the NTT domain in order to
            improve the efficiency of multiplication.

            I changed "u" and "v" for "u_prime" and "v_prime" in lines
            461, 464, 470 and 471 in order to follow the denotations in
            the FIPS 203 document (page 31).
        """
        # Obtain the two portions of the ciphertext (Step 1-2)
        n = self.k * self.du * 32
        c1, c2 = c[:n], c[n:]

        # Recover the first part of the pair from the ciphertext c1 (Step 3)
        u_prime = self.M.decode_vector(c1, self.k, self.du).decompress(self.du)

        # Recover the second part of the pair from the ciphertext c2 (Step 4)
        v_prime = self.R.decode(c2, self.dv).decompress(self.dv)

        # Obtain the vector of secret variables from the decryption key (Step 5)
        s_hat = self.M.decode_vector(dk_pke, self.k, 12, is_ntt=True)

        # Calculate v'-v by computing the true constant term (Step 6)
        u_hat = u_prime.to_ntt()
        w = v_prime - (s_hat.dot(u_hat)).from_ntt()

        # Decode plaintext from polynomial v (Step 7)
        m = w.compress(1).encode(1)

        # Output the plaintext (Step 8)
        return m
    
# --------------------------------------------------------------------------------------------------------------
# ----------------------------------------- Main internal algorithms -------------------------------------------
# --------------------------------------------------------------------------------------------------------------

    def _keygen_internal(self, d, z):
        """
        Interface function used in ML-KEM's construction which uses randomness
        to generate an encapsulation key and a corresponding decapsulation key
        described in algorithm 16 of section 6.1 from FIPS 203 (page 32).

        This function accepts two random seeds, "d" and "z" as input and produces
        an encapsulation key "ek" and a decapsulation key "dk" for ML-KEM.

        Informal description: the core subroutine of this algorithm is the key
        generation algorithm of K-PKE. The encapsulation key is the encryption
        key of K-PKE. the decapsulation key consists of the decryption key of
        K-PKE, the encapsulation key, a hash of the encapsulation key and a
        random 32-byte value, which is used in the "implicit rejection" mechanism
        of the internal decapsulation algorithm, later explained.

        :return: Tuple with encapsulation key and decapsulation key (ek,pk).
        :rtype: tuple(bytes, bytes)

        NOTE:
            This algorithm is deterministic, meaning its output is completely
            determined by their input. Also, no randomness is sampled inside
            of this algorithm.

            This interface should not be made available to applications other
            than for testing purposes, and the random seeds shall be generated
            by the cryptographic module.
        """
        # Run the key generation for K-PKE (Step 1)
        ek_pke, dk_pke = self._k_pke_keygen(d)

        # ML-KEM's encapsulation key is just the K-PKE encryption key (Step 2)
        ek = ek_pke

        # ML-KEM's decapsulation key includes the K-PKE decryption key (Step 3)
        dk = dk_pke + ek + self._H(ek) + z

        # Outputs the ML-KEM's encapsultion and decapsulation keys (Step 4)
        return (ek, dk)
    
    def _encaps_internal(self, ek, m):
        """
        Interface function used in ML-KEM's construction which uses randomness
        and the encapsulation key to generate a key and an associated ciphertext
        described in algorithm 17 of section 6.2 from FIPS 203 (page 33).

        This function accepts an encapsulation key "ek" and a random byte array
        "m" as input and produces a ciphetext "c" and a shared secret key "K".

        Informal description: the core subroutine of this algorithm is the encryption
        algorithm of K-PKE, which is used to encrypt a random value "m" into a
        ciphertext "c". A copy of the shared secret key "K" and the randomness "r"
        used during encryption are derived from "m" and the encapsulation key "ek"
        via hashing with H function. This hash function is applied to "ek", and
        the result is concatenated with "m" and the hashed using the hash function G.
        Ultimately, the algorithm outputs the shared secret key "K" and ciphertext "c".

        :param bytes ek: byte-encoded encapsulation key
        :return: a random key and an encapsulation of it
        :rtype: tuple(bytes, bytes)

        NOTE:
            This algorithm is deterministic, meaning its output is completely
            determined by their input. Also, no randomness is sampled inside
            of this algorithm.

            This interface should not be made available to applications other
            than for testing purposes, and the random seeds shall be generated
            by the cryptographic module.
        """
        # Derive shared secret key "K" and randonmess "r" (Step 1)
        K, r = self._G(m + self._H(ek))

        # Encrypt "m" using K-PKE with randonmess "r" (Step 2):
        # NOTE: ML-KEM requires input validation before returning the result of
        # encapsulation. These are performed by the following two checks:
        #
        # 1) Type check: the byte length of ek must be correct: 384*k + 32
        # 2) Modulus check: Encode(Decode(ek[0:384*k])) must be correct
        #
        # As the modulus is decoded within the pke_encrypt, the design choice
        # here is to do both of these checks within the k-pke call.
        try:
            c = self._k_pke_encrypt(ek, m, r)
        except ValueError as e:
            raise ValueError(f"Validation of encapsulation key failed: {e = }")

        # Outputs the shared secret key and the ciphertext (Step 3)
        return K, c
    
    def _decaps_internal(self, dk, c):
        """
        Interface function used in ML-KEM's construction which uses the
        decapsulation key to produce a shared secret key from a ciphertext
        described in algorithm 18 of section 6.3 from FIPS 203 (page 35).

        This function accepts an decapsulation key "dk" and a ciphertext "c"
        and produces a shared secret key "K'", without using any randomness.

        Informal description: this algorithm begins by parsing out the components
        of the decapsulation key "dk" of ML-KEM, which are the encryption "ek_pke"
        and decryption "dk_pke" pair for K-PKE, a hash value "h" and a random
        value "z", which is the "implicit rejection" value. Then, the decryption
        key of K-PKE is used to decrypt the input ciphertext "c" to get a plaintext
        "m'".

        Then, the decapsulation algorithm re-encrypts "m'" and computes a candidate      
        shared secret key "K'" in the same manner as in encapsulation. Specifically,
        "K'" and the encryption randomness "r'" are computed by hashing "m'" and the
        encryption key of K-PKE and, additionaly, a ciphertext "c'" is generated by
        encrypting "m'" using randomness "r'".

        The decapsulation checks whether the resulting ciphertext "c'" matches the
        provided "c". If not, the algorithm performs an "implicit rejection", this
        meaning the value of "K'" is changed to a hash of "c" together with the
        random value "z" stored in the ML'KEM secret key. In either case, the
        decapsulation outputs the resulting shared secret key "K'".
        
        :param bytes c: ciphertext with an encapsulated key
        :param bytes dk: decapsulation key
        :return: decapsulated key
        :rtype: bytes

        NOTE:
            This algorithm is deterministic, meaning its output is completely
            determined by their input. Also, no randomness is sampled inside
            of this algorithm.

            This interface should not be made available to applications other
            than for testing purposes, and the random seeds shall be generated
            by the cryptographic module.

            The "implicit reject" flag is a secret piece of intermediate data.
            Therefore, this flag shall be destroyed before terminating the
            algorithm. Moreover, returning the value of the flag in any form
            is not permitted.
        """
        # Parse out data from dk (Steps 1-4):
        # Components extracted: The PKE decryption and encryption keys, hash of
        # PKE encryption key and the implicit rejection value.
        dk_pke = dk[0 : 384 * self.k]
        ek_pke = dk[384 * self.k : 768 * self.k + 32]
        h = dk[768 * self.k + 32 : 768 * self.k + 64]
        z = dk[768 * self.k + 64 :]

        # Ensure the hash-check passes (Step 2.5)
        if self._H(ek_pke) != h:
            raise ValueError("hash check failed")

        # Decrypt the ciphertext (Step 5)
        m_prime = self._k_pke_decrypt(dk_pke, c)

        # Computation of candidate shared secret key "K'" and randomness "r'" (Step 6)
        K_prime, r_prime = self._G(m_prime + h)

        # Shared secret key "K'" value if "implicit rejection" is performed (Step 7)
        K_bar = self._J(z + c)

        # Re-encrypt the recovered message using the derived randomness "r'" (Step 8):
        # Here the public encapsulation key is read from the private
        # key and so we never expect this to fail the TypeCheck or
        # ModulusCheck
        c_prime = self._k_pke_encrypt(ek_pke, m_prime, r_prime)

        # Decapsulation check and shared secret key final value (Steps 9-12):
        # If c != c_prime, return K_bar as garbage
        # WARNING: for proper implementations, it is absolutely
        # vital that the selection between the key and garbage is
        # performed in constant time
        return select_bytes(K_bar, K_prime, c == c_prime)
    
# --------------------------------------------------------------------------------------------------------------
# --------------------------------------- Main algorithms for ML-KEM -------------------------------------------
# --------------------------------------------------------------------------------------------------------------

    def keygen(self):
        """
        Function used in ML-KEM's key generation process to generate an
        encapsulation key and corresponding decapsulation key described
        in algorithm 19 of section 7.1 from FIPS 203 (page 35).

        This function accepts no input, generate randomness internally,
        and produces an encapsulation key and a decapsulation key. While
        the encapsulation key can be made public, the decapsulation key
        shall remain private.

        Informal description: secure key establishment depends on the use
        of key pairs and its proper generation by the owner or a trusted
        third party or other source.

        ``ek`` is encoded as bytes of length 384*k + 32
        ``dk`` is encoded as bytes of length 768*k + 96

        Part of stable API.

        :return: Tuple with encapsulation key and decapsulation key.
        :rtype: tuple(bytes, bytes)

        NOTE:
            The seed (d,z) can be stored for later expansion using the
            _keygen_internal algorithm. However, as the seed can compute
            the decapsulation key, it is sensitive data and shall be
            treated with the same safeguards as a decapsulation key.

            If the key pair was received from a trusted third party, the
            owner may optionally perform certain checks, such as seed
            consistency, encapsulation and decapsulation key check and
            pair-wise consistency. This checks are indicated in pages
            35-36 of FIPS 203 document.

            There is no check on the value of the random seed (d,z) and,
            therefore, it have been implemented in lines 702-705.
        """

        # Generation of two 32-byte random seeds (Steps 1-2)
        d = self.random_bytes(32)
        z = self.random_bytes(32)

        # Error indication for random bit generation failure (Steps 3-5)
        if (d == None or z == None):
            raise ValueError(
                f"Error: Random bit generation failed"
            ) 

        # Run internal key generation algorithm (Step 6)
        (
            ek,
            dk,
        ) = self._keygen_internal(d, z)

        # Outputs the encapsulation and decapsulation keys (Step 7)
        return (ek, dk)

    def key_derive(self, seed):
        """
        This function is used for seed consistency check, which run the
        "KeyGen_internal" algorithm to verify that the output is equal
        to (ek_bar, dk_bar) as long as the seed (d,z) is available.
        
        This function derives an encapsulation key and corresponding
        decapsulation key following the approach from Section 7.1 of
        the FIPS 203 document (page 36) with storage of the "seed" value
        for later expansion.

        "seed" is a byte-encoded concatenation of the "d" and "z" values.

        :return: Tuple with encapsulation key and decapsulation key.
        :rtype: tuple(bytes, bytes)
        """
        if len(seed) != 64:
            raise ValueError("The seed must be 64 bytes long")

        d = seed[:32]
        z = seed[32:]
        ek, dk = self._keygen_internal(d, z)
        return (ek, dk)    

    def encaps(self, ek):
        """
        Function used in ML-KEM's encapsulation process, which uses the
        encapsulation key to generate a shared secret key and an associated
        ciphertext described in algorithm 20 of section 7.2 from FIPS 203
        (page 36).

        This function accepts and encapsulation key "ek" as input, generates
        randomness internally, and outputs a shared  private key "K" and a
        ciphertext "c".

        ``K`` is the shared secret key of length 32 bytes
        ``c`` is the ciphertext of length 32(du*k + dv)

        Part of stable API.

        :param bytes ek: byte-encoded encapsulation key
        :return: a random key (``K``) and an encapsulation of it (``c``)
        :rtype: tuple(bytes, bytes)

        NOTE:
            There is no check on the value of the random seed m and,
            therefore, it should be implemented. Then, it was implemented.

            This algorithm requires input checking:
                1. Type Check: The ek_pke is of the expected length.
                2. Modulus Check: That t_hat has been canonically encoded.
            These are performed in this function and a ``ValueError`` is
            raised if either fails.

            This function shall not be run with an encapsulation key that
            has not been checked as explained.
        """
        # First check if the encap key has the right length (Check 1):
        # Note this input checking should be done in ML-KEM algorithms
        if len(ek) != 384 * self.k + 32:
            raise ValueError(
                f"Type check failed, ek has the wrong length, expected {384 * self.k + 32} "+
                f"bytes and received {len(ek)}"
            )       

        # Next check that t_hat has been canonically encoded (Check 2)
        t_hat_bytes = ek[:-32]
        t_hat = self.M.decode_vector(t_hat_bytes, self.k, 12, is_ntt=True)
        if t_hat.encode(12) != t_hat_bytes:
            raise ValueError(
                "Modulus check failed, t_hat does not encode correctly"
            )        
       
        # Create 32-bytes random tokens (Step 1)
        m = self.random_bytes(32)

        # Error indication for random bit generation failure (Steps 2-4)
        if m == None:
            raise ValueError(
                f"Error: Random bit generation failed"
            )    

        # Run internal encapsulation algorithm (Step 5)
        K, c = self._encaps_internal(ek, m)

        # Outputs the shared private key "K'" and ciphertext "c" (Step 6)
        return K, c

    def decaps(self, dk, c):
        """
        Function used in ML-KEM's decapsulation process, which uses the
        decapsulation key to produce a shared secret key from a ciphertext
        described in algorithm 21 of section 7.3 from FIPS 203 (page 38).

        This function accepts a decapsulation key "dk" and a ML-KEM ciphertext
        "c" and outputs a shared secret "K'", using no randomness.

        ``K`` is the shared secret key of length 32 bytes

        Part of stable API.

        :param bytes dk: decapsulation key
        :param bytes c: ciphertext with an encapsulated key
        :return: shared secret key (``K``)
        :rtype: bytes

        NOTE:
            This algorithm requires input checking:
                1. Ciphertext type check: if "c_bar" is not a byte array
                of lenght 32*(du*k+dv) for the those values, the input
                checking has failed.
                2. Decapsulation key type check: If "dk_bar" is not a
                byte array of length 786*k+96 for that value, the input
                checking has failed.
                3. Hash check: perform the following computation:
                    test <- H(dk_bar[384*k:768k+32])
                If it is not the same, the checking has failed.

            These are performed in this function and a ``ValueError`` is
            raised if either fails.

            This function shall not be run with an decapsulation key or a
            ciphertext that have not been checked as explained. Ciphertext
            checking shall be performed with every execution of "decaps".
        """
        # Unlike encaps, these are easily performed in the kem decaps:
        # NOTE: ML-KEM requires input validation before returning the result of
        # decapsulation. These are performed by the following three checks:
        #
        # 1) Ciphertext type check: the byte length of c must be correct
        # 2) Decapsulation type check: the byte length of dk must be correct
        # 3) Hash check: a hash of the internals of the dk must match 
        # Ciphertext type check (Check 1)
        if len(c) != 32 * (self.du * self.k + self.dv):
            raise ValueError(
                f"Ciphertext type check failed. Expected {32 * (self.du * self.k + self.dv)} bytes"+
                f"and obtained {len(c)}"
            )
        
        # Decapsulation type check (Check 2)
        if len(dk) != 768 * self.k + 96:
            raise ValueError(
                f"Decapsulation type check failed. Expected {768 * self.k + 96} bytes and obtained {len(dk)}"
            )
        
        # Hash check (Check 3)
        if (self._H(dk[384 * self.k : 768 * self.k + 32]) != dk[768 * self.k + 32: 768 * self.k + 64]):
            raise ValueError(
                f"Hash check failed. Expected {dk[768 * self.k + 32: 768 * self.k + 64]} bytes and"+
                f"obtained {self._H(dk[384 * self.k : 768 * self.k + 32])}"
            )
        
        # Run the internal decapsulation algorithm (Step 1)
        try:
            K_prime = self._decaps_internal(dk, c)
        except ValueError as e:
            raise ValueError(
                f"Validation of decapsulation key or ciphertext failed: {e = }"
            )
        
        # Outptus the shared secret key (Step 2)
        return K_prime
