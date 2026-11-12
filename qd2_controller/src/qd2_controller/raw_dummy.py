import sys
import json
import numpy as np

n = int(sys.argv[1])           # number of rounds requested
# sys.argv[2] = link length, sys.argv[3] = params yaml (unused in the dummy)

rng = np.random.default_rng()
alice_bits = rng.integers(0, 2, n)
alice_bases = rng.integers(0, 2, n)   # 0 = Z, 1 = X
bob_bases = rng.integers(0, 2, n)
bob_bits = np.where(alice_bases == bob_bases, alice_bits, rng.integers(0, 2, n))

to_s = lambda a: "".join(map(str, a.tolist()))

print(json.dumps({
    "alice_bits": to_s(alice_bits),
    "alice_bases": to_s(alice_bases),
    "bob_bits": to_s(bob_bits),
    "bob_bases": to_s(bob_bases),
    "time": 0.0
}))