# Firma digital utilizando RSA
# 2025-02-19
# Joel Saravia
# Anáhuac Mayab

# Import libraries

import Crypto.Util.number
import hashlib

# Fermat 4th number will be used for "e"
e = 65537

# Calculating keys for Alice and Bob
pA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
print("\n", "RSA Public Key for Alice (nA): ", nA)

# Calculating Bob Keys
pB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(1024, randfunc=Crypto.Random.get_random_bytes)
nB = pB * qB
print("\n", "RSA Public Key for Bob (nB): ", nB)

# Calculating Alice's private key
phiA = (pA - 1) * (qA - 1)
dA = Crypto.Util.number.inverse(e, phiA)
print("\n", "Private key for Alice (dA): ", dA)

# Calculating Bob's private key
phiB = (pB - 1) * (qB - 1)
dB = Crypto.Util.number.inverse(e, phiB)
print("\n", "Private key for Bob (dB): ", dB)

# Message
msg = "Hello darkness my old friend"
print("\n", "Msg: ", msg)

# Hash for message
hM = int.from_bytes(hashlib.sha256(msg.encode('UTF-8')).digest(), byteorder='big')
print("\n", "Hash hM: ", hex(hM))

# Sign hash using Alice private key so we can send it to Bob
sA = pow(hM, dA, nA)
print("\n", "Alice signature ", sA)

# Bob verifies Alice's signature using her public key
hM1 = pow(sA, e, nA)
print("\n", "Verifying Alice signature ", hex(hM1))

# Verifying
print("\n", "Is a valid signature? ", hM==hM1, "\n")

