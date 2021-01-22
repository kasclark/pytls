#!/usr/bin/env python3

# This script simulates a TLS protected conversation between Alice and Bob. 

# Libraries
from tinyec import registry
import secrets, binascii, os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from base64 import b64decode,b64encode

# global variables

# Objects for Alice and Bob
class Person:
    def __init__(self, name):
        self.name = name

    def generate_ecc_key_pairs(self, curve):
        self.ecc_private_key = secrets.randbelow(curve.field.n)
        self.ecc_public_key = self.ecc_private_key * curve.g

    def generate_rsa_key_pairs(self):
        self.RSA_keypair = RSA.generate(bits = 1024)

    def generate_ecc_shared_key(self,key):
        self.ecc_shared_key = key * self.ecc_private_key


alice = Person("alice")
bob = Person("bob")

# Establish shared secret using Elliptic Curve Diffie-Hellman.
# This will use the P-256 curve, approved by NIST SP 800-56A Rev 3.
def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def create_ecc_key_pairs():
    curve = registry.get_curve('brainpoolP256r1')
    alice.generate_ecc_key_pairs(curve)
    bob.generate_ecc_key_pairs(curve)
    print("Alice's public ECC key: ", compress(alice.ecc_public_key))
    print("Bob's public ECC key:  ", compress(bob.ecc_public_key))

def exchange_ecc_public_keys():
    # In reality, this would be through the internet...
    alice.generate_ecc_shared_key(bob.ecc_public_key)
    bob.generate_ecc_shared_key(alice.ecc_public_key)
    print("Alice's shared ECC key: ", compress(alice.ecc_shared_key))
    print("Bob's shared ECC key: ", compress(bob.ecc_shared_key))

# Encrypt with AES-GCM and sign with RSA
def encrypt(plain_text, shared_secret):
    cipher = AES.new(shared_secret, AES.MODE_GCM)
    cipher_text = cipher.encrypt(plain_text)
    return (cipher_text, cipher.nonce)

def create_rsa_key_pairs():
    alice.generate_rsa_key_pairs()
    bob.generate_rsa_key_pairs()
    print(f"Alice's public RSA key:  (n={hex(alice.RSA_keypair.n)}, e={hex(alice.RSA_keypair.e)})")
    print(f"Bob's public RSA key:  (n={hex(alice.RSA_keypair.n)}, e={hex(alice.RSA_keypair.e)})")

# Decrypt and verify




    



# Main
print("\nGenerate public/private key pairs and establishing shared secret.")
create_ecc_key_pairs()
create_rsa_key_pairs()
exchange_ecc_public_keys()

print("\nEncrypt and send the message using AES-GCM.")
secret_message = "The attack will happen at dawn!"
print("Alice's message: ", secret_message)
# encrypted_message = encrypt(secret_message, compress(alice.ecc_shared_key))
# print("Encrypted message: ", encrypted_message)


print("\nVerify and decrypt the message.")