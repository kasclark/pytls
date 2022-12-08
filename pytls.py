#!/usr/bin/env python3

# This script simulates a TLS protected conversation between Alice and Bob. 

# Libraries
from tinyec import registry
import secrets, binascii, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from hashlib import sha256
from Crypto.Hash import SHA256
from Crypto.Signature import pss
from Crypto import Random

# Objects for Alice and Bob
class Person:
    def __init__(self, name):
        self.name = name

    def generate_ecc_key_pairs(self, curve):
        self.ecc_private_key = secrets.randbelow(curve.field.n)
        self.ecc_public_key = self.ecc_private_key * curve.g

    def generate_rsa_key_pairs(self):
        self.RSA_keypair = RSA.generate(bits = 4096)

    def generate_ecc_shared_key(self,key):
        self.ecc_shared_key = key * self.ecc_private_key

# global variables
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

def exchange_ecc_public_keys():
    # In reality, this would be through the internet...
    alice.generate_ecc_shared_key(bob.ecc_public_key)
    bob.generate_ecc_shared_key(alice.ecc_public_key)

# Encrypt with AES-GCM
def encrypt(plain_text, shared_secret):
    aes_key = sha256(int.to_bytes(shared_secret.x, 32, 'big'))
    aes_key.update(int.to_bytes(shared_secret.y, 32, 'big'))
    cipher = AES.new(aes_key.digest(), AES.MODE_GCM)
    cipher_text = cipher.encrypt(plain_text.encode())
    return (cipher_text, cipher.nonce)

# Generate RSA keypairs
def create_rsa_key_pairs():
    alice.generate_rsa_key_pairs()
    bob.generate_rsa_key_pairs()

# RSA sign the message
def sign(message, key):
    h = SHA256.new(message.encode())
    signature = pss.new(key).sign(h)
    return signature

# Decrypt with AES-GCM
def decrypt(encrypted_message, shared_secret):
    (cipher_text, nonce) = encrypted_message
    aes_key = sha256(int.to_bytes(shared_secret.x, 32, 'big'))
    aes_key.update(int.to_bytes(shared_secret.y, 32, 'big'))
    cipher = AES.new(aes_key.digest(), AES.MODE_GCM, nonce)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text

# Verify with RSA
def verify(message, signature):
    h = SHA256.new(message.encode())
    verifier = pss.new(alice.RSA_keypair)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


# Main
print("\nALICE and BOB both generate ECC and RSA public/private key pairs and establish a shared secret.")
create_ecc_key_pairs()
create_rsa_key_pairs()
exchange_ecc_public_keys()
print("Alice's public ECC key:", compress(alice.ecc_public_key))
print("Bob's public ECC key: ", compress(bob.ecc_public_key))
print("Alice's shared ECC key:", compress(alice.ecc_shared_key))
print("Bob's shared ECC key:", compress(bob.ecc_shared_key))
print(f"Alice's public RSA key:  (n={hex(alice.RSA_keypair.n)}, e={hex(alice.RSA_keypair.e)})")
print(f"Bob's public RSA key:  (n={hex(alice.RSA_keypair.n)}, e={hex(alice.RSA_keypair.e)})")

secret_message = "The attack will happen at dawn!"
print("Alice's message:", secret_message)
print("\nALICE signs it with RSA.")
signature = sign(secret_message, alice.RSA_keypair)
print("Signature:", signature)
print("\nALICE encrypts the message using AES-GCM.")
encrypted_message = encrypt(secret_message, alice.ecc_shared_key)
print("Encrypted message: ", encrypted_message)

print("\nALICE sends the message and signature to Bob...")

print("\nBOB decrypts the AES message.")
decrypted_text = decrypt(encrypted_message, bob.ecc_shared_key)
print("Bob receives:", decrypted_text.decode())
print("\nBOB verifies the RSA signature.")
if(verify(decrypted_text.decode(),signature)):
    print("Signature is valid.")
else:
    print("Signature if invalid!")


