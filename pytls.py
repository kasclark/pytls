#!/usr/bin/env python3

# This script simulates a TLS protected conversation between Alice and Bob. 

# Libraries
import tinyec

# Objects for Alice and Bob
class Person:
    def __init__(self, name):
        self.name = name
    ecdh_key = ""

alice = Person("alice")
bob = Person("bob")




# Step 1: Elliptic Curve Diffie-Hellman exchange to establish a shared secret.
#         This will use the P-256 curve, approved by NIST SP 800-56A Rev 3.




# Step 2: For each chunk of public information sent generate an RSA Digital Signature.

# Step 3: Validate the RSA digital signature of the packets you receive.

# Step 4: Encrypt a message using AES in GCM mode.
