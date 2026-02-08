# PyTLS

A Python simulation of a TLS-like protected conversation between two parties (Alice and Bob).

## What it demonstrates

- **ECDH Key Exchange** (brainpoolP256r1) — Establishes a shared secret between Alice and Bob
- **AES-256-GCM** — Authenticated encryption of messages using the shared secret
- **RSA-PSS (4096-bit)** — Digital signatures for message authentication

## Usage

```bash
pip install -r requirements.txt
python pytls.py
```

## How it works

1. Alice and Bob each generate ECC and RSA key pairs
2. They exchange ECC public keys and derive a shared secret (ECDH)
3. Alice signs her message with RSA-PSS
4. Alice encrypts the message with AES-GCM using the shared secret
5. Bob decrypts using the same shared secret
6. Bob verifies Alice's RSA signature
