#!/usr/bin/env python3
"""
aescrypt.py - Passphrase-based file encryption/decryption CLI tool.

Uses AES-256-GCM (authenticated encryption) with a key derived from a
user-supplied passphrase via PBKDF2-HMAC-SHA256.

This is an educational tool. Do NOT use it to protect anything you truly
care about -- use a well-reviewed, battle-tested tool such as `age` or
`gpg` for real-world sensitive data. See README.md for details on the
file format and design rationale.

Usage:
    python aescrypt.py encrypt <input> <output> [--passphrase PASS]
    python aescrypt.py decrypt <input> <output> [--passphrase PASS]
"""

import argparse
import getpass
import os
import struct
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

__version__ = "0.1.0"

MAGIC = b"AESC"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 390_000

# File format (all integers big-endian):
#   4 bytes  magic         b"AESC"
#   1 byte   version       0x01
#   1 byte   kdf id        0x01 = PBKDF2-HMAC-SHA256
#   4 bytes  kdf iterations
#   16 bytes salt
#   12 bytes nonce (GCM IV)
#   N bytes  ciphertext (includes the 16-byte GCM authentication tag
#            appended at the end, as produced by AESGCM.encrypt)
HEADER_STRUCT = struct.Struct(">4sBBI16s12s")
KDF_PBKDF2 = 1


class DecryptionError(Exception):
    """Raised when decryption fails due to a bad passphrase or tampering."""


def derive_key(passphrase: bytes, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase)


def encrypt_bytes(plaintext: bytes, passphrase: bytes) -> bytes:
    """Encrypt plaintext with a fresh random salt and nonce. Returns full file bytes."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    header = HEADER_STRUCT.pack(MAGIC, VERSION, KDF_PBKDF2, PBKDF2_ITERATIONS, salt, nonce)
    return header + ciphertext


def decrypt_bytes(data: bytes, passphrase: bytes) -> bytes:
    """Decrypt file bytes produced by encrypt_bytes. Raises DecryptionError on failure."""
    if len(data) < HEADER_STRUCT.size:
        raise DecryptionError("File is too short to be a valid encrypted file.")

    header = data[: HEADER_STRUCT.size]
    ciphertext = data[HEADER_STRUCT.size :]

    magic, version, kdf_id, iterations, salt, nonce = HEADER_STRUCT.unpack(header)

    if magic != MAGIC:
        raise DecryptionError("Not a recognized aescrypt file (bad magic bytes).")
    if version != VERSION:
        raise DecryptionError(f"Unsupported file format version: {version}")
    if kdf_id != KDF_PBKDF2:
        raise DecryptionError(f"Unsupported KDF id: {kdf_id}")
    if len(ciphertext) < 16:
        raise DecryptionError("Ciphertext is too short to contain a valid auth tag.")

    key = derive_key(passphrase, salt, iterations)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong passphrase or corrupted/tampered file."
        ) from exc
    return plaintext


def _get_passphrase(args, confirm: bool) -> bytes:
    if args.passphrase is not None:
        if not args.passphrase:
            print(
                "Error: passphrase must not be empty "
                "(--passphrase '' provides no protection).",
                file=sys.stderr,
            )
            sys.exit(1)
        return args.passphrase.encode("utf-8")
    passphrase = getpass.getpass("Passphrase: ")
    if confirm:
        confirm_pass = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm_pass:
            print("Error: passphrases do not match.", file=sys.stderr)
            sys.exit(1)
    if not passphrase:
        print("Error: passphrase must not be empty.", file=sys.stderr)
        sys.exit(1)
    return passphrase.encode("utf-8")


def cmd_encrypt(args) -> int:
    passphrase = _get_passphrase(args, confirm=(args.passphrase is None))
    try:
        with open(args.input, "rb") as f:
            plaintext = f.read()
    except OSError as exc:
        print(f"Error reading input file: {exc}", file=sys.stderr)
        return 1

    output_bytes = encrypt_bytes(plaintext, passphrase)

    try:
        with open(args.output, "wb") as f:
            f.write(output_bytes)
    except OSError as exc:
        print(f"Error writing output file: {exc}", file=sys.stderr)
        return 1

    print(f"Encrypted '{args.input}' -> '{args.output}' ({len(output_bytes)} bytes).")
    return 0


def cmd_decrypt(args) -> int:
    passphrase = _get_passphrase(args, confirm=False)
    try:
        with open(args.input, "rb") as f:
            data = f.read()
    except OSError as exc:
        print(f"Error reading input file: {exc}", file=sys.stderr)
        return 1

    try:
        plaintext = decrypt_bytes(data, passphrase)
    except DecryptionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        with open(args.output, "wb") as f:
            f.write(plaintext)
    except OSError as exc:
        print(f"Error writing output file: {exc}", file=sys.stderr)
        return 1

    print(f"Decrypted '{args.input}' -> '{args.output}' ({len(plaintext)} bytes).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aescrypt.py",
        description="Encrypt/decrypt files with AES-256-GCM using a passphrase.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    enc = subparsers.add_parser("encrypt", help="Encrypt a file.")
    enc.add_argument("input", help="Path to the plaintext input file.")
    enc.add_argument("output", help="Path to write the encrypted output file.")
    enc.add_argument(
        "--passphrase",
        help="Passphrase (for scripting/tests). If omitted, you will be prompted.",
    )
    enc.set_defaults(func=cmd_encrypt)

    dec = subparsers.add_parser("decrypt", help="Decrypt a file.")
    dec.add_argument("input", help="Path to the encrypted input file.")
    dec.add_argument("output", help="Path to write the decrypted output file.")
    dec.add_argument(
        "--passphrase",
        help="Passphrase (for scripting/tests). If omitted, you will be prompted.",
    )
    dec.set_defaults(func=cmd_decrypt)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
