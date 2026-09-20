"""Unit tests for aescrypt.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aescrypt import encrypt_bytes, decrypt_bytes, DecryptionError, HEADER_STRUCT, _get_passphrase


class TestAesCrypt(unittest.TestCase):
    def test_roundtrip_text(self):
        """Encrypt-then-decrypt recovers original text bytes exactly."""
        plaintext = b"The quick brown fox jumps over the lazy dog.\nSecond line here."
        passphrase = b"correct-horse-battery-staple"
        ciphertext_file = encrypt_bytes(plaintext, passphrase)
        recovered = decrypt_bytes(ciphertext_file, passphrase)
        self.assertEqual(recovered, plaintext)

    def test_roundtrip_binary(self):
        """Encrypt-then-decrypt recovers original binary bytes exactly."""
        plaintext = os.urandom(4096)
        passphrase = b"binary-test-pass"
        ciphertext_file = encrypt_bytes(plaintext, passphrase)
        recovered = decrypt_bytes(ciphertext_file, passphrase)
        self.assertEqual(recovered, plaintext)

    def test_wrong_passphrase_fails_cleanly(self):
        """Decrypting with the wrong passphrase raises DecryptionError, not garbage output."""
        plaintext = b"super secret data"
        ciphertext_file = encrypt_bytes(plaintext, b"right-passphrase")
        with self.assertRaises(DecryptionError):
            decrypt_bytes(ciphertext_file, b"wrong-passphrase")

    def test_tampered_ciphertext_fails(self):
        """Flipping a single byte in the ciphertext causes decryption to fail, not silently corrupt."""
        plaintext = b"data that must not be silently corrupted"
        passphrase = b"tamper-test-pass"
        ciphertext_file = bytearray(encrypt_bytes(plaintext, passphrase))

        # Flip a byte well inside the ciphertext region (after the header).
        tamper_index = HEADER_STRUCT.size + 2
        ciphertext_file[tamper_index] ^= 0xFF

        with self.assertRaises(DecryptionError):
            decrypt_bytes(bytes(ciphertext_file), passphrase)

    def test_empty_file_roundtrip(self):
        """An empty plaintext file round-trips correctly."""
        plaintext = b""
        passphrase = b"empty-file-pass"
        ciphertext_file = encrypt_bytes(plaintext, passphrase)
        recovered = decrypt_bytes(ciphertext_file, passphrase)
        self.assertEqual(recovered, b"")

    def test_large_file_roundtrip(self):
        """A multi-megabyte file round-trips correctly."""
        plaintext = os.urandom(5 * 1024 * 1024)  # 5 MB
        passphrase = b"large-file-pass"
        ciphertext_file = encrypt_bytes(plaintext, passphrase)
        recovered = decrypt_bytes(ciphertext_file, passphrase)
        self.assertEqual(recovered, plaintext)
        self.assertEqual(len(recovered), len(plaintext))

    def test_salt_and_nonce_are_unique_per_encryption(self):
        """Two encryptions of the same plaintext/passphrase must use different salt and nonce."""
        plaintext = b"same plaintext every time"
        passphrase = b"same-passphrase-every-time"

        file_a = encrypt_bytes(plaintext, passphrase)
        file_b = encrypt_bytes(plaintext, passphrase)

        header_a = HEADER_STRUCT.unpack(file_a[: HEADER_STRUCT.size])
        header_b = HEADER_STRUCT.unpack(file_b[: HEADER_STRUCT.size])

        salt_a, nonce_a = header_a[4], header_a[5]
        salt_b, nonce_b = header_b[4], header_b[5]

        self.assertNotEqual(salt_a, salt_b)
        self.assertNotEqual(nonce_a, nonce_b)
        # Ciphertexts should also differ as a result.
        self.assertNotEqual(file_a, file_b)

    def test_decrypt_rejects_garbage_input(self):
        """Decrypting a file that is not a valid aescrypt file fails cleanly."""
        with self.assertRaises(DecryptionError):
            decrypt_bytes(b"not a real encrypted file", b"any-passphrase")

    def test_decrypt_rejects_truncated_ciphertext(self):
        """A file with a valid header but a ciphertext shorter than the
        16-byte GCM auth tag must be rejected explicitly, not passed to
        the AEAD layer to fail in a less clear way."""
        plaintext = b"short"
        passphrase = b"truncate-test-pass"
        full_file = encrypt_bytes(plaintext, passphrase)

        # Keep the header intact but cut the ciphertext down to fewer than
        # 16 bytes (smaller than the GCM auth tag alone).
        truncated = full_file[: HEADER_STRUCT.size + 8]

        with self.assertRaises(DecryptionError):
            decrypt_bytes(truncated, passphrase)

    def test_roundtrip_with_unicode_passphrase(self):
        """Passphrases containing non-ASCII characters must round-trip
        correctly, since the CLI encodes user input as UTF-8."""
        plaintext = b"data protected by a non-ascii passphrase"
        passphrase = "correct-cheval-batterie-étoile-☃".encode("utf-8")

        ciphertext_file = encrypt_bytes(plaintext, passphrase)
        recovered = decrypt_bytes(ciphertext_file, passphrase)
        self.assertEqual(recovered, plaintext)

        # A different unicode passphrase must still fail cleanly.
        wrong_passphrase = "correct-cheval-batterie-étoile-☄".encode("utf-8")
        with self.assertRaises(DecryptionError):
            decrypt_bytes(ciphertext_file, wrong_passphrase)

    def test_empty_passphrase_flag_is_rejected(self):
        """`--passphrase ''` must be rejected up front instead of silently
        encrypting with no real protection."""

        class FakeArgs:
            passphrase = ""

        with self.assertRaises(SystemExit) as ctx:
            _get_passphrase(FakeArgs(), confirm=False)
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
