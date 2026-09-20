# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - Initial release

The first working version of `aescrypt.py`, a passphrase-based file
encryption/decryption CLI.

### Added
- AES-256-GCM authenticated encryption via the `cryptography` package
  (no hand-rolled crypto primitives).
- Passphrase-based key derivation using PBKDF2-HMAC-SHA256 with 390,000
  iterations and a fresh random 16-byte salt per encryption.
- A versioned file format (`AESC` magic, format version, KDF id, KDF
  iteration count, salt, nonce, ciphertext+tag) that can evolve without
  breaking older encrypted files.
- `encrypt` and `decrypt` CLI subcommands, with interactive passphrase
  prompting (with confirmation on encrypt) or a `--passphrase` flag for
  scripting.
- Clean, explicit failure handling: wrong passphrase and tampered
  ciphertext both raise `DecryptionError` with an actionable message
  instead of returning corrupted plaintext.
- Test suite covering round-trips (text, binary, empty file, 5 MB
  file), wrong-passphrase rejection, tamper detection, and salt/nonce
  uniqueness across encryptions.
- GitHub Actions CI running the test suite on Python 3.11 and 3.12.
- MIT license and a README documenting the design, file format, and
  usage.
