# AES Encryption Tool

A small, self-contained command-line tool for encrypting and decrypting
files with **AES-256-GCM**, using a key derived from a user-supplied
passphrase.

> **Educational project.** This was built to demonstrate correct usage of
> an audited crypto library (Python's `cryptography` package) for
> authenticated file encryption. It has not undergone a professional
> security audit. If you need to protect data that actually matters,
> please use a well-reviewed, battle-tested tool such as
> [age](https://github.com/FiloSottile/age) or
> [GnuPG (gpg)](https://gnupg.org/) instead.

## Design

### Key derivation

The tool never accepts a raw hex/binary key from the user. Instead, you
provide a passphrase, and a 256-bit AES key is derived from it using
**PBKDF2-HMAC-SHA256** with 390,000 iterations and a random 16-byte salt
generated fresh for every encryption operation. The salt is stored in the
output file so decryption can re-derive the same key from the same
passphrase.

PBKDF2 was chosen (over scrypt/Argon2) because it is available directly
in the `cryptography` package with no extra native dependencies, keeping
this project simple to install and run anywhere. The iteration count
follows current OWASP guidance for PBKDF2-HMAC-SHA256.

### Encryption

Encryption uses **AES-256 in GCM mode** (`cryptography.hazmat.primitives.
ciphers.aead.AESGCM`), which provides authenticated encryption: it
protects both the confidentiality *and* the integrity of the plaintext.
A fresh random 12-byte nonce is generated for every encryption operation
and stored alongside the ciphertext. The 16-byte GCM authentication tag
is appended to the ciphertext automatically by the library and verified
automatically on decrypt.

**No AES primitive is implemented by hand.** All cryptographic
primitives come from the `cryptography` package, which wraps OpenSSL.

### File format

Encrypted files produced by this tool have the following layout (all
multi-byte integers are big-endian):

| Field            | Size     | Description                              |
|------------------|----------|-------------------------------------------|
| Magic            | 4 bytes  | Literal ASCII bytes `AESC`                |
| Version          | 1 byte   | Format version, currently `1`             |
| KDF ID           | 1 byte   | `1` = PBKDF2-HMAC-SHA256                  |
| KDF iterations   | 4 bytes  | Iteration count used for this file        |
| Salt             | 16 bytes | Random salt used for key derivation       |
| Nonce            | 12 bytes | Random GCM nonce (IV)                     |
| Ciphertext+Tag   | rest     | AES-GCM ciphertext, with the 16-byte auth tag appended at the end |

Storing the iteration count and KDF id in the header means the format can
evolve (e.g. a future version could switch to scrypt/Argon2) without
breaking the ability to decrypt older files.

### Failure behavior

- **Wrong passphrase:** the derived key will be wrong, so GCM's
  authentication tag check fails and decryption raises a clear error
  (`InvalidTag`, surfaced as `DecryptionError`) instead of returning
  incorrect plaintext.
- **Tampered ciphertext:** any modification to the ciphertext bytes
  (even a single flipped bit) causes the same authentication failure,
  so corruption is always detected — never silently passed through as
  wrong plaintext.

## Requirements

- Python 3.11+
- [`cryptography`](https://pypi.org/project/cryptography/)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Encrypt a file (you'll be prompted for a passphrase, twice, to confirm):

```bash
python aescrypt.py encrypt input.txt output.enc
```

Decrypt a file (you'll be prompted for the passphrase once):

```bash
python aescrypt.py decrypt output.enc restored.txt
```

For scripting or automated tests, pass the passphrase directly (avoid
this for anything sensitive, since it may end up in shell history):

```bash
python aescrypt.py encrypt input.txt output.enc --passphrase "correct-horse-battery-staple"
python aescrypt.py decrypt output.enc restored.txt --passphrase "correct-horse-battery-staple"
```

### Example

```bash
$ echo "hello world" > input.txt
$ python aescrypt.py encrypt input.txt output.enc --passphrase "hunter2"
Encrypted 'input.txt' -> 'output.enc' (46 bytes).

$ python aescrypt.py decrypt output.enc restored.txt --passphrase "hunter2"
Decrypted 'output.enc' -> 'restored.txt' (12 bytes).

$ diff input.txt restored.txt && echo "Match!"
Match!

$ python aescrypt.py decrypt output.enc restored.txt --passphrase "wrong-passphrase"
Error: Decryption failed: wrong passphrase or corrupted/tampered file.
```

## Running the tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests cover:
- Encrypt-then-decrypt round-trips for text and binary content
- Wrong-passphrase decryption failing cleanly
- Tampered-ciphertext detection
- Empty-file handling
- Large file (multi-megabyte) round-trips
- Salt/nonce uniqueness across separate encryption calls

Continuous integration runs this same test suite on Python 3.11, 3.12,
and 3.13 via GitHub Actions (see `.github/workflows/tests.yml`).

## Troubleshooting / FAQ

**"Error: Decryption failed: wrong passphrase or corrupted/tampered file."**
This message is intentionally the same for both causes — AES-GCM cannot
tell "wrong key" apart from "tampered ciphertext," since both fail the
same authentication tag check. Double-check the passphrase first (it's
by far the more common cause); if you're sure it's correct, the file may
have been truncated or modified (e.g. by a text-mode file transfer that
mangled newlines).

**`ModuleNotFoundError: No module named 'cryptography'`**
Install dependencies before running the tool: `pip install -r
requirements.txt`. If you have multiple Python installations, make sure
you're using the same interpreter for `pip install` and for running
`aescrypt.py` (a virtualenv is the easiest way to guarantee this).

**"Error: File is too short to be a valid encrypted file." / "Not a
recognized aescrypt file (bad magic bytes)."**
You're pointing `decrypt` at something that isn't an aescrypt output
file (or it got truncated). Encrypted files always start with the 4-byte
magic `AESC`; if that's missing or the file is shorter than the fixed
38-byte header, decryption is rejected before it even attempts to derive
a key.

**Why not scrypt or Argon2 for key derivation?**
PBKDF2-HMAC-SHA256 ships in the `cryptography` package with no extra
native dependencies, which keeps installation trivial on any platform.
Argon2/scrypt are generally preferred for new designs, but the format's
`KDF ID` byte was added specifically so a future version could add
support for them without breaking existing encrypted files.

## License

MIT — see [LICENSE](LICENSE).
