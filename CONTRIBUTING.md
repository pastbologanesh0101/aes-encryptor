# Contributing

Thanks for considering a contribution to `aes-encryptor`. This is a small,
single-file educational tool, so the bar for changes is: keep it simple,
keep it correct, and keep it well-tested.

## Running the tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

All tests must pass before a change is merged. CI runs the same command
on every push and pull request (see `.github/workflows/tests.yml`).

## Code style

- Target Python 3.11+, stdlib + `cryptography` only (no new dependencies
  without a good reason — this project is meant to be trivially
  installable).
- Follow the existing style in `aescrypt.py`: type hints on function
  signatures, docstrings on every public function, and errors surfaced as
  `DecryptionError` (not raw exceptions) at the library boundary.
- Never implement a cryptographic primitive by hand. All crypto must go
  through the audited `cryptography` package.
- Keep the CLI's error messages specific and actionable — a user should
  understand what went wrong from the message alone.

## Submitting changes

1. Fork the repo and create a branch for your change.
2. Add or update tests in `tests/test_aescrypt.py` for any behavior
   change, including edge cases (empty input, wrong passphrase, tampered
   data, etc.).
3. Run the full test suite locally and make sure it's green.
4. Open a pull request with a clear description of what changed and why.

## Reporting security issues

This is an educational project and has not had a professional security
audit (see the README). If you find a genuine cryptographic flaw, please
still open an issue so it can be fixed and documented — just don't rely
on this tool for production secrets in the meantime.
