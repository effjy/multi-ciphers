<div align="center">
 
<a href="https://github.com/effjy/multi-ciphers/"><img src="titles/multi-ciphers-title.svg" height="44" alt="Multi Ciphers"></a>

</div>

[![version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/effjy/multi-ciphers/releases)
[![language: C](https://img.shields.io/badge/language-C11-00599C.svg?logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![dependencies: none](https://img.shields.io/badge/dependencies-none-success.svg)](#building)
[![platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](#building)
[![ciphers](https://img.shields.io/badge/ciphers-AES--GCM%20%7C%20XChaCha20%20%7C%20Serpent-purple.svg)](#features)
[![KDF: Argon2id](https://img.shields.io/badge/KDF-Argon2id-orange.svg)](#argon2id-strength-profiles)
[![license](https://img.shields.io/badge/license-public%20domain-green.svg)](#license)

A small, **dependency-free** command-line tool for authenticated file
encryption in C. It offers three independent ciphers and uses
**Argon2id** for password-based key derivation. There is nothing to install
beyond a C compiler and the C standard library — every cryptographic
primitive is bundled in `src/`.

> Repository: **https://github.com/effjy/multi-ciphers**

---

## Features

- **Three ciphers**, all AEAD (encrypt + authenticate in one pass):
  - `AES-256-GCM`
  - `XChaCha20-Poly1305`
  - `Serpent-256-GCM`
- **Argon2id** key derivation with three selectable strength profiles
  (`low` / `medium` / `high`). Medium is 1 GiB of memory across 4 lanes.
- **Two ways to drive it**: a friendly **interactive menu** and a full
  **command-line interface** suitable for scripting.
- **Authenticated**: any modification to the file (or a wrong password) is
  detected and decryption refuses to produce output.
- **Self-describing files**: the cipher and KDF parameters are stored in the
  file header, so decryption needs only the file and the password.
- **No external dependencies**: only libc and the Linux `getrandom`/
  `/dev/urandom` interface for randomness.
- **Built-in self-test** with known-answer vectors.

---

## Building

```sh
git clone https://github.com/effjy/multi-ciphers.git
cd multi-ciphers

make            # builds ./multiciphers
make test       # builds, then runs the self-test
make clean
```

Requirements: a C11 compiler (`cc`/`gcc`/`clang`) and a POSIX libc (Linux).

### Installing system-wide

```sh
sudo make install      # installs to /usr/local/bin/multiciphers
sudo make uninstall    # removes it again
```

After installing you can run `multiciphers` from anywhere. To install somewhere
that does not need `sudo`, override `PREFIX`:

```sh
make install PREFIX=$HOME/.local      # installs to ~/.local/bin/multiciphers
```

---

## What it looks like

Launch with no arguments to get the interactive menu:

```
$ ./multiciphers

=============================================
  Multi Ciphers 1.0.3  -  interactive menu
=============================================
  1) Encrypt a file
  2) Decrypt a file
  3) Run self-test
  4) Help / command-line usage
  5) Quit
Choose an option [1-5]: 1
```

### Encrypting a file (interactive)

```
Input file to encrypt: secret.pdf
Output file: secret.pdf.mc

--- Choose cipher ---------------------------
  1) AES-256-GCM          (default)
  2) XChaCha20-Poly1305
  3) Serpent-256-GCM
  0) Cancel
Cipher [1]: 3

--- Choose Argon2id strength ----------------
  1) low      64 MiB,  t=3, 1 lane
  2) medium   1 GiB,   t=3, 4 lanes   (default)
  3) high     2 GiB,   t=4, 8 lanes
  0) Cancel
Strength [2]: 2

Cipher: Serpent-256-GCM
Password:
Confirm password:
Deriving key (Argon2id, m=1024 MiB, t=3, lanes=4)...
Encrypted 48213 bytes -> secret.pdf.mc
```

### Decrypting a file (interactive)

```
Choose an option [1-5]: 2
Input file to decrypt: secret.pdf.mc
Output file: secret.pdf
Password:
Deriving key (Argon2id, m=1024 MiB, t=3, lanes=4)...
Decrypted 48213 bytes -> secret.pdf
```

> The cipher and Argon2id parameters are read back from the file header, so
> decryption only asks for the password.

### Same thing, one-liners

```sh
./multiciphers encrypt -i secret.pdf -o secret.pdf.mc -c serpent -s medium
./multiciphers decrypt -i secret.pdf.mc -o secret.pdf
```

---

## Usage

### Interactive menu

Run with no arguments (or `menu`):

```sh
./multiciphers
```

```
=============================================
  Multi Ciphers 1.0.3  -  interactive menu
=============================================
  1) Encrypt a file
  2) Decrypt a file
  3) Run self-test
  4) Help / command-line usage
  5) Quit
```

When encrypting, you are walked through a **cipher menu** and an
**Argon2id strength menu**, then prompted for the password (input is hidden).

### Command line

```sh
# Encrypt (defaults: AES-256-GCM, medium strength, interactive password)
./multiciphers encrypt -i secret.pdf -o secret.pdf.mc

# Pick a cipher and strength explicitly
./multiciphers encrypt -i data.bin -o data.mc -c serpent -s high

# Decrypt (cipher + KDF params come from the file header)
./multiciphers decrypt -i data.mc -o data.bin

# Non-interactive password (useful in scripts; note: visible in shell history)
./multiciphers encrypt -i a.txt -o a.mc -c xchacha -s low -p 'my password'

./multiciphers selftest      # run known-answer + round-trip tests
./multiciphers --version
./multiciphers --help
```

#### Options

| Option | Meaning |
|--------|---------|
| `-i <path>` | input file (required) |
| `-o <path>` | output file (required) |
| `-c <cipher>` | `aes` (default), `xchacha`, or `serpent` |
| `-s <strength>` | `low`, `medium` (default), or `high` |
| `-p <password>` | supply the password inline (otherwise prompted) |

---

## Argon2id strength profiles

| Profile | Memory | Passes (t) | Lanes (p) |
|---------|--------|-----------|-----------|
| `low`    | 64 MiB | 3 | 1 |
| `medium` | 1 GiB  | 3 | 4 |
| `high`   | 2 GiB  | 4 | 8 |

> Higher strength makes password guessing dramatically more expensive but
> uses more RAM and time on **your** machine too. `medium` requires ~1 GiB
> of free memory; `high` requires ~2 GiB.

The chosen parameters are recorded in the file header, so a file encrypted at
`high` is always decrypted using the same Argon2id cost.

---

## File format

All multi-byte integers are little-endian. The 60-byte header is also used as
**additional authenticated data (AAD)**, so tampering with any header field is
detected.

```
offset  size  field
------  ----  -------------------------------------------
  0      4    magic "MCPH"
  4      1    format version (1)
  5      1    cipher id   (1=AES-256-GCM, 2=XChaCha20-Poly1305, 3=Serpent-256-GCM)
  6      1    kdf id      (1=Argon2id)
  7      1    strength    (1=low, 2=medium, 3=high; informational)
  8      4    Argon2 t_cost (passes)
 12      4    Argon2 m_cost (KiB)
 16      4    Argon2 lanes
 20     16    salt
 36     24    nonce (GCM uses the first 12 bytes; XChaCha20 uses all 24)
 60    ...    ciphertext (same length as plaintext)
 EOF-16 16    authentication tag
```

A 32-byte key is derived with Argon2id and used directly as the cipher key.
Serpent is a 128-bit block cipher, so it is run in the same GCM construction
as AES, giving an authenticated `Serpent-256-GCM`.

---

## Security notes

- Encryption is **authenticated**: decryption fails closed if the password is
  wrong or the file was altered.
- A fresh random salt and nonce are generated for every encryption.
- Keys, passwords, and intermediate buffers are zeroed after use.
- This is an independent, audited-by-test-vectors implementation, **not** a
  FIPS-certified library. It is suitable for personal use and learning. For
  high-assurance needs, prefer a vetted library (libsodium, OpenSSL).
- Avoid `-p` on shared systems: the password becomes visible in the process
  list and shell history. Prefer the interactive prompt.

---

## Implementation & credits

Every primitive is bundled and was verified against published known-answer
test vectors (`./multiciphers selftest`).

| Primitive | Source / standard |
|-----------|-------------------|
| AES-256 | FIPS-197; verified against the FIPS-197 test vector |
| GCM (GHASH) | NIST SP 800-38D |
| ChaCha20 / Poly1305 | RFC 8439 |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03 (verified against §A.3.1) |
| Serpent | Anderson/Biham/Knudsen; S-box equations by Dag Arne Osvik; verified against a published Serpent-256 vector |
| BLAKE2b | RFC 7693 |
| Argon2id | PHC winner / RFC 9106; verified byte-for-byte against the reference implementation (https://github.com/P-H-C/phc-winner-argon2) |

The Serpent S-box boolean equations are the canonical formulas common to the
public-domain Serpent reference implementations; the Argon2id and BLAKE2b code
follow the PHC reference algorithm. All bundled code here is provided as a
clean reimplementation for this project.

---

## Project layout

```
multiciphers/
├── Makefile
├── README.md
└── src/
    ├── main.c               CLI + interactive menu + file format
    ├── selftest.c           known-answer & round-trip tests
    ├── aes.c / aes.h        AES-256 block cipher
    ├── serpent.c / serpent.h Serpent block cipher
    ├── gcm.c / gcm.h        generic GCM over a 128-bit block cipher
    ├── chacha20poly1305.*   XChaCha20-Poly1305 AEAD
    ├── argon2.c / argon2.h  Argon2id KDF
    ├── blake2b.c / blake2b.h BLAKE2b (used by Argon2)
    └── random.c / random.h  CSPRNG (getrandom / /dev/urandom)
```

---

## License

You may use this code freely. The bundled algorithm implementations are based
on public specifications and public-domain reference code; see the credits
table above for the upstream sources.
