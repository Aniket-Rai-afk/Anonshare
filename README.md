# AnonShare 🔐

> Anonymous · Ephemeral · End‑to‑End Encrypted File Transfer

AnonShare is a CLI tool that lets two people exchange files with **dark‑web–grade privacy**: no accounts, no central storage, minimal metadata, and self‑destructing sessions.  
Under the hood it combines **Magic Wormhole** (SPAKE2/PAKE), **NaCl / AES‑256‑GCM** encryption, and optional **Tor** routing for network anonymity.

---

## Why AnonShare? (Problems it solves)

Traditional file sharing (email, cloud drives, messengers) leaks a lot:

- Files sit on third‑party servers for years.
- Providers can inspect content unless you encrypt manually.
- IP addresses, accounts, timestamps, and filenames create a metadata trail.
- Links are often guessable, reusable, or forwarded without control.

**AnonShare is designed to fix this:**

- No accounts, no logins, no emails.
- End‑to‑end encryption by default, with optional double‑encryption on top.
- Short‑lived, single‑use “wormhole codes” instead of permanent links.
- No file ever persists on a server; data moves peer‑to‑peer.
- Optionally routes all traffic over Tor to hide IPs and resist surveillance.

This makes it a good fit for security‑conscious users, red teams, and situations where both content and metadata need to stay private.

---

## Features at a Glance

- 🔑 **SPAKE2 / PAKE key exchange** via Magic Wormhole (no raw keys shared).
- 🧱 **Primary crypto:** NaCl SecretBox (XSalsa20‑Poly1305).
- 🧱 **Optional second layer:** AES‑256‑GCM via `--double-encrypt` + passphrase.
- 🧂 **Key derivation:** PBKDF2‑HMAC‑SHA256 (100K) → HKDF‑SHA256 → 256‑bit keys.
- 🎭 **Metadata defenses:** 64 KB padding, random protocol delays, no accounts.
- 🕵️ **Tor integration:** Route over a local SOCKS5 Tor proxy (`anonshare check`).
- 🧪 **Tests:** Crypto, Tor integration, and utilities covered by unit tests.

---

## Threat Model

| Threat                     | Mitigation                                                       |
|----------------------------|------------------------------------------------------------------|
| Man‑in‑the‑Middle          | SPAKE2 PAKE; tampering breaks the key exchange                  |
| Network surveillance       | Optional Tor routing; cleartext never leaves devices           |
| Relay server compromise    | Relay only sees encrypted blobs; zero‑knowledge design         |
| Brute‑forcing codes        | Single‑use codes with expiry; relay can rate‑limit             |
| File tampering             | SHA‑256 hash verification + AEAD MACs                          |
| File size fingerprinting   | Plaintext padded to 64 KB boundaries                           |
| Timing analysis            | Random 0.5–3 s delays between protocol messages                |
| Persistent identifiers     | No accounts, emails, or user IDs stored                        |

**Out of scope:** Malware inside transferred files (always scan on receipt).

---

## Quick Start

### 1. Prerequisites

- Python 3.10+
- (Recommended) Tor running locally for anonymity

```bash
# Check Python
python --version

# Linux (Debian/Ubuntu/Kali)
sudo apt install tor
sudo systemctl start tor

# macOS
brew install tor
brew services start tor

# Windows
# Install Python 3 (with "Add to PATH")
# Install Tor Browser or Tor Expert Bundle from https://www.torproject.org
