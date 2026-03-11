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
```

### 2. Install AnonShare

```bash
git clone https://github.com/<your-username>/anonshare.git
cd anonshare

# Optional but recommended: virtualenv
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

pip install -r requirements.txt
```

### 3. Send a file

```bash
python anonshare.py send --file secret.pdf
```

Example output:

```text
🔐 Your wormhole code:  7-plum-snowflake
Share this code via a secure out-of-band channel (Signal, verbally, …)
⏳ Waiting for receiver …
```

### 4. Receive a file

```bash
python anonshare.py receive --code 7-plum-snowflake
```

---

## CLI Commands

### `send`

```bash
python anonshare.py send [OPTIONS]

  -f, --file PATH          File to send (required)
  -p, --passphrase TEXT    Extra passphrase for a second auth layer
  --tor / --no-tor         Route via Tor (default: on)
  -2, --double-encrypt     Add AES-256-GCM on top of NaCl SecretBox
  -t, --timeout SECONDS    Code expiry (default: 3600)
  -c, --code TEXT          Pre-set a wormhole code (testing)
  -v, --verbose            Debug logging
```

### `receive`

```bash
python anonshare.py receive [OPTIONS]

  -c, --code TEXT          Wormhole code from sender (required)
  -p, --passphrase TEXT    Passphrase (must match sender)
  --tor / --no-tor         Route via Tor (default: on)
  -o, --output DIR         Output directory (default: current)
  -t, --timeout SECONDS    Max wait for sender (default: 3600)
  -v, --verbose            Debug logging
```

### `check`

```bash
python anonshare.py check
```

Verifies that the Tor SOCKS proxy is reachable and traffic is exiting via Tor.

---

## Usage Examples

### Basic transfer (Tor on by default)

```bash
# Machine A
python anonshare.py send --file report.pdf

# Machine B
python anonshare.py receive --code 7-plum-snowflake
```

### With extra passphrase + double encryption

```bash
# Machine A
python anonshare.py send --file secrets.zip \
  --passphrase "CorrectHorseBatteryStaple" \
  --double-encrypt

# Machine B
python anonshare.py receive --code 4-apple-thunder \
  --passphrase "CorrectHorseBatteryStaple"
```

### Testing without Tor (for local/dev only)

```bash
python anonshare.py send --file test.txt --no-tor
python anonshare.py receive --code <code> --no-tor
```

---

## Encryption Architecture

```text
Plaintext
    │
    ▼ (if --double-encrypt + passphrase)
AES-256-GCM  ← PBKDF2-HMAC-SHA256 (100 000 iters) + HKDF
    │
    ▼ (always)
NaCl SecretBox (XSalsa20 + Poly1305)  ← SPAKE2 wormhole session key
    │
    ▼
[4-byte length][data][random padding to nearest 64 KB]
    │
    ▼  (over Tor SOCKS5 when enabled)
Magic-Wormhole transit relay
```

- **Key derivation:**  
  `PBKDF2-HMAC-SHA256(passphrase, salt, 100_000)` → `HKDF-SHA256` → 256‑bit key.
- **Session keys:** kept in memory only; wiped when the session ends.

---

## Project Structure

```text
anonshare/
├── anonshare.py      # Main CLI entry point (send/receive/check/version)
├── sender.py         # Async sender flow
├── receiver.py       # Async receiver flow
├── crypto.py         # NaCl + AES-256-GCM + KDFs + padding
├── tor_manager.py    # Tor SOCKS5 integration, circuit management
├── utils.py          # Hashing, file I/O, progress bar, code validation
├── config.py         # Relay URL, timeouts, crypto/timing constants
├── requirements.txt  # Python dependencies
├── README.md         # This document
└── tests/
    ├── test_crypto.py
    ├── test_tor.py
    └── test_utils.py
```

---

## Running Tests

```bash
pip install pytest
pytest -v
```

All core crypto, Tor integration helpers, and utilities are covered by unit tests.

---

## Self‑Hosted Relay (Maximum Privacy)

By default you can use the public Magic Wormhole relay, but for maximum privacy you can host your own mailbox + transit relay (optionally as a Tor hidden service) and point AnonShare to it via `config.py`.

High‑level steps:

1. On a server (e.g., EC2), install:
   ```bash
   pip install magic-wormhole-mailbox-server magic-wormhole-transit-relay
   ```
2. Run the mailbox (e.g. port 4000) and transit relay (e.g. 4001).
3. (Optional) Put both behind a Tor hidden service.
4. Set in `config.py`:
   ```python
   RELAY_URL = "ws://<your-relay-host>:4000/v1"
   # And transit helper if you expose it
   ```

Now all AnonShare clients will meet on your infrastructure instead of a third‑party relay.

---

## Security Hardening Checklist

- [ ] Run Tor in a separate VM or container.
- [ ] Use a self‑hosted mailbox + transit relay (ideally over Tor).
- [ ] Enable full‑disk encryption on sender and receiver machines.
- [ ] Use `--double-encrypt` + strong passphrase for sensitive files.
- [ ] Share wormhole codes via secure messengers (Signal, etc.).
- [ ] Run `anonshare check` before important transfers.
- [ ] Keep dependencies updated (`pip-audit`, `pip list --outdated`).
- [ ] Consider sandboxing (AppArmor/SELinux, containers).

---

## License

GPLv3 — see [LICENSE](LICENSE).

---

## Responsible Disclosure

If you find a security issue or potential vulnerability, please contact me privately rather than opening a public issue.  
You can reach me at: **<your-security-email-or-contact>**.
```
