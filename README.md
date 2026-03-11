# AnonShare 🔐

> Anonymous · Ephemeral · End-to-End Encrypted File Transfer

AnonShare lets two people exchange a file with **dark-web-level security**: no accounts, no central storage, no metadata leakage, self-destructing sessions.  
It combines **Magic Wormhole** (PAKE/SPAKE2), **NaCl/libsodium** encryption, and the **Tor** anonymity network.

---

## Threat Model

| Threat | Mitigation |
|---|---|
| Man-in-the-Middle | SPAKE2 PAKE – any tampering is cryptographically detected |
| Network surveillance | All traffic routed via Tor; cleartext never leaves the device |
| Relay server compromise | Server sees only encrypted blobs – zero-knowledge architecture |
| Brute-force wormhole codes | Codes expire in 1 hour; relay enforces rate-limits |
| File tampering | SHA-256 hash verified before saving; Poly1305 MAC in NaCl |
| File size fingerprinting | Plaintext padded to 64 KB boundaries before encryption |
| Timing analysis | Random 0.5–3 s delays injected between protocol messages |
| Persistent identifiers | No accounts, emails, or logs |

**Out of scope:** Malware hidden inside transferred files – always scan received files.

---

## Quick Start

### 1. Prerequisites

```bash
# Python 3.10+
python --version

# Install Tor
# Debian/Ubuntu:
sudo apt install tor
sudo systemctl start tor

# macOS:
brew install tor
brew services start tor

# Windows: Download Tor Browser or Expert Bundle from https://torproject.org
```

### 2. Install AnonShare

```bash
git clone https://github.com/yourname/anonshare
cd anonshare
pip install -r requirements.txt
```

### 3. Send a file

```bash
python anonshare.py send --file secret.pdf
```

Output:
```
  🔐 Your wormhole code:  7-plum-snowflake
  Share the code via a secure out-of-band channel (Signal, verbally, …)
  ⏳ Waiting for receiver …
```

### 4. Receive a file

```bash
python anonshare.py receive --code 7-plum-snowflake
```

---

## All Options

### `send`

```
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

```
python anonshare.py receive [OPTIONS]

  -c, --code TEXT          Wormhole code from sender (required)
  -p, --passphrase TEXT    Passphrase (must match sender)
  --tor / --no-tor         Route via Tor (default: on)
  -o, --output DIR         Output directory (default: current)
  -t, --timeout SECONDS    Max wait for sender (default: 3600)
  -v, --verbose            Debug logging
```

### `check`

```
python anonshare.py check
```

Verifies the Tor SOCKS proxy is running and traffic is exiting via Tor.

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

### Testing without Tor

```bash
python anonshare.py send --file test.txt --no-tor
python anonshare.py receive --code <code> --no-tor
```

---

## Encryption Architecture

```
Plaintext
    │
    ▼ (if --double-encrypt + passphrase)
AES-256-GCM  ← PBKDF2-HMAC-SHA256 (100 000 itr) + HKDF
    │
    ▼ (always)
NaCl SecretBox (XSalsa20 + Poly1305)  ← SPAKE2 wormhole key
    │
    ▼
Padded ciphertext (nearest 64 KB)
    │
    ▼ (via Tor SOCKS5)
Magic-Wormhole transit relay
```

**Key derivation:**  
`PBKDF2-HMAC-SHA256(passphrase, salt, 100_000)` → `HKDF-SHA256` → 256-bit key

**Session keys** are never written to disk and are overwritten with zeros when the session ends.

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Self-Hosted Relay (Maximum Privacy)

Run your own wormhole relay as a Tor hidden service so no third-party relay ever sees your traffic metadata:

```bash
# Install relay servers
pip install magic-wormhole-mailbox-server magic-wormhole-transit-relay

# Add to /etc/tor/torrc:
HiddenServiceDir /var/lib/tor/wormhole/
HiddenServicePort 4000 127.0.0.1:4000

# Restart Tor and get onion address
sudo systemctl restart tor
sudo cat /var/lib/tor/wormhole/hostname   # e.g. abc123.onion

# Start relay
twist wormhole-mailbox --websocket tcp:4000
```

Then edit `config.py`:
```python
RELAY_URL = "ws://abc123.onion:4000/v1"
```

---

## Security Hardening Checklist

- [ ] Run Tor in a separate container or VM
- [ ] Use a self-hosted relay on a Tor hidden service
- [ ] Enable full-disk encryption on both devices
- [ ] Use `--double-encrypt` with a strong passphrase for sensitive files
- [ ] Share the wormhole code via Signal (not SMS or email)
- [ ] Verify Tor is running (`python anonshare.py check`) before each session
- [ ] Keep dependencies updated (`pip-audit` to check for CVEs)
- [ ] Use AppArmor/SELinux profiles for process isolation

---

## Project Structure

```
anonshare/
├── anonshare.py      Main CLI entry point
├── sender.py         Sender workflow
├── receiver.py       Receiver workflow
├── crypto.py         NaCl + AES-256-GCM encryption
├── tor_manager.py    Tor SOCKS5 connection management
├── utils.py          Hashing, file I/O, progress bar
├── config.py         Relay URLs, timeouts, constants
├── requirements.txt  Python dependencies
├── README.md         This file
└── tests/
    ├── test_crypto.py
    ├── test_tor.py
    └── test_utils.py
```

---

## License

GPLv3 — see [LICENSE](LICENSE).

---

## Responsible Disclosure

Found a security bug? Please email **security@yourproject.example** with details.  
Do **not** open a public GitHub issue for security vulnerabilities.
