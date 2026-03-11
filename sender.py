"""
sender.py - Sender-side logic for AnonShare.

Handles:
  1. File validation and SHA-256 hashing
  2. Tor circuit setup (optional)
  3. Magic-Wormhole channel creation and code display
  4. Passphrase key derivation
  5. File encryption (single or double layer)
  6. Streaming transfer with progress reporting
  7. Session teardown and key destruction
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

import click

import wormhole as _wormhole_pkg
from wormhole._interfaces import IWormhole  # noqa: F401

from config import APP_ID, RELAY_URL, TRANSIT_HELPER, DEFAULT_TIMEOUT, CHUNK_SIZE
from crypto import (
    derive_key_from_passphrase,
    encrypt_payload,
    sha256_file,
)
from tor_manager import TorManager, TorError
from utils import human_size, timing_delay, validate_code, ProgressBar

log = logging.getLogger(__name__)


# ------------------------------------------------------------------ helpers --

def _build_metadata(
    file_path: str,
    file_hash: str,
    salt: bytes | None,
    double_encrypted: bool,
) -> bytes:
    meta = {
        "filename": os.path.basename(file_path),
        "size": os.path.getsize(file_path),
        "hash": file_hash,
        "salt": salt.hex() if salt else None,
        "double_encrypted": double_encrypted,
        "version": 1,
    }
    return json.dumps(meta).encode()


# --------------------------------------------------------------- async core --

async def _async_send(
    file_path: str,
    passphrase: str | None,
    double_encrypt: bool,
    timeout: int,
    code: str | None,
) -> None:
    """Core async sender using the wormhole Deferred API."""

    # Compute file hash up front (streaming, memory-safe)
    click.echo("  Hashing file …", nl=False)
    file_hash = sha256_file(file_path)
    click.echo(f" {file_hash[:12]}…")

    # Key derivation
    extra_key: bytes | None = None
    salt: bytes | None = None
    if passphrase:
        extra_key, salt = derive_key_from_passphrase(passphrase)

    # Read file into memory (for simplicity; chunk streaming is in roadmap)
    file_size = os.path.getsize(file_path)
    click.echo(f"  Reading {human_size(file_size)} …", nl=False)
    with open(file_path, "rb") as fh:
        plaintext = fh.read()
    click.echo(" done.")

    # Encrypt
    click.echo("  Encrypting …", nl=False)
    ciphertext = encrypt_payload(
        plaintext,
        primary_key=b"\x00" * 32,   # placeholder; replaced by wormhole key below
        extra_key=extra_key if double_encrypt else None,
    )
    # NOTE: We derive the real wormhole key after PAKE completes (see below).
    # For clarity, encryption using wormhole-derived key happens post-PAKE.
    click.echo(" done.")

    # Wormhole session
    w = _wormhole_pkg.create(
        appid=APP_ID,
        relay_url=RELAY_URL,
        reactor=None,  # use default reactor
    )

    await w.get_welcome()

    # Either allocate a new code or use a pre-set one
    if code:
        w.set_code(code)
        display_code = code
    else:
        await w.allocate_code()
        display_code = await w.get_code()

    click.echo(f"\n  🔐 Your wormhole code:  {display_code}")
    if passphrase:
        click.echo(f"  🔑 Passphrase:          {passphrase}")
    click.echo("\n  Share the code via a secure out-of-band channel (Signal, verbally, …)")
    click.echo("  ⏳ Waiting for receiver …\n")

    # PAKE key exchange happens when the receiver connects.
    # derive_key gives us a domain-separated symmetric key from the PAKE result.
    timing_delay()

    # Send metadata
    metadata_bytes = _build_metadata(
        file_path,
        file_hash,
        salt,
        double_encrypt and extra_key is not None,
    )
    await w.send_message(metadata_bytes)

    # Derive wormhole key
    wormhole_key = w.derive_key(APP_ID + "/file-key", 32)
    
    # Setup transit relay
    t = w.connect_transit()
    if TRANSIT_HELPER:
        t.set_helper(TRANSIT_HELPER)
    
    # hints are exchanged automatically via the mailbox session 'w'
    click.echo("  🔌 Connecting to transit relay …", nl=False)
    await t.connect()
    click.echo(" done.")

    # Send payload size hint first (via mailbox for reliability)
    total_size = os.path.getsize(file_path)
    # For chunked encryption, the encrypted size will be slightly larger than plaintext.
    # We'll send the expected encrypted size calculated by summing up the encrypted chunks.
    # Since we use NaCl SecretBox/AES-GCM, overhead is 16 bytes per chunk (MAC) + 24/12 bytes (nonce).
    # But encrypt_payload includes the nonce and length header.
    # Let's simplify: send the raw file size in metadata (already done) 
    # and send the stream on transit. The receiver will read until it gets enough data.
    size_msg = json.dumps({"payload_size": total_size}).encode() # Keep it simple for now
    await w.send_message(size_msg)

    # Send payload via transit
    click.echo(f"  📤 Sending {human_size(total_size)} (encrypted) via transit …")
    progress = ProgressBar(total_size, "  ")
    
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            
            encrypted_chunk = encrypt_payload(
                chunk,
                primary_key=wormhole_key,
                extra_key=extra_key if double_encrypt else None,
            )
            await t.send_record(encrypted_chunk)
            progress.update(len(chunk))
    progress.finish()

    click.echo(f"  📤 Sent {human_size(total_size)} (encrypted).")

    # Wait for receiver ack
    ack_bytes = await asyncio.wait_for(w.get_message(), timeout=timeout)
    ack = json.loads(ack_bytes)
    if ack.get("status") == "ok":
        click.echo("  ✅ Receiver verified file integrity. Transfer complete!")
    else:
        click.echo(f"  ❌ Receiver reported error: {ack.get('error', 'unknown')}")

    await w.close()

    # Destroy key material from local variables
    if extra_key:
        extra_key = b"\x00" * len(extra_key)  # best-effort overwrite
    wormhole_key = b"\x00" * len(wormhole_key)
    del extra_key, wormhole_key, plaintext


# ------------------------------------------------------------------ public --

def run_send(
    file_path: str,
    passphrase: str | None = None,
    use_tor: bool = True,
    double_encrypt: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    code: str | None = None,
) -> None:
    """Entry point called by the CLI."""

    # --- Tor setup ---
    tm: TorManager | None = None
    if use_tor:
        tm = TorManager()
        try:
            tm.require_tor()
        except TorError as exc:
            click.echo(f"  ❌ Tor error: {exc}", err=True)
            sys.exit(1)
        tm.enable_tor()
        if tm.verify_tor_connection():
            click.echo("  ✓ Traffic routed via Tor.")
        else:
            click.echo(
                "  ⚠️  Could not verify Tor routing. Proceeding anyway.\n"
                "     Check https://check.torproject.org manually.",
                err=True,
            )

    try:
        asyncio.run(
            _async_send(file_path, passphrase, double_encrypt, timeout, code)
        )
    finally:
        if tm:
            tm.disable_tor()
