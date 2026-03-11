"""
receiver.py - Receiver-side logic for AnonShare.

Handles:
  1. Tor circuit setup (optional)
  2. Magic-Wormhole rendezvous using the sender's code
  3. Metadata receipt and display
  4. Payload download with progress bar
  5. Decryption (single or double layer)
  6. SHA-256 integrity verification
  7. Secure file save (chmod 600) and session cleanup
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys

import click

import wormhole as _wormhole_pkg

from config import APP_ID, RELAY_URL, TRANSIT_HELPER, DEFAULT_TIMEOUT
from crypto import (
    derive_key_from_passphrase,
    decrypt_payload,
    sha256_bytes,
)
from tor_manager import TorManager, TorError
from utils import human_size, timing_delay, save_file_securely, ProgressBar

log = logging.getLogger(__name__)


# --------------------------------------------------------------- async core --

async def _async_receive(
    code: str,
    passphrase: str | None,
    output_dir: str,
    timeout: int,
) -> None:
    """Core async receiver."""

    w = _wormhole_pkg.create(
        appid=APP_ID,
        relay_url=RELAY_URL,
        reactor=None,
    )

    await w.get_welcome()
    w.set_code(code.strip())

    click.echo("  🔗 Connecting to wormhole …")
    timing_delay()

    # Receive metadata
    metadata_raw = await asyncio.wait_for(w.get_message(), timeout=timeout)
    metadata = json.loads(metadata_raw)

    filename: str = metadata["filename"]
    expected_size: int = metadata["size"]
    expected_hash: str = metadata["hash"]
    salt_hex: str | None = metadata.get("salt")
    double_encrypted: bool = metadata.get("double_encrypted", False)
    version: int = metadata.get("version", 1)

    click.echo(
        f"  📥 Incoming:  {filename}  ({human_size(expected_size)})\n"
        f"     SHA-256:  {expected_hash[:16]}…\n"
        f"     Double-encrypted: {'yes' if double_encrypted else 'no'}"
    )

    # Receive size hint
    size_msg_raw = await asyncio.wait_for(w.get_message(), timeout=timeout)
    size_msg = json.loads(size_msg_raw)
    payload_size: int = size_msg["payload_size"]

    # Setup transit relay
    t = w.connect_transit()
    if TRANSIT_HELPER:
        t.set_helper(TRANSIT_HELPER)
    
    click.echo("  🔌 Connecting to transit relay …", nl=False)
    await t.connect()
    click.echo(" done.")

    # Receive payload in chunks
    click.echo(f"  📥 Receiving {human_size(payload_size)} encrypted payload via transit …")
    
    all_chunks = [] # For small files, can store in memory. For large, should use disk.
    # We'll use memory for now to match the original integrity check logic, 
    # but ideally we'd stream to a temp file and hash on the fly.
    
    progress = ProgressBar(payload_size, "  ")
    received_encrypted_bytes = 0
    
    # We don't know exactly how many chunks, but we know total encrypted size is roughly payload_size.
    # Note: In our sender, we sent total_size (plaintext) as 'payload_size' hint.
    # But we'll receive chunks until the sender closes the transit or we hit a limit.
    # Actually, magic-wormhole transit will close when done.
    
    while True:
        try:
            encrypted_chunk = await asyncio.wait_for(t.receive_record(), timeout=30)
            all_chunks.append(encrypted_chunk)
            # Roughly update progress (using encrypted size as estimate)
            received_encrypted_bytes += len(encrypted_chunk)
            progress.update(len(encrypted_chunk)) 
        except (asyncio.TimeoutError, Exception):
            break
    progress.finish()
    
    # Combine chunks
    ciphertext = b"".join(all_chunks)
    click.echo(f"  Received {human_size(len(ciphertext))}.")

    # Key derivation
    wormhole_key = w.derive_key(APP_ID + "/file-key", 32)

    extra_key: bytes | None = None
    if passphrase and salt_hex and double_encrypted:
        salt = bytes.fromhex(salt_hex)
        extra_key, _ = derive_key_from_passphrase(passphrase, salt)
    elif passphrase and double_encrypted and not salt_hex:
        click.echo("  ❌ Passphrase required but no salt in metadata.", err=True)
        await w.close()
        return

    # Combined decryption
    click.echo("  Decrypting …", nl=False)
    all_plaintexts = []
    try:
        for chunk in all_chunks:
            p = decrypt_payload(
                chunk,
                primary_key=wormhole_key,
                extra_key=extra_key if double_encrypted else None,
            )
            all_plaintexts.append(p)
        plaintext = b"".join(all_plaintexts)
    except Exception as exc:
        click.echo(f"\n  ❌ Decryption failed: {exc}", err=True)
        ack = json.dumps({"status": "error", "error": "decryption_failed"}).encode()
        await w.send_message(ack)
        await w.close()
        return
    click.echo(" done.")

    # Verify integrity
    received_hash = sha256_bytes(plaintext)
    if received_hash != expected_hash:
        click.echo(
            f"  ❌ Integrity check FAILED!\n"
            f"     Expected: {expected_hash}\n"
            f"     Got:      {received_hash}",
            err=True,
        )
        ack = json.dumps({"status": "error", "error": "hash_mismatch"}).encode()
        await w.send_message(ack)
        await w.close()
        return

    click.echo("  ✅ Integrity verified.")

    # Save file
    dest = save_file_securely(plaintext, filename, output_dir)
    click.echo(f"  💾 Saved: {dest}  (permissions: 600)")

    # Send ack to sender
    ack = json.dumps({"status": "ok"}).encode()
    await w.send_message(ack)

    await w.close()

    # Best-effort key destruction
    wormhole_key = b"\x00" * len(wormhole_key)
    if extra_key:
        extra_key = b"\x00" * len(extra_key)
    del wormhole_key, extra_key, plaintext


# ------------------------------------------------------------------ public --

def run_receive(
    code: str,
    passphrase: str | None = None,
    use_tor: bool = True,
    output_dir: str = ".",
    timeout: int = DEFAULT_TIMEOUT,
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
                "  ⚠️  Could not verify Tor routing. Proceeding anyway.",
                err=True,
            )

    try:
        asyncio.run(
            _async_receive(code, passphrase, output_dir, timeout)
        )
    finally:
        if tm:
            tm.disable_tor()
