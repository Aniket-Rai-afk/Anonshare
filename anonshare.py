#!/usr/bin/env python3
"""
anonshare.py - Main CLI entry point for AnonShare.

Commands:
  send     Encrypt and transmit a file to a waiting receiver.
  receive  Claim an incoming file using a wormhole code.
  check    Verify the Tor connection is active.
  version  Print version and dependency info.

Usage examples:
  python anonshare.py send --file report.pdf --passphrase "SuperSecret123!"
  python anonshare.py receive --code 7-plum-snowflake --passphrase "SuperSecret123!"
  python anonshare.py send --file data.zip --no-tor   # testing only
"""

from __future__ import annotations

import logging
import os
import sys

import click

from config import DEFAULT_TIMEOUT, MIN_PASSPHRASE_LENGTH
from utils import validate_code

# ------------------------------------------------------------------ logging --
# Production: suppress all log output to prevent leaking info.
# Use --verbose / -v to re-enable.

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.CRITICAL
    logging.basicConfig(
        level=level,
        format="[%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )


# ------------------------------------------------------------------ styles --

BANNER = r"""
   _    _   _  ___  _   _ ____  _   _    _    ____  _____
  / \  | \ | |/ _ \| \ | / ___|| | | |  / \  |  _ \| ____|
 / _ \ |  \| | | | |  \| \___ \| |_| | / _ \ | |_) |  _|
/ ___ \| |\  | |_| | |\  |___) |  _  |/ ___ \|  _ <| |___
/_/   \_\_| \_|\___/|_| \_|____/|_| |_/_/   \_\_| \_\_____|

  Anonymous · Ephemeral · End-to-End Encrypted File Transfer
"""


# ---------------------------------------------------------------- CLI root --

@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging.")
@click.version_option(version="1.0.0", prog_name="AnonShare")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """AnonShare - secure, anonymous, ephemeral file sharing via Magic Wormhole + Tor."""
    _setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose

    if ctx.invoked_subcommand is None:
        click.echo(BANNER)
        click.echo(ctx.get_help())


# ------------------------------------------------------------------ send ---

@cli.command()
@click.option(
    "--file", "-f",
    "file_path",
    required=True,
    type=click.Path(exists=True, readable=True, resolve_path=True),
    help="Path to the file to send.",
)
@click.option(
    "--passphrase", "-p",
    default=None,
    help=(
        f"Optional extra passphrase (min {MIN_PASSPHRASE_LENGTH} chars). "
        "Receiver must supply the same value."
    ),
)
@click.option(
    "--tor/--no-tor",
    default=True,
    show_default=True,
    help="Route traffic via Tor (default: on). Use --no-tor for testing only.",
)
@click.option(
    "--double-encrypt", "-2",
    is_flag=True,
    default=False,
    help="Apply AES-256-GCM on top of NaCl SecretBox for a second encryption layer.",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Session expiry in seconds.",
)
@click.option(
    "--code", "-c",
    default=None,
    help="Pre-set a specific wormhole code instead of auto-generating one.",
)
@click.pass_context
def send(
    ctx: click.Context,
    file_path: str,
    passphrase: str | None,
    tor: bool,
    double_encrypt: bool,
    timeout: int,
    code: str | None,
) -> None:
    """Encrypt and send FILE to a receiver.

    \b
    Example:
      anonshare send --file secret.pdf --passphrase "CorrectHorseBatteryStaple"
    """
    click.echo(BANNER)
    click.echo(f"  📂 File:  {file_path}  ({_file_size_str(file_path)})")

    # Validate passphrase length
    if passphrase is not None and len(passphrase) < MIN_PASSPHRASE_LENGTH:
        click.echo(
            f"  ❌ Passphrase too short (min {MIN_PASSPHRASE_LENGTH} chars).",
            err=True,
        )
        sys.exit(1)

    if not tor:
        click.echo(
            "  ⚠️  --no-tor active. Your IP address is NOT hidden. "
            "Use only for testing!\n",
            err=True,
        )

    click.echo(f"  {'🧅' if tor else '🌐'} Tor: {'enabled' if tor else 'disabled'}")
    click.echo(f"  🔒 Double-encrypt: {'yes' if double_encrypt else 'no'}\n")

    from sender import run_send
    run_send(
        file_path=file_path,
        passphrase=passphrase,
        use_tor=tor,
        double_encrypt=double_encrypt,
        timeout=timeout,
        code=code,
    )


# --------------------------------------------------------------- receive ---

@cli.command()
@click.option(
    "--code", "-c",
    required=True,
    help="Wormhole code supplied by the sender (e.g. 7-plum-snowflake).",
)
@click.option(
    "--passphrase", "-p",
    default=None,
    help="Passphrase used by sender (required if sender used one).",
)
@click.option(
    "--tor/--no-tor",
    default=True,
    show_default=True,
    help="Route traffic via Tor.",
)
@click.option(
    "--output", "-o",
    "output_dir",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False, writable=True, resolve_path=True),
    help="Directory to save the received file.",
)
@click.option(
    "--timeout", "-t",
    default=DEFAULT_TIMEOUT,
    show_default=True,
    help="Maximum wait for sender in seconds.",
)
@click.pass_context
def receive(
    ctx: click.Context,
    code: str,
    passphrase: str | None,
    tor: bool,
    output_dir: str,
    timeout: int,
) -> None:
    """Receive a file using the WORMHOLE code from the sender.

    \b
    Example:
      anonshare receive --code 7-plum-snowflake --passphrase "CorrectHorseBatteryStaple"
    """
    click.echo(BANNER)

    # Validate code format
    if not validate_code(code):
        click.echo(
            f"  ❌ Invalid code format: '{code}'\n"
            "     Expected format: <digit>-<word>-<word>  e.g.  7-plum-snowflake",
            err=True,
        )
        sys.exit(1)

    if not tor:
        click.echo(
            "  ⚠️  --no-tor active. Your IP address is NOT hidden. "
            "Use only for testing!\n",
            err=True,
        )

    click.echo(f"  🔗 Code: {code}")
    click.echo(f"  {'🧅' if tor else '🌐'} Tor: {'enabled' if tor else 'disabled'}")
    click.echo(f"  💾 Output dir: {output_dir}\n")

    from receiver import run_receive
    run_receive(
        code=code,
        passphrase=passphrase,
        use_tor=tor,
        output_dir=output_dir,
        timeout=timeout,
    )


# ------------------------------------------------------------------ check --

@cli.command()
def check() -> None:
    """Verify that the Tor SOCKS proxy is reachable and in use."""
    click.echo(BANNER)
    click.echo("  Checking Tor connection …\n")

    from tor_manager import TorManager, TorError
    tm = TorManager()

    reachable = tm.is_tor_reachable()
    click.echo(f"  SOCKS proxy reachable:  {'✅ yes' if reachable else '❌ no'}")
    if not reachable:
        click.echo(
            "\n  Start Tor:\n"
            "    Linux:  sudo systemctl start tor\n"
            "    macOS:  brew services start tor\n"
            "    Windows: use the Tor Browser or Expert Bundle\n"
        )
        sys.exit(1)

    click.echo("  Verifying traffic exits via Tor (may take ~10 s) …")
    is_tor = tm.verify_tor_connection()
    click.echo(f"  Traffic via Tor:        {'✅ yes' if is_tor else '❌ NO (check Tor config!)'}")
    sys.exit(0 if is_tor else 2)


# --------------------------------------------------------------- version ---

@cli.command(name="version")
def version_cmd() -> None:
    """Print version information and dependency status."""
    click.echo(BANNER)
    click.echo("  AnonShare v1.0.0\n")

    deps = {
        "magic-wormhole": "wormhole",
        "PyNaCl":         "nacl",
        "cryptography":   "cryptography",
        "click":          "click",
        "PySocks":        "socks",
        "requests":       "requests",
        "stem":           "stem",
    }
    for name, module in deps.items():
        try:
            m = __import__(module)
            ver = getattr(m, "__version__", "installed")
            status = f"✅ {ver}"
        except ImportError:
            status = "❌ NOT INSTALLED"
        click.echo(f"  {name:<20} {status}")


# ----------------------------------------------------------------- helpers --

def _file_size_str(path: str) -> str:
    from utils import human_size
    try:
        return human_size(os.path.getsize(path))
    except OSError:
        return "?"


# --------------------------------------------------------------- entrypoint --

if __name__ == "__main__":
    cli()
