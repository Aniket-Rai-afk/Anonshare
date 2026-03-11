# AnonShare – Configuration

# Using localhost because of the active SSH tunnel to the EC2 relay
RELAY_URL      = "ws://127.0.0.1:4000/v1"
TRANSIT_HELPER = "tcp:127.0.0.1:4001"
APP_ID         = "anonshare.secure.v1"

# Tor
TOR_SOCKS_HOST   = "127.0.0.1"
TOR_SOCKS_PORT   = 9050
TOR_CONTROL_PORT = 9051
TOR_CHECK_URL    = "https://check.torproject.org/api/ip"
TOR_CHECK_TIMEOUT = 15

# Session
DEFAULT_TIMEOUT      = 3600
MIN_PASSPHRASE_LENGTH = 12

# Crypto
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH        = 32          # bytes (256 bits)
ENABLE_PADDING    = True
PADDING_BLOCK_SIZE = 65536      # 64 KB

# I/O
CHUNK_SIZE = 65532              # optimized to fit PADDING_BLOCK_SIZE (65536 - 4)

# Timing-analysis resistance
TIMING_DELAY_MIN = 0.5          # seconds
TIMING_DELAY_MAX = 3.0
