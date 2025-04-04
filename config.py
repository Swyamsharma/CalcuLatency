"""
Configuration constants for the CalcuLatency server.
"""

# --- Network Configuration ---
SERVER_PORT = 8080
STATIC_SERVER_PORT = 8081
STATIC_DIR = "static"

# --- WebSocket Ping Configuration ---
WEBSOCKET_PING_COUNT = 10
WEBSOCKET_RECV_TIMEOUT_S = 5.0
WEBSOCKET_PING_INTERVAL_S = 0.1

# --- 0trace Configuration ---
MAX_TTL = 32
TRACE_TIMEOUT_S = 1.0 # Timeout for waiting for ICMP responses for a given TTL
PROBES_PER_TTL = 3 # Number of probe packets to send for each TTL
EARLY_EXIT_TIMEOUT_COUNT = 5 # Stop trace if this many consecutive TTLs timeout

# --- Analysis Configuration ---
RTT_THRESHOLD_MS = 50.0 # Threshold for detecting proxy based on RTT difference

# --- Scapy Configuration ---
SCAPY_VERBOSITY = 0 # 0 for quiet, 1 for default
