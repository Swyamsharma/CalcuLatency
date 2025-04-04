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
TRACE_TIMEOUT_S = 1.0 # Timeout for waiting for ICMP response for a given TTL
PROBES_PER_TTL = 1 # Number of probe packets to send for each TTL (set to 1 as requested)
# EARLY_EXIT_TIMEOUT_COUNT = 5 # Removed - Scan runs up to MAX_TTL unless destination found
FINAL_RTT_PROBE_COUNT = 10 # Restore: Number of probes to send to find the minimum RTT to the final hop
FINAL_RTT_PROBE_TIMEOUT_S = 0.75 # Restore: Timeout for waiting for responses during final RTT probing

# --- Analysis Configuration ---
RTT_THRESHOLD_MS = 50.0 # Threshold for detecting proxy based on RTT difference

# --- Scapy Configuration ---
SCAPY_VERBOSITY = 0 # 0 for quiet, 1 for default
