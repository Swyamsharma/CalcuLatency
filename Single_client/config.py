"""
Configuration constants for the CalcuLatency server.
"""

SERVER_PORT = 8080
STATIC_SERVER_PORT = 8081
STATIC_DIR = "static"

WEBSOCKET_PING_COUNT = 10
WEBSOCKET_RECV_TIMEOUT_S = 5.0
WEBSOCKET_PING_INTERVAL_S = 0.1

MAX_TTL = 32
TRACE_TIMEOUT_S = 1.0 # Timeout for ICMP response per TTL
PROBES_PER_TTL = 1 # Probes per TTL
FINAL_RTT_PROBE_COUNT = 10 # Probes for final hop RTT calculation
FINAL_RTT_PROBE_TIMEOUT_S = 0.75 # Timeout for final RTT probes

RTT_THRESHOLD_MS = 50.0 # RTT difference threshold for proxy detection

SCAPY_VERBOSITY = 0 # Scapy verbosity (0=quiet)
