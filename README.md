# CalcuLatency: Proxy Detection via RTT Comparison

CalcuLatency is a Python-based tool designed to detect the presence of network proxies between a client and a server. It achieves this by comparing the Round-Trip Time (RTT) measured over a WebSocket connection against the RTT measured using a low-level network path tracing technique (0trace).

## How it Works

The core principle is that a direct network path (measured by 0trace) should generally have a lower RTT than a path going through an application-level proxy (measured via WebSocket ping/pong). If the WebSocket RTT is significantly higher than the 0trace RTT, it suggests the WebSocket connection is being routed through an intermediary, likely a proxy.

The process involves two key measurements performed when a client connects:

1.  **WebSocket RTT Measurement:**
    *   The server sends a configurable number of ping messages (`WEBSOCKET_PING_COUNT`) over the established WebSocket connection.
    *   Each ping is a JSON message containing a unique timestamp (`{"type": "ping", "timestamp": ...}`).
    *   The client-side JavaScript is expected to immediately reply with a corresponding pong message (`{"type": "pong", "timestamp": ...}`).
    *   The server calculates the RTT for each successful ping/pong exchange.
    *   The minimum RTT observed across all pings is used for comparison. This is implemented in `websocket_ping.py`.

2.  **0trace RTT Measurement:**
    *   This technique uses the Scapy library to send low-level network packets and sniff for responses, bypassing potential application-level proxies.
    *   **Packet Crafting:** It sends TCP ACK packets towards the client. Using ACK packets is often effective as they are less likely to be blocked by firewalls than SYN packets and don't typically elicit an application-level response from the client.
    *   **TTL Probing (Phase 1):** Packets are sent with incrementally increasing Time-To-Live (TTL) values, starting from 1 up to `MAX_TTL`.
    *   **ICMP Sniffing:** The server sniffs for incoming ICMP "Time Exceeded" (type 11) messages (sent by routers when TTL expires) or "Destination Unreachable" (type 3) messages (potentially sent by the destination or firewalls). These ICMP messages typically contain the header of the original packet that triggered them.
    *   **Hop Discovery:** By matching the sequence number in the returned TCP header within the ICMP message to the sequence number of a sent probe, the server identifies the IP address of the router (hop) at each TTL and calculates the RTT to that hop. Phase 1 sends one probe per TTL to find the furthest responding hop.
    *   **Final RTT Measurement (Phase 2):** Once the furthest hop (or the destination itself) is identified in Phase 1, the server sends multiple probes (`FINAL_RTT_PROBE_COUNT`) directly to that hop using the corresponding TTL. The minimum RTT recorded from these probes provides a more accurate measurement of the network path RTT to the final reachable point.
    *   This logic is encapsulated within the `Tracer` class in `tracer.py`.

3.  **Comparison and Detection:**
    *   The server compares the minimum WebSocket RTT (`ws_min_rtt_ms`) with the minimum 0trace RTT to the final hop (`trace_rtt_ms`).
    *   If `ws_min_rtt_ms - trace_rtt_ms > RTT_THRESHOLD_MS` (where `RTT_THRESHOLD_MS` is a configurable value in `config.py`), the tool concludes that a proxy is likely present.
    *   The results, including RTT values, the final 0trace hop IP, and the detection conclusion, are sent back to the client via WebSocket.

## Project Components

The repository contains two versions of the server implementation:

*   **`Single_client/`**:
    *   Designed to handle only one client connection at a time.
    *   Uses a single, global `Tracer` instance to manage 0trace state.
    *   Simpler implementation but not suitable for concurrent use.

*   **`Multi_client/`**:
    *   Designed to handle multiple client connections concurrently.
    *   Uses module-level shared dictionaries (protected by locks) to store probe/response information from the global ICMP sniffer.
    *   Each connection handler creates a *stateless* `Tracer` instance that interacts with this shared state via unique TCP sequence numbers.
    *   Allows multiple 0trace and WebSocket measurements to run in parallel without interfering with each other.

Both versions share the same `config.py`, `websocket_ping.py`, `static_server.py`, and client-side `static/` files (`index.html`, `script.js`).

## Dependencies

*   Python 3
*   `websockets` (`pip install websockets`)
*   `scapy` (`pip install scapy`)
*   `netifaces` (`pip install netifaces`)

**Note:** Scapy requires root/administrator privileges to send raw packets and perform network sniffing.

## Usage

1.  **Clone the repository.**
2.  **Navigate to either the `Single_client` or `Multi_client` directory.**
    ```bash
    cd CalcuLatency/calculatency_py/Multi_client # Or Single_client
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt # (You might need to create this file based on the imports)
    # Or manually: pip install websockets scapy netifaces
    ```
4.  **Run the server with root privileges:**
    ```bash
    sudo python3 server.py
    ```
5.  **Access the client interface:**
    *   The server will log the IP address and port for the static file server (defaulting to port 8081).
    *   Open a web browser and navigate to `http://13.203.195.215:8081`.
6.  **Click the "Start Test" button** on the web page to initiate the WebSocket connection and measurements.
7.  The results will be displayed on the web page.

## Configuration

Key parameters can be adjusted in `config.py`:

*   `SERVER_PORT`: Port for the main WebSocket server.
*   `STATIC_SERVER_PORT`: Port for the HTTP server serving the static files.
*   `WEBSOCKET_PING_COUNT`: Number of WebSocket pings to perform.
*   `MAX_TTL`: Maximum TTL value for 0trace probes.
*   `TRACE_TIMEOUT_S`: Timeout for waiting for an ICMP response for a specific TTL in 0trace Phase 1.
*   `FINAL_RTT_PROBE_COUNT`: Number of probes sent to the final hop in 0trace Phase 2.
*   `RTT_THRESHOLD_MS`: The RTT difference threshold (WebSocket RTT - 0trace RTT) used for proxy detection.
*   `SCAPY_VERBOSITY`: Controls Scapy's output level.
