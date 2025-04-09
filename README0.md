# CalcuLatency - Single Client Setup Guide

This guide explains how to set up and run the Single_client version of the CalcuLatency application. This version involves a single server process that handles WebSocket communication, 0trace measurements, and serves the static web client.

## Prerequisites

1.  **Python:** Ensure you have Python 3 installed. You can check by running `python --version` or `python3 --version` in your terminal.
2.  **pip:** Python's package installer is required. It usually comes with Python. Check with `pip --version` or `pip3 --version`.
3.  **Root/Administrator Privileges:** The 0trace functionality uses Scapy to send raw network packets and sniff ICMP responses. This typically requires root (Linux/macOS) or Administrator (Windows) privileges to run the server script.

## Setup Steps

1.  **Navigate to the Directory:**
    Open your terminal or command prompt and navigate to the `Single_client` directory within the project.
    ```bash
    cd path/to/CalcuLatency/calculatency_py/Single_client
    ```
    *(Replace `path/to/` with the actual path to the project)*

2.  **Install Dependencies:**
    Install the required Python libraries using the `requirements.txt` file located in the parent directory (`calculatency_py`).
    ```bash
    # Navigate back to the parent directory first
    cd ..
    # Install using pip (use pip3 if needed)
    pip install -r requirements.txt
    # Navigate back into Single_client
    cd Single_client
    ```
    *Note: If you encounter permission errors during installation, you might need to use `sudo pip install -r requirements.txt` on Linux/macOS or run the command prompt as Administrator on Windows.*

3.  **Configure the Server:**
    *   Open the `config.py` file inside the `Single_client` directory (`Single_client/config.py`).
    *   **`SERVER_IP`**: This is the most crucial setting. It's the IP address the WebSocket server will bind to and the IP the client-side JavaScript will try to connect to.
        *   **Scenario 1: Running Server and Client on the Same Machine:** You can often use `'localhost'` or `'127.0.0.1'`.
        *   **Scenario 2: Running Server and Client on Different Machines on the Same Local Network:** Set `SERVER_IP` to the server machine's **private IP address** on the local network (e.g., `'192.168.1.100'`). You can find this using `ip addr` (Linux), `ipconfig` (Windows), or `ifconfig` (macOS).
        *   ***Important Note on Scenarios 1 & 2:*** While these setups are useful for testing the application's functionality, the latency measurements (WebSocket RTT and 0trace RTT) will primarily reflect your local machine or local network performance, *not* the latency across the public internet to the target destination. For realistic internet latency measurements, Scenario 3 is required.
        *   **Scenario 3: Client Accessing Server Over the Internet:** This is the most complex scenario and the one required for meaningful internet latency results.
            *   The server *must* be running on a machine with a **publicly accessible IP address** (e.g., a cloud server like AWS EC2, Google Cloud Compute Engine, or a home router configured for port forwarding).
            *   Set `SERVER_IP` in `config.py` to this **public IP address**.
            *   **Firewall Configuration:** Ensure that the server's firewall allows incoming connections on the `WEBSOCKET_PORT` (default 8765) and `STATIC_SERVER_PORT` (default 8081) specified in `config.py`.
            *   **Port Forwarding (Home Network):** If running on a home network behind a router, you'll need to configure port forwarding on your router to direct traffic arriving at your public IP on ports 8765 and 8081 to the private IP address of the machine running the server on those same ports.
    *   **`WEBSOCKET_PORT`**: The port for the WebSocket server (default: 8765). Ensure this port is not already in use and is allowed through firewalls.
    *   **`STATIC_SERVER_PORT`**: The port for the simple HTTP server that serves the `index.html` and `script.js` files (default: 8081). Ensure this port is allowed through firewalls.
    *   **`INTERFACE`**: The network interface Scapy should use for sniffing ICMP packets. Leave as `None` to let Scapy try to auto-detect, or specify an interface name (e.g., `'eth0'`, `'en0'`). Auto-detection might fail; specifying the correct interface is more reliable.
    *   Other settings (like `MAX_TTL`, `TRACE_TIMEOUT_S`, etc.) control the 0trace behavior. Adjust if needed.

## Running the Application

1.  **Start the Server:**
    Run the `server.py` script. Remember that you likely need root/administrator privileges because of Scapy.
    ```bash
    # On Linux/macOS
    sudo python server.py

    # On Windows (in an Administrator Command Prompt)
    python server.py
    ```
    The server will start logging output to the console, indicating that the WebSocket and static HTTP servers are running.

2.  **Access the Client:**
    *   Open a web browser (like Chrome, Firefox, Edge).
    *   Navigate to the address of the static server. This will be `http://<SERVER_IP>:<STATIC_SERVER_PORT>`.
        *   If running locally (Scenario 1), use `http://localhost:8081` or `http://127.0.0.1:8081`.
        *   If using a private IP (Scenario 2), use `http://<server's_private_ip>:8081`.
        *   If using a public IP (Scenario 3), use `http://<server's_public_ip>:8081`.
    *   The `index.html` page should load.

3.  **Using the Application:**
    *   The web page will attempt to connect to the WebSocket server at the `ws://<SERVER_IP>:<WEBSOCKET_PORT>` address configured implicitly via the `config.py` settings used by the server (and embedded in the client JS).
    *   Enter a target domain or IP address in the input field and click "Start Measurement".
    *   The server will perform the WebSocket ping and 0trace measurement, sending results back to the browser to be displayed.

## Troubleshooting and Important Notes

*   **Permissions:** The most common issue is needing root/administrator privileges to run `server.py` because Scapy requires raw socket access.
*   **Firewalls:** Ensure ports `WEBSOCKET_PORT` (8765) and `STATIC_SERVER_PORT` (8081) are open on the server machine's firewall for incoming TCP connections. If accessing publicly, check router/cloud provider firewalls too.
*   **ICMP Blocking:** 0trace relies on ICMP "Time Exceeded" messages. Some networks or firewalls might block these, preventing 0trace from working correctly. This is especially common in corporate environments or some cloud providers' default settings.
*   **Interface:** If 0trace fails with errors about sniffing, explicitly set the correct network `INTERFACE` name in `config.py`.
*   **Server IP:** Double-check that the `SERVER_IP` in `config.py` is correct for your specific scenario (localhost, private IP, or public IP). The client JavaScript *relies* on the server correctly identifying and using this IP when serving the initial HTML/JS, as the JS will try to connect back to that same IP. If the server binds to `0.0.0.0` but the client tries to connect to `localhost`, it might only work if the client is on the same machine. Using the specific, correct IP is generally safer.
