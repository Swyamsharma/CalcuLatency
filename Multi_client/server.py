#!/usr/bin/env python3

import asyncio
import websockets
import time
import logging
import netifaces
import socket
import threading
import random
from concurrent.futures import ThreadPoolExecutor
# Remove http.server and socketserver imports as they are now in static_server.py
# import http.server
# import socketserver
import os
import json
import config # Import the configuration module
# Import Tracer class for local instantiation, module callback, and sniffer runner
from tracer import Tracer, icmp_packet_callback as tracer_callback, run_sniffer as run_tracer_sniffer
from websocket_ping import measure_websocket_rtt # Import WebSocket ping function
from static_server import start_static_server_thread # Import static server starter

try:
    # Scapy import needed for conf object access, even if logic moved
    from scapy.all import conf
    # No longer need direct IP, TCP, ICMP etc. imports here
except ImportError:
    logging.error("Scapy base import failed in server.py. Is it installed?")
    exit(1)
except OSError as e:
    logging.error(f"Error initializing Scapy (maybe npcap/libpcap issue?): {e}")
    exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# Set Scapy verbosity from config
# Ensure conf was imported successfully before accessing
if 'conf' in locals() or 'conf' in globals():
    conf.verb = config.SCAPY_VERBOSITY
else:
    logging.warning("Scapy 'conf' object not available, cannot set verbosity.")


# --- Global State (Reduced) ---
sniffer_stop_event = threading.Event() # Used to signal sniffer thread termination
sniffer_thread = None # Holds the sniffer thread object
server_ip = None      # Holds the determined server IP
# tracer_instance = None # No longer needed globally

# --- Helper Functions ---
# get_local_ip remains the same
def get_local_ip():
    """Finds a suitable non-loopback IPv4 address for the server."""
    try:
        interfaces = netifaces.interfaces()
        for iface_name in interfaces:
            if iface_name == 'lo': continue
            ifaddresses = netifaces.ifaddresses(iface_name)
            if netifaces.AF_INET in ifaddresses:
                for link in ifaddresses[netifaces.AF_INET]:
                    ip = link.get('addr')
                    # Basic check to prefer non-link-local, non-loopback
                    if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                        logging.info(f"Using local IP {ip} from interface {iface_name}")
                        return ip
    except Exception as e:
        logging.error(f"Could not determine local IP: {e}")
    logging.warning("Could not automatically determine local IP. Using 0.0.0.0")
    return "0.0.0.0"

# --- WebSocket Handler ---
# No longer needs tracer passed in
async def handle_connection(websocket, path):
    """Handles WebSocket connections and runs measurements."""
    client_addr = websocket.remote_address
    client_ip, client_port_str = client_addr
    client_port = int(client_port_str)
    logging.info(f"WebSocket connection established from: {client_ip}:{client_port}")

    client_log_prefix = f"[{client_ip}:{client_port}]" # For consistent logging

    try:
        server_addr = websocket.local_address
        server_ip_local, server_port_str = server_addr
        server_port_local = int(server_port_str)

        # --- Run 0trace ---
        # Create a local Tracer instance for this connection's measurement logic
        local_tracer = Tracer()

        # Run the blocking Scapy code in a separate thread using the local tracer instance's method
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
             # Pass the global sniffer thread to the local tracer's method
             trace_rtt_ms, trace_hop_ip, trace_success = await loop.run_in_executor(
                 pool,
                 local_tracer.measure_0trace_rtt, # Call the method on the local instance
                 server_ip_local,
                 server_port_local,
                 client_ip,
                 client_port,
                 sniffer_thread # Pass the global sniffer thread object
             )

        # --- Process 0trace Results ---
        if not trace_success:
            logging.info(f"{client_log_prefix} 0trace measurement failed or did not reach destination.")
        else:
            logging.info(f"{client_log_prefix} 0trace Results: Furthest Hop = {trace_hop_ip}, RTT = {trace_rtt_ms:.2f}ms")

        # --- WebSocket Ping Measurement ---
        # Check connection before starting ping
        if websocket.closed:
             logging.info(f"{client_log_prefix} Connection closed before WebSocket ping sequence.")
             return
        ws_rtts_ms = await measure_websocket_rtt(websocket, client_log_prefix)

        # --- Analyze Results ---
        # Check connection again before analysis
        if websocket.closed:
            logging.info(f"{client_log_prefix} Connection closed after WebSocket ping sequence. Skipping analysis.")
            return

        if not ws_rtts_ms:
            logging.error(f"{client_log_prefix} No successful WebSocket pings.")
            # Try sending error to client
            await websocket.send(json.dumps({"type": "error", "message": "Failed to get WebSocket RTT."}))
            return

        min_ws_rtt = min(ws_rtts_ms) if ws_rtts_ms else 0
        logging.info(f"{client_log_prefix} WebSocket Results: Min RTT = {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} successful pings)")

        result_data = {
            "ws_min_rtt_ms": min_ws_rtt,
            "ws_rtt_samples": len(ws_rtts_ms),
            "trace_rtt_ms": trace_rtt_ms if trace_success else None,
            "trace_hop_ip": trace_hop_ip if trace_success else None,
            "trace_success": trace_success,
            "threshold_ms": config.RTT_THRESHOLD_MS,
            "proxy_detected": None, # Default to unknown
            "message": ""
        }

        if not trace_success:
            logging.info(f"{client_log_prefix} Conclusion: Cannot determine proxy status reliably (0trace failed or incomplete).")
            result_data["message"] = (f"WebSocket Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples). "
                                      f"0trace measurement did not succeed.")
        else:
            # This block executes if trace_success is True
            # Compare WebSocket RTT with the refined 0trace RTT
            # Calculate difference as WS - 0trace (positive value suggests proxy)
            rtt_difference = min_ws_rtt - trace_rtt_ms
        logging.info(f"{client_log_prefix} RTT Difference (WS Min - 0trace Min): {rtt_difference:.2f}ms")

        # Determine proxy status based on the difference and threshold
        # A significantly positive difference (WS RTT >> 0trace RTT) indicates a proxy.
        if rtt_difference > config.RTT_THRESHOLD_MS:
            conclusion = "Proxy DETECTED"
            result_data["proxy_detected"] = True
            result_data["message"] = (
                f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) > Threshold ({config.RTT_THRESHOLD_MS:.1f}ms). "
                f"WS Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples), 0trace Min RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})"
            )
        else:
            # Includes cases where difference is small positive, zero, or negative (0trace slightly higher but within tolerance)
            conclusion = "Proxy NOT detected"
            result_data["proxy_detected"] = False
            result_data["message"] = (
                f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) <= Threshold ({config.RTT_THRESHOLD_MS:.1f}ms). "
                f"WS Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples), 0trace Min RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})"
            )
            logging.info(f"{client_log_prefix} Conclusion: {conclusion}.")

        # --- Send Result to Client (inside the main try block) ---
        # Check connection one last time before sending
        if websocket.closed:
             logging.info(f"{client_log_prefix} Connection closed before sending final result.")
             return

        await websocket.send(json.dumps({"type": "result", "data": result_data}))
        logging.info(f"{client_log_prefix} Result sent successfully.")

    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"{client_log_prefix} Connection closed normally during handling.")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"{client_log_prefix} Connection closed abnormally during handling: {e}")
    except Exception as e:
        # Catch any other unexpected errors during the handler execution
        logging.error(f"{client_log_prefix} Unexpected error in handle_connection: {e}", exc_info=True)
        # Try to close the connection gracefully if it's still open
        if not websocket.closed:
            try:
                await websocket.close(code=1011, reason="Internal server error")
            except Exception as close_err:
                logging.error(f"{client_log_prefix} Error closing websocket after exception: {close_err}")
    finally:
        # This block executes whether an exception occurred or not.
        # Ensures we log completion or disconnection for every connection attempt.
        if websocket.closed:
             logging.info(f"{client_log_prefix} WebSocket connection already closed.")
        else:
             # If the handler finished normally and the socket isn't closed, close it now.
             logging.info(f"{client_log_prefix} Handler finished, closing WebSocket.")
             try:
                 await websocket.close(code=1000, reason="Measurement complete") # Normal closure
             except Exception as close_err:
                 logging.error(f"{client_log_prefix} Error during explicit close: {close_err}")

        logging.info(f"{client_log_prefix} Measurement handling complete.")

# --- Main Server Logic ---
async def main():
    # Declare globals that will be assigned in this function
    # No longer need tracer_instance here
    global server_ip, sniffer_thread, sniffer_stop_event

    # tracer_instance = Tracer() # No longer needed globally

    server_ip = get_local_ip()
    if server_ip == "0.0.0.0":
         logging.warning("Server IP detected as 0.0.0.0. ICMP filtering might not be precise.")
         # Attempt fallback using hostname resolution
         try:
             hostname = socket.gethostname()
             ip_via_hostname = socket.gethostbyname(hostname)
             if not ip_via_hostname.startswith("127."):
                  logging.info(f"Using IP from hostname for filter fallback: {ip_via_hostname}")
                  server_ip = ip_via_hostname
         except socket.gaierror: logging.error("Could not resolve hostname to IP either.")

    # Determine the interface for Scapy sniffing
    # Using conf.iface is usually the best default, but might need adjustment
    # depending on the system or if multiple active interfaces exist.
    iface = conf.iface # Use Scapy's default interface detection
    logging.info(f"Attempting to start sniffer on default interface: {iface}")

    # Start the ICMP sniffer thread using the function from tracer module
    sniffer_stop_event.clear() # Ensure the stop event is not set initially
    sniffer_thread = threading.Thread(
        target=run_tracer_sniffer, # Use the imported sniffer function
        args=(
            iface,
            server_ip,
            tracer_callback, # Pass the module-level callback function
            sniffer_stop_event # Pass the stop event
        ),
        daemon=True # Allows main program to exit even if thread is running
    )
    sniffer_thread.start()
    await asyncio.sleep(1) # Give sniffer time to initialize

    if not sniffer_thread.is_alive():
         logging.error("Sniffer thread failed to start. Exiting. Check permissions and interface name.")
         # Exit if sniffer fails to start, as 0trace depends on it.
         # Exit if sniffer fails to start, as 0trace depends on it.
         return

    # Start the static file server using the dedicated function
    static_server_thread = start_static_server_thread(config.STATIC_SERVER_PORT, config.STATIC_DIR)
    if not static_server_thread or not static_server_thread.is_alive():
        logging.error("Static file server thread failed to start. Check logs.")
        # Decide if you want to exit or continue without the static server
        # return # Uncomment to exit if static server fails

    # Give the static server a moment to start up (optional, but can be helpful)
    await asyncio.sleep(0.5)

    logging.info(f"Starting WebSocket server on ws://0.0.0.0:{config.SERVER_PORT}")
    # Determine the accessible IP for the client page message
    display_ip = server_ip if server_ip != "0.0.0.0" else "localhost"
    logging.info(f"Access the client HTML page at http://{display_ip}:{config.STATIC_SERVER_PORT}")
    logging.info("NOTE: Server likely needs root privileges (sudo) for Scapy raw sockets and sniffing.")

    # Start the WebSocket server
    stop_signal = asyncio.Future() # Used to keep the server running

    # --- Start WebSocket Server ---
    # No need for functools.partial anymore, just pass the handle_connection function directly
    # logging.info(f"Initializing connection handler. Global tracer_instance type: {type(tracer_instance)}, is None: {tracer_instance is None}")
    # connection_handler_with_tracer = functools.partial(handle_connection, tracer=tracer_instance)

    try:
        # The `serve` context manager handles server startup and shutdown
        # Pass the handle_connection function directly
        async with websockets.serve(handle_connection, "0.0.0.0", config.SERVER_PORT):
            logging.info("WebSocket server started successfully.")
            await stop_signal # Keep the server running until stop_signal is set or an error occurs
    except OSError as e:
         # Handle common startup errors like port already in use
         if "address already in use" in str(e).lower():
             logging.error(f"WebSocket server failed to start: Port {config.SERVER_PORT} is already in use.")
         else:
             logging.error(f"WebSocket server failed to start due to OS error: {e}")
    except Exception as e:
        logging.error(f"WebSocket server encountered an unexpected error: {e}")
    finally:
        # --- Cleanup ---
        logging.info("Server shutting down...")

        # Signal the sniffer thread to stop
        logging.debug("Setting sniffer stop event.")
        sniffer_stop_event.set()

        # Wait for the sniffer thread to finish
        if sniffer_thread and sniffer_thread.is_alive():
             logging.debug("Joining sniffer thread...")
             sniffer_thread.join(timeout=2.0) # Wait max 2 seconds
             if sniffer_thread.is_alive():
                 logging.warning("Sniffer thread did not exit cleanly after 2 seconds.")

        # Note: The static server thread is a daemon, so it will exit automatically
        # when the main thread exits. No explicit shutdown needed here unless
        # serve_forever was interrupted differently.

        logging.info("Server shutdown complete.")

if __name__ == "__main__":
    import os
    # NOTE: Root privileges are required for Scapy raw sockets and sniffing.
    if os.geteuid() != 0:
        logging.error("Scapy requires root privileges. Please run with sudo.")
        # exit(1) # Uncomment to enforce root check
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
