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
import os
import functools
import json
import config
from tracer import Tracer, run_sniffer as run_tracer_sniffer # Tracer class and sniffer runner
from websocket_ping import measure_websocket_rtt
from static_server import start_static_server_thread

try:
    # Scapy needed for conf object access
    from scapy.all import conf
except ImportError:
    logging.error("Scapy import failed in server.py. Is it installed?")
    exit(1)
except OSError as e:
    logging.error(f"Error initializing Scapy (maybe npcap/libpcap issue?): {e}")
    exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

if 'conf' in locals() or 'conf' in globals():
    conf.verb = config.SCAPY_VERBOSITY # Set Scapy verbosity from config
else:
    logging.warning("Scapy 'conf' object not available, cannot set verbosity.")


# Global State
sniffer_stop_event = threading.Event() # Signals sniffer thread termination
sniffer_thread = None # Holds the sniffer thread object
server_ip = None      # Holds the determined server IP
tracer_instance = None # Holds the single Tracer instance


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
                    # Prefer non-link-local, non-loopback IPs
                    if ip and not ip.startswith('127.') and not ip.startswith('169.254.'):
                        logging.info(f"Using local IP {ip} from interface {iface_name}")
                        return ip
    except Exception as e:
        logging.error(f"Could not determine local IP: {e}")
    logging.warning("Could not automatically determine local IP. Using 0.0.0.0")
    return "0.0.0.0"


# WebSocket Handler (receives the global tracer instance)
async def handle_connection(websocket, path, tracer):
    """Handles WebSocket connections and runs measurements using the provided tracer."""
    client_addr = websocket.remote_address
    client_ip, client_port_str = client_addr
    client_port = int(client_port_str)
    logging.info(f"WebSocket connection established from: {client_ip}:{client_port}")

    client_log_prefix = f"[{client_ip}:{client_port}]" # Prefix for client logs

    try:
        server_addr = websocket.local_address
        server_ip_local, server_port_str = server_addr
        server_port_local = int(server_port_str)

        # Run 0trace
        if tracer is None: # Check if tracer was passed correctly
            logging.error(f"{client_log_prefix} Tracer instance not available. Cannot perform 0trace.")
            try:
                await websocket.send(json.dumps({"type": "error", "message": "Server tracer not initialized."}))
            except websockets.exceptions.ConnectionClosed: pass
            return

        # Run blocking Scapy code in a thread pool
        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as pool:
             trace_rtt_ms, trace_hop_ip, trace_success = await loop.run_in_executor(
                 pool,
                 tracer.measure_0trace_rtt, # Use the passed tracer instance's method
                 server_ip_local,
                 server_port_local,
                 client_ip,
                 client_port,
                 sniffer_thread # Pass the global sniffer thread
             )

        # Process 0trace results
        if not trace_success:
            logging.info(f"{client_log_prefix} 0trace measurement failed or did not reach destination.")
        else:
            logging.info(f"{client_log_prefix} 0trace Results: Furthest Hop = {trace_hop_ip}, RTT = {trace_rtt_ms:.2f}ms")

        # WebSocket Ping Measurement
        if websocket.closed: # Check connection before ping
             logging.info(f"{client_log_prefix} Connection closed before WebSocket ping sequence.")
             return
        ws_rtts_ms = await measure_websocket_rtt(websocket, client_log_prefix)

        # Analyze Results
        if websocket.closed: # Check connection again before analysis
            logging.info(f"{client_log_prefix} Connection closed after WebSocket ping sequence. Skipping analysis.")
            return

        if not ws_rtts_ms:
            logging.error(f"{client_log_prefix} No successful WebSocket pings.")
            await websocket.send(json.dumps({"type": "error", "message": "Failed to get WebSocket RTT."})) # Try sending error
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
            "proxy_detected": None, # Default: unknown
            "message": ""
        }

        if not trace_success:
            logging.info(f"{client_log_prefix} Conclusion: Cannot determine proxy status reliably (0trace failed or incomplete).")
            result_data["message"] = (f"WebSocket Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples). "
                                      f"0trace measurement did not succeed.")
        else:
            # Compare WebSocket RTT with 0trace RTT
            rtt_difference = min_ws_rtt - trace_rtt_ms # Positive difference suggests proxy
            logging.info(f"{client_log_prefix} RTT Difference (WS Min - 0trace Min): {rtt_difference:.2f}ms")

            # Determine proxy status based on threshold
            # A significantly positive difference (WS RTT >> 0trace RTT) indicates a proxy.
            if rtt_difference > config.RTT_THRESHOLD_MS:
                conclusion = "Proxy DETECTED"
                result_data["proxy_detected"] = True
                result_data["message"] = (
                    f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) > Threshold ({config.RTT_THRESHOLD_MS:.1f}ms). "
                    f"WS Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples), 0trace Min RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})"
                )
            else:
                # Includes small positive, zero, or negative differences (within tolerance)
                conclusion = "Proxy NOT detected"
                result_data["proxy_detected"] = False
                result_data["message"] = (
                    f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) <= Threshold ({config.RTT_THRESHOLD_MS:.1f}ms). "
                    f"WS Min RTT: {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} samples), 0trace Min RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})"
                )
            logging.info(f"{client_log_prefix} Conclusion: {conclusion}.")

        # Send Result to Client
        if websocket.closed: # Check connection one last time
             logging.info(f"{client_log_prefix} Connection closed before sending final result.")
             return

        await websocket.send(json.dumps({"type": "result", "data": result_data}))
        logging.info(f"{client_log_prefix} Result sent successfully.")

    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"{client_log_prefix} Connection closed normally during handling.")
    except websockets.exceptions.ConnectionClosedError as e:
        logging.warning(f"{client_log_prefix} Connection closed abnormally during handling: {e}")
    except Exception as e:
        logging.error(f"{client_log_prefix} Unexpected error in handle_connection: {e}", exc_info=True) # Catch unexpected errors
        if not websocket.closed: # Try to close gracefully
            try:
                await websocket.close(code=1011, reason="Internal server error")
            except Exception as close_err:
                logging.error(f"{client_log_prefix} Error closing websocket after exception: {close_err}")
    finally:
        # Ensure logging completion/disconnection for every attempt
        if websocket.closed:
             logging.info(f"{client_log_prefix} WebSocket connection already closed.")
        else:
             # Close if handler finished normally and socket isn't closed
             logging.info(f"{client_log_prefix} Handler finished, closing WebSocket.")
             try:
                 await websocket.close(code=1000, reason="Measurement complete") # Normal closure
             except Exception as close_err:
                 logging.error(f"{client_log_prefix} Error during explicit close: {close_err}")

        logging.info(f"{client_log_prefix} Measurement handling complete.")


async def main():
    # Globals assigned here
    global server_ip, sniffer_thread, sniffer_stop_event, tracer_instance

    # Initialize the single Tracer instance
    tracer_instance = Tracer()

    server_ip = get_local_ip()
    if server_ip == "0.0.0.0":
         logging.warning("Server IP detected as 0.0.0.0. ICMP filtering might not be precise.")
         # Attempt fallback via hostname
         try:
             hostname = socket.gethostname()
             ip_via_hostname = socket.gethostbyname(hostname)
             if not ip_via_hostname.startswith("127."):
                  logging.info(f"Using IP from hostname for filter fallback: {ip_via_hostname}")
                  server_ip = ip_via_hostname
         except socket.gaierror: logging.error("Could not resolve hostname to IP either.")

    # Determine Scapy sniffing interface (adjust if needed)
    iface = conf.iface # Use Scapy's default
    logging.info(f"Attempting to start sniffer on default interface: {iface}")

    # Start the ICMP sniffer thread
    sniffer_stop_event.clear() # Ensure stop event is clear
    sniffer_thread = threading.Thread(
        target=run_tracer_sniffer, # Use imported sniffer function
        args=(
            iface,
            server_ip,
            tracer_instance.icmp_packet_callback, # Pass the instance's callback method
            sniffer_stop_event # Pass stop event
        ),
        daemon=True # Allow main program exit even if thread runs
    )
    sniffer_thread.start()
    await asyncio.sleep(1) # Give sniffer time to init

    if not sniffer_thread.is_alive():
         logging.error("Sniffer thread failed to start. Exiting. Check permissions and interface.")
         # Exit if sniffer fails, 0trace depends on it.
         return

    # Start the static file server
    static_server_thread = start_static_server_thread(config.STATIC_SERVER_PORT, config.STATIC_DIR)
    if not static_server_thread or not static_server_thread.is_alive():
        logging.error("Static file server thread failed to start. Check logs.")
        # Consider exiting if static server is critical

    await asyncio.sleep(0.5) # Optional delay for static server startup

    logging.info(f"Starting WebSocket server on ws://0.0.0.0:{config.SERVER_PORT}")
    # Determine accessible IP for client message
    display_ip = server_ip if server_ip != "0.0.0.0" else "localhost"
    logging.info(f"Access the client HTML page at http://{display_ip}:{config.STATIC_SERVER_PORT}")
    logging.info("NOTE: Server likely needs root privileges (sudo) for Scapy.")

    # Start WebSocket server
    stop_signal = asyncio.Future() # Keeps server running

    # Create connection handler with the tracer instance partially applied
    logging.info(f"Initializing connection handler with tracer instance: {type(tracer_instance)}")
    connection_handler_with_tracer = functools.partial(handle_connection, tracer=tracer_instance)

    try:
        # `serve` context manager handles startup/shutdown
        async with websockets.serve(connection_handler_with_tracer, "0.0.0.0", config.SERVER_PORT):
            logging.info("WebSocket server started successfully.")
            await stop_signal # Keep running until stop_signal is set or error
    except OSError as e:
         # Handle common startup errors (e.g., port in use)
         if "address already in use" in str(e).lower():
             logging.error(f"WebSocket server failed to start: Port {config.SERVER_PORT} is already in use.")
         else:
             logging.error(f"WebSocket server failed to start due to OS error: {e}")
    except Exception as e:
        logging.error(f"WebSocket server encountered an unexpected error: {e}")
    finally:
        # Cleanup
        logging.info("Server shutting down...")

        # Signal sniffer thread to stop
        logging.debug("Setting sniffer stop event.")
        sniffer_stop_event.set()

        # Wait for sniffer thread to finish
        if sniffer_thread and sniffer_thread.is_alive():
             logging.debug("Joining sniffer thread...")
             sniffer_thread.join(timeout=2.0) # Wait max 2s
             if sniffer_thread.is_alive():
                 logging.warning("Sniffer thread did not exit cleanly after 2 seconds.")

        # Static server thread is daemon, exits automatically.

        logging.info("Server shutdown complete.")

if __name__ == "__main__":
    import os
    # NOTE: Root privileges required for Scapy raw sockets/sniffing.
    if os.geteuid() != 0:
        logging.error("Scapy requires root privileges. Please run with sudo.")
        # Consider enforcing root check by uncommenting exit(1)
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
