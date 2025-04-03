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
import http.server
import socketserver
import os
import functools
import json

try:
    from scapy.all import IP, TCP, ICMP, sr1, send, sniff, conf
    from scapy.layers.inet import IPerror, TCPerror
    conf.verb = 0 # Make Scapy less verbose
except ImportError:
    logging.error("Scapy is not installed or import failed. Please run: pip install scapy")
    exit(1)
except OSError as e:
    logging.error(f"Error initializing Scapy (maybe npcap/libpcap issue?): {e}")
    exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# --- Configuration ---
SERVER_PORT = 8080
WEBSOCKET_PING_COUNT = 10
RTT_THRESHOLD_MS = 50.0
MAX_TTL = 32
TRACE_TIMEOUT_S = 1.0
PROBES_PER_TTL = 3
EARLY_EXIT_TIMEOUT_COUNT = 5
STATIC_DIR = "static"

# --- 0trace Globals / Shared State ---
icmp_responses = {}
icmp_responses_lock = threading.Lock()
probes_sent = {}
probes_sent_lock = threading.Lock()
sniffer_stop_event = threading.Event()
sniffer_thread = None
server_ip = None

# --- Helper Functions ---
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
                    if ip and not ip.startswith('127.'):
                        logging.info(f"Using local IP {ip} from interface {iface_name}")
                        return ip
    except Exception as e:
        logging.error(f"Could not determine local IP: {e}")
    logging.warning("Could not automatically determine local IP. Using 0.0.0.0")
    return "0.0.0.0"

# --- 0trace Implementation ---

def icmp_packet_callback(packet):
    """Callback function for the Scapy sniffer."""
    global icmp_responses, icmp_responses_lock
    try:
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            icmp_layer = packet.getlayer(ICMP)
            outer_ip = packet.getlayer(IP)
            if icmp_layer.type == 11 or icmp_layer.type == 3: # Time Exceeded or Dest Unreachable
                if packet.haslayer(IPerror) and packet.haslayer(TCPerror):
                    inner_tcp = packet.getlayer(TCPerror)
                    original_seq = inner_tcp.seq
                    response_info = (time.time(), outer_ip.src)
                    with icmp_responses_lock:
                        icmp_responses[original_seq] = response_info
    except Exception as e:
        logging.error(f"Error in ICMP callback: {e}")

def stop_sniffer_filter(packet):
    """Used by Scapy's sniff function to know when to stop."""
    return sniffer_stop_event.is_set()

def run_sniffer(interface, server_ip_filter):
    """Runs the Scapy sniffer in a separate thread."""
    global sniffer_stop_event
    logging.info(f"Starting ICMP sniffer on interface {interface}...")
    bpf_filter = f"icmp and dst host {server_ip_filter}"
    try:
        sniff(iface=interface, filter=bpf_filter, prn=icmp_packet_callback, stop_filter=stop_sniffer_filter, store=0)
    except OSError as e:
         logging.error(f"Sniffer failed to start on {interface}. Error: {e}. Check permissions/interface.")
    except Exception as e:
        logging.error(f"Sniffer encountered an error: {e}")
    logging.info("ICMP sniffer stopped.")

def measure_0trace_rtt(local_ip_str, local_port, remote_ip_str, remote_port):
    """Performs the 0trace measurement using Scapy."""
    global probes_sent, probes_sent_lock, icmp_responses, icmp_responses_lock, sniffer_thread
    logging.info(f"[{remote_ip_str}:{remote_port}] Starting 0trace measurement...")

    if sniffer_thread is None or not sniffer_thread.is_alive():
         logging.error("Sniffer thread not running. Cannot perform 0trace.")
         return 0, None, False

    results = {}
    max_responded_ttl = 0
    final_rtt = 0
    final_hop_ip = None
    trace_success = False
    destination_reached_flag = False
    consecutive_timeouts = 0

    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Starting TTL loop...")
    for ttl in range(1, MAX_TTL + 1):
        received_in_ttl = False
        sent_seqs_this_ttl = []

        for i in range(PROBES_PER_TTL):
            tcp_seq = random.randint(1, 2**32 - 1)
            ip_layer = IP(dst=remote_ip_str, ttl=ttl)
            tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=random.randint(1, 2**32 - 1))
            packet = ip_layer / tcp_layer

            send_time = time.time()
            try:
                send(packet, verbose=0)
                with probes_sent_lock:
                    probes_sent[tcp_seq] = (send_time, ttl)
                sent_seqs_this_ttl.append(tcp_seq)
            except OSError as e:
                 logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}. Check permissions.")
                 if i == PROBES_PER_TTL - 1 and not sent_seqs_this_ttl: return 0, None, False
                 continue
            except Exception as e:
                logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}")
                continue

        wait_deadline = time.time() + TRACE_TIMEOUT_S
        processed_seqs_in_wait = set()

        while time.time() < wait_deadline and not received_in_ttl:
            time.sleep(0.05)
            found_response_this_poll = False
            with icmp_responses_lock:
                keys_to_check = list(icmp_responses.keys())
                for seq in keys_to_check:
                    if seq in processed_seqs_in_wait or seq not in sent_seqs_this_ttl: continue
                    resp_time, hop_ip_str = icmp_responses[seq]
                    with probes_sent_lock:
                        if seq in probes_sent:
                            send_time, probe_ttl = probes_sent[seq]
                            if probe_ttl == ttl:
                                rtt_s = resp_time - send_time
                                rtt_ms = rtt_s * 1000.0
                                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Received ICMP: TTL={ttl}, Hop={hop_ip_str}, RTT={rtt_ms:.2f}ms (Orig Seq: {seq})")
                                if ttl not in results or rtt_s < results[ttl][1]:
                                    results[ttl] = (hop_ip_str, rtt_s)
                                max_responded_ttl = ttl
                                received_in_ttl = True
                                found_response_this_poll = True
                                processed_seqs_in_wait.add(seq)
                                del icmp_responses[seq]
                                if hop_ip_str == remote_ip_str:
                                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Destination reached at TTL {ttl}")
                                    trace_success = True
                                    destination_reached_flag = True
                                    break
            if destination_reached_flag: break

        if destination_reached_flag: break

        if not received_in_ttl:
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Timeout: No response for TTL {ttl}")
            consecutive_timeouts += 1
            if consecutive_timeouts >= EARLY_EXIT_TIMEOUT_COUNT:
                logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace: Exiting early after {EARLY_EXIT_TIMEOUT_COUNT} consecutive timeouts.")
                break
        else:
            consecutive_timeouts = 0

    if max_responded_ttl > 0 and max_responded_ttl in results:
        final_hop_ip_str, final_rtt_s = results[max_responded_ttl]
        final_rtt = final_rtt_s * 1000.0
        final_hop_ip = final_hop_ip_str
        if not trace_success: trace_success = True
        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Final Result: MaxTTL={max_responded_ttl}, Hop={final_hop_ip}, RTT={final_rtt:.2f}ms")
    else:
        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Final Result: No responsive hops found.")
        trace_success = False

    with probes_sent_lock:
        keys_to_delete = list(probes_sent.keys())
        for seq in keys_to_delete:
            del probes_sent[seq]
            with icmp_responses_lock:
                 icmp_responses.pop(seq, None)

    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace measurement finished. Success: {trace_success}")
    return final_rtt, final_hop_ip, trace_success

# --- WebSocket Handler ---
async def handle_connection(websocket, path):
    """Handles WebSocket connections and runs measurements."""
    client_addr = websocket.remote_address
    client_ip, client_port_str = client_addr
    client_port = int(client_port_str)
    logging.info(f"WebSocket connection established from: {client_ip}:{client_port}")

    server_addr = websocket.local_address
    server_ip_local, server_port_str = server_addr
    server_port_local = int(server_port_str)

    loop = asyncio.get_running_loop()
    with ThreadPoolExecutor() as pool:
         trace_rtt_ms, trace_hop_ip, trace_success = await loop.run_in_executor(
             pool, measure_0trace_rtt, server_ip_local, server_port_local, client_ip, client_port
         )

    if not trace_success:
        logging.info(f"[{client_ip}:{client_port}] 0trace measurement failed or did not reach destination.")
    else:
        logging.info(f"[{client_ip}:{client_port}] 0trace Results: Furthest Hop = {trace_hop_ip}, RTT = {trace_rtt_ms:.2f}ms")

    logging.info(f"[{client_ip}:{client_port}] Starting WebSocket ping...")
    ws_rtts_ms = []
    try:
        for i in range(WEBSOCKET_PING_COUNT):
            start_time = time.time()
            ping_payload = {"type": "ping", "timestamp": int(start_time * 1000)}
            await websocket.send(json.dumps(ping_payload))
            try:
                pong_data = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                end_time = time.time()
                try:
                    pong_payload = json.loads(pong_data)
                    if pong_payload.get("type") == "pong" and pong_payload.get("timestamp") == ping_payload["timestamp"]:
                        rtt_s = end_time - start_time
                        ws_rtts_ms.append(rtt_s * 1000.0)
                    else:
                        logging.warning(f"[{client_ip}:{client_port}] Pong mismatch or wrong type: {pong_payload}")
                except json.JSONDecodeError:
                     logging.warning(f"[{client_ip}:{client_port}] Could not parse pong JSON: {pong_data}")
                except Exception as parse_err:
                    logging.warning(f"[{client_ip}:{client_port}] Error processing pong: {parse_err}")
            except asyncio.TimeoutError:
                logging.warning(f"[{client_ip}:{client_port}] WebSocket pong timeout.")
                continue
            except Exception as e:
                 logging.error(f"[{client_ip}:{client_port}] Error receiving WebSocket pong: {e}")
                 break
            await asyncio.sleep(0.1)
    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"Connection closed normally by {client_ip}:{client_port}")
        return
    except Exception as e:
        logging.error(f"WebSocket error with {client_ip}:{client_port}: {e}")
        return

    if not ws_rtts_ms:
        logging.error(f"[{client_ip}:{client_port}] No successful WebSocket pings.")
        try: await websocket.send("Error: Failed to get WebSocket RTT.")
        except: pass
        return

    min_ws_rtt = min(ws_rtts_ms) if ws_rtts_ms else 0
    logging.info(f"[{client_ip}:{client_port}] WebSocket Results: Min RTT = {min_ws_rtt:.2f}ms ({len(ws_rtts_ms)} successful pings)")

    result_message = ""
    if not trace_success:
        logging.info(f"[{client_ip}:{client_port}] Conclusion: Cannot determine proxy status reliably without successful 0trace RTT.")
        result_message = f"Result: WebSocket Min RTT = {min_ws_rtt:.2f}ms. 0trace measurement failed, cannot reliably detect proxy."
    else:
        rtt_difference = abs(min_ws_rtt - trace_rtt_ms)
        logging.info(f"[{client_ip}:{client_port}] RTT Difference (WebSocket Min vs 0trace): {rtt_difference:.2f}ms")
        if rtt_difference > RTT_THRESHOLD_MS:
            conclusion = "Proxy DETECTED"
            result_message = (f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) > Threshold ({RTT_THRESHOLD_MS:.1f}ms). "
                              f"WS Min RTT: {min_ws_rtt:.2f}ms, 0trace RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})")
        else:
            conclusion = "Proxy NOT detected"
            result_message = (f"Result: {conclusion}. RTT Difference ({rtt_difference:.2f}ms) <= Threshold ({RTT_THRESHOLD_MS:.1f}ms). "
                              f"WS Min RTT: {min_ws_rtt:.2f}ms, 0trace RTT: {trace_rtt_ms:.2f}ms (Hop: {trace_hop_ip})")
        logging.info(f"[{client_ip}:{client_port}] Conclusion: {conclusion}.")

    try:
        await websocket.send(result_message)
    except websockets.exceptions.ConnectionClosedOK: pass
    except Exception as e: logging.error(f"Error sending final result to {client_ip}:{client_port}: {e}")

    logging.info(f"[{client_ip}:{client_port}] Measurement complete.")

# --- Static File Server ---
def run_static_server(port, directory):
    """Runs a simple HTTP server for static files."""
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)
    socketserver.TCPServer.allow_reuse_address = True
    try:
        if not os.path.isdir(directory):
             logging.error(f"Static directory '{directory}' not found. Cannot start static server.")
             return
        with socketserver.TCPServer(("", port), handler) as httpd:
            logging.info(f"Static file server thread started on port {port}, serving '{directory}'")
            httpd.serve_forever()
    except OSError as e: logging.error(f"Static file server failed to start on port {port}: {e}")
    except Exception as e: logging.error(f"Static file server encountered an error: {e}")
    logging.info("Static file server thread stopped.")

# --- Main Server Logic ---
async def main():
    global server_ip, sniffer_thread, sniffer_stop_event
    server_ip = get_local_ip()
    if server_ip == "0.0.0.0":
         logging.warning("Server IP detected as 0.0.0.0. ICMP filtering might not be precise.")
         try:
             hostname = socket.gethostname()
             ip_via_hostname = socket.gethostbyname(hostname)
             if not ip_via_hostname.startswith("127."):
                  logging.info(f"Using IP from hostname for filter fallback: {ip_via_hostname}")
                  server_ip = ip_via_hostname
         except socket.gaierror: logging.error("Could not resolve hostname to IP either.")

    iface = conf.iface
    logging.info(f"Attempting to start sniffer on interface: {iface}")
    sniffer_stop_event.clear()
    sniffer_thread = threading.Thread(target=run_sniffer, args=(iface, server_ip), daemon=True)
    sniffer_thread.start()
    await asyncio.sleep(1)

    if not sniffer_thread.is_alive():
         logging.error("Sniffer thread failed to start. Exiting. Check permissions and interface name.")
         return

    logging.info(f"Starting WebSocket server on {server_ip}:{SERVER_PORT}")
    logging.info(f"Access the client HTML page at http://{server_ip}:8081")
    logging.info(f"WebSocket connections should go to ws://{server_ip}:{SERVER_PORT}")
    logging.info("NOTE: Server needs root privileges (sudo) for Scapy raw sockets and sniffing.")

    static_file_port = 8081
    static_server_thread = threading.Thread(target=run_static_server, args=(static_file_port, STATIC_DIR), daemon=True)
    static_server_thread.start()
    logging.info(f"Started static file server for '{STATIC_DIR}' on port {static_file_port}")
    await asyncio.sleep(0.5)

    try:
        async with websockets.serve(handle_connection, "0.0.0.0", SERVER_PORT):
            await asyncio.Future()
    except OSError as e:
         if "address already in use" in str(e).lower(): logging.error(f"Server failed to start: Port {SERVER_PORT} is already in use.")
         else: logging.error(f"Server failed to start (WebSocket): {e}")
    except Exception as e: logging.error(f"Server encountered an error: {e}")
    finally:
        logging.info("Server shutting down...")
        sniffer_stop_event.set()
        if sniffer_thread and sniffer_thread.is_alive():
             sniffer_thread.join(timeout=2.0)
             if sniffer_thread.is_alive(): logging.warning("Sniffer thread did not exit cleanly.")

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
