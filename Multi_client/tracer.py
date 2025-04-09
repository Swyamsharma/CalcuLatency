#!/usr/bin/env python3

import time
import logging
import threading
import random
import config
import functools # Import functools here as it's used in run_sniffer

try:
    from scapy.all import IP, TCP, ICMP, send, sniff, conf
    from scapy.layers.inet import IPerror, TCPerror
except ImportError:
    logging.error("Scapy is not installed or import failed. Please run: pip install scapy")
    raise
except OSError as e:
    logging.error(f"Error initializing Scapy in tracer module: {e}")
    raise

# Module-level state for sharing ICMP responses and sent probe info across Tracer instances
icmp_responses = {}  # Key: original TCP seq, Value: (timestamp, hop_ip)
icmp_responses_lock = threading.Lock()
probes_sent = {}     # Key: original TCP seq, Value: (send_time, ttl)
probes_sent_lock = threading.Lock()
logging.info("Tracer module shared state initialized.")


def icmp_packet_callback(packet):
    """Scapy sniffer callback. Stores relevant ICMP responses in module globals."""
    global icmp_responses # Modifies global state
    try:
        if ICMP in packet and IP in packet:
            icmp_layer = packet[ICMP]
            outer_ip = packet[IP]
            if icmp_layer.type in (11, 3): # Time Exceeded or Dest Unreachable
                if IPerror in packet and TCPerror in packet:
                    inner_tcp = packet[TCPerror]
                    original_seq = inner_tcp.seq
                    response_info = (time.time(), outer_ip.src)
                    with icmp_responses_lock:
                        icmp_responses[original_seq] = response_info
    except Exception as e:
        logging.error(f"Error in ICMP callback: {e}")


class Tracer:
    """Encapsulates logic for one 0trace measurement, using shared module state."""

    def __init__(self):
        pass # Stateless instance

    def _cleanup_trace_state(self, trace_sent_seqs):
        """Removes state for given sequences from module globals after a trace."""
        global probes_sent, icmp_responses # Access globals
        logging.debug(f"Cleaning up state for {len(trace_sent_seqs)} sequences.")
        cleaned_probes = 0
        cleaned_responses = 0
        with probes_sent_lock:
            for seq in trace_sent_seqs:
                if probes_sent.pop(seq, None) is not None:
                    cleaned_probes += 1

        with icmp_responses_lock:
            keys_to_check = list(icmp_responses.keys()) # Avoid modifying dict while iterating
            for seq in keys_to_check:
                if seq in trace_sent_seqs:
                    del icmp_responses[seq] # Remove late/unprocessed responses
                    cleaned_responses += 1
        logging.debug(f"Cleanup complete. Removed {cleaned_probes} probes, {cleaned_responses} late/unprocessed responses.")


    def measure_0trace_rtt(self, local_ip_str, local_port, remote_ip_str, remote_port, current_sniffer_thread):
        """
        Performs 0trace measurement.
        Phase 1: 1 probe/TTL scan.
        Phase 2: Multiple probes to final hop for min RTT.
        Uses locked module globals for state.
        """
        global probes_sent, icmp_responses # Access module globals

        logging.info(f"[{remote_ip_str}:{remote_port}] Starting 0trace measurement (Phase 1: 1 probe/TTL, Phase 2: {config.FINAL_RTT_PROBE_COUNT} probes)...")

        if current_sniffer_thread is None or not current_sniffer_thread.is_alive():
             logging.error(f"[{remote_ip_str}:{remote_port}] Sniffer thread not running. Cannot perform 0trace.")
             return 0, None, False # RTT (ms), Hop IP, Success

        # State for this specific measurement run
        results = {} # Key: ttl, Value: (hop_ip_str, rtt_s) - Phase 1 results
        max_responded_ttl = 0
        phase1_final_rtt = 0.0 # RTT (ms) from Phase 1 for the final hop
        final_hop_ip = None
        trace_success = False # True if at least one hop responds
        destination_reached = False
        phase1_sent_seqs = set() # Track sequences sent in Phase 1
        phase2_sent_seqs = set() # Track sequences sent in Phase 2
        all_sent_seqs = set() # Combined for cleanup

        try: # Use finally for cleanup
            # Phase 1: Single Probe per TTL Scan
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: Scanning TTLs (Max TTL: {config.MAX_TTL})...")
            for ttl in range(1, config.MAX_TTL + 1):
                if destination_reached: break

                received_in_ttl = False
                tcp_seq = random.randint(1, 2**32 - 1)
                # Ensure unique seq across concurrent runs (can be slow if probes_sent is huge)
                with probes_sent_lock:
                    while tcp_seq in probes_sent:
                        tcp_seq = random.randint(1, 2**32 - 1)
                phase1_sent_seqs.add(tcp_seq)
                sent_seq_this_ttl = tcp_seq

                tcp_ack = random.randint(1, 2**32 - 1)
                ip_layer = IP(dst=remote_ip_str, ttl=ttl)
                tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                packet = ip_layer / tcp_layer

                ip_layer = IP(dst=remote_ip_str, ttl=ttl)
                tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                packet = ip_layer / tcp_layer

                send_time = time.time()
                try:
                    send(packet, verbose=0)
                    with probes_sent_lock:
                        probes_sent[tcp_seq] = (send_time, ttl)
                except OSError as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace OS Error sending packet (TTL {ttl}, Seq {tcp_seq}): {e}. Check permissions.")
                    trace_success = False
                    break # Exit TTL loop on send error
                except Exception as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Seq {tcp_seq}): {e}")
                    trace_success = False
                    break # Exit TTL loop on send error

                # Wait for response using module global state
                wait_deadline = time.time() + config.TRACE_TIMEOUT_S
                processed_seq_this_ttl = False
                while time.time() < wait_deadline and not processed_seq_this_ttl:
                    with icmp_responses_lock:
                        if sent_seq_this_ttl in icmp_responses:
                            resp_time, hop_ip_str = icmp_responses[sent_seq_this_ttl]
                            with probes_sent_lock:
                                if sent_seq_this_ttl in probes_sent:
                                    send_time_probe, probe_ttl = probes_sent[sent_seq_this_ttl]
                                    if probe_ttl == ttl: # Ensure response matches current TTL probe
                                        rtt_s = resp_time - send_time_probe
                                        rtt_ms = rtt_s * 1000.0
                                        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1 Received ICMP: TTL={ttl}, Hop={hop_ip_str}, RTT={rtt_ms:.2f}ms (Seq: {sent_seq_this_ttl})")
                                        results[ttl] = (hop_ip_str, rtt_s)
                                        max_responded_ttl = ttl
                                        received_in_ttl = True
                                        processed_seq_this_ttl = True
                                        del icmp_responses[sent_seq_this_ttl] # Remove processed response
                                        if hop_ip_str == remote_ip_str:
                                            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Destination {remote_ip_str} reached at TTL {ttl}")
                                            destination_reached = True
                    if not processed_seq_this_ttl:
                        time.sleep(0.02) # Small sleep to avoid busy-waiting

                if destination_reached: break

                if not received_in_ttl:
                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Timeout: No ICMP response for TTL {ttl} within {config.TRACE_TIMEOUT_S}s")
                    # Continue to next TTL even on timeout

            # Determine Phase 1 result
            if max_responded_ttl > 0 and max_responded_ttl in results:
                final_hop_ip_str, final_rtt_s = results[max_responded_ttl]
                phase1_final_rtt = final_rtt_s * 1000.0 # RTT (ms) from Phase 1
                final_hop_ip = final_hop_ip_str
                trace_success = True # Success if at least one hop responded
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1 Result: Max Responding TTL={max_responded_ttl}, Furthest Hop={final_hop_ip}, RTT={phase1_final_rtt:.2f}ms")
            elif not trace_success: # Check if send failed earlier
                 logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: Failed due to packet send error.")
                 # trace_success is already False
            else: # No hops responded
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: No responsive hops found.")
                # trace_success is already False

            # Phase 2: Final RTT Probing (only if Phase 1 succeeded)
            final_rtt = phase1_final_rtt # Default to Phase 1 RTT

            if trace_success and max_responded_ttl > 0 and final_hop_ip:
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: Probing final hop TTL {max_responded_ttl} ({final_hop_ip}) for minimum RTT ({config.FINAL_RTT_PROBE_COUNT} probes)...")
                final_rtt_values_s = []
                final_ttl_phase2 = max_responded_ttl

                for i in range(config.FINAL_RTT_PROBE_COUNT):
                    tcp_seq = random.randint(1, 2**32 - 1)
                    # Ensure unique seq
                    with probes_sent_lock:
                        while tcp_seq in probes_sent:
                            tcp_seq = random.randint(1, 2**32 - 1)
                    phase2_sent_seqs.add(tcp_seq)

                    tcp_ack = random.randint(1, 2**32 - 1)
                    ip_layer = IP(dst=remote_ip_str, ttl=final_ttl_phase2)
                    tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                    packet = ip_layer / tcp_layer

                    send_time = time.time()
                    try:
                        send(packet, verbose=0)
                        with probes_sent_lock:
                            probes_sent[tcp_seq] = (send_time, final_ttl_phase2)
                    except Exception as e:
                        logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Error sending packet (TTL {final_ttl_phase2}, Probe {i}, Seq {tcp_seq}): {e}")
                        continue # Skip this probe if send fails
                    time.sleep(0.05) # Pace probes slightly

                # Wait for Phase 2 responses
                wait_deadline = time.time() + config.FINAL_RTT_PROBE_TIMEOUT_S
                processed_phase2_seqs = set()
                while time.time() < wait_deadline:
                    time.sleep(0.02)
                    with icmp_responses_lock:
                        # Check for unprocessed responses relevant to this phase
                        relevant_seqs = [seq for seq in phase2_sent_seqs if seq in icmp_responses and seq not in processed_phase2_seqs]
                        for seq in relevant_seqs:
                            resp_time, hop_ip_str = icmp_responses[seq]
                            with probes_sent_lock:
                                if seq in probes_sent:
                                    send_time_probe, probe_ttl = probes_sent[seq]
                                    if probe_ttl == final_ttl_phase2:
                                        # Could optionally check if hop_ip_str matches final_hop_ip
                                        rtt_s = resp_time - send_time_probe
                                        final_rtt_values_s.append(rtt_s)
                                        processed_phase2_seqs.add(seq)
                                        del icmp_responses[seq] # Remove processed response

                if final_rtt_values_s:
                    min_rtt_s = min(final_rtt_values_s)
                    min_rtt_ms = min_rtt_s * 1000.0
                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Result: Min RTT to TTL {final_ttl_phase2} ({final_hop_ip}) = {min_rtt_ms:.2f}ms ({len(final_rtt_values_s)}/{config.FINAL_RTT_PROBE_COUNT} responses)")
                    final_rtt = min_rtt_ms # Update with Phase 2 minimum
                else:
                    logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: No responses received for TTL {final_ttl_phase2}. Using RTT from Phase 1 scan ({final_rtt:.2f}ms).")
                    # final_rtt keeps the Phase 1 value

            # Combine sequences for cleanup
            all_sent_seqs = phase1_sent_seqs.union(phase2_sent_seqs)

        finally:
            # Cleanup state regardless of errors
            logging.debug("Executing 0trace finally block for cleanup...")
            # Handle case where all_sent_seqs might not be defined if error occurred early
            if 'all_sent_seqs' not in locals():
                 all_sent_seqs = phase1_sent_seqs
            self._cleanup_trace_state(all_sent_seqs)

        # Log final result (using potentially updated final_rtt)
        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace measurement finished. Final RTT: {final_rtt:.2f}ms, Hop: {final_hop_ip}, Success: {trace_success}, Destination Reached: {destination_reached}")
        return final_rtt, final_hop_ip, trace_success # Return final RTT (ms)

    def _cleanup_trace_state(self, all_sent_seqs):
        """Removes state for given sequences from module globals after a trace."""
        global probes_sent, icmp_responses # Access globals
        logging.debug(f"Cleaning up state for {len(all_sent_seqs)} sequences.")
        cleaned_probes = 0
        cleaned_responses = 0
        with probes_sent_lock:
            for seq in all_sent_seqs:
                if probes_sent.pop(seq, None) is not None:
                    cleaned_probes += 1

        with icmp_responses_lock:
            keys_to_check = list(icmp_responses.keys()) # Avoid modifying dict while iterating
            for seq in keys_to_check:
                if seq in all_sent_seqs:
                    del icmp_responses[seq] # Remove late/unprocessed responses
                    cleaned_responses += 1
        logging.debug(f"Cleanup complete. Removed {cleaned_probes} probes, {cleaned_responses} late/unprocessed responses.")


# Standalone Sniffer Functions

def stop_sniffer_filter(packet, stop_event):
    """Filter function for Scapy sniff to check the stop event."""
    return stop_event.is_set()

def run_sniffer(interface, server_ip_filter, callback_func, stop_event):
    """
    Runs the Scapy sniffer in the current thread, designed to be run in a dedicated thread.

    Args:
        interface: Network interface to sniff on.
        server_ip_filter: Server IP to filter incoming ICMP packets (dst host).
        callback_func: Packet processing callback (e.g., icmp_packet_callback).
        stop_event: threading.Event() to signal sniffer shutdown.
    """
    logging.info(f"Starting ICMP sniffer on interface '{interface}'...")
    bpf_filter = f"icmp and dst host {server_ip_filter}"
    logging.info(f"Using BPF filter: '{bpf_filter}'")

    # Create a stopper function that checks the event
    stopper = functools.partial(stop_sniffer_filter, stop_event=stop_event)

    try:
        # Sniff packets, calling callback_func for each, until stop_filter returns True
        sniff(iface=interface, filter=bpf_filter, prn=callback_func, stop_filter=stopper, store=0)
    except OSError as e:
         logging.error(f"Sniffer failed to start on {interface}. Error: {e}. Check permissions/interface name.")
    except Exception as e:
        logging.error(f"Sniffer encountered an error: {e}")
    finally:
        logging.info(f"ICMP sniffer on interface '{interface}' stopped.")
