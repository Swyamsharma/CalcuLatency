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

# --- Module-level Globals for Shared State ---
icmp_responses = {}  # Key: original TCP seq, Value: (timestamp, hop_ip)
icmp_responses_lock = threading.Lock()
probes_sent = {}     # Key: original TCP seq, Value: (send_time, ttl)
probes_sent_lock = threading.Lock()
logging.info("Tracer module shared state initialized.")

# --- Module-level Callback ---
def icmp_packet_callback(packet):
    """Callback function for the Scapy sniffer. Operates on module globals."""
    global icmp_responses # Explicitly state we are modifying the global
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
                        # logging.debug(f"ICMP Callback: Stored response for seq {original_seq} from {outer_ip.src}")
    except Exception as e:
        logging.error(f"Error in ICMP callback: {e}")


class Tracer:
    """Encapsulates the logic for a single 0trace measurement run."""

    def __init__(self):
        # No instance state needed anymore, state is global in the module
        # logging.info("Tracer instance created for a measurement run.")
        pass

    def _cleanup_trace_state(self, trace_sent_seqs):
        """Cleans up probes_sent and icmp_responses for the given sequence numbers from module globals."""
        global probes_sent, icmp_responses # Explicitly state access to globals
        logging.debug(f"Cleaning up state for {len(trace_sent_seqs)} sequences.")
        cleaned_probes = 0
        cleaned_responses = 0
        with probes_sent_lock:
            for seq in trace_sent_seqs:
                if probes_sent.pop(seq, None) is not None:
                    cleaned_probes += 1

        with icmp_responses_lock:
            # Check remaining responses - should be empty if processed correctly, but clean just in case
            keys_to_check = list(icmp_responses.keys())
            for seq in keys_to_check:
                if seq in trace_sent_seqs:
                    # Silently remove unprocessed responses found during cleanup
                    del icmp_responses[seq]
                    cleaned_responses += 1
        # Add count of cleaned responses to the debug log
        logging.debug(f"Cleanup complete. Removed {cleaned_probes} probes, {cleaned_responses} late/unprocessed responses.")


    def measure_0trace_rtt(self, local_ip_str, local_port, remote_ip_str, remote_port, current_sniffer_thread):
        """
        Performs the 0trace measurement using Scapy.
        Requires the sniffer thread to be passed in for checking its status.
        Uses module global state for responses and sent probes, protected by locks.
        """
        # Access module globals directly, using locks
        global probes_sent, icmp_responses

        logging.info(f"[{remote_ip_str}:{remote_port}] Starting 0trace measurement...")

        if current_sniffer_thread is None or not current_sniffer_thread.is_alive():
             logging.error(f"[{remote_ip_str}:{remote_port}] Sniffer thread not running. Cannot perform 0trace.")
             return 0, None, False # RTT, Hop IP, Success

        results = {}
        max_responded_ttl = 0
        final_rtt = 0.0
        final_hop_ip = None
        trace_success = False
        destination_reached = False
        consecutive_timeouts = 0
        trace_sent_seqs = set() # Track sequences for phase 1
        final_rtt_probes_sent = set() # Track sequences for phase 2
        all_sent_seqs = set() # Combined set for cleanup

        try: # Wrap the main measurement logic (both phases) in try/finally
            # --- Phase 1: Initial TTL Scan ---
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: Scanning TTLs (Max TTL: {config.MAX_TTL})...")
            for ttl in range(1, config.MAX_TTL + 1):
                if destination_reached: break # Stop scan if destination found

                received_in_ttl = False
                sent_seqs_this_ttl = []

                for i in range(config.PROBES_PER_TTL):
                    tcp_seq = random.randint(1, 2**32 - 1)
                    while tcp_seq in trace_sent_seqs: # Ensure unique within this trace run
                        tcp_seq = random.randint(1, 2**32 - 1)
                    trace_sent_seqs.add(tcp_seq)

                    tcp_ack = random.randint(1, 2**32 - 1)
                    ip_layer = IP(dst=remote_ip_str, ttl=ttl)
                    tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                    packet = ip_layer / tcp_layer

                    send_time = time.time()
                    try:
                        send(packet, verbose=0)
                        with probes_sent_lock: # Use global lock
                            probes_sent[tcp_seq] = (send_time, ttl) # Use global dict
                        sent_seqs_this_ttl.append(tcp_seq)
                    except OSError as e:
                        logging.error(f"[{remote_ip_str}:{remote_port}] 0trace OS Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}. Check permissions.")
                        if i == config.PROBES_PER_TTL - 1 and not sent_seqs_this_ttl:
                            logging.error(f"[{remote_ip_str}:{remote_port}] 0trace failed: Could not send any probes for TTL {ttl}.")
                            # No return here, let finally block handle cleanup
                            raise # Re-raise to be caught by outer try/except? Or just break? Let's break.
                        continue # Try next probe
                    except Exception as e:
                        logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}")
                        continue # Try next probe
                # If we broke due to OSError on last probe, exit TTL loop
                if i == config.PROBES_PER_TTL - 1 and not sent_seqs_this_ttl:
                    trace_success = False
                    break


                wait_deadline = time.time() + config.TRACE_TIMEOUT_S
                processed_seqs_in_wait = set()

                while time.time() < wait_deadline:
                    if received_in_ttl and destination_reached: break

                    found_response_this_poll = False
                    with icmp_responses_lock: # Use global lock
                        relevant_seqs = [seq for seq in sent_seqs_this_ttl if seq in icmp_responses and seq not in processed_seqs_in_wait]

                        for seq in relevant_seqs:
                            resp_time, hop_ip_str = icmp_responses[seq] # Use global dict
                            with probes_sent_lock: # Use global lock
                                if seq in probes_sent: # Use global dict
                                    send_time, probe_ttl = probes_sent[seq]
                                    if probe_ttl == ttl:
                                        rtt_s = resp_time - send_time
                                        rtt_ms = rtt_s * 1000.0
                                        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Received ICMP: TTL={ttl}, Hop={hop_ip_str}, RTT={rtt_ms:.2f}ms (Seq: {seq})")

                                        if ttl not in results or rtt_s < results[ttl][1]:
                                            results[ttl] = (hop_ip_str, rtt_s)

                                        max_responded_ttl = max(max_responded_ttl, ttl)
                                        received_in_ttl = True
                                        found_response_this_poll = True
                                        processed_seqs_in_wait.add(seq)

                                        # Clean up processed response immediately from shared state
                                        del icmp_responses[seq] # Use global dict

                                        if hop_ip_str == remote_ip_str:
                                            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Destination {remote_ip_str} reached at TTL {ttl}")
                                            trace_success = True
                                            destination_reached = True
                                            break
                    # End ICMP responses lock

                    if destination_reached: break
                    if not found_response_this_poll: time.sleep(0.02)
                # End wait loop

                if not received_in_ttl:
                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Timeout: No ICMP response for TTL {ttl} within {config.TRACE_TIMEOUT_S}s")
                    consecutive_timeouts += 1
                    if consecutive_timeouts >= config.EARLY_EXIT_TIMEOUT_COUNT:
                        logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace: Exiting early after {config.EARLY_EXIT_TIMEOUT_COUNT} consecutive TTL timeouts.")
                        break
                else:
                    consecutive_timeouts = 0
            # End TTL loop

            if max_responded_ttl > 0 and max_responded_ttl in results:
                final_hop_ip_str, final_rtt_s = results[max_responded_ttl]
                final_rtt = final_rtt_s * 1000.0
                final_hop_ip = final_hop_ip_str
                if not destination_reached: trace_success = True # Mark success if any hop responded
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Final Result: Max Responding TTL={max_responded_ttl}, Hop={final_hop_ip}, RTT={final_rtt:.2f}ms")
            elif not trace_success: # Only log if not already marked success
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: No responsive hops found.")
                trace_success = False # Ensure trace_success is False if no hops responded

            # --- Phase 2: Final RTT Probing ---
            min_final_rtt_ms = 0.0 # Initialize here

            if max_responded_ttl > 0 and final_hop_ip:
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: Probing TTL {max_responded_ttl} ({final_hop_ip}) for minimum RTT ({config.FINAL_RTT_PROBE_COUNT} probes)...")
                final_rtt_values_s = []
            final_ttl = max_responded_ttl # Use the max TTL found in phase 1

            for i in range(config.FINAL_RTT_PROBE_COUNT):
                tcp_seq = random.randint(1, 2**32 - 1)
                # Ensure unique across *all* sequences sent in this measurement run
                while tcp_seq in trace_sent_seqs or tcp_seq in final_rtt_probes_sent:
                    tcp_seq = random.randint(1, 2**32 - 1)
                final_rtt_probes_sent.add(tcp_seq)

                tcp_ack = random.randint(1, 2**32 - 1)
                ip_layer = IP(dst=remote_ip_str, ttl=final_ttl)
                tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                packet = ip_layer / tcp_layer

                send_time = time.time()
                try:
                    send(packet, verbose=0)
                    with probes_sent_lock:
                        probes_sent[tcp_seq] = (send_time, final_ttl)
                except Exception as e:
                    logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Error sending packet (TTL {final_ttl}, Probe {i}, Seq {tcp_seq}): {e}")
                    continue # Skip this probe if sending fails

            # Wait for responses for the final probing phase
            wait_deadline = time.time() + config.FINAL_RTT_PROBE_TIMEOUT_S
            processed_final_seqs = set()

            while time.time() < wait_deadline:
                time.sleep(0.02) # Brief sleep
                with icmp_responses_lock:
                    relevant_seqs = [seq for seq in final_rtt_probes_sent if seq in icmp_responses and seq not in processed_final_seqs]
                    for seq in relevant_seqs:
                        resp_time, hop_ip_str = icmp_responses[seq]
                        # Check if response is from the expected hop IP (optional but good)
                        # if hop_ip_str != final_hop_ip: continue
                        with probes_sent_lock:
                            if seq in probes_sent:
                                send_time, probe_ttl = probes_sent[seq]
                                if probe_ttl == final_ttl: # Ensure it's for the correct TTL
                                    rtt_s = resp_time - send_time
                                    final_rtt_values_s.append(rtt_s)
                                    processed_final_seqs.add(seq)
                                    del icmp_responses[seq] # Clean up processed response

            if final_rtt_values_s:
                min_final_rtt_s = min(final_rtt_values_s)
                min_final_rtt_ms = min_final_rtt_s * 1000.0
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Result: Min RTT to TTL {final_ttl} ({final_hop_ip}) = {min_final_rtt_ms:.2f}ms ({len(final_rtt_values_s)}/{config.FINAL_RTT_PROBE_COUNT} responses)")
                # Update the final RTT to this minimum value
                final_rtt = min_final_rtt_ms
            else:
                logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: No responses received for TTL {final_ttl}. Using RTT from initial scan ({final_rtt:.2f}ms).")
                # Keep the final_rtt calculated from the initial scan if phase 2 fails

            # Combine sequence numbers from both phases for final cleanup
            all_sent_seqs = trace_sent_seqs.union(final_rtt_probes_sent)

        finally:
            # Ensure state cleanup happens regardless of errors or how the measurement exits
            logging.debug("Executing 0trace finally block for cleanup...")
            self._cleanup_trace_state(all_sent_seqs) # Pass combined set

        # Final logging and return statement *after* the finally block
        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace measurement finished. Final RTT: {final_rtt:.2f}ms, Hop: {final_hop_ip}, Success: {trace_success}, Destination Reached: {destination_reached}")
        return final_rtt, final_hop_ip, trace_success


# --- Standalone Sniffer Functions ---

def stop_sniffer_filter(packet, stop_event):
    """Used by Scapy's sniff function to know when to stop."""
    return stop_event.is_set()

def run_sniffer(interface, server_ip_filter, callback_func, stop_event):
    """
    Runs the Scapy sniffer in a separate thread. Uses module-level callback.
    Args:
        interface: The network interface to sniff on.
        server_ip_filter: The IP address of the server to filter incoming ICMP packets.
        callback_func: The function to call for each captured packet (module-level icmp_packet_callback).
        stop_event: A threading.Event() object to signal when the sniffer should stop.
    """
    logging.info(f"Starting ICMP sniffer on interface '{interface}'...")
    bpf_filter = f"icmp and dst host {server_ip_filter}"
    logging.info(f"Using BPF filter: '{bpf_filter}'")

    stopper = functools.partial(stop_sniffer_filter, stop_event=stop_event)

    try:
        # Pass the module-level callback function
        sniff(iface=interface, filter=bpf_filter, prn=callback_func, stop_filter=stopper, store=0)
    except OSError as e:
         logging.error(f"Sniffer failed to start on {interface}. Error: {e}. Check permissions/interface name.")
    except Exception as e:
        logging.error(f"Sniffer encountered an error: {e}")
    finally:
        logging.info(f"ICMP sniffer on interface '{interface}' stopped.")
