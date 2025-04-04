#!/usr/bin/env python3

import time
import logging
import threading
import random
import config

try:
    from scapy.all import IP, TCP, ICMP, send, sniff, conf
    from scapy.layers.inet import IPerror, TCPerror
except ImportError:
    logging.error("Scapy is not installed or import failed. Please run: pip install scapy")
    # Re-raise or handle appropriately if this module is imported elsewhere
    raise
except OSError as e:
    logging.error(f"Error initializing Scapy in tracer module: {e}")
    raise

class Tracer:
    """Encapsulates the state and logic for 0trace measurements."""

    def __init__(self):
        self.icmp_responses = {}  # Key: original TCP seq, Value: (timestamp, hop_ip)
        self.icmp_responses_lock = threading.Lock()
        self.probes_sent = {}     # Key: original TCP seq, Value: (send_time, ttl)
        self.probes_sent_lock = threading.Lock()
        logging.info("Tracer instance initialized.")

    def icmp_packet_callback(self, packet):
        """Callback function for the Scapy sniffer, associated with this Tracer instance."""
        try:
            # Ensure the packet has the necessary layers before accessing them
            if ICMP in packet and IP in packet:
                icmp_layer = packet[ICMP]
                outer_ip = packet[IP]
                # Check for ICMP Time Exceeded (11) or Destination Unreachable (3)
                if icmp_layer.type in (11, 3):
                    # Check if the ICMP payload contains the original IP/TCP header
                    if IPerror in packet and TCPerror in packet:
                        inner_tcp = packet[TCPerror]
                        original_seq = inner_tcp.seq
                        response_info = (time.time(), outer_ip.src) # (timestamp, hop_ip)
                        with self.icmp_responses_lock:
                            # Store response keyed by the original TCP sequence number
                            self.icmp_responses[original_seq] = response_info
                            # logging.debug(f"ICMP Callback: Stored response for seq {original_seq} from {outer_ip.src}")
        except Exception as e:
            logging.error(f"Error in ICMP callback: {e}")

    def measure_0trace_rtt(self, local_ip_str, local_port, remote_ip_str, remote_port, current_sniffer_thread):
        """
        Performs the 0trace measurement using Scapy.
        Requires the sniffer thread to be passed in for checking its status.
        Uses the instance's state for responses and sent probes.
        """
        logging.info(f"[{remote_ip_str}:{remote_port}] Starting 0trace measurement...")

        if current_sniffer_thread is None or not current_sniffer_thread.is_alive():
             logging.error(f"[{remote_ip_str}:{remote_port}] Sniffer thread not running. Cannot perform 0trace.")
             return 0, None, False # RTT, Hop IP, Success

        # Results specific to this measurement call
        results = {} # Key: ttl, Value: (hop_ip_str, rtt_s)
        max_responded_ttl = 0
        final_rtt = 0.0
        final_hop_ip = None
        trace_success = False
        destination_reached = False
        consecutive_timeouts = 0
        # Keep track of sequences sent specifically during *this* trace run
        trace_sent_seqs = set()

        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Starting TTL loop (Max TTL: {config.MAX_TTL})...")
        for ttl in range(1, config.MAX_TTL + 1):
            if destination_reached: # Optimization: stop if destination already reached
                break

            received_in_ttl = False
            sent_seqs_this_ttl = [] # Keep track of seq numbers sent for *this* TTL

            # Send multiple probes per TTL for robustness
            for i in range(config.PROBES_PER_TTL):
                tcp_seq = random.randint(1, 2**32 - 1)
                # Ensure sequence number is unique for this trace run (highly likely, but check)
                while tcp_seq in trace_sent_seqs:
                    tcp_seq = random.randint(1, 2**32 - 1)
                trace_sent_seqs.add(tcp_seq)

                tcp_ack = random.randint(1, 2**32 - 1)
                ip_layer = IP(dst=remote_ip_str, ttl=ttl)
                tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                packet = ip_layer / tcp_layer

                send_time = time.time()
                try:
                    send(packet, verbose=0)
                    with self.probes_sent_lock: # Lock before accessing shared dict
                        self.probes_sent[tcp_seq] = (send_time, ttl) # Store (send_time, ttl)
                    sent_seqs_this_ttl.append(tcp_seq)
                    # logging.debug(f"[{remote_ip_str}:{remote_port}] 0trace Sent: TTL={ttl}, Probe={i}, Seq={tcp_seq}")
                except OSError as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace OS Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}. Check permissions.")
                    if i == config.PROBES_PER_TTL - 1 and not sent_seqs_this_ttl:
                        logging.error(f"[{remote_ip_str}:{remote_port}] 0trace failed: Could not send any probes for TTL {ttl}.")
                        self._cleanup_trace_state(trace_sent_seqs) # Cleanup before returning
                        return 0, None, False
                    continue
                except Exception as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Probe {i}, Seq {tcp_seq}): {e}")
                    continue

            # Wait for responses for this TTL
            wait_deadline = time.time() + config.TRACE_TIMEOUT_S
            processed_seqs_in_wait = set() # Track seqs processed in this wait period

            while time.time() < wait_deadline:
                if received_in_ttl and destination_reached:
                    break

                found_response_this_poll = False
                with self.icmp_responses_lock:
                    # Check only sequences sent for the *current* TTL that haven't been processed yet
                    relevant_seqs = [seq for seq in sent_seqs_this_ttl if seq in self.icmp_responses and seq not in processed_seqs_in_wait]

                    for seq in relevant_seqs:
                        resp_time, hop_ip_str = self.icmp_responses[seq]
                        with self.probes_sent_lock:
                            # Ensure the probe info still exists (it should)
                            if seq in self.probes_sent:
                                send_time, probe_ttl = self.probes_sent[seq]
                                if probe_ttl == ttl: # Ensure response matches current TTL
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
                                    del self.icmp_responses[seq]
                                    # We'll clean up probes_sent at the end of the trace

                                    if hop_ip_str == remote_ip_str:
                                        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Destination {remote_ip_str} reached at TTL {ttl}")
                                        trace_success = True # Mark success explicitly when destination reached
                                        destination_reached = True
                                        break # Break inner seq loop
                # End ICMP responses lock

                if destination_reached:
                    break # Break wait loop

                if not found_response_this_poll:
                    time.sleep(0.02) # Avoid busy-waiting

            # End of wait loop for TTL

            if not received_in_ttl:
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Timeout: No ICMP response for TTL {ttl} within {config.TRACE_TIMEOUT_S}s")
                consecutive_timeouts += 1
                if consecutive_timeouts >= config.EARLY_EXIT_TIMEOUT_COUNT:
                    logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace: Exiting early after {config.EARLY_EXIT_TIMEOUT_COUNT} consecutive TTL timeouts.")
                    break # Break TTL loop
            else:
                consecutive_timeouts = 0 # Reset counter

        # End of TTL loop

        if max_responded_ttl > 0 and max_responded_ttl in results:
            final_hop_ip_str, final_rtt_s = results[max_responded_ttl]
            final_rtt = final_rtt_s * 1000.0 # Convert to ms
            final_hop_ip = final_hop_ip_str
            # If we got *any* response, consider trace partially successful,
            # unless destination_reached already set trace_success=True
            if not destination_reached:
                 trace_success = True
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Final Result: Max Responding TTL={max_responded_ttl}, Hop={final_hop_ip}, RTT={final_rtt:.2f}ms")
        else:
            # No hops responded at all
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Final Result: No responsive hops found.")
            trace_success = False # Explicitly false if no responses

        self._cleanup_trace_state(trace_sent_seqs)

        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace measurement finished. Success: {trace_success}, Destination Reached: {destination_reached}")
        return final_rtt, final_hop_ip, trace_success

    def _cleanup_trace_state(self, trace_sent_seqs):
        """Cleans up probes_sent and icmp_responses for the given sequence numbers."""
        logging.debug(f"Cleaning up state for {len(trace_sent_seqs)} sequences.")
        with self.probes_sent_lock:
            for seq in trace_sent_seqs:
                self.probes_sent.pop(seq, None) # Remove if exists

        with self.icmp_responses_lock:
            # Check remaining responses - should be empty if processed correctly, but clean just in case
            keys_to_check = list(self.icmp_responses.keys())
            for seq in keys_to_check:
                if seq in trace_sent_seqs:
                    logging.warning(f"Found unprocessed ICMP response for seq {seq} during cleanup.")
                    del self.icmp_responses[seq]


# --- Standalone Sniffer Functions ---

def stop_sniffer_filter(packet, stop_event):
    """Used by Scapy's sniff function to know when to stop."""
    return stop_event.is_set()

def run_sniffer(interface, server_ip_filter, packet_callback, stop_event):
    """
    Runs the Scapy sniffer in a separate thread.
    Args:
        interface: The network interface to sniff on.
        server_ip_filter: The IP address of the server to filter incoming ICMP packets.
        packet_callback: The function to call for each captured packet (e.g., tracer.icmp_packet_callback).
        stop_event: A threading.Event() object to signal when the sniffer should stop.
    """
    logging.info(f"Starting ICMP sniffer on interface '{interface}'...")
    bpf_filter = f"icmp and dst host {server_ip_filter}"
    logging.info(f"Using BPF filter: '{bpf_filter}'")

    # Use functools.partial to pass the stop_event to the stop_filter
    import functools
    stopper = functools.partial(stop_sniffer_filter, stop_event=stop_event)

    try:
        # Pass the instance method as the callback
        sniff(iface=interface, filter=bpf_filter, prn=packet_callback, stop_filter=stopper, store=0)
    except OSError as e:
         # Permissions errors are common here if not run as root
         logging.error(f"Sniffer failed to start on {interface}. Error: {e}. Check permissions/interface name.")
    except Exception as e:
        logging.error(f"Sniffer encountered an error: {e}")
    finally:
        logging.info(f"ICMP sniffer on interface '{interface}' stopped.")
