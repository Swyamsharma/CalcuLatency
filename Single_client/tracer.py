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
            if ICMP in packet and IP in packet:
                icmp_layer = packet[ICMP]
                outer_ip = packet[IP]
                if icmp_layer.type in (11, 3):
                    if IPerror in packet and TCPerror in packet:
                        inner_tcp = packet[TCPerror]
                        original_seq = inner_tcp.seq
                        response_info = (time.time(), outer_ip.src)
                        with self.icmp_responses_lock:
                            self.icmp_responses[original_seq] = response_info
        except Exception as e:
            logging.error(f"Error in ICMP callback: {e}")

    def measure_0trace_rtt(self, local_ip_str, local_port, remote_ip_str, remote_port, current_sniffer_thread):
        """
        Performs the 0trace measurement using Scapy.
        Phase 1: Single probe per TTL up to MAX_TTL or destination reached.
        Phase 2: If Phase 1 successful, send multiple paced probes to final hop TTL for min RTT.
        """
        logging.info(f"[{remote_ip_str}:{remote_port}] Starting 0trace measurement (Phase 1: 1 probe/TTL, Phase 2: {config.FINAL_RTT_PROBE_COUNT} probes)...")

        if current_sniffer_thread is None or not current_sniffer_thread.is_alive():
             logging.error(f"[{remote_ip_str}:{remote_port}] Sniffer thread not running. Cannot perform 0trace.")
             return 0, None, False # RTT, Hop IP, Success

        # --- State for this measurement run ---
        results = {} # Key: ttl, Value: (hop_ip_str, rtt_s) - Stores the single RTT received in Phase 1
        max_responded_ttl = 0
        phase1_final_rtt = 0.0 # RTT from Phase 1 for the final hop (in ms)
        final_hop_ip = None
        trace_success = False # Overall success, requires at least one hop response
        destination_reached = False
        # consecutive_timeouts = 0 # No longer needed
        phase1_sent_seqs = set() # Track sequences sent during Phase 1

        try: # Wrap Phase 1 loop for cleanup
            # --- Phase 1: Single Probe per TTL Scan ---
            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: Scanning TTLs (Max TTL: {config.MAX_TTL})...")
            for ttl in range(1, config.MAX_TTL + 1):
                if destination_reached: break

                received_in_ttl = False
                tcp_seq = random.randint(1, 2**32 - 1)
                while tcp_seq in phase1_sent_seqs:
                    tcp_seq = random.randint(1, 2**32 - 1)
                phase1_sent_seqs.add(tcp_seq)
                sent_seq_this_ttl = tcp_seq

                tcp_ack = random.randint(1, 2**32 - 1)
                ip_layer = IP(dst=remote_ip_str, ttl=ttl)
                tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                packet = ip_layer / tcp_layer

                send_time = time.time()
                try:
                    send(packet, verbose=0)
                    with self.probes_sent_lock:
                        self.probes_sent[tcp_seq] = (send_time, ttl)
                except OSError as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace OS Error sending packet (TTL {ttl}, Seq {tcp_seq}): {e}. Check permissions.")
                    trace_success = False # Mark as failed if send fails
                    break # Exit TTL loop
                except Exception as e:
                    logging.error(f"[{remote_ip_str}:{remote_port}] 0trace Error sending packet (TTL {ttl}, Seq {tcp_seq}): {e}")
                    trace_success = False # Mark as failed if send fails
                    break # Exit TTL loop

                # Wait for response
                wait_deadline = time.time() + config.TRACE_TIMEOUT_S
                processed_seq_this_ttl = False
                while time.time() < wait_deadline and not processed_seq_this_ttl:
                    with self.icmp_responses_lock:
                        if sent_seq_this_ttl in self.icmp_responses:
                            resp_time, hop_ip_str = self.icmp_responses[sent_seq_this_ttl]
                            with self.probes_sent_lock:
                                if sent_seq_this_ttl in self.probes_sent:
                                    send_time_probe, probe_ttl = self.probes_sent[sent_seq_this_ttl]
                                    if probe_ttl == ttl:
                                        rtt_s = resp_time - send_time_probe
                                        rtt_ms = rtt_s * 1000.0
                                        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1 Received ICMP: TTL={ttl}, Hop={hop_ip_str}, RTT={rtt_ms:.2f}ms (Seq: {sent_seq_this_ttl})")
                                        results[ttl] = (hop_ip_str, rtt_s)
                                        max_responded_ttl = ttl
                                        received_in_ttl = True
                                        processed_seq_this_ttl = True
                                        del self.icmp_responses[sent_seq_this_ttl]
                                        if hop_ip_str == remote_ip_str:
                                            logging.info(f"[{remote_ip_str}:{remote_port}] 0trace: Destination {remote_ip_str} reached at TTL {ttl}")
                                            destination_reached = True
                    if not processed_seq_this_ttl:
                        time.sleep(0.02)
                # End wait loop

                if destination_reached: break

                if not received_in_ttl:
                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Timeout: No ICMP response for TTL {ttl} within {config.TRACE_TIMEOUT_S}s")
                    # consecutive_timeouts += 1 # No longer needed
                    # Remove early exit based on timeouts
            # End TTL loop

            # Determine result of Phase 1
            if max_responded_ttl > 0 and max_responded_ttl in results:
                final_hop_ip_str, final_rtt_s = results[max_responded_ttl]
                phase1_final_rtt = final_rtt_s * 1000.0 # RTT from Phase 1 scan (in ms)
                final_hop_ip = final_hop_ip_str
                trace_success = True # Mark success if at least one hop responded
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1 Result: Max Responding TTL={max_responded_ttl}, Furthest Hop={final_hop_ip}, RTT={phase1_final_rtt:.2f}ms")
            elif not trace_success: # Check if send failed earlier
                 logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: Failed due to packet send error.")
                 trace_success = False
            else: # No hops responded at all
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 1: No responsive hops found.")
                trace_success = False

            # --- Phase 2: Final RTT Probing (if Phase 1 was successful) ---
            final_rtt = phase1_final_rtt # Default to Phase 1 result
            phase2_sent_seqs = set()

            if trace_success and max_responded_ttl > 0 and final_hop_ip:
                logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: Probing final hop TTL {max_responded_ttl} ({final_hop_ip}) for minimum RTT ({config.FINAL_RTT_PROBE_COUNT} probes)...")
                final_rtt_values_s = []
                final_ttl_phase2 = max_responded_ttl

                for i in range(config.FINAL_RTT_PROBE_COUNT):
                    tcp_seq = random.randint(1, 2**32 - 1)
                    while tcp_seq in phase1_sent_seqs or tcp_seq in phase2_sent_seqs:
                        tcp_seq = random.randint(1, 2**32 - 1)
                    phase2_sent_seqs.add(tcp_seq)

                    tcp_ack = random.randint(1, 2**32 - 1)
                    ip_layer = IP(dst=remote_ip_str, ttl=final_ttl_phase2)
                    tcp_layer = TCP(dport=remote_port, sport=local_port, flags='A', seq=tcp_seq, ack=tcp_ack)
                    packet = ip_layer / tcp_layer

                    send_time = time.time()
                    try:
                        send(packet, verbose=0)
                        with self.probes_sent_lock:
                            self.probes_sent[tcp_seq] = (send_time, final_ttl_phase2)
                    except Exception as e:
                        logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Error sending packet (TTL {final_ttl_phase2}, Probe {i}, Seq {tcp_seq}): {e}")
                        continue
                    time.sleep(0.05) # Pacing

                # Wait for Phase 2 responses
                wait_deadline = time.time() + config.FINAL_RTT_PROBE_TIMEOUT_S
                processed_phase2_seqs = set()
                while time.time() < wait_deadline:
                    time.sleep(0.02)
                    with self.icmp_responses_lock:
                        relevant_seqs = [seq for seq in phase2_sent_seqs if seq in self.icmp_responses and seq not in processed_phase2_seqs]
                        for seq in relevant_seqs:
                            resp_time, hop_ip_str = self.icmp_responses[seq]
                            with self.probes_sent_lock:
                                if seq in self.probes_sent:
                                    send_time_probe, probe_ttl = self.probes_sent[seq]
                                    if probe_ttl == final_ttl_phase2:
                                        # Optional: Check if hop_ip_str matches final_hop_ip?
                                        # if hop_ip_str == final_hop_ip:
                                        rtt_s = resp_time - send_time_probe
                                        final_rtt_values_s.append(rtt_s)
                                        processed_phase2_seqs.add(seq)
                                        del self.icmp_responses[seq]

                if final_rtt_values_s:
                    min_rtt_s = min(final_rtt_values_s)
                    min_rtt_ms = min_rtt_s * 1000.0
                    logging.info(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2 Result: Min RTT to TTL {final_ttl_phase2} ({final_hop_ip}) = {min_rtt_ms:.2f}ms ({len(final_rtt_values_s)}/{config.FINAL_RTT_PROBE_COUNT} responses)")
                    final_rtt = min_rtt_ms # Update final RTT with Phase 2 minimum
                else:
                    logging.warning(f"[{remote_ip_str}:{remote_port}] 0trace Phase 2: No responses received for TTL {final_ttl_phase2}. Using RTT from Phase 1 scan ({final_rtt:.2f}ms).")
                    # final_rtt remains the value from Phase 1

            # Combine sequences from both phases for cleanup
            all_sent_seqs = phase1_sent_seqs.union(phase2_sent_seqs)

        finally:
            # Ensure state cleanup happens regardless of errors
            logging.debug("Executing 0trace finally block for cleanup...")
            # If all_sent_seqs wasn't assigned due to early exit/error, use phase1_sent_seqs
            if 'all_sent_seqs' not in locals():
                 all_sent_seqs = phase1_sent_seqs
            self._cleanup_trace_state(all_sent_seqs)

        # Final log uses the potentially updated final_rtt
        logging.info(f"[{remote_ip_str}:{remote_port}] 0trace measurement finished. Final RTT: {final_rtt:.2f}ms, Hop: {final_hop_ip}, Success: {trace_success}, Destination Reached: {destination_reached}")
        return final_rtt, final_hop_ip, trace_success # Return final RTT in ms

    def _cleanup_trace_state(self, all_sent_seqs):
        """Cleans up instance's probes_sent and icmp_responses for the given sequence numbers."""
        logging.debug(f"Cleaning up instance state for {len(all_sent_seqs)} sequences.")
        cleaned_probes = 0
        cleaned_responses = 0
        with self.probes_sent_lock:
            for seq in all_sent_seqs:
                if self.probes_sent.pop(seq, None) is not None:
                    cleaned_probes += 1

        with self.icmp_responses_lock:
            keys_to_check = list(self.icmp_responses.keys())
            for seq in keys_to_check:
                if seq in all_sent_seqs:
                    del self.icmp_responses[seq]
                    cleaned_responses += 1
        logging.debug(f"Cleanup complete. Removed {cleaned_probes} probes, {cleaned_responses} late/unprocessed responses.")


# --- Standalone Sniffer Functions ---

def stop_sniffer_filter(packet, stop_event):
    """Used by Scapy's sniff function to know when to stop."""
    return stop_event.is_set()

def run_sniffer(interface, server_ip_filter, packet_callback, stop_event):
    """
    Runs the Scapy sniffer in a separate thread.
    """
    logging.info(f"Starting ICMP sniffer on interface '{interface}'...")
    bpf_filter = f"icmp and dst host {server_ip_filter}"
    logging.info(f"Using BPF filter: '{bpf_filter}'")

    stopper = functools.partial(stop_sniffer_filter, stop_event=stop_event)

    try:
        sniff(iface=interface, filter=bpf_filter, prn=packet_callback, stop_filter=stopper, store=0)
    except OSError as e:
         logging.error(f"Sniffer failed to start on {interface}. Error: {e}. Check permissions/interface name.")
    except Exception as e:
        logging.error(f"Sniffer encountered an error: {e}")
    finally:
        logging.info(f"ICMP sniffer on interface '{interface}' stopped.")
