#!/usr/bin/env python3

import asyncio
import time
import json
import logging
import websockets
import config

async def measure_websocket_rtt(websocket, client_log_prefix):
    """
    Performs WebSocket ping measurements and returns a list of RTTs in ms.

    Args:
        websocket: The active WebSocket connection object.
        client_log_prefix: A string prefix for logging (e.g., "[ip:port]").

    Returns:
        A list of successful RTT measurements in milliseconds.
    """
    logging.info(f"{client_log_prefix} Starting WebSocket ping ({config.WEBSOCKET_PING_COUNT} pings)...")
    ws_rtts_ms = []
    try:
        for i in range(config.WEBSOCKET_PING_COUNT):
            send_time = time.time()
            ping_id = int(send_time * 1000) # Use timestamp as a simple ping ID
            ping_payload = {"type": "ping", "timestamp": ping_id}

            try:
                await websocket.send(json.dumps(ping_payload))
            except websockets.exceptions.ConnectionClosed:
                logging.warning(f"{client_log_prefix} Connection closed before sending ping {i+1}.")
                break # Exit ping loop if connection closed

            try:
                # Wait for the corresponding pong message
                pong_data = await asyncio.wait_for(websocket.recv(), timeout=config.WEBSOCKET_RECV_TIMEOUT_S)
                recv_time = time.time()

                # Validate the pong message
                try:
                    pong_payload = json.loads(pong_data)
                    # Check type and timestamp match
                    if pong_payload.get("type") == "pong" and pong_payload.get("timestamp") == ping_id:
                        rtt_s = recv_time - send_time
                        rtt_ms = rtt_s * 1000.0
                        ws_rtts_ms.append(rtt_ms)
                        # logging.debug(f"{client_log_prefix} WS Ping {i+1}: RTT = {rtt_ms:.2f}ms")
                    else:
                        logging.warning(f"{client_log_prefix} Pong mismatch or wrong type (Expected ID: {ping_id}): {pong_payload}")
                except json.JSONDecodeError:
                     logging.warning(f"{client_log_prefix} Could not parse pong JSON: '{pong_data}'")
                except Exception as parse_err:
                    logging.warning(f"{client_log_prefix} Error processing pong payload: {parse_err}")

            except asyncio.TimeoutError:
                logging.warning(f"{client_log_prefix} WebSocket pong timeout for ping {i+1} (ID: {ping_id}).")
                continue # Continue to next ping attempt
            except websockets.exceptions.ConnectionClosed:
                 logging.warning(f"{client_log_prefix} Connection closed while waiting for pong {i+1}.")
                 break # Exit ping loop
            except Exception as recv_err:
                 logging.error(f"{client_log_prefix} Error receiving WebSocket pong {i+1}: {recv_err}")
                 break # Break on unexpected errors during receive

            # Small delay between pings
            await asyncio.sleep(config.WEBSOCKET_PING_INTERVAL_S)

    # Handle potential connection closures during the ping loop
    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"{client_log_prefix} WebSocket connection closed normally during ping sequence.")
    except websockets.exceptions.ConnectionClosedError as e:
         logging.warning(f"{client_log_prefix} WebSocket connection closed abnormally during ping sequence: {e}")
    except Exception as e:
        # Catch other potential errors during the ping process
        logging.error(f"{client_log_prefix} Unexpected error during WebSocket ping sequence: {e}")
        # The caller (handle_connection) should manage closing the connection if needed

    logging.info(f"{client_log_prefix} WebSocket ping sequence finished ({len(ws_rtts_ms)} successful pings).")
    return ws_rtts_ms
