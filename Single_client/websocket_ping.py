#!/usr/bin/env python3

import asyncio
import time
import json
import logging
import websockets
import config

async def measure_websocket_rtt(websocket, client_log_prefix):
    """
    Performs WebSocket ping measurements.

    Args:
        websocket: Active WebSocket connection.
        client_log_prefix: Logging prefix string.

    Returns:
        List of successful RTTs in milliseconds.
    """
    logging.info(f"{client_log_prefix} Starting WebSocket ping ({config.WEBSOCKET_PING_COUNT} pings)...")
    ws_rtts_ms = []
    try:
        for i in range(config.WEBSOCKET_PING_COUNT):
            send_time = time.time()
            ping_id = int(send_time * 1000)
            ping_payload = {"type": "ping", "timestamp": ping_id}

            try:
                await websocket.send(json.dumps(ping_payload))
            except websockets.exceptions.ConnectionClosed:
                logging.warning(f"{client_log_prefix} Connection closed before sending ping {i+1}.")
                break # Exit loop if connection closed

            try:
                # Wait for the corresponding pong
                pong_data = await asyncio.wait_for(websocket.recv(), timeout=config.WEBSOCKET_RECV_TIMEOUT_S)
                recv_time = time.time()

                try:
                    pong_payload = json.loads(pong_data)
                    if pong_payload.get("type") == "pong" and pong_payload.get("timestamp") == ping_id:
                        rtt_s = recv_time - send_time
                        rtt_ms = rtt_s * 1000.0
                        ws_rtts_ms.append(rtt_ms)
                    else:
                        logging.warning(f"{client_log_prefix} Pong mismatch or wrong type (Expected ID: {ping_id}): {pong_payload}")
                except json.JSONDecodeError:
                     logging.warning(f"{client_log_prefix} Could not parse pong JSON: '{pong_data}'")
                except Exception as parse_err:
                    logging.warning(f"{client_log_prefix} Error processing pong payload: {parse_err}")

            except asyncio.TimeoutError:
                logging.warning(f"{client_log_prefix} WebSocket pong timeout for ping {i+1} (ID: {ping_id}).")
                continue # Continue to next ping on timeout
            except websockets.exceptions.ConnectionClosed:
                 logging.warning(f"{client_log_prefix} Connection closed while waiting for pong {i+1}.")
                 break # Exit loop if connection closed
            except Exception as recv_err:
                 logging.error(f"{client_log_prefix} Error receiving WebSocket pong {i+1}: {recv_err}")
                 break # Exit loop on other receive errors

            # Delay between pings
            await asyncio.sleep(config.WEBSOCKET_PING_INTERVAL_S)

    # Handle connection closures during the loop
    except websockets.exceptions.ConnectionClosedOK:
        logging.info(f"{client_log_prefix} WebSocket connection closed normally during ping sequence.")
    except websockets.exceptions.ConnectionClosedError as e:
         logging.warning(f"{client_log_prefix} WebSocket connection closed abnormally during ping sequence: {e}")
    except Exception as e:
        # Catch other errors during the ping process
        logging.error(f"{client_log_prefix} Unexpected error during WebSocket ping sequence: {e}")

    logging.info(f"{client_log_prefix} WebSocket ping sequence finished ({len(ws_rtts_ms)} successful pings).")
    return ws_rtts_ms
