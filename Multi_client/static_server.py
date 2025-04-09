#!/usr/bin/env python3

import http.server
import socketserver
import functools
import logging
import os
import threading

def run_static_server(port, directory):
    """
    Runs a simple HTTP server for static files. Meant to run in a thread.

    Args:
        port (int): Port to bind to.
        directory (str): Root directory to serve files from.
    """
    # Ensure the directory exists
    if not os.path.isdir(directory):
        logging.error(f"Static directory '{directory}' not found. Cannot start static server.")
        return

    # Set the directory for the handler using partial
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)

    socketserver.TCPServer.allow_reuse_address = True # Allow address reuse

    try:
        with socketserver.TCPServer(("", port), handler) as httpd:
            thread_name = threading.current_thread().name
            logging.info(f"Static file server thread '{thread_name}' started on http://0.0.0.0:{port}, serving '{directory}'")
            httpd.serve_forever() # Blocks until shutdown() is called
    except OSError as e:
        logging.error(f"Static file server failed to start on port {port}: {e}") # Common error: Port in use
    except Exception as e:
        logging.error(f"Static file server encountered an unexpected error: {e}")
    finally:
        # Reached when serve_forever() finishes
        thread_name = threading.current_thread().name
        logging.info(f"Static file server thread '{thread_name}' stopped.")

def start_static_server_thread(port, directory):
    """
    Starts the static file server in a separate daemon thread.

    Args:
        port (int): Port for the server.
        directory (str): Directory to serve.

    Returns:
        threading.Thread: The server thread object, or None if failed.
    """
    server_thread = threading.Thread(
        target=run_static_server,
        args=(port, directory),
        daemon=True, # Allows main program exit even if thread runs
        name=f"StaticServerThread-{port}"
    )
    try:
        server_thread.start()
        logging.info(f"Static server thread '{server_thread.name}' initiated for directory '{directory}' on port {port}.")
        return server_thread
    except Exception as e:
        logging.error(f"Failed to start static server thread: {e}")
        return None

# Example usage (if run directly, though typically imported)
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    PORT = 8081
    DIRECTORY = "static" # Assuming 'static' directory exists in the same folder
    logging.info(f"Starting static server directly on port {PORT} for directory '{DIRECTORY}'...")
    server_thread = start_static_server_thread(PORT, DIRECTORY)
    if server_thread:
        logging.info("Static server running in background thread. Press Ctrl+C to stop.")
        try:
            # Keep the main thread alive to allow the daemon thread to run
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Main thread interrupted. Static server (daemon) will exit.")
    else:
        logging.error("Failed to start static server.")
