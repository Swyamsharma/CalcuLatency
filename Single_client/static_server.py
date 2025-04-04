#!/usr/bin/env python3

import http.server
import socketserver
import functools
import logging
import os
import threading

def run_static_server(port, directory):
    """
    Runs a simple HTTP server for static files in the current thread.
    Intended to be run in a separate thread by the caller.

    Args:
        port (int): The port number to bind the server to.
        directory (str): The root directory from which to serve files.
    """
    # Ensure the directory exists relative to the server's execution path
    if not os.path.isdir(directory):
        logging.error(f"Static directory '{directory}' not found. Cannot start static server.")
        return

    # Use functools.partial to set the directory for the handler
    # This ensures the handler knows where to find files relative to 'directory'
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=directory)

    # Allow address reuse (useful for quick restarts)
    socketserver.TCPServer.allow_reuse_address = True

    try:
        # Create and serve the server, binding to all interfaces
        with socketserver.TCPServer(("", port), handler) as httpd:
            # Get the current thread's name for logging
            thread_name = threading.current_thread().name
            logging.info(f"Static file server thread '{thread_name}' started on http://0.0.0.0:{port}, serving '{directory}'")
            httpd.serve_forever() # This blocks the current thread until shutdown() is called
    except OSError as e:
        # Common error: Port already in use
        logging.error(f"Static file server failed to start on port {port}: {e}")
    except Exception as e:
        logging.error(f"Static file server encountered an unexpected error: {e}")
    finally:
        # This part is reached when serve_forever() finishes (e.g., after httpd.shutdown())
        thread_name = threading.current_thread().name
        logging.info(f"Static file server thread '{thread_name}' stopped.")

def start_static_server_thread(port, directory):
    """
    Starts the static file server in a separate daemon thread.

    Args:
        port (int): The port number for the server.
        directory (str): The directory to serve.

    Returns:
        threading.Thread: The thread object running the server, or None if failed to start.
    """
    server_thread = threading.Thread(
        target=run_static_server,
        args=(port, directory),
        daemon=True, # Allows main program to exit even if this thread is running
        name=f"StaticServerThread-{port}" # Give the thread a descriptive name
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
