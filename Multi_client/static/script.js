const statusDiv = document.getElementById('status');
const resultDiv = document.getElementById('result');

// Determine WebSocket protocol based on window location protocol
const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
// Construct URL using current hostname but explicit port 8080 for WebSocket, removing the /ws path
const wsUrl = `${wsProtocol}//${window.location.hostname}:8080`; // Connect to root path

let socket;

function connectWebSocket() {
    statusDiv.textContent = 'Connecting to server...';
    statusDiv.className = 'connecting';
    resultDiv.textContent = 'Waiting for results...'; // Reset result on reconnect attempt

    console.log(`Attempting to connect WebSocket to: ${wsUrl}`); // Log the URL
    socket = new WebSocket(wsUrl);

    socket.onopen = function(event) {
        console.log('WebSocket connection opened:', event);
        statusDiv.textContent = 'Connected. Starting measurements...';
        statusDiv.className = 'connected measuring';
    };

    socket.onmessage = function(event) {
        console.log('Message from server:', event.data);

        try {
            // Try parsing as JSON first (for ping/pong structure if implemented)
            const message = JSON.parse(event.data);

            // Handle ping requests from server (if server sends JSON pings)
            if (message.type === 'ping' && message.timestamp) {
                console.log('Received ping, sending pong with timestamp:', message.timestamp);
                const pongMessage = {
                    type: 'pong',
                    timestamp: message.timestamp
                };
                // Ensure socket is open before sending
                if (socket.readyState === WebSocket.OPEN) {
                    socket.send(JSON.stringify(pongMessage));
                } else {
                    console.warn('WebSocket not open, cannot send pong.');
                }
            }
            // --- Check for Result Type ---
            else if (message.type === 'result' && message.data) {
                // Handle the structured result message from the server
                console.log('Received result data:', message.data);
                // Display the pre-formatted message string from the server's result_data
                    resultDiv.textContent = message.data.message || 'Result received but message field missing.';
                statusDiv.textContent = 'Measurement Complete.';
                statusDiv.className = 'complete';
                // Optionally display more details if needed:
                // resultDiv.innerHTML += `<br><small>WS RTT: ${message.data.ws_min_rtt_ms?.toFixed(2)} ms (${message.data.ws_rtt_samples} samples)</small>`;
                // resultDiv.innerHTML += `<br><small>0trace RTT: ${message.data.trace_rtt_ms?.toFixed(2)} ms (Hop: ${message.data.trace_hop_ip || 'N/A'})</small>`;
            }
            // --- Check for Error Type ---
            else if (message.type === 'error' && message.message) {
                 // Handle specific error messages sent by the server
                 console.error('Received error message from server:', message.message);
                 resultDiv.textContent = `Server Error: ${message.message}`;
                     statusDiv.textContent = 'Measurement Error.';
                     statusDiv.className = 'error';
                } else {
                    // Handle other valid JSON messages if necessary
                    console.warn('Received unexpected JSON message format:', message);
                    resultDiv.textContent = `Received unexpected JSON data: ${event.data}`;
                    statusDiv.textContent = 'Received unexpected data.';
                    statusDiv.className = 'error';
                }
        } catch (e) {
            // This block now likely indicates a non-JSON message or a parsing error
            console.error('Failed to parse message or received non-JSON data:', event.data, e);
            resultDiv.textContent = `Error processing server message: ${event.data}`;
            statusDiv.textContent = 'Communication Error.';
            statusDiv.className = 'error';
        }
    };

    socket.onerror = function(event) {
        console.error('WebSocket error:', event);
        statusDiv.textContent = 'WebSocket connection error. Check server logs and ensure ws:// URL is correct.';
        statusDiv.className = 'error';
    };

    socket.onclose = function(event) {
        console.log('WebSocket connection closed:', event);
        // Avoid reconnect spam if measurement completed or errored definitively
        const currentStatus = statusDiv.textContent.toLowerCase();
        if (!event.wasClean && !currentStatus.includes('complete') && !currentStatus.includes('error')) {
            statusDiv.textContent = `Connection closed unexpectedly (Code: ${event.code}). Trying to reconnect in 5 seconds...`;
            statusDiv.className = 'error';
            // Simple reconnect logic
            setTimeout(connectWebSocket, 5000);
        } else if (!currentStatus.includes('complete') && !currentStatus.includes('error')) {
             statusDiv.textContent = 'Connection closed.';
             statusDiv.className = 'error'; // Or 'complete' if expected close
        }
    };
}

// Initial connection attempt
connectWebSocket();
