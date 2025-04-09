const statusDiv = document.getElementById('status');
const resultDiv = document.getElementById('result');

const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
// Connect to WebSocket on port 8080 of the current host
const wsUrl = `${wsProtocol}//${window.location.hostname}:8080`;

let socket;

function connectWebSocket() {
    statusDiv.textContent = 'Connecting to server...';
    statusDiv.className = 'connecting';
    resultDiv.textContent = 'Waiting for results...'; // Reset result display

    console.log(`Attempting to connect WebSocket to: ${wsUrl}`);
    socket = new WebSocket(wsUrl);

    socket.onopen = function(event) {
        console.log('WebSocket connection opened:', event);
        statusDiv.textContent = 'Connected. Starting measurements...';
        statusDiv.className = 'connected measuring';
    };

    socket.onmessage = function(event) {
        console.log('Message from server:', event.data);

        try {
            const message = JSON.parse(event.data);

            // Handle ping requests from server
            if (message.type === 'ping' && message.timestamp) {
                console.log('Received ping, sending pong with timestamp:', message.timestamp);
                const pongMessage = { type: 'pong', timestamp: message.timestamp };
                if (socket.readyState === WebSocket.OPEN) {
                    socket.send(JSON.stringify(pongMessage));
                } else {
                    console.warn('WebSocket not open, cannot send pong.');
                }
            }
            // Handle result messages
            else if (message.type === 'result' && message.data) {
                console.log('Received result data:', message.data);
                resultDiv.textContent = message.data.message || 'Result received but message field missing.';
                statusDiv.textContent = 'Measurement Complete.';
                statusDiv.className = 'complete';
            }
            // Handle error messages from server
            else if (message.type === 'error' && message.message) {
                 console.error('Received error message from server:', message.message);
                 resultDiv.textContent = `Server Error: ${message.message}`;
                 statusDiv.textContent = 'Measurement Error.';
                 statusDiv.className = 'error';
            } else {
                // Handle other unexpected JSON formats
                console.warn('Received unexpected JSON message format:', message);
                resultDiv.textContent = `Received unexpected JSON data: ${event.data}`;
                statusDiv.textContent = 'Received unexpected data.';
                statusDiv.className = 'error';
            }
        } catch (e) {
            // Handle non-JSON messages or parsing errors
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
        // Reconnect logic: only if closed unexpectedly and not already complete/errored
        const currentStatus = statusDiv.textContent.toLowerCase();
        if (!event.wasClean && !currentStatus.includes('complete') && !currentStatus.includes('error')) {
            statusDiv.textContent = `Connection closed unexpectedly (Code: ${event.code}). Trying to reconnect in 5 seconds...`;
            statusDiv.className = 'error';
            setTimeout(connectWebSocket, 5000);
        } else if (!currentStatus.includes('complete') && !currentStatus.includes('error')) {
             statusDiv.textContent = 'Connection closed.';
             statusDiv.className = 'error';
        }
    };
}

connectWebSocket(); // Start the connection
