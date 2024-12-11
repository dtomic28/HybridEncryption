#!/bin/bash

# Set the host and port you want to close
HOST="127.0.0.1"
PORT="12345"

# Find the PID using the port
PID=$(ss -ltnp | grep ":$PORT" | awk '{print $6}' | cut -d',' -f2 | cut -d'=' -f2)

if [ -z "$PID" ]; then
  echo "No process found using port $PORT."
else
  echo "Closing socket on port $PORT (PID: $PID)..."
  kill -9 "$PID"
  echo "Socket closed."
fi
