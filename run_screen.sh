#!/bin/bash

# Check if the input file is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <domains.txt>"
    exit 1
fi

# Input file
DOMAINS_FILE="$1"

# Check if the file exists
if [ ! -f "$DOMAINS_FILE" ]; then
    echo "Error: File '$DOMAINS_FILE' not found!"
    exit 1
fi

# Read the file line by line
while IFS= read -r DOMAIN || [ -n "$DOMAIN" ]; do
    if [ -n "$DOMAIN" ]; then
        echo "Starting screen session for domain: $DOMAIN"
        screen -dmS "$DOMAIN" ./main.sh "$DOMAIN"
    fi
done < "$DOMAINS_FILE"

echo "All screen sessions have been started."
