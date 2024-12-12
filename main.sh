#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

domain=$1

# Ensure all required scripts are executable
# chmod +x subdomain_find.sh url_find.sh information.sh detection_engine.sh

# Run subdomain enumeration 
./subdomain_find.sh "$domain"

# Run URL enumeration 
./url_find.sh "$domain"

# Run JavaScript file analysis 
./information.sh "$domain"

./virustotal_url.sh "/root/main/"$domain"/live_subdomains.txt" > "/root/main/"$domain"/u.txt" 
grep -oP 'https?://[^\s]+'  "/root/main/"$domain"/u.txt"  > "/root/main/"$domain"/url.txt"


# Run detection engine 
./detection_engine.sh "$domain"
