#!/bin/bash

# Function to fetch and display undetected URLs for a domain

fetch_undetected_urls() {
    local domain=$1
    local api_key_index=$2
    local api_key

    if [ $api_key_index -eq 1 ]; then
        api_key="c13a272527b1fa04617d4eb59c7ef731c64dac0edf9b4e29b70f6a0d641fc4e9"
    elif [ $api_key_index -eq 2 ]; then
        api_key="9c20b5b13edce40aa91449cef9c37c6e5f6bc873a70857c68f8124b666debf54"
    else
        api_key="afbb0dc32e256f2f480591199a9df085cbc05ecbf979be46bf17976a581ed0b5"
    fi

    local URL="https://www.virustotal.com/vtapi/v2/domain/report?apikey=$api_key&domain=$domain"

    echo -e "\nFetching data for domain: \033[1;34m$domain\033[0m (using API key $api_key_index)"
    response=$(curl -s "$URL")

    if [[ $? -ne 0 ]]; then
        echo -e "\033[1;31mError fetching data for domain: $domain\033[0m"
        return
    fi

    if ! echo "$response" | jq . >/dev/null 2>&1; then
        echo -e "\033[1;31mInvalid JSON response for domain: $domain\033[0m"
        return
    fi

    undetected_urls=$(echo "$response" | jq -r 'if .undetected_urls then .undetected_urls[][0] else empty end')
    if [[ -z "$undetected_urls" ]]; then
        echo -e "\033[1;33mNo undetected URLs found for domain: $domain\033[0m"
    else
        echo -e "\033[1;32mUndetected URLs for domain: $domain\033[0m"
        echo "$undetected_urls"
    fi
}


# Function to display a countdown
countdown() {
  local seconds=$1
  while [ $seconds -gt 0 ]; do
    echo -ne "\033[1;36mWaiting for $seconds seconds...\033[0m\r"
    sleep 1
    : $((seconds--))
  done
  echo -ne "\033[0K"  # Clear the countdown line
}

# Check if an argument is provided
if [ -z "$1" ]; then
  echo -e "\033[1;31mUsage: $0 <domain or file_with_domains>\033[0m"
  exit 1
fi

# Initialize variables for API key rotation
api_key_index=1
request_count=0

# Check if the argument is a file
if [ -f "$1" ]; then
  while IFS= read -r domain; do
    # Remove the scheme (http:// or https://) if present
    domain=$(echo "$domain" | sed 's|https\?://||')
    fetch_undetected_urls "$domain" $api_key_index
    countdown 20

    # Increment the request count and switch API key if needed
    request_count=$((request_count + 1))
    if [ $request_count -ge 5 ]; then
      request_count=0
      if [ $api_key_index -eq 1 ]; then
        api_key_index=c13a272527b1fa04617d4eb59c7ef731c64dac0edf9b4e29b70f6a0d641fc4e9
      elif [ $api_key_index -eq 2 ]; then
        api_key_index=9c20b5b13edce40aa91449cef9c37c6e5f6bc873a70857c68f8124b666debf54
      else
        api_key_index=afbb0dc32e256f2f480591199a9df085cbc05ecbf979be46bf17976a581ed0b5
      fi
    fi
  done < "$1"
else
  # Argument is not a file, treat it as a single domain
  domain=$(echo "$1" | sed 's|https\?://||')
  fetch_undetected_urls "$domain" $api_key_index
fi

