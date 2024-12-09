#!/bin/bash

# Function to perform PII detection for a given domain's URLs
detect_pii() {
    local domain=$1
    local date=$(date +'%Y-%m-%d')
    local base_dir="${domain}/$([ "$IGNORE_SPLIT" = "false" ] && echo "${date}/")"
    mkdir -p "${base_dir}"

    local input_file="${base_dir}/liveallurls.txt"
    local output_file="${base_dir}/pii_detected_urls.txt"

    # Regex patterns for PII detection
    email_regex="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
    phone_regex="\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"
    credit_card_regex="\b(?:\d[ -]*?){13,16}\b"
    address_regex="\b\d{1,5}\s\w+(?:\s\w+)*,\s\w+(?:\s\w+)*,\s?[A-Za-z]{2}\s?\d{5}(?:-\d{4})?\b"

    # Clear the output file
    > "$output_file"

    echo "Processing URLs for PII detection..."

    # Read live URLs and check for PII
    while IFS= read -r url || [ -n "$url" ]; do
        if [ -n "$url" ]; then
            # Fetch the content of the URL
            content=$(curl -s "$url")
            
            # Check for PII
            if [[ "$content" =~ $email_regex ]] || [[ "$content" =~ $phone_regex ]] || [[ "$content" =~ $credit_card_regex ]] || [[ "$content" =~ $address_regex ]]; then
                echo "$url" >> "$output_file"
            fi
        fi
    done < "$input_file"

    echo "PII detection completed. Results saved to '${output_file}'."
}

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Run the PII detection function with the provided domain
detect_pii "$1"
