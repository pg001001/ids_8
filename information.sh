#!/bin/bash

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Function to scan for JavaScript files, download them, and search for sensitive information
scan_information() {
    local domain=$1
    local base_dir="${domain}"
    mkdir -p "${base_dir}"
    mkdir -p "${base_dir}/information/"

    # sensitive information in downloaded JavaScript files
    mkdir -p "${base_dir}/js_files/"  && xargs -a "${base_dir}/js.txt" -I {} wget -q {} -P "${base_dir}/js_files/"
    cat "${base_dir}/allurls.txt" | grep "\.js$"  "${base_dir}/allurls.txt" | httpx -mc 200 | tee "${base_dir}/js.txt"
    jshunter -l "${base_dir}/js.txt" | tee "${base_dir}/js_info.txt"
    grep -r --color=always -i -E "api_key|apikey" "${base_dir}/js_files/" | tee "${base_dir}/information/js.txt"
   
    # parameter 
    grep -r --color=always -i -E '\?.+=.+(&.+=.+)*' "${base_dir}/allurls.txt" > "${base_dir}/information/parameterized_urls.txt"

    # billngs
    grep -r --color=always -i -E "invoice|billing|payment|receipt|bill|order|checkout|transaction" "${base_dir}/allurls.txt" >> "${base_dir}/information/pay.txt"

    # search sensitive files 
    grep -r --color=always -i -E "\.pdf|.\xlsx|\.doc|\.docx|\.pptx|\.xls" "${base_dir}/allurls.txt" >> "${base_dir}/information/documents.txt"
    
    # Backup files 
    grep -r --color=always -i -E "\.zip|\.tgz|\.bak|\.7z|\.rar\.zip|\.exe|\.tar|\.gz|\.dll|\.iso" "${base_dir}/allurls.txt" >> "${base_dir}/information/backup.txt"
}

scan_information "$1"
