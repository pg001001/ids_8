#!/bin/bash

# Function to find subdomains for a given domain
find_subdomains() {
    local domain=$1
    local date=$(date +'%Y-%m-%d')
    local base_dir="${domain}/$([ "$IGNORE_SPLIT" = "false" ] && echo "${date}/")"
    mkdir -p "${base_dir}"
    
    # Subdomain enumeration
    
    # subfinder
    echo "Running Subfinder for ${domain}..."
    subfinder -d "${domain}" -all -recursive -o "${base_dir}/subfinder.txt"
        
    # amass
    echo "Running Amass for ${domain}..."
    amass intel -whois -d "${domain}" -o "${base_dir}/amass-intel.txt"
    
    # findomain subdomain
    echo "Running findomain for ${domain}..."
    findomain -t "${domain}" | tee -a "${base_dir}/findomain.txt"
    
    # assetfinder subdomain
    echo "Running assetfinder for ${domain}..."
    assetfinder "${domain}" | tee -a "${base_dir}/assetfinder.txt"
    
    # Combine all results into one file, sort and make unique
    echo "Combining all subdomain results..."
    # cat "${base_dir}"/*.txt | sort -u > "${base_dir}/all_subdomains.txt"
    find "${base_dir}" -name "*.txt" -exec cat {} + | sort -u | grep -i "${domain}" | tee "${base_dir}/subdomains.txt"

    # Check for live domains using httprobe or httpx
    echo "Checking for live domains..."
    if command -v httprobe &> /dev/null; then
        cat "${base_dir}/subdomains.txt" | httprobe > "${base_dir}/live_subdomains.txt"
    elif command -v httpx &> /dev/null; then
        cat "${base_dir}/subdomains.txt" | httpx -silent -o "${base_dir}/live_subdomains.txt"
    else
        echo "Neither httprobe nor httpx is installed. Please install one of them to check for live domains."
    fi

    cat "${base_dir}/live_subdomains.txt" | sed -E 's|https?://([^/]+).*|\1|' > "${base_dir}/clean_subdomains.txt"


    touch /tmp/sub-drill-tmp.txt
    curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://rapiddns.io/subdomain/$1?full=1#result" | grep "<td><a" | cut -d '"' -f 2 | grep http | cut -d '/' -f3 | sed 's/#results//g' | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://crt.sh/?q=%.$1&group=none" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://crt.sh/?q=%.%.$1 | grep -oP "\<TD\>\K.*\.$1" | sed -e 's/\<BR\>/\n/g' | sed -e 's/[\<|\>]//g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://crt.sh/?q=%.%.%.$1 | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://crt.sh/?q=%.%.%.%.$1 | grep "$1" | cut -d '>' -f2 | cut -d '<' -f1 | grep -v " " | grep -o -E "[a-zA-Z0-9._-]+\.$1" |  sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://api.hackertarget.com/hostsearch/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://certspotter.com/api/v0/certs?domain=$1 | grep  -o '\[\".*\"\]' | sed -e 's/\[//g' | sed -e 's/\"//g' | sed -e 's/\]//g' | sed -e 's/\,/\n/g' | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://spyse.com/target/domain/$1 | grep -E -o "button.*>.*\.$1\/button>" |  grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://tls.bufferover.run/dns?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://dns.bufferover.run/dns?q=.$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://urlscan.io/api/v1/search/?q=$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://synapsint.com/report.php -d "name=http%3A%2F%2F$1" | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://jldc.me/anubis/subdomains/$1 | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://sonar.omnisint.io/subdomains/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://riddler.io/search/exportcsv?q=pld:$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://suip.biz/?act=amass -d "url=$1&Submit1=Submit"  | grep $1 | cut -d ">" -f 2 | awk 'NF' >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay -X POST https://suip.biz/?act=subfinder -d "url=$1&Submit1=Submit"  | grep $1 | cut -d ">" -f 2 | awk 'NF' >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://securitytrails.com/list/apex_domain/$1" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | grep ".$1" | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://certificatedetails.com/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sed -e 's/^.//g' | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://columbus.elmasy.com/report/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay https://webscout.io/lookup/$1 | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> /tmp/sub-drill-tmp.txt &
    curl --silent --insecure --tcp-fastopen --tcp-nodelay "https://api.subdomain.center/?domain=$1&engine=cuttlefish" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u >> /tmp/sub-drill-tmp.txt &

    cat /tmp/sub-drill-tmp.txt | sed -e "s/\*\.$1//g" | sed -e "s/^\..*//g" | grep -o -E "[a-zA-Z0-9._-]+\.$1" | sort -u > "${base_dir}/subdomains.txt"
    rm -f /tmp/sub-drill-tmp.txt
    cat "${base_dir}/subdomains.txt" | httpx -silent -o "${base_dir}/alive_domains.txt"
}

# Check if domain is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

# Run the subdomain finder function with the provided domain
find_subdomains "$1"
