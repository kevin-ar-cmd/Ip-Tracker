#!/bin/bash

# Check if an argument was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>"
    exit 1
fi

TARGET="$1"

echo "==================== IP Tracer ===================="

# Traceroute
echo "Traceroute to $TARGET:"
traceroute "$TARGET"
echo

# Ping
echo "Pinging $TARGET:"
ping -c 4 "$TARGET"
echo

# Get IP Info using curl
echo "IP Information for $TARGET:"
curl -s ipinfo.io/"$TARGET"
echo

# GeoIP Lookup
echo "GeoIP Lookup for $TARGET:"
geoiplookup "$TARGET"
echo

# NSLookup
echo "NSLookup for $TARGET:"
nslookup "$TARGET"
echo

# WHOIS Lookup
echo "WHOIS Lookup for $TARGET:"
whois "$TARGET"
echo

echo "==================== End of Trace ===================="
