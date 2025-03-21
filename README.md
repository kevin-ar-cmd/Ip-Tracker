# IP Tracer

## Overview
The IP Tracer is a comprehensive shell script that allows you to trace IP addresses and hostnames. It performs a series of network diagnostics, including traceroute, ping, IP information lookup, GeoIP lookups, and WHOIS queries. This tool is useful for network administrators, security professionals, and anyone interested in understanding the geographical location and routing of IP addresses.

## Features
- Traces the route to an IP address or hostname using `traceroute`.
- Pings the target to check its availability.
- Retrieves IP information from various sources.
- Performs GeoIP lookups to determine the geographical location of the IP address.
- Executes WHOIS queries to gather registration details.
- Validates inputs to ensure they are valid IPv4 or IPv6 addresses (including IPv4-mapped IPv6 addresses) or hostnames.
- Displays a progress bar during command execution.
- Logs all results and errors to a file.

## Dependencies
- `curl`: For making HTTP requests to fetch IP information from APIs.
- `traceroute`: For tracing the route to the target IP.
- `ping`: For checking if the target is reachable.
- `whois`: For retrieving domain registration information.
- `geoiplookup` (optional): For performing GeoIP lookups. If not installed, the script will use fallback APIs.

## Alternative GeoIP Tools
If `geoiplookup` is not installed, the script will utilize other GeoIP APIs, such as:
- `ipinfo.io`
- `ip-api.com`
- `ipstack.com` (requires an access key)
- `db-ip.com`
- `maxminddb` (for local queries)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/kevin-ar-cmd/ip-tracer.git
   cd ip-tracer
   
