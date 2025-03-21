#!/bin/bash

# Colors for the progress bar
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"  # No Color

# Create logs directory if it doesn't exist
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Set the log file path
LOG_FILE="$LOG_DIR/ip_tracer.log"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate IPv4 address format
validate_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
        if [ "$i1" -le 255 ] && [ "$i2" -le 255 ] && [ "$i3" -le 255 ] && [ "$i4" -le 255 ]; then
            return 0
        fi
    fi
    return 1
}

# Function to validate IPv6 address format, including IPv4-mapped IPv6 addresses
validate_ipv6() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$ || 
          "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,7}:$ || 
          "$ip" =~ ^::([0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}$ ||
          "$ip" =~ ^[0-9a-fA-F]{1,4}::[0-9a-fA-F]{1,4}$ || 
          "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,6}::$ || 
          "$ip" =~ ^::ffff:([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi
    return 1
}

# Function to validate hostname format
validate_hostname() {
    local hostname="$1"
    if [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        return 0
    fi
    return 1
}

# Function to show progress bar with percentage
show_progress() {
    local pid="$1"
    local delay=0.1
    local total_steps=100
    local progress=0

    echo -ne "Progress: ["
    while kill -0 "$pid" 2>/dev/null; do
        local filled=$((progress / 2))
        local empty=$((50 - filled))

        local bar=""
        for ((i = 0; i < filled; i++)); do
            bar+="${GREEN}#${NC}"
        done
        for ((; i < 50; i++)); do
            bar+=" "
        done

        printf "\rProgress: [%s] %d%%" "$bar" "$progress"
        sleep "$delay"
        ((progress += 2))
        if [ "$progress" -ge "$total_steps" ]; then
            progress=100
        fi
    done
    echo -ne "\rProgress: [${GREEN}##################################################${NC}] 100%\n"
}

# Check if required commands are available
if ! command_exists "curl"; then
    echo -e "${RED}Error: curl is not installed.${NC}"
    exit 1
fi

if ! command_exists "geoiplookup"; then
    GEOIPLOOKUP_INSTALLED=false
    echo -e "${YELLOW}Warning: geoiplookup is not installed. GeoIP lookups will be skipped.${NC}"
else
    GEOIPLOOKUP_INSTALLED=true
fi

# Check if an argument was provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_ip_or_hostname>"
    exit 1
fi

TARGET="$1"

# Function to execute a command and check for errors
execute_command() {
    echo "$1"
    shift
    local command="$*"
    "$@" &
    local pid=$!
    show_progress "$pid"

    if wait "$pid"; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: $command" >> "$LOG_FILE"
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Command failed: $command" >> "$LOG_FILE"
        echo -e "${RED}Error: Command failed: $command${NC}"
    fi
    echo
}

# Initialize log file
echo "==================== IP Tracer ====================" > "$LOG_FILE"
echo "Tracing for: $TARGET" >> "$LOG_FILE"

# Validate IP address or hostname
if validate_ipv4 "$TARGET"; then
    # Proceed with commands if it is a valid IPv4
    execute_command "Traceroute to $TARGET:" traceroute "$TARGET"
    execute_command "Pinging $TARGET:" ping -c 4 "$TARGET"
    
    # Handle IP Information lookup with error checking
    echo "Getting IP Information for $TARGET:"
    if ! IP_INFO=$(curl -s ipinfo.io/"$TARGET"); then
        echo -e "${RED}Error: IP information lookup for '$TARGET' failed.${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: IP information lookup failed: $TARGET" >> "$LOG_FILE"
    else
        echo "$IP_INFO"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: IP information retrieved for $TARGET" >> "$LOG_FILE"
    fi

    # Handle GeoIP lookup with error checking
    if $GEOIPLOOKUP_INSTALLED; then
        if ! geoiplookup "$TARGET"; then
            echo -e "${RED}Error: GeoIP lookup for '$TARGET' failed.${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: GeoIP lookup failed: $TARGET" >> "$LOG_FILE"
        fi
    fi

    execute_command "NSLookup for $TARGET:" nslookup "$TARGET"

    # Handle WHOIS lookup with error checking
    if ! whois "$TARGET"; then
        echo -e "${RED}Error: WHOIS lookup for '$TARGET' failed.${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: WHOIS lookup failed: $TARGET" >> "$LOG_FILE"
    fi

elif validate_ipv6 "$TARGET"; then
    # Proceed with commands if it is a valid IPv6
    execute_command "Traceroute to $TARGET:" traceroute "$TARGET"
    execute_command "Pinging $TARGET:" ping -c 4 "$TARGET"
    
    # Handle IP Information lookup with error checking
    echo "Getting IP Information for $TARGET:"
    if ! IP_INFO=$(curl -s ipinfo.io/"$TARGET"); then
        echo -e "${RED}Error: IP information lookup for '$TARGET' failed.${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: IP information lookup failed: $TARGET" >> "$LOG_FILE"
    else
        echo "$IP_INFO"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: IP information retrieved for $TARGET" >> "$LOG_FILE"
    fi

    # Handle GeoIP lookup with error checking
    if $GEOIPLOOKUP_INSTALLED; then
        if ! geoiplookup "$TARGET"; then
            echo -e "${RED}Error: GeoIP lookup for '$TARGET' failed.${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: GeoIP lookup failed: $TARGET" >> "$LOG_FILE"
        fi
    fi

    execute_command "NSLookup for $TARGET:" nslookup "$TARGET"

    # Handle WHOIS lookup with error checking
    if ! whois "$TARGET"; then
        echo -e "${RED}Error: WHOIS lookup for '$TARGET' failed.${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: WHOIS lookup failed: $TARGET" >> "$LOG_FILE"
    fi
else
    if validate_hostname "$TARGET"; then
        # Check if hostname can be resolved
        if ! ping -c 1 "$TARGET" > /dev/null 2>&1; then
            echo -e "${RED}Error: Hostname '$TARGET' could not be resolved.${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Hostname could not be resolved: $TARGET" >> "$LOG_FILE"
            exit 1
        fi

        # Proceed with commands if it is a valid hostname
        execute_command "Traceroute to $TARGET:" traceroute "$TARGET"
        execute_command "Pinging $TARGET:" ping -c 4 "$TARGET"

        # Handle IP Information lookup with error checking
        echo "Getting IP Information for $TARGET:"
        if ! IP_INFO=$(curl -s ipinfo.io/"$TARGET"); then
            echo -e "${RED}Error: IP information lookup for '$TARGET' failed.${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: IP information lookup failed: $TARGET" >> "$LOG_FILE"
        else
            echo "$IP_INFO"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - SUCCESS: IP information retrieved for $TARGET" >> "$LOG_FILE"
        fi

        # Handle GeoIP lookup
        if $GEOIPLOOKUP_INSTALLED; then
            if ! geoiplookup "$TARGET"; then
                echo -e "${RED}Error: GeoIP lookup for '$TARGET' failed.${NC}"
                echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: GeoIP lookup failed: $TARGET" >> "$LOG_FILE"
            fi
        fi

        execute_command "NSLookup for $TARGET:" nslookup "$TARGET"

        # Handle WHOIS lookup
        if ! whois "$TARGET"; then
            echo -e "${RED}Error: WHOIS lookup for '$TARGET' failed.${NC}"
            echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: WHOIS lookup failed: $TARGET" >> "$LOG_FILE"
        fi
    else
        echo -e "${RED}Error: Invalid IP address or hostname format. Please provide a valid IPv4 or IPv6 address.${NC}"
        echo "$(date '+%Y-%m-%d %H:%M:%S') - ERROR: Invalid format: $TARGET" >> "$LOG_FILE"
        exit 1
    fi
fi

echo "==================== End of Trace ===================="
echo "Log file created at: $LOG_FILE"
