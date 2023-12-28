#!/bin/bash

start_ip="192.168.1.1"
end_ip="192.168.1.10"

# Function to test if an IP is reachable
ping_ip() {
    if ping -c 1 -W 1 "$1" &> /dev/null; then
        echo "$1 is reachable"
    else
        echo "$1 is not reachable"
    fi
}

# Iterate over the IP range
current_ip=$(printf "%d.%d.%d.%d\n" $(echo $start_ip | tr "." " "))
end_ip_number=$(printf "%d\n" $(echo $end_ip | tr "." " " | awk '{print $4}'))

while [ "$(printf "%d\n" $(echo $current_ip | tr "." " " | awk '{print $4}'))" -le "$end_ip_number" ]; do
    ping_ip "$current_ip"
    current_ip=$(echo $current_ip | awk -F. '{print $1"."$2"."$3"."$4+1}')
done
