#!/bin/bash

# Simple test script to verify traffic control delays
# Usage: ./test-delay.sh <IP_ADDRESS>

if [ $# -eq 0 ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    echo "This will test ping delays to the specified IP"
    exit 1
fi

IP=$1

echo "🧪 Testing network delay to $IP"
echo "📊 Measuring baseline ping times (before throttling)..."

# Test 5 pings and get average
ping -c 5 $IP | tail -1 | awk -F'/' '{print "Average: " $5 "ms"}'

echo ""
echo "💡 Now add the IP '$IP' to Traffic Control with throttle action"
echo "💡 Set a delay (e.g., 2000ms) and test again"
echo "💡 You should see significantly higher ping times"
echo ""
echo "🔄 To test again after adding throttling, run:"
echo "   ping -c 5 $IP"