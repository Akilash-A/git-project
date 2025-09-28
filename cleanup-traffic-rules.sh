#!/bin/bash

# NetGuardian Traffic Control Cleanup Script
# This script removes all iptables and tc rules created by the application

echo "🧹 Cleaning up NetGuardian traffic control rules..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    SUDO="sudo"
    echo "⚠️  Running with sudo for system-level cleanup"
else
    SUDO=""
    echo "✓ Running as root"
fi

# Clean up iptables rules
echo "🛡️ Cleaning up iptables rules..."

# Remove all rules from mangle table (marks)
$SUDO iptables -t mangle -F

# Remove hashlimit rules (rate limiting)
$SUDO iptables -L INPUT --line-numbers | grep hashlimit | while read line; do
    line_num=$(echo $line | cut -d' ' -f1)
    $SUDO iptables -D INPUT $line_num 2>/dev/null
done

$SUDO iptables -L OUTPUT --line-numbers | grep hashlimit | while read line; do
    line_num=$(echo $line | cut -d' ' -f1)  
    $SUDO iptables -D OUTPUT $line_num 2>/dev/null
done

# Remove connlimit rules
$SUDO iptables -L INPUT --line-numbers | grep connlimit | while read line; do
    line_num=$(echo $line | cut -d' ' -f1)
    $SUDO iptables -D INPUT $line_num 2>/dev/null
done

# Remove DROP rules (blocks)
$SUDO iptables -L INPUT --line-numbers | grep "DROP.*src" | while read line; do
    line_num=$(echo $line | cut -d' ' -f1)
    $SUDO iptables -D INPUT $line_num 2>/dev/null
done

echo "⏱️ Cleaning up traffic control (tc) rules..."

# Get all network interfaces
for interface in $(ip link show | grep '^[0-9]' | cut -d':' -f2 | tr -d ' '); do
    if [ "$interface" != "lo" ]; then
        echo "  🔧 Cleaning interface: $interface"
        
        # Remove all tc qdiscs (this removes classes and filters too)
        $SUDO tc qdisc del dev $interface root 2>/dev/null
        $SUDO tc qdisc del dev $interface ingress 2>/dev/null
    fi
done

# Clean up IFB interfaces if they exist
if ip link show ifb0 >/dev/null 2>&1; then
    echo "  🔧 Cleaning IFB interfaces..."
    $SUDO tc qdisc del dev ifb0 root 2>/dev/null
    $SUDO ip link set dev ifb0 down 2>/dev/null
fi

echo "✅ Traffic control cleanup completed!"
echo ""
echo "💡 To verify cleanup:"
echo "   - Check iptables: sudo iptables -L -n"
echo "   - Check tc rules: sudo tc qdisc show"
echo "   - Test connectivity: ping [previously throttled IP]"