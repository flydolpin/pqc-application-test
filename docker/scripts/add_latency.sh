#!/bin/bash
# Add network latency, jitter, and packet loss to a container's interface
# Usage: add_latency.sh <delay_ms> <jitter_ms> <loss_percent> <bandwidth>
#
# Examples:
#   add_latency.sh 50 10 0.1       # 50ms delay, 10ms jitter, 0.1% loss
#   add_latency.sh 100 20 1 10mbit # 100ms delay, 1% loss, 10Mbps bandwidth
#
# Run inside the target container:
#   docker exec pqc-server add_latency.sh 50 5 0.1

DELAY=${1:-50}
JITTER=${2:-10}
LOSS=${3:-0}
BANDWIDTH=${4:-""}

IFACE=$(ip route | head -1 | awk '{print $5}' 2>/dev/null || echo "eth0")

echo "Configuring network on $IFACE:"
echo "  Delay: ${DELAY}ms ± ${JITTER}ms"
echo "  Loss: ${LOSS}%"
[ -n "$BANDWIDTH" ] && echo "  Bandwidth: $BANDWIDTH"

# Check if tc is available
if ! command -v tc &>/dev/null; then
    echo "Error: tc (iproute2) not available. Install with: apt-get install iproute2"
    exit 1
fi

# Remove existing qdisc
tc qdisc del dev "$IFACE" root netem 2>/dev/null || true

# Add network emulation
if [ -n "$BANDWIDTH" ]; then
    tc qdisc add dev "$IFACE" root handle 1:0 netem \
        delay ${DELAY}ms ${JITTER}ms loss ${LOSS}% \
        rate "$BANDWIDTH"
else
    tc qdisc add dev "$IFACE" root netem \
        delay ${DELAY}ms ${JITTER}ms loss ${LOSS}%
fi

echo "Network conditions applied. Verify with: tc qdisc show dev $IFACE"
