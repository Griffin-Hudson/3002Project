"""
main.py
=======
Entry point for the Mini Internet Protocol Stack Simulator.

Usage:
    python main.py <message_size>

Builds the three-node topology (Host A -> Router R1 -> Host B), generates a
deterministic payload of the requested size, and transmits it using the full
Layer 2/3/4 stack. Messages larger than 500 bytes are split into multiple
segments and sent with rdt2.2 (alternating-bit) acknowledgement.
"""

import sys

from config import (
    HOST_A_IP,        HOST_B_IP,
    ROUTER_R1_IF1_IP, ROUTER_R1_IF2_IP,
    HOST_A_MAC,       HOST_B_MAC,
    ROUTER_R1_IF1_MAC, ROUTER_R1_IF2_MAC,
    SUBNET_1_NETWORK, SUBNET_1_MASK,
    SUBNET_2_NETWORK, SUBNET_2_MASK,
    DEFAULT_NETWORK,  DEFAULT_MASK,
)
from devices import Host, Router


def build_network():
    """
    Create and wire up the three-node topology, returning (host_a, router_r1, host_b).

    Topology: Host A (10.0.1.10) -- R1 -- Host B (10.0.2.20)
    Subnet 1: 10.0.1.0/24  (Host A <-> R1 Interface 1)
    Subnet 2: 10.0.2.0/24  (R1 Interface 2 <-> Host B)
    """

    # Create devices
    host_a  = Host("Host A",   HOST_A_IP, HOST_A_MAC)
    host_b  = Host("Host B",   HOST_B_IP, HOST_B_MAC)
    router  = Router("Router R1")

    # Configure router interfaces
    router.add_interface("Interface 1", ROUTER_R1_IF1_IP, ROUTER_R1_IF1_MAC)
    router.add_interface("Interface 2", ROUTER_R1_IF2_IP, ROUTER_R1_IF2_MAC)

    # Routing tables
    host_a.add_route(SUBNET_1_NETWORK, SUBNET_1_MASK, None,            'eth0')
    host_a.add_route(DEFAULT_NETWORK,  DEFAULT_MASK,  ROUTER_R1_IF1_IP,'eth0')

    host_b.add_route(SUBNET_2_NETWORK, SUBNET_2_MASK, None,            'eth0')
    host_b.add_route(DEFAULT_NETWORK,  DEFAULT_MASK,  ROUTER_R1_IF2_IP,'eth0')

    router.add_route(SUBNET_1_NETWORK, SUBNET_1_MASK, None, 'Interface 1')
    router.add_route(SUBNET_2_NETWORK, SUBNET_2_MASK, None, 'Interface 2')

    # Static ARP entries
    host_a.add_arp_entry(ROUTER_R1_IF1_IP, ROUTER_R1_IF1_MAC)
    host_b.add_arp_entry(ROUTER_R1_IF2_IP, ROUTER_R1_IF2_MAC)
    router.add_arp_entry(HOST_A_IP, HOST_A_MAC)
    router.add_arp_entry(HOST_B_IP, HOST_B_MAC)

    # Link connections
    host_a.set_uplink(router, 'Interface 1')
    router.set_uplink('Interface 1', host_a, 'eth0')
    router.set_uplink('Interface 2', host_b, 'eth0')
    host_b.set_uplink(router, 'Interface 2')

    return host_a, router, host_b


def main():
    """Parse args, build the network, and run the simulation."""
    sys.stdout.reconfigure(encoding='utf-8')

    if len(sys.argv) != 2:
        print("Usage: python main.py <message_size>")
        sys.exit(1)

    try:
        msg_size = int(sys.argv[1])
    except ValueError:
        print("Error: <message_size> must be a positive integer.")
        sys.exit(1)

    if msg_size <= 0:
        print("Error: <message_size> must be a positive integer.")
        sys.exit(1)

    host_a, router_r1, host_b = build_network()

    # Deterministic payload: bytes 0, 1, 2, ... mod 256
    message = bytes(i % 256 for i in range(msg_size))

    host_a.send_message(HOST_B_IP, message)


if __name__ == '__main__':
    main()
