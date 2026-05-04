"""
main.py
=======
Entry point for the Mini Internet Protocol Stack Simulator.

Usage
-----
    python main.py <message_size>

where ``<message_size>`` is the number of application-data bytes to send from
Host A to Host B.  The simulator builds the following topology, configures all
routing and ARP tables, generates a deterministic byte payload of the requested
size, and transmits it using the full Layer-2/3/4 stack:

    Host A (10.0.1.10) ──[L1]──  Router R1  ──[L2]──  Host B (10.0.2.20)
    subnet 10.0.1.0/24                                  subnet 10.0.2.0/24

If the payload exceeds 500 bytes it is automatically split into multiple
transport segments, each transmitted and acknowledged individually (rdt2.2).

No external libraries are used; only ``sys`` from the Python standard library.
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


# ═════════════════════════════════════════════════════════════════════════════
# Network construction
# ═════════════════════════════════════════════════════════════════════════════

def build_network():
    """
    Instantiate and fully configure the three-node network topology.

    Creates Host A, Router R1 (two interfaces), and Host B; sets up routing
    tables, static ARP tables, and logical link connections.

    Topology
    --------
    Host A (10.0.1.10)
      └── eth0 → R1 Interface 1 (10.0.1.1)  [Link L1, subnet 10.0.1.0/24]
    Router R1
      ├── Interface 1 (10.0.1.1) ← Host A
      └── Interface 2 (10.0.2.1) → Host B   [Link L2, subnet 10.0.2.0/24]
    Host B (10.0.2.20)
      └── eth0 → R1 Interface 2 (10.0.2.1)

    Returns
    -------
    tuple
        ``(host_a, router_r1, host_b)``
    """

    # ── Create device instances ───────────────────────────────────────────────
    host_a  = Host("Host A",   HOST_A_IP, HOST_A_MAC)
    host_b  = Host("Host B",   HOST_B_IP, HOST_B_MAC)
    router  = Router("Router R1")

    # ── Configure router interfaces ──────────────────────────────────────────
    router.add_interface("Interface 1", ROUTER_R1_IF1_IP, ROUTER_R1_IF1_MAC)
    router.add_interface("Interface 2", ROUTER_R1_IF2_IP, ROUTER_R1_IF2_MAC)

    # ── Routing tables ───────────────────────────────────────────────────────
    # Host A:
    #   10.0.1.0/24  → directly connected (next_hop=None)
    #   0.0.0.0/0    → via R1 Interface 1 (default gateway)
    host_a.add_route(SUBNET_1_NETWORK, SUBNET_1_MASK, None,            'eth0')
    host_a.add_route(DEFAULT_NETWORK,  DEFAULT_MASK,  ROUTER_R1_IF1_IP,'eth0')

    # Host B:
    #   10.0.2.0/24  → directly connected
    #   0.0.0.0/0    → via R1 Interface 2 (default gateway)
    host_b.add_route(SUBNET_2_NETWORK, SUBNET_2_MASK, None,            'eth0')
    host_b.add_route(DEFAULT_NETWORK,  DEFAULT_MASK,  ROUTER_R1_IF2_IP,'eth0')

    # Router R1:
    #   10.0.1.0/24  → directly connected via Interface 1
    #   10.0.2.0/24  → directly connected via Interface 2
    router.add_route(SUBNET_1_NETWORK, SUBNET_1_MASK, None, 'Interface 1')
    router.add_route(SUBNET_2_NETWORK, SUBNET_2_MASK, None, 'Interface 2')

    # ── Static ARP / MAC-resolution tables ───────────────────────────────────
    # Host A only ever needs to reach its gateway (R1 Interface 1)
    host_a.add_arp_entry(ROUTER_R1_IF1_IP, ROUTER_R1_IF1_MAC)
    # Host B only ever needs to reach its gateway (R1 Interface 2)
    host_b.add_arp_entry(ROUTER_R1_IF2_IP, ROUTER_R1_IF2_MAC)
    # Router R1 needs to resolve both hosts for direct delivery
    router.add_arp_entry(HOST_A_IP, HOST_A_MAC)
    router.add_arp_entry(HOST_B_IP, HOST_B_MAC)

    # ── Logical link connections ──────────────────────────────────────────────
    # Link L1:  Host A ↔ Router R1 Interface 1
    host_a.set_uplink(router, 'Interface 1')
    router.set_uplink('Interface 1', host_a, 'eth0')

    # Link L2:  Router R1 Interface 2 ↔ Host B
    router.set_uplink('Interface 2', host_b, 'eth0')
    host_b.set_uplink(router, 'Interface 2')

    return host_a, router, host_b


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """
    Parse the command-line argument, build the network, and run the simulation.

    The application generates a deterministic payload of the requested size
    (bytes 0, 1, 2, … mod 256) and calls ``host_a.send_message`` to initiate
    the full Layer-2/3/4 transmission to Host B.
    """
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

    # Build the three-node network
    host_a, router_r1, host_b = build_network()

    # Generate a deterministic payload of the requested length
    message = bytes(i % 256 for i in range(msg_size))

    # Transmit from Host A to Host B through Router R1
    host_a.send_message(HOST_B_IP, message)


if __name__ == '__main__':
    main()
