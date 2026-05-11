"""
Fixed network parameters for the Mini Internet Protocol Stack Simulator.
All IP addresses, MAC addresses, subnet definitions, and protocol constants
are defined here so other modules never hard-code these values.
"""

# IP Addresses
HOST_A_IP         = "10.0.1.10"
HOST_B_IP         = "10.0.2.20"
ROUTER_R1_IF1_IP  = "10.0.1.1"    # Router R1 - Interface 1 (subnet 1 side)
ROUTER_R1_IF2_IP  = "10.0.2.1"    # Router R1 - Interface 2 (subnet 2 side)

# Subnet Definitions
SUBNET_1_NETWORK  = "10.0.1.0"
SUBNET_1_MASK     = "255.255.255.0"
SUBNET_2_NETWORK  = "10.0.2.0"
SUBNET_2_MASK     = "255.255.255.0"
DEFAULT_NETWORK   = "0.0.0.0"     # default route (catch-all)
DEFAULT_MASK      = "0.0.0.0"

# MAC Addresses
HOST_A_MAC        = "AA:AA:AA:AA:AA:AA"
ROUTER_R1_IF1_MAC = "BB:BB:BB:BB:BB:BB"
ROUTER_R1_IF2_MAC = "CC:CC:CC:CC:CC:CC"
HOST_B_MAC        = "DD:DD:DD:DD:DD:DD"

# Layer 2 constants
ETHERTYPE_IPV4    = 0x0800

# Layer 3 constants
IP_PROTOCOL_UDP   = 17
DEFAULT_TTL       = 100

# Layer 4 / Transport constants
SRC_PORT          = 5000
DST_PORT          = 80
MAX_SEGMENT_SIZE  = 500            # max application data bytes per segment
TYPE_DATA         = 0
TYPE_ACK          = 1
