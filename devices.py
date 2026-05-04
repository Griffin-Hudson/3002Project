"""
devices.py
==========
Host and Router classes that implement the Layer 2/3/4 simulation logic.

Routing tables use longest-prefix-match.  Each entry is a 4-tuple:
    (network: str, mask: str, next_hop: str | None, interface: str)
where next_hop=None means the destination is directly connected.
"""

from protocol import (Layer2Frame, Layer3Packet, Layer4Segment)
from config import (
    ETHERTYPE_IPV4, IP_PROTOCOL_UDP, DEFAULT_TTL,
    MAX_SEGMENT_SIZE, TYPE_DATA, TYPE_ACK,
    SRC_PORT, DST_PORT,
)


# ---------------------------------------------------------------------------
# Routing helpers (module-private)
# ---------------------------------------------------------------------------

def _ip_to_int(ip):
    """Convert dotted-decimal IP string to a 32-bit integer."""
    parts = [int(x) for x in ip.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _ip_in_network(ip, network, mask):
    """Return True if ip falls inside network/mask."""
    ip_int  = _ip_to_int(ip)
    net_int = _ip_to_int(network)
    msk_int = _ip_to_int(mask)
    return (ip_int & msk_int) == (net_int & msk_int)


def _prefix_length(mask):
    """Return the number of set bits in a dotted-decimal subnet mask."""
    return bin(_ip_to_int(mask)).count('1')


def _longest_prefix_match(routing_table, dst_ip):
    """
    Find the best (longest-prefix) route for dst_ip.
    Returns (next_hop, interface) or None if no route matches.
    next_hop=None signals a directly connected network.
    """
    best_entry  = None
    best_length = -1
    for network, mask, next_hop, interface in routing_table:
        if _ip_in_network(dst_ip, network, mask):
            plen = _prefix_length(mask)
            if plen > best_length:
                best_length = plen
                best_entry  = (next_hop, interface)
    return best_entry


# ---------------------------------------------------------------------------
# Host
# ---------------------------------------------------------------------------

class Host:
    """
    End-host implementing Layers 2, 3, and 4.

    Layer 4: UDP-like segments with checksum and rdt2.2 alternating-bit protocol.
    Layer 3: IP-like encapsulation with longest-prefix-match routing.
    Layer 2: Ethernet-like framing with ARP-table MAC resolution and MAC learning.
    """

    def __init__(self, name, ip, mac):
        self.name          = name
        self.ip            = ip
        self.mac           = mac

        self.routing_table = []   # [(network, mask, next_hop, iface), ...]
        self.arp_table     = {}   # next_hop_ip -> MAC string
        self.mac_table     = {}   # src_mac -> interface (learned from received frames)
        self.uplink        = None # (device, remote_interface_name)

        # rdt2.2 sender state
        self.send_seq      = 0
        # rdt2.2 receiver state
        self.expected_seq  = 0
        self.last_ack_seq  = None

        self.received_data = []   # application-layer receive buffer

        # stored so we can retransmit if we get a bad ACK
        self._pending_data_dst_ip  = None
        self._pending_data_segment = None

    # --- configuration ---

    def set_uplink(self, device, remote_interface):
        """Connect this host's single interface to device at remote_interface."""
        self.uplink = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface='eth0'):
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        self.arp_table[ip] = mac

    # --- application layer ---

    def send_message(self, dst_ip, data):
        """
        Split data into MAX_SEGMENT_SIZE chunks and send each via rdt2.2.
        Blocks until the ACK for each segment is received before sending the next.
        """
        chunks = [data[i:i + MAX_SEGMENT_SIZE]
                  for i in range(0, len(data), MAX_SEGMENT_SIZE)]
        for chunk in chunks:
            self._layer4_send_data(dst_ip, SRC_PORT, DST_PORT, chunk)

    # --- Layer 4 (Transport) ---

    def _layer4_send_data(self, dst_ip, src_port, dst_port, data):
        """
        Build a DATA segment for data, compute its checksum, and hand it to Layer 3.
        Because the simulation is synchronous the full round-trip (DATA + ACK)
        completes inside _layer3_send, so send_seq is toggled before this returns.
        """
        print(f"{self.name}: Layer 4: Data received from Application Layer. "
              f"Data size={len(data)}")

        seg = Layer4Segment(src_port, dst_port, TYPE_DATA, self.send_seq, data)
        seg.compute_checksum()
        self._pending_data_dst_ip  = dst_ip
        self._pending_data_segment = seg
        print(f"{self.name}: Layer 4: Checksum computed")
        print(f"{self.name}: Layer 4: Segment created by adding transport layer "
              f"header (DATA, seq={self.send_seq}) (encapsulation)")
        print(f"{self.name}: Layer 4: Segment sent to Network Layer")

        self._layer3_send(self.ip, dst_ip, seg)

    def _layer4_send_ack(self, dst_ip, src_port, dst_port, seq_num):
        """Build and send an ACK segment for seq_num."""
        seg = Layer4Segment(src_port, dst_port, TYPE_ACK, seq_num, b'')
        seg.compute_checksum()
        print(f"{self.name}: Layer 4: Segment created by adding transport layer "
              f"header (ACK, seq={seq_num})")
        print(f"{self.name}: Layer 4: Segment sent to Network Layer")
        self._layer3_send(self.ip, dst_ip, seg)

    def _layer4_receive(self, seg, src_ip, dst_ip):
        """
        rdt2.2 receive handler for both DATA and ACK segments.

        DATA (receiver side):
          - bad checksum  → discard, re-send last ACK
          - in-order      → deliver to app, send ACK, advance expected_seq
          - duplicate     → re-send last ACK

        ACK (sender side):
          - correct ACK   → advance send_seq
          - wrong ACK     → retransmit current DATA segment
        """
        print()
        print(f"{self.name}: Layer 4: Segment received from Network Layer")

        if not seg.verify_checksum():
            print(f"{self.name}: Layer 4: Segment discarded due to checksum error")
            if seg.seg_type == TYPE_DATA and self.last_ack_seq is not None:
                self._layer4_send_ack(src_ip, seg.dst_port, seg.src_port,
                                      self.last_ack_seq)
            return

        print(f"{self.name}: Layer 4: Checksum verified")

        if seg.seg_type == TYPE_DATA:
            if seg.seq_num == self.expected_seq:
                print(f"{self.name}: Layer 4: DATA segment delivered to "
                      f"Application Layer. Data size={len(seg.data)}")
                self.received_data.append(seg.data)
                self.last_ack_seq = seg.seq_num
                self._layer4_send_ack(src_ip, seg.dst_port, seg.src_port,
                                      seg.seq_num)
                self.expected_seq = 1 - self.expected_seq
            else:
                # duplicate or out-of-order — re-send last ACK
                if self.last_ack_seq is not None:
                    self._layer4_send_ack(src_ip, seg.dst_port, seg.src_port,
                                          self.last_ack_seq)

        elif seg.seg_type == TYPE_ACK:
            print(f"{self.name}: Layer 4: ACK received: seq={seg.seq_num}")
            if seg.seq_num == self.send_seq:
                self.send_seq = 1 - self.send_seq
                self._pending_data_dst_ip  = None
                self._pending_data_segment = None
            else:
                print(f"{self.name}: Layer 4: Segment retransmitted due to "
                      f"incorrect ACK")
                if self._pending_data_dst_ip and self._pending_data_segment:
                    self._layer3_send(self.ip, self._pending_data_dst_ip,
                                      self._pending_data_segment)

    # --- Layer 3 (Network) ---

    def _layer3_send(self, src_ip, dst_ip, seg):
        """
        Encapsulate seg into an IP packet, look up the route, and pass to Layer 2.
        """
        seg_bytes = seg.to_bytes()
        pkt = Layer3Packet(src_ip, dst_ip, DEFAULT_TTL, IP_PROTOCOL_UDP, seg_bytes)

        print()
        print(f"{self.name}: Layer 3: Segment received from Transport Layer: "
              f"SRC_IP={src_ip}, DST_IP={dst_ip}, TTL={DEFAULT_TTL}")
        print(f"{self.name}: Layer 3: Destination IP read: {dst_ip}")
        print(f"{self.name}: Layer 3: Routing table lookup performed")

        route = _longest_prefix_match(self.routing_table, dst_ip)
        if route is None:
            print(f"{self.name}: Layer 3: No route to {dst_ip}. Packet dropped.")
            return

        next_hop, iface = route
        if next_hop is None:
            next_hop = dst_ip   # directly connected — use destination IP as next hop

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_send(pkt, next_hop)

    def _layer3_receive(self, pkt):
        """
        Accept a packet from Layer 2.  Deliver to Layer 4 if addressed to this
        host, otherwise drop it.
        """
        print()
        print(f"{self.name}: Layer 3: Packet received from Data Link Layer: "
              f"SRC_IP={pkt.src_ip}, DST_IP={pkt.dst_ip}, TTL={pkt.ttl}")
        print(f"{self.name}: Layer 3: Destination IP read: {pkt.dst_ip}")

        if pkt.dst_ip == self.ip:
            print(f"{self.name}: Layer 3: Packet identified as local delivery")
            print(f"{self.name}: Layer 3: Segment delivered to Transport Layer")
            seg = Layer4Segment.from_bytes(pkt.payload)
            self._layer4_receive(seg, pkt.src_ip, pkt.dst_ip)
        else:
            print(f"{self.name}: Layer 3: Destination not local. Packet dropped.")

    # --- Layer 2 (Data Link) ---

    def _layer2_send(self, pkt, next_hop_ip):
        """
        Look up next_hop_ip in the ARP table, wrap pkt in a frame, and transmit.
        """
        print()
        print(f"{self.name}: Layer 2: Packet received from Network Layer")

        dst_mac = self.arp_table.get(next_hop_ip)
        if dst_mac is None:
            print(f"{self.name}: Layer 2: No ARP entry for {next_hop_ip}. "
                  "Frame dropped.")
            return

        print(f"{self.name}: Layer 2: Destination MAC lookup for next-hop IP "
              f"({next_hop_ip}) → {dst_mac}")

        frame = Layer2Frame(dst_mac, self.mac, ETHERTYPE_IPV4, pkt.to_bytes())
        print(f"{self.name}: Layer 2: Frame created: "
              f"SRC_MAC={self.mac}, DST_MAC={dst_mac}")
        print(f"{self.name}: Layer 2: Frame sent")

        if self.uplink:
            device, remote_iface = self.uplink
            device.receive_frame(frame, remote_iface)

    def receive_frame(self, frame, interface='eth0'):
        """
        Accept an incoming frame.  Learn the source MAC (first time only),
        then deliver the payload to Layer 3 if the frame is addressed to us.
        """
        print()
        print(f"{self.name}: Layer 2: Frame received")

        src_mac = frame.src_mac
        if src_mac not in self.mac_table:
            self.mac_table[src_mac] = interface
            print(f"{self.name}: Layer 2: Source MAC learned: {src_mac}")

        if frame.dst_mac in (self.mac, 'FF:FF:FF:FF:FF:FF'):
            if frame.ether_type == ETHERTYPE_IPV4:
                print(f"{self.name}: Layer 2: Packet delivered to Network Layer")
                pkt = Layer3Packet.from_bytes(frame.payload)
                self._layer3_receive(pkt)


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

class Router:
    """
    Layer 2/3 router — no transport layer.

    Layer 3: receives packets, decrements TTL, performs longest-prefix-match
             routing, and forwards to the appropriate outgoing interface.
    Layer 2: per-interface MAC learning, ARP-table MAC resolution, framing.
    """

    def __init__(self, name):
        self.name          = name
        self.interfaces    = {}   # {iface_name: {ip, mac, uplink}}
        self.routing_table = []   # [(network, mask, next_hop, iface), ...]
        self.arp_table     = {}   # next_hop_ip -> MAC string
        self.mac_table     = {}   # {iface_name: {src_mac: iface_name}}

    # --- configuration ---

    def add_interface(self, name, ip, mac):
        """Register a network interface with the given IP and MAC."""
        self.interfaces[name] = {'ip': ip, 'mac': mac, 'uplink': None}
        self.mac_table[name]  = {}

    def set_uplink(self, iface_name, device, remote_interface):
        """Connect iface_name to a neighbouring device."""
        self.interfaces[iface_name]['uplink'] = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface):
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        self.arp_table[ip] = mac

    # --- Layer 2 (Data Link) ---

    def receive_frame(self, frame, interface):
        """
        Accept a frame on interface.  Learn the source MAC (first time only),
        then pass the payload up to Layer 3.
        """
        print()
        print(f"{self.name}: Layer 2: Frame received on {interface}")

        src_mac = frame.src_mac
        if src_mac not in self.mac_table[interface]:
            self.mac_table[interface][src_mac] = interface
            print(f"{self.name}: Layer 2: Source MAC learned: "
                  f"{src_mac} on {interface}")

        if frame.ether_type == ETHERTYPE_IPV4:
            print(f"{self.name}: Layer 2: Packet delivered to Network Layer")
            pkt = Layer3Packet.from_bytes(frame.payload)
            self._layer3_receive(pkt, interface)

    def _layer2_forward(self, pkt, next_hop, out_iface):
        """
        Wrap pkt in a frame using the ARP table and send it out on out_iface.
        """
        print()
        print(f"{self.name}: Layer 2: Packet received from Network Layer")

        dst_mac = self.arp_table.get(next_hop)
        if dst_mac is None:
            print(f"{self.name}: Layer 2: No ARP entry for {next_hop}. "
                  "Frame dropped.")
            return

        print(f"{self.name}: Layer 2: Destination MAC lookup for next-hop IP "
              f"({next_hop}) → {dst_mac}")

        src_mac = self.interfaces[out_iface]['mac']
        frame   = Layer2Frame(dst_mac, src_mac, ETHERTYPE_IPV4, pkt.to_bytes())
        print(f"{self.name}: Layer 2: Frame created: "
              f"SRC_MAC={src_mac}, DST_MAC={dst_mac}")
        print(f"{self.name}: Layer 2: Frame forwarded on {out_iface}")

        uplink = self.interfaces[out_iface].get('uplink')
        if uplink:
            device, remote_iface = uplink
            device.receive_frame(frame, remote_iface)

    # --- Layer 3 (Network) ---

    def _layer3_receive(self, pkt, in_iface):
        """
        Process a packet from Layer 2:
          1. Decrement TTL (drop if it hits 0).
          2. Longest-prefix-match routing lookup.
          3. Forward to Layer 2 on the selected outgoing interface.
        """
        print()
        print(f"{self.name}: Layer 3: Packet received from Data Link Layer: "
              f"SRC_IP={pkt.src_ip}, DST_IP={pkt.dst_ip}, TTL={pkt.ttl}")
        print(f"{self.name}: Layer 3: Destination IP read: {pkt.dst_ip}")

        old_ttl  = pkt.ttl
        pkt.ttl -= 1
        print(f"{self.name}: Layer 3: TTL decremented: {old_ttl} → {pkt.ttl}")

        if pkt.ttl <= 0:
            print(f"{self.name}: Layer 3: TTL expired. Packet dropped.")
            return

        print(f"{self.name}: Layer 3: Routing table lookup performed")
        route = _longest_prefix_match(self.routing_table, pkt.dst_ip)

        if route is None:
            print(f"{self.name}: Layer 3: No route to {pkt.dst_ip}. "
                  "Packet dropped.")
            return

        next_hop, out_iface = route
        if next_hop is None:
            next_hop = pkt.dst_ip   # directly connected network

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected ({out_iface})")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_forward(pkt, next_hop, out_iface)
