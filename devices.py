"""
Host and Router classes implementing the Layer 2/3/4 network simulation.
Both devices communicate through direct Python method calls rather than real
sockets.  Routing uses longest-prefix-match; next_hop=None means the route is
directly connected (dst_ip is used as the next-hop address in that case).
"""
from protocol import (Layer2Frame, Layer3Packet, Layer4Segment)
from config import (
    ETHERTYPE_IPV4, IP_PROTOCOL_UDP, DEFAULT_TTL,
    MAX_SEGMENT_SIZE, TYPE_DATA, TYPE_ACK,
    SRC_PORT, DST_PORT,
)

# Routing helpers

def _ip_to_int(ip):
    """Dotted-decimal IP string to an unsigned 32-bit integer."""
    parts = [int(x) for x in ip.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

def _ip_in_network(ip, network, mask):
    """True if ip falls within network/mask."""
    ip_int  = _ip_to_int(ip)
    net_int = _ip_to_int(network)
    msk_int = _ip_to_int(mask)
    return (ip_int & msk_int) == (net_int & msk_int)

def _prefix_length(mask):
    """Number of set bits in a dotted-decimal subnet mask."""
    return bin(_ip_to_int(mask)).count('1')

def _longest_prefix_match(routing_table, dst_ip):
    """Longest-prefix-match lookup; returns (next_hop, interface) or None.
    A next_hop of None signals a directly connected network — the caller
    should substitute dst_ip as the next-hop address in that case.
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

class Host:
    """End-host with a full Layer 2/3/4 stack.
    L4 uses rdt2.2 alternating-bit reliable transfer with UDP-like checksums.
    L3 does IP-like encapsulation with longest-prefix-match routing.
    L2 does Ethernet-like framing, static ARP resolution, and source-MAC learning.
    """
    def __init__(self, name, ip, mac):
        self.name          = name
        self.ip            = ip
        self.mac           = mac

        self.routing_table = []   # [(network, mask, next_hop, iface), ...]
        self.arp_table     = {}   # next_hop_ip -> MAC string
        self.mac_table     = {}   # src_mac -> interface (learned on receipt)
        self.uplink        = None # (device, remote_interface_name)

        # rdt2.2 sender state
        self.send_seq      = 0
        # rdt2.2 receiver state
        self.expected_seq  = 0
        self.last_ack_seq  = 1     # last ACK sent; ACK1 is the initial ACK for "expecting DATA0"

        self.received_data = []    # application-layer receive buffer

        # in-flight segment kept so we can retransmit on a bad ACK
        self._pending_data_dst_ip  = None
        self._pending_data_segment = None

    def set_uplink(self, device, remote_interface):
        """Wire this host's single uplink to device."""
        self.uplink = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface='eth0'):
        """Add a routing table entry."""
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        """Map ip to mac in the ARP table."""
        self.arp_table[ip] = mac

    def send_message(self, dst_ip, data):
        """Slice data into MAX_SEGMENT_SIZE chunks and deliver each via rdt2.2."""
        chunks = [data[i:i + MAX_SEGMENT_SIZE]
                  for i in range(0, len(data), MAX_SEGMENT_SIZE)]
        for chunk in chunks:
            self._layer4_send_data(dst_ip, SRC_PORT, DST_PORT, chunk)

    def _layer4_send_data(self, dst_ip, src_port, dst_port, data):
        """Build a DATA segment, compute its checksum, and send it down the stack.
        Because the simulation is synchronous the full round-trip (DATA + ACK)
        completes inside _layer3_send, so send_seq is updated before this returns.
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
        """Build and send an ACK for seq_num back to dst_ip."""
        seg = Layer4Segment(src_port, dst_port, TYPE_ACK, seq_num, b'')
        seg.compute_checksum()  # computed for correctness but not logged (per spec)
        print(f"{self.name}: Layer 4: Segment created by adding transport layer "
              f"header (ACK, seq={seq_num})")
        print(f"{self.name}: Layer 4: Segment sent to Network Layer")

        self._layer3_send(self.ip, dst_ip, seg)

    def _layer4_receive(self, seg, src_ip, dst_ip):
        """rdt2.2 receive handler for both DATA and ACK segments.
        DATA (receiver): verify checksum -> deliver in-order data and ACK, or
                         replay last ACK for duplicate/corrupt segments.
        ACK (sender): advance send_seq on correct ACK; retransmit on wrong
                      or corrupt ACK.
        """
        print()
        print(f"{self.name}: Layer 4: Segment received from Network Layer")

        if not seg.verify_checksum():
            print(f"{self.name}: Layer 4: Segment discarded due to checksum error")
            if seg.seg_type == TYPE_DATA:
                # rdt2.2 receiver: re-send last ACK so the sender retransmits
                self._layer4_send_ack(src_ip,
                                      seg.dst_port, seg.src_port,
                                      self.last_ack_seq)
            elif (seg.seg_type == TYPE_ACK
                  and self._pending_data_dst_ip is not None
                  and self._pending_data_segment is not None):
                # rdt2.2 sender: corrupted ACK -> retransmit current DATA segment
                print(f"{self.name}: Layer 4: Segment retransmitted due to "
                      f"checksum error in ACK")
                self._layer3_send(self.ip,
                                  self._pending_data_dst_ip,
                                  self._pending_data_segment)
            return

        print(f"{self.name}: Layer 4: Checksum verified")

        if seg.seg_type == TYPE_DATA:
            if seg.seq_num == self.expected_seq:
                print(f"{self.name}: Layer 4: DATA segment delivered to "
                      f"Application Layer. Data size={len(seg.data)}")
                self.received_data.append(seg.data)
                self.last_ack_seq = seg.seq_num
                self.expected_seq = 1 - self.expected_seq
                # ports are swapped so the ACK flows back to the original sender
                self._layer4_send_ack(src_ip,
                                      seg.dst_port, seg.src_port,
                                      seg.seq_num)
            else:
                # duplicate or out-of-order — re-send last ACK
                self._layer4_send_ack(src_ip,
                                      seg.dst_port, seg.src_port,
                                      self.last_ack_seq)

        elif seg.seg_type == TYPE_ACK:
            print(f"{self.name}: Layer 4: ACK received: seq={seg.seq_num}")
            if seg.seq_num == self.send_seq:
                self.send_seq = 1 - self.send_seq
                self._pending_data_dst_ip  = None
                self._pending_data_segment = None
            else:
                # wrong or duplicate ACK — retransmit the in-flight segment
                print(f"{self.name}: Layer 4: Segment retransmitted due to "
                      f"incorrect ACK")
                if self._pending_data_dst_ip is not None and self._pending_data_segment is not None:
                    self._layer3_send(self.ip, self._pending_data_dst_ip,
                                      self._pending_data_segment)

    def _layer3_send(self, src_ip, dst_ip, seg):
        """Wrap seg in an IP packet, look up the route, and pass to Layer 2."""
        seg_bytes = seg.to_bytes()
        pkt = Layer3Packet(src_ip, dst_ip, DEFAULT_TTL,
                           IP_PROTOCOL_UDP, seg_bytes)

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
            next_hop = dst_ip  # directly connected network

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_send(pkt, next_hop)

    def _layer3_receive(self, pkt):
        """Deliver the packet to Layer 4 if it's addressed to this host."""
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

    def _layer2_send(self, pkt, next_hop_ip):
        """ARP-resolve next_hop_ip, build a frame, and transmit over the uplink."""
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
        """Learn the source MAC if new, then pass the payload up to Layer 3."""
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


class Router:
    """Layer 2/3 router — no transport layer.
    Receives frames on any interface, decrements TTL, performs longest-prefix-
    match routing, and forwards packets out the appropriate outgoing interface.
    """
    def __init__(self, name):
        self.name          = name
        self.interfaces    = {}  # {iface_name: {ip, mac, uplink}}
        self.routing_table = []  # [(network, mask, next_hop, iface), ...]
        self.arp_table     = {}  # next_hop_ip -> MAC string
        self.mac_table     = {}  # {iface_name: {src_mac: iface_name}}

    def add_interface(self, name, ip, mac):
        """Register a named interface on the router."""
        self.interfaces[name] = {'ip': ip, 'mac': mac, 'uplink': None}
        self.mac_table[name]  = {}

    def set_uplink(self, iface_name, device, remote_interface):
        """Connect iface_name to a neighbouring device."""
        self.interfaces[iface_name]['uplink'] = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface):
        """Add a routing table entry."""
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        """Map ip to mac in the ARP table."""
        self.arp_table[ip] = mac

    def receive_frame(self, frame, interface):
        """Learn source MAC on interface, then route the IP packet via Layer 3."""
        print()
        print(f"{self.name}: Layer 2: Frame received on {interface}")

        src_mac = frame.src_mac
        if src_mac not in self.mac_table[interface]:
            self.mac_table[interface][src_mac] = interface
            print(f"{self.name}: Layer 2: Source MAC learned: "
                  f"{src_mac} on {interface}")

        iface_mac = self.interfaces[interface]['mac']
        if frame.dst_mac not in (iface_mac, 'FF:FF:FF:FF:FF:FF'):
            return

        if frame.ether_type == ETHERTYPE_IPV4:
            print(f"{self.name}: Layer 2: Packet delivered to Network Layer")
            pkt = Layer3Packet.from_bytes(frame.payload)
            self._layer3_receive(pkt, interface)

    def _layer2_forward(self, pkt, next_hop, out_iface):
        """ARP-resolve next_hop, build a frame with out_iface's MAC, and send."""
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

    def _layer3_receive(self, pkt, in_iface):
        """Receive a packet from L2, decrement TTL, and route it out via L2.
        Drops the packet silently if TTL hits zero after decrement.
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
            next_hop = pkt.dst_ip  # directly connected network

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected ({out_iface})")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_forward(pkt, next_hop, out_iface)
