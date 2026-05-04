"""
devices.py
==========
Network device implementations for the Mini Internet Protocol Stack Simulator.

Classes
-------
Host   – End-host with full Layer 2 / 3 / 4 (Transport → Network → Data Link).
Router – Intermediate node with Layer 2 / 3 (Data Link + Network) only.

Both classes communicate through direct Python method calls that simulate the
logical transmission of frames over links – no real sockets are used.

Routing
-------
Both devices use *longest-prefix-match* to select the best route.  A routing
table entry is a 4-tuple::

    (network: str, mask: str, next_hop: str | None, interface: str)

where ``next_hop=None`` means the destination is directly connected (the
packet's destination IP is used as the next-hop address).
"""

from protocol import (Layer2Frame, Layer3Packet, Layer4Segment)
from config import (
    ETHERTYPE_IPV4, IP_PROTOCOL_UDP, DEFAULT_TTL,
    MAX_SEGMENT_SIZE, TYPE_DATA, TYPE_ACK,
    SRC_PORT, DST_PORT,
)


# ═════════════════════════════════════════════════════════════════════════════
# Routing / address utilities (module-private)
# ═════════════════════════════════════════════════════════════════════════════

def _ip_to_int(ip):
    """
    Convert a dotted-decimal IP string to an unsigned 32-bit integer.

    Parameters
    ----------
    ip : str   e.g. ``"10.0.1.10"``

    Returns
    -------
    int
        32-bit representation.
    """
    parts = [int(x) for x in ip.split('.')]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def _ip_in_network(ip, network, mask):
    """
    Return ``True`` if *ip* is contained within *network*/*mask*.

    Parameters
    ----------
    ip      : str  IP address to test.
    network : str  Network address (e.g. ``"10.0.1.0"``).
    mask    : str  Subnet mask    (e.g. ``"255.255.255.0"``).

    Returns
    -------
    bool
    """
    ip_int  = _ip_to_int(ip)
    net_int = _ip_to_int(network)
    msk_int = _ip_to_int(mask)
    return (ip_int & msk_int) == (net_int & msk_int)


def _prefix_length(mask):
    """
    Return the number of set (``1``) bits in a dotted-decimal subnet mask.

    Parameters
    ----------
    mask : str  e.g. ``"255.255.255.0"``

    Returns
    -------
    int
        Prefix length (0–32).
    """
    return bin(_ip_to_int(mask)).count('1')


def _longest_prefix_match(routing_table, dst_ip):
    """
    Perform a longest-prefix-match lookup for *dst_ip* in *routing_table*.

    Each entry in *routing_table* is a tuple::

        (network: str, mask: str, next_hop: str | None, interface: str)

    Returns the ``(next_hop, interface)`` pair of the best-matching entry, or
    ``None`` if no entry matches.  When ``next_hop`` is ``None``, the caller
    should substitute the actual destination IP (directly connected network).

    Parameters
    ----------
    routing_table : list   List of routing table entries.
    dst_ip        : str    Destination IP address.

    Returns
    -------
    tuple or None
        ``(next_hop, interface)`` or ``None``.
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


# ═════════════════════════════════════════════════════════════════════════════
# Host
# ═════════════════════════════════════════════════════════════════════════════

class Host:
    """
    Simulates an end-host that implements Layers 2, 3, and 4.

    Layer 4 (Transport)
        UDP-like segments with checksum and rdt2.2 (alternating-bit) reliable
        data transfer.

    Layer 3 (Network)
        IP-like packet encapsulation and longest-prefix-match routing.

    Layer 2 (Data Link)
        Ethernet-like frame creation, ARP-table-based MAC resolution, and
        source-MAC learning from received frames.

    Attributes
    ----------
    name          : str    Human-readable name (e.g. ``"Host A"``).
    ip            : str    IP address.
    mac           : str    MAC address.
    routing_table : list   List of ``(network, mask, next_hop, iface)`` tuples.
    arp_table     : dict   Mapping of next-hop IP → MAC string.
    mac_table     : dict   Learned source-MAC → interface mapping.
    uplink        : tuple  ``(device, remote_interface)`` for the single link.
    send_seq      : int    rdt2.2 sender sequence number (0 or 1).
    expected_seq  : int    rdt2.2 receiver expected sequence number (0 or 1).
    last_ack_seq  : int    Sequence number of the most-recently sent ACK.
    received_data : list   Application-layer byte strings delivered to this host.
    """

    def __init__(self, name, ip, mac):
        """
        Initialise a Host.

        Parameters
        ----------
        name : str   Human-readable label (e.g. ``"Host A"``).
        ip   : str   Dotted-decimal IP address.
        mac  : str   Colon-separated MAC address.
        """
        self.name          = name
        self.ip            = ip
        self.mac           = mac

        # Routing: list of (network, mask, next_hop, interface) tuples
        self.routing_table = []
        # ARP / MAC-resolution: next_hop_ip -> MAC string
        self.arp_table     = {}
        # MAC learning: src_mac -> interface (hosts have one interface)
        self.mac_table     = {}
        # Physical connection to the next device
        self.uplink        = None   # (device, remote_interface_name)

        # rdt2.2 sender state
        self.send_seq      = 0
        # rdt2.2 receiver state
        self.expected_seq  = 0
        self.last_ack_seq  = None   # sequence number of last ACK sent

        # Application receive buffer
        self.received_data = []

    # ── Configuration helpers ─────────────────────────────────────────────────

    def set_uplink(self, device, remote_interface):
        """
        Connect this host's single interface to *device* at *remote_interface*.

        Parameters
        ----------
        device           : Host | Router   The connected neighbour.
        remote_interface : str             Interface name on *device*.
        """
        self.uplink = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface='eth0'):
        """
        Append a routing-table entry.

        Parameters
        ----------
        network   : str        Network address (e.g. ``"10.0.1.0"``).
        mask      : str        Subnet mask.
        next_hop  : str|None   Next-hop IP, or ``None`` for direct delivery.
        interface : str        Outgoing interface name (default ``'eth0'``).
        """
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        """
        Add a static ARP entry mapping *ip* → *mac*.

        Parameters
        ----------
        ip  : str   Next-hop IP address.
        mac : str   Corresponding MAC address.
        """
        self.arp_table[ip] = mac

    # ── Application Layer ─────────────────────────────────────────────────────

    def send_message(self, dst_ip, data):
        """
        Application-layer send: transmit *data* to *dst_ip*.

        Splits *data* into chunks of at most ``MAX_SEGMENT_SIZE`` bytes and
        transmits each chunk as a separate DATA segment using the rdt2.2
        protocol.  The ACK for each segment is received synchronously before
        the next chunk is processed.

        Parameters
        ----------
        dst_ip : str    Destination IP address.
        data   : bytes  Raw bytes to send.
        """
        chunks = [data[i:i + MAX_SEGMENT_SIZE]
                  for i in range(0, len(data), MAX_SEGMENT_SIZE)]
        for chunk in chunks:
            self._layer4_send_data(dst_ip, SRC_PORT, DST_PORT, chunk)

    # ── Layer 4 – Transport ───────────────────────────────────────────────────

    def _layer4_send_data(self, dst_ip, src_port, dst_port, data):
        """
        Layer 4 sender: encapsulate *data* into a DATA segment and send it.

        Creates a Layer4Segment with the current sender sequence number,
        computes its checksum, logs the required events, and passes the
        segment down to Layer 3.

        Because the simulation is synchronous, the entire round-trip (DATA
        delivery + ACK return) completes inside the ``_layer3_send`` call.
        ``_layer4_receive`` advances ``self.send_seq`` when the correct ACK
        arrives, so subsequent calls automatically use the toggled value.

        Parameters
        ----------
        dst_ip   : str   Destination IP address.
        src_port : int   Source port.
        dst_port : int   Destination port.
        data     : bytes Chunk of application data to send.
        """
        print(f"{self.name}: Layer 4: Data received from Application Layer. "
              f"Data size={len(data)}")

        # Build the DATA segment
        seg = Layer4Segment(src_port, dst_port, TYPE_DATA, self.send_seq, data)
        seg.compute_checksum()
        print(f"{self.name}: Layer 4: Checksum computed")
        print(f"{self.name}: Layer 4: Segment created by adding transport layer "
              f"header (DATA, seq={self.send_seq}) (encapsulation)")
        print(f"{self.name}: Layer 4: Segment sent to Network Layer")

        # Pass down to Layer 3; ACK will arrive synchronously via the call stack
        self._layer3_send(self.ip, dst_ip, seg)

    def _layer4_send_ack(self, dst_ip, src_port, dst_port, seq_num):
        """
        Layer 4 receiver: build and send an ACK segment for *seq_num*.

        Called immediately after a valid in-order DATA segment has been
        delivered to the application.

        Parameters
        ----------
        dst_ip   : str   IP of the original sender (ACK destination).
        src_port : int   Source port for the ACK (= original dst_port).
        dst_port : int   Destination port for the ACK (= original src_port).
        seq_num  : int   Sequence number being acknowledged.
        """
        seg = Layer4Segment(src_port, dst_port, TYPE_ACK, seq_num, b'')
        # Checksum is computed for correctness but not logged (per spec example)
        seg.compute_checksum()
        print(f"{self.name}: Layer 4: Segment created by adding transport layer "
              f"header (ACK, seq={seq_num})")
        print(f"{self.name}: Layer 4: Segment sent to Network Layer")

        self._layer3_send(self.ip, dst_ip, seg)

    def _layer4_receive(self, seg, src_ip, dst_ip):
        """
        Layer 4 receive handler: process a segment arriving from Layer 3.

        For DATA segments (rdt2.2 receiver behaviour):
          - Verify checksum; discard and re-send last ACK on failure.
          - Deliver in-order data to the application and send ACK.
          - Re-send last ACK for duplicate/out-of-order segments.

        For ACK segments (rdt2.2 sender behaviour):
          - Verify checksum.
          - If correct ACK: advance ``self.send_seq``.
          - If incorrect ACK: log retransmission event (no actual retransmit
            needed in the no-loss/no-corruption scenario).

        Parameters
        ----------
        seg    : Layer4Segment   Received segment.
        src_ip : str             IP address of the sender.
        dst_ip : str             IP address of the receiver (this host).
        """
        print(f"{self.name}: Layer 4: Segment received from Network Layer")

        # ── Checksum verification ─────────────────────────────────────────────
        if not seg.verify_checksum():
            print(f"{self.name}: Layer 4: Segment discarded due to checksum error")
            # rdt2.2: re-send the last ACK so the sender retransmits
            if seg.seg_type == TYPE_DATA and self.last_ack_seq is not None:
                self._layer4_send_ack(src_ip,
                                      seg.dst_port, seg.src_port,
                                      self.last_ack_seq)
            return

        print(f"{self.name}: Layer 4: Checksum verified")

        # ── DATA segment ──────────────────────────────────────────────────────
        if seg.seg_type == TYPE_DATA:
            if seg.seq_num == self.expected_seq:
                # In-order, correct segment
                print(f"{self.name}: Layer 4: DATA segment delivered to "
                      f"Application Layer. Data size={len(seg.data)}")
                self.received_data.append(seg.data)
                self.last_ack_seq = seg.seq_num
                # Send ACK with ports swapped
                self._layer4_send_ack(src_ip,
                                      seg.dst_port, seg.src_port,
                                      seg.seq_num)
                # Advance expected sequence number (0 ↔ 1)
                self.expected_seq = 1 - self.expected_seq
            else:
                # Duplicate or out-of-order: re-send the most recent ACK
                if self.last_ack_seq is not None:
                    self._layer4_send_ack(src_ip,
                                          seg.dst_port, seg.src_port,
                                          self.last_ack_seq)

        # ── ACK segment ───────────────────────────────────────────────────────
        elif seg.seg_type == TYPE_ACK:
            print(f"{self.name}: Layer 4: ACK received: seq={seg.seq_num}")
            if seg.seq_num == self.send_seq:
                # Correct ACK – advance sender sequence number (0 ↔ 1)
                self.send_seq = 1 - self.send_seq
            else:
                # Incorrect / duplicate ACK
                print(f"{self.name}: Layer 4: Segment retransmitted due to "
                      f"incorrect ACK")

    # ── Layer 3 – Network ─────────────────────────────────────────────────────

    def _layer3_send(self, src_ip, dst_ip, seg):
        """
        Layer 3 sender: encapsulate *seg* into an IP-like packet and forward
        it to Layer 2 after a routing-table lookup.

        Logs: segment received from transport, destination IP read, routing
        lookup, next-hop determination, interface selection, and forwarding.

        Parameters
        ----------
        src_ip : str            IP address of this host.
        dst_ip : str            Final destination IP address.
        seg    : Layer4Segment  Segment to encapsulate.
        """
        seg_bytes = seg.to_bytes()
        pkt = Layer3Packet(src_ip, dst_ip, DEFAULT_TTL,
                           IP_PROTOCOL_UDP, seg_bytes)

        print(f"{self.name}: Layer 3: Segment received from Transport Layer: "
              f"SRC_IP={src_ip}, DST_IP={dst_ip}, TTL={DEFAULT_TTL}")
        print(f"{self.name}: Layer 3: Destination IP read: {dst_ip}")
        print(f"{self.name}: Layer 3: Routing table lookup performed")

        route = _longest_prefix_match(self.routing_table, dst_ip)
        if route is None:
            print(f"{self.name}: Layer 3: No route to {dst_ip}. Packet dropped.")
            return

        next_hop, iface = route
        # Directly connected network: use the destination IP as the next hop
        if next_hop is None:
            next_hop = dst_ip

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_send(pkt, next_hop)

    def _layer3_receive(self, pkt):
        """
        Layer 3 receiver: process an IP-like packet delivered by Layer 2.

        Checks whether the packet's destination IP matches this host.  If so,
        delivers the payload to Layer 4.  Otherwise drops the packet.

        Parameters
        ----------
        pkt : Layer3Packet   The received packet.
        """
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

    # ── Layer 2 – Data Link ───────────────────────────────────────────────────

    def _layer2_send(self, pkt, next_hop_ip):
        """
        Layer 2 sender: wrap *pkt* in a frame and transmit it over the uplink.

        Resolves the destination MAC address from the ARP table, creates the
        frame, logs the required events, and hands the frame to the connected
        device via ``receive_frame``.

        Parameters
        ----------
        pkt         : Layer3Packet   Packet to encapsulate.
        next_hop_ip : str            Next-hop IP for ARP table lookup.
        """
        print(f"{self.name}: Layer 2: Packet received from Network Layer")

        dst_mac = self.arp_table.get(next_hop_ip)
        if dst_mac is None:
            print(f"{self.name}: Layer 2: No ARP entry for {next_hop_ip}. "
                  "Frame dropped.")
            return

        print(f"{self.name}: Layer 2: Destination MAC lookup for next-hop IP "
              f"({next_hop_ip}) \u2192 {dst_mac}")

        frame = Layer2Frame(dst_mac, self.mac, ETHERTYPE_IPV4, pkt.to_bytes())
        print(f"{self.name}: Layer 2: Frame created: "
              f"SRC_MAC={self.mac}, DST_MAC={dst_mac}")
        print(f"{self.name}: Layer 2: Frame sent")

        if self.uplink:
            device, remote_iface = self.uplink
            device.receive_frame(frame, remote_iface)

    def receive_frame(self, frame, interface='eth0'):
        """
        Layer 2 receiver: process a frame arriving at this host.

        Learns the source MAC (only logged on first encounter), then – if the
        frame is addressed to this host – strips the Layer 2 header and passes
        the payload to Layer 3.

        Parameters
        ----------
        frame     : Layer2Frame   The received Ethernet-like frame.
        interface : str           Name of the receiving interface (informational).
        """
        print(f"{self.name}: Layer 2: Frame received")

        # Source MAC learning (log only on first encounter)
        src_mac = frame.src_mac
        if src_mac not in self.mac_table:
            self.mac_table[src_mac] = interface
            print(f"{self.name}: Layer 2: Source MAC learned: {src_mac}")

        # Accept frames addressed to this host or to broadcast
        if frame.dst_mac in (self.mac, 'FF:FF:FF:FF:FF:FF'):
            if frame.ether_type == ETHERTYPE_IPV4:
                print(f"{self.name}: Layer 2: Packet delivered to Network Layer")
                pkt = Layer3Packet.from_bytes(frame.payload)
                self._layer3_receive(pkt)


# ═════════════════════════════════════════════════════════════════════════════
# Router
# ═════════════════════════════════════════════════════════════════════════════

class Router:
    """
    Simulates a Layer 2 / 3 router (no transport layer).

    Layer 3 (Network)
        IP-like packet reception, TTL decrement, routing-table lookup, and
        packet forwarding to the appropriate outgoing interface.

    Layer 2 (Data Link)
        Frame reception per interface, per-interface source-MAC learning, MAC
        resolution via ARP table, and frame transmission on the chosen
        interface.

    Attributes
    ----------
    name          : str    Human-readable name (e.g. ``"Router R1"``).
    interfaces    : dict   ``{iface_name: {ip, mac, uplink}}``
    routing_table : list   List of ``(network, mask, next_hop, iface)`` tuples.
    arp_table     : dict   Global mapping of next-hop IP → MAC string.
    mac_table     : dict   Per-interface learned MAC tables
                           ``{iface_name: {src_mac: iface_name}}``.
    """

    def __init__(self, name):
        """
        Initialise a Router.

        Parameters
        ----------
        name : str   Human-readable label (e.g. ``"Router R1"``).
        """
        self.name          = name
        self.interfaces    = {}    # {iface_name: {ip, mac, uplink}}
        self.routing_table = []    # [(network, mask, next_hop, iface), ...]
        self.arp_table     = {}    # {next_hop_ip: mac_str}
        self.mac_table     = {}    # {iface_name: {src_mac: iface_name}}

    # ── Configuration helpers ─────────────────────────────────────────────────

    def add_interface(self, name, ip, mac):
        """
        Register a network interface.

        Parameters
        ----------
        name : str   Interface name (e.g. ``"Interface 1"``).
        ip   : str   IP address assigned to this interface.
        mac  : str   MAC address assigned to this interface.
        """
        self.interfaces[name] = {'ip': ip, 'mac': mac, 'uplink': None}
        self.mac_table[name]  = {}

    def set_uplink(self, iface_name, device, remote_interface):
        """
        Attach *iface_name* to a neighbouring *device*.

        Parameters
        ----------
        iface_name       : str             Local interface name.
        device           : Host | Router   Connected neighbour.
        remote_interface : str             Interface name on *device*.
        """
        self.interfaces[iface_name]['uplink'] = (device, remote_interface)

    def add_route(self, network, mask, next_hop, interface):
        """
        Append a routing-table entry.

        Parameters
        ----------
        network   : str        Network address.
        mask      : str        Subnet mask.
        next_hop  : str|None   Next-hop IP, or ``None`` for directly connected.
        interface : str        Outgoing interface name.
        """
        self.routing_table.append((network, mask, next_hop, interface))

    def add_arp_entry(self, ip, mac):
        """
        Add a static ARP entry mapping *ip* → *mac*.

        Parameters
        ----------
        ip  : str   Next-hop IP address.
        mac : str   Corresponding MAC address.
        """
        self.arp_table[ip] = mac

    # ── Layer 2 – Data Link ───────────────────────────────────────────────────

    def receive_frame(self, frame, interface):
        """
        Layer 2 receiver: process a frame arriving on *interface*.

        Learns the source MAC for that interface (only logged on first
        encounter), then delivers the payload to Layer 3 for routing.

        Parameters
        ----------
        frame     : Layer2Frame   The received frame.
        interface : str           Name of the receiving interface.
        """
        print(f"{self.name}: Layer 2: Frame received on {interface}")

        # Per-interface source MAC learning
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
        Layer 2 forwarder: encapsulate *pkt* in a frame and send it on
        *out_iface* toward *next_hop*.

        Parameters
        ----------
        pkt       : Layer3Packet   Packet to forward (TTL already decremented).
        next_hop  : str            Next-hop IP for ARP lookup.
        out_iface : str            Outgoing interface name.
        """
        print(f"{self.name}: Layer 2: Packet received from Network Layer")

        dst_mac = self.arp_table.get(next_hop)
        if dst_mac is None:
            print(f"{self.name}: Layer 2: No ARP entry for {next_hop}. "
                  "Frame dropped.")
            return

        print(f"{self.name}: Layer 2: Destination MAC lookup for next-hop IP "
              f"({next_hop}) \u2192 {dst_mac}")

        src_mac = self.interfaces[out_iface]['mac']
        frame   = Layer2Frame(dst_mac, src_mac, ETHERTYPE_IPV4, pkt.to_bytes())
        print(f"{self.name}: Layer 2: Frame created: "
              f"SRC_MAC={src_mac}, DST_MAC={dst_mac}")
        print(f"{self.name}: Layer 2: Frame forwarded on {out_iface}")

        uplink = self.interfaces[out_iface].get('uplink')
        if uplink:
            device, remote_iface = uplink
            device.receive_frame(frame, remote_iface)

    # ── Layer 3 – Network ─────────────────────────────────────────────────────

    def _layer3_receive(self, pkt, in_iface):
        """
        Layer 3 receiver: process an IP-like packet from Layer 2.

        Steps
        -----
        1. Read destination IP.
        2. Decrement TTL; drop the packet if TTL reaches 0.
        3. Perform a longest-prefix-match routing-table lookup.
        4. Forward the packet to Layer 2 on the selected outgoing interface.

        Parameters
        ----------
        pkt      : Layer3Packet   Received packet.
        in_iface : str            Interface on which the frame was received.
        """
        print(f"{self.name}: Layer 3: Packet received from Data Link Layer: "
              f"SRC_IP={pkt.src_ip}, DST_IP={pkt.dst_ip}, TTL={pkt.ttl}")
        print(f"{self.name}: Layer 3: Destination IP read: {pkt.dst_ip}")

        # ── TTL handling ──────────────────────────────────────────────────────
        old_ttl  = pkt.ttl
        pkt.ttl -= 1
        print(f"{self.name}: Layer 3: TTL decremented: {old_ttl} \u2192 {pkt.ttl}")

        if pkt.ttl <= 0:
            print(f"{self.name}: Layer 3: TTL expired. Packet dropped.")
            return

        # ── Routing lookup ────────────────────────────────────────────────────
        print(f"{self.name}: Layer 3: Routing table lookup performed")
        route = _longest_prefix_match(self.routing_table, pkt.dst_ip)

        if route is None:
            print(f"{self.name}: Layer 3: No route to {pkt.dst_ip}. "
                  "Packet dropped.")
            return

        next_hop, out_iface = route
        # Directly connected: use the destination IP as the next hop
        if next_hop is None:
            next_hop = pkt.dst_ip

        print(f"{self.name}: Layer 3: Next-hop IP determined: {next_hop}")
        print(f"{self.name}: Layer 3: Outgoing interface selected ({out_iface})")
        print(f"{self.name}: Layer 3: Packet forwarded to Data Link Layer")

        self._layer2_forward(pkt, next_hop, out_iface)
