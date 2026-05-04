"""
protocol.py
===========
Protocol header definitions for Layers 2, 3, and 4.

Classes
-------
Layer4Segment  – UDP-like transport segment with rdt2.2 ACK support.
Layer3Packet   – IP-like network packet.
Layer2Frame    – Ethernet-like data-link frame.

Helper functions
----------------
compute_checksum  – 16-bit one's-complement Internet checksum.
ip_to_bytes / bytes_to_ip   – Dotted-decimal ↔ 4-byte conversions.
mac_to_bytes / bytes_to_mac – Colon-hex ↔ 6-byte conversions.
"""

import struct


# ═════════════════════════════════════════════════════════════════════════════
# Checksum and address helpers
# ═════════════════════════════════════════════════════════════════════════════

def compute_checksum(data):
    """
    Compute a 16-bit Internet checksum (RFC 1071 one's-complement sum).

    An odd-length *data* buffer is padded with a trailing zero byte before
    summing.  Returns the one's complement of the 16-bit accumulated sum.

    Parameters
    ----------
    data : bytes
        The byte sequence to checksum.

    Returns
    -------
    int
        16-bit checksum value (0–65535).
    """
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
    # Fold any carry bits back into the lower 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_to_bytes(ip):
    """
    Convert a dotted-decimal IP address string to a 4-byte :class:`bytes`.

    Parameters
    ----------
    ip : str
        e.g. ``"10.0.1.10"``

    Returns
    -------
    bytes
        4-byte big-endian representation.
    """
    return bytes(int(octet) for octet in ip.split('.'))


def bytes_to_ip(raw):
    """
    Convert 4 bytes to a dotted-decimal IP address string.

    Parameters
    ----------
    raw : bytes
        Exactly 4 bytes.

    Returns
    -------
    str
        e.g. ``"10.0.1.10"``
    """
    return '.'.join(str(b) for b in raw)


def mac_to_bytes(mac):
    """
    Convert a colon-separated MAC address string to a 6-byte :class:`bytes`.

    Parameters
    ----------
    mac : str
        e.g. ``"AA:AA:AA:AA:AA:AA"``

    Returns
    -------
    bytes
        6-byte representation.
    """
    return bytes(int(h, 16) for h in mac.split(':'))


def bytes_to_mac(raw):
    """
    Convert 6 bytes to an upper-case colon-separated MAC address string.

    Parameters
    ----------
    raw : bytes
        Exactly 6 bytes.

    Returns
    -------
    str
        e.g. ``"AA:AA:AA:AA:AA:AA"``
    """
    return ':'.join(f'{b:02X}' for b in raw)


# ═════════════════════════════════════════════════════════════════════════════
# Layer 4 – Transport (UDP-like segment with rdt2.2 ACK)
# ═════════════════════════════════════════════════════════════════════════════

class Layer4Segment:
    """
    UDP-like transport-layer segment supporting rdt2.2 (alternating-bit).

    Header layout (10 bytes total, big-endian)
    ------------------------------------------
    Offset  Size  Field
    0       2 B   src_port   – Source port number
    2       2 B   dst_port   – Destination port number
    4       2 B   length     – Total segment length (header + data)
    6       2 B   checksum   – 16-bit checksum for error detection
    8       1 B   seg_type   – 0 = DATA, 1 = ACK
    9       1 B   seq_num    – Alternating-bit sequence number (0 or 1)

    The header is followed by variable-length application data (empty for ACK).
    """

    # Struct format: all unsigned  H=2B  B=1B  (big-endian)
    HEADER_FORMAT = '!HHHHBB'
    HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 10 bytes

    def __init__(self, src_port, dst_port, seg_type, seq_num, data=b''):
        """
        Initialise a Layer4Segment.

        Parameters
        ----------
        src_port : int   Source port number.
        dst_port : int   Destination port number.
        seg_type : int   Segment type – TYPE_DATA (0) or TYPE_ACK (1).
        seq_num  : int   Alternating-bit sequence number, 0 or 1.
        data     : bytes Application payload (pass ``b''`` or omit for ACK).
        """
        self.src_port = src_port
        self.dst_port = dst_port
        self.seg_type = seg_type
        self.seq_num  = seq_num
        self.data     = data if data else b''
        self.length   = self.HEADER_SIZE + len(self.data)
        self.checksum = 0   # set by compute_checksum()

    # ── Internal helper ───────────────────────────────────────────────────────

    def _checksum_payload(self):
        """
        Build the byte string used as input to the checksum calculation.

        Includes every header field *except* the checksum field itself,
        followed by the data payload.  This matches the standard Internet
        pseudo-header approach.
        """
        pseudo = struct.pack('!HHHBB',
                             self.src_port,
                             self.dst_port,
                             self.length,
                             self.seg_type,
                             self.seq_num)
        return pseudo + self.data

    # ── Checksum API ──────────────────────────────────────────────────────────

    def compute_checksum(self):
        """
        Compute and store the segment checksum.

        Calculates the 16-bit checksum over all fields (excluding the
        checksum field) plus the data payload, then stores the result in
        ``self.checksum``.

        Returns
        -------
        int
            The computed checksum value.
        """
        self.checksum = compute_checksum(self._checksum_payload())
        return self.checksum

    def verify_checksum(self):
        """
        Verify the segment's stored checksum against a freshly computed value.

        Returns
        -------
        bool
            ``True`` if the checksum is valid; ``False`` if the segment is
            corrupted.
        """
        return compute_checksum(self._checksum_payload()) == self.checksum

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self):
        """
        Serialise the segment (header + data) to a :class:`bytes` object.

        Returns
        -------
        bytes
            Byte representation suitable for embedding in a Layer3Packet.
        """
        header = struct.pack(self.HEADER_FORMAT,
                             self.src_port,
                             self.dst_port,
                             self.length,
                             self.checksum,
                             self.seg_type,
                             self.seq_num)
        return header + self.data

    @classmethod
    def from_bytes(cls, raw):
        """
        Deserialise a Layer4Segment from a :class:`bytes` object.

        Parameters
        ----------
        raw : bytes
            Raw bytes starting at the segment header.

        Returns
        -------
        Layer4Segment
            The reconstructed segment instance.
        """
        (src_port, dst_port, length,
         checksum, seg_type, seq_num) = struct.unpack(
             cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE])
        data         = raw[cls.HEADER_SIZE:]
        seg          = cls(src_port, dst_port, seg_type, seq_num, data)
        seg.length   = length
        seg.checksum = checksum
        return seg


# ═════════════════════════════════════════════════════════════════════════════
# Layer 3 – Network (IP-like packet)
# ═════════════════════════════════════════════════════════════════════════════

class Layer3Packet:
    """
    IP-like network-layer packet.

    Header layout (12 bytes total, big-endian)
    ------------------------------------------
    Offset  Size  Field
    0       4 B   src_ip       – Source IP address
    4       4 B   dst_ip       – Destination IP address
    8       1 B   ttl          – Time-to-Live (decremented at each router)
    9       1 B   protocol     – Upper-layer protocol (17 = UDP-like)
    10      2 B   total_length – Total size in bytes (header + payload)

    The header is followed by a variable-length payload (serialised
    Layer4Segment bytes).
    """

    HEADER_SIZE = 12   # 4 + 4 + 1 + 1 + 2

    def __init__(self, src_ip, dst_ip, ttl, protocol, payload=b''):
        """
        Initialise a Layer3Packet.

        Parameters
        ----------
        src_ip   : str   Dotted-decimal source IP address.
        dst_ip   : str   Dotted-decimal destination IP address.
        ttl      : int   Initial Time-to-Live value.
        protocol : int   Protocol identifier (17 for UDP-like).
        payload  : bytes Serialised Layer4Segment bytes.
        """
        self.src_ip       = src_ip
        self.dst_ip       = dst_ip
        self.ttl          = ttl
        self.protocol     = protocol
        self.payload      = payload if payload else b''
        self.total_length = self.HEADER_SIZE + len(self.payload)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self):
        """
        Serialise the packet (header + payload) to bytes.

        Returns
        -------
        bytes
            Byte representation suitable for embedding in a Layer2Frame.
        """
        fixed = struct.pack('!BBH', self.ttl, self.protocol, self.total_length)
        return ip_to_bytes(self.src_ip) + ip_to_bytes(self.dst_ip) + fixed + self.payload

    @classmethod
    def from_bytes(cls, raw):
        """
        Deserialise a Layer3Packet from bytes.

        Parameters
        ----------
        raw : bytes
            Raw bytes starting at the packet header.

        Returns
        -------
        Layer3Packet
            The reconstructed packet instance.
        """
        src_ip = bytes_to_ip(raw[0:4])
        dst_ip = bytes_to_ip(raw[4:8])
        ttl, protocol, total_length = struct.unpack('!BBH', raw[8:12])
        payload          = raw[12:]
        pkt              = cls(src_ip, dst_ip, ttl, protocol, payload)
        pkt.total_length = total_length
        return pkt


# ═════════════════════════════════════════════════════════════════════════════
# Layer 2 – Data Link (Ethernet-like frame)
# ═════════════════════════════════════════════════════════════════════════════

class Layer2Frame:
    """
    Ethernet-like data-link layer frame.

    Header layout (14 bytes total, big-endian)
    ------------------------------------------
    Offset  Size  Field
    0       6 B   dst_mac    – Destination MAC address
    6       6 B   src_mac    – Source MAC address
    12      2 B   ether_type – EtherType (0x0800 = IPv4)

    The header is followed by a variable-length payload (serialised
    Layer3Packet bytes).
    """

    HEADER_SIZE = 14   # 6 + 6 + 2

    def __init__(self, dst_mac, src_mac, ether_type, payload=b''):
        """
        Initialise a Layer2Frame.

        Parameters
        ----------
        dst_mac    : str   Colon-separated destination MAC address.
        src_mac    : str   Colon-separated source MAC address.
        ether_type : int   EtherType value (``0x0800`` for IPv4).
        payload    : bytes Serialised Layer3Packet bytes.
        """
        self.dst_mac    = dst_mac
        self.src_mac    = src_mac
        self.ether_type = ether_type
        self.payload    = payload if payload else b''

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_bytes(self):
        """
        Serialise the frame (header + payload) to bytes.

        Returns
        -------
        bytes
            Byte representation ready for transmission.
        """
        return (mac_to_bytes(self.dst_mac)
                + mac_to_bytes(self.src_mac)
                + struct.pack('!H', self.ether_type)
                + self.payload)

    @classmethod
    def from_bytes(cls, raw):
        """
        Deserialise a Layer2Frame from bytes.

        Parameters
        ----------
        raw : bytes
            Raw bytes starting at the frame header.

        Returns
        -------
        Layer2Frame
            The reconstructed frame instance.
        """
        dst_mac    = bytes_to_mac(raw[0:6])
        src_mac    = bytes_to_mac(raw[6:12])
        ether_type = struct.unpack('!H', raw[12:14])[0]
        payload    = raw[14:]
        return cls(dst_mac, src_mac, ether_type, payload)
