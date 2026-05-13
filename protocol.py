"""
Header classes for Layers 2, 3, and 4, plus a few address/checksum helpers.
"""
import struct


def compute_checksum(data):
    """16-bit one's-complement Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'             # pad to even length for 16-bit word alignment
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | data[i + 1]
        total += word
        while total >> 16:          # fold carry back into low 16 bits after each addition
            total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ip_to_bytes(ip):
    """Convert dotted-decimal string to 4-byte big-endian bytes, e.g. '10.0.1.10'."""
    return bytes(int(octet) for octet in ip.split('.'))


def bytes_to_ip(raw):
    """Convert 4 bytes back to a dotted-decimal string."""
    return '.'.join(str(b) for b in raw)


def mac_to_bytes(mac):
    """Convert colon-hex MAC string to 6 bytes, e.g. 'AA:AA:AA:AA:AA:AA'."""
    return bytes(int(h, 16) for h in mac.split(':'))


def bytes_to_mac(raw):
    """Convert 6 bytes to an upper-case colon-hex MAC string."""
    return ':'.join(f'{b:02X}' for b in raw)


class Layer4Segment:
    """
    UDP-like transport segment.
    Header layout (10 bytes, big-endian):
        0-1  src_port   source port number
        2-3  dst_port   destination port number
        4-5  length     total segment length (header + data)
        6-7  checksum   16-bit error-detection checksum
        8    seg_type   0 = DATA, 1 = ACK
        9    seq_num    alternating-bit sequence number (0 or 1)
    Followed by variable-length data (empty for ACK segments).
    """

    HEADER_FORMAT = '!HHHHBB'
    HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 10 bytes

    def __init__(self, src_port, dst_port, seg_type, seq_num, data=b''):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seg_type = seg_type
        self.seq_num  = seq_num
        self.data     = data if data else b''
        self.length   = self.HEADER_SIZE + len(self.data)
        self.checksum = 0

    def _checksum_payload(self):
        """Build the byte string fed to compute_checksum (all fields except checksum)."""
        pseudo = struct.pack('!HHHBB',
                             self.src_port,
                             self.dst_port,
                             self.length,
                             self.seg_type,
                             self.seq_num)
        return pseudo + self.data

    def compute_checksum(self):
        """Compute and store the segment checksum; returns the value."""
        self.checksum = compute_checksum(self._checksum_payload())
        return self.checksum

    def verify_checksum(self):
        """Return True if the stored checksum matches a fresh computation."""
        return compute_checksum(self._checksum_payload()) == self.checksum

    def to_bytes(self):
        """Serialise the segment to bytes."""
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
        """Deserialise a Layer4Segment from raw bytes."""
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError("Layer 4 segment is shorter than the header")
        (src_port, dst_port, length,
         checksum, seg_type, seq_num) = struct.unpack(
             cls.HEADER_FORMAT, raw[:cls.HEADER_SIZE])
        if length != len(raw):
            raise ValueError("Layer 4 segment length field does not match payload size")
        data         = raw[cls.HEADER_SIZE:]
        seg          = cls(src_port, dst_port, seg_type, seq_num, data)
        seg.length   = length
        seg.checksum = checksum
        return seg


class Layer3Packet:
    """
    IP-like network packet.
    Header layout (12 bytes, big-endian):
        0-3   src_ip        source IP address
        4-7   dst_ip        destination IP address
        8     ttl           time-to-live (decremented at each router)
        9     protocol      upper-layer protocol (17 = UDP-like)
        10-11 total_length  header + payload size in bytes
    Followed by a variable-length payload (serialised Layer4Segment).
    """

    HEADER_SIZE = 12   # 4 + 4 + 1 + 1 + 2

    def __init__(self, src_ip, dst_ip, ttl, protocol, payload=b''):
        self.src_ip       = src_ip
        self.dst_ip       = dst_ip
        self.ttl          = ttl
        self.protocol     = protocol
        self.payload      = payload if payload else b''
        self.total_length = self.HEADER_SIZE + len(self.payload)

    def to_bytes(self):
        """Serialise the packet to bytes."""
        fixed = struct.pack('!BBH', self.ttl, self.protocol, self.total_length)
        return ip_to_bytes(self.src_ip) + ip_to_bytes(self.dst_ip) + fixed + self.payload

    @classmethod
    def from_bytes(cls, raw):
        """Deserialise a Layer3Packet from raw bytes."""
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError("Layer 3 packet is shorter than the header")
        src_ip = bytes_to_ip(raw[0:4])
        dst_ip = bytes_to_ip(raw[4:8])
        ttl, protocol, total_length = struct.unpack('!BBH', raw[8:12])
        if total_length != len(raw):
            raise ValueError("Layer 3 packet length field does not match payload size")
        payload          = raw[12:]
        pkt              = cls(src_ip, dst_ip, ttl, protocol, payload)
        pkt.total_length = total_length
        return pkt


class Layer2Frame:
    """
    Ethernet-like data-link frame.
    Header layout (14 bytes, big-endian):
        0-5   dst_mac     destination MAC address
        6-11  src_mac     source MAC address
        12-13 ether_type  EtherType (0x0800 = IPv4)
    Followed by a variable-length payload (serialised Layer3Packet).
    """

    HEADER_SIZE = 14   # 6 + 6 + 2

    def __init__(self, dst_mac, src_mac, ether_type, payload=b''):
        self.dst_mac    = dst_mac
        self.src_mac    = src_mac
        self.ether_type = ether_type
        self.payload    = payload if payload else b''

    def to_bytes(self):
        """Serialise the frame to bytes."""
        return (mac_to_bytes(self.dst_mac)
                + mac_to_bytes(self.src_mac)
                + struct.pack('!H', self.ether_type)
                + self.payload)

    @classmethod
    def from_bytes(cls, raw):
        """Deserialise a Layer2Frame from raw bytes."""
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError("Layer 2 frame is shorter than the header")
        dst_mac    = bytes_to_mac(raw[0:6])
        src_mac    = bytes_to_mac(raw[6:12])
        ether_type = struct.unpack('!H', raw[12:14])[0]
        payload    = raw[14:]
        return cls(dst_mac, src_mac, ether_type, payload)
