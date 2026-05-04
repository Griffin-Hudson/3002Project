# Mini Internet Protocol Stack Simulator

A pure-Python, logical simulation of a three-layer (Data Link / Network / Transport) network stack.  No sockets or external libraries are used.

---

## Running the Simulator

```bash
python main.py <message_size>
```

`<message_size>` is the number of application-data bytes to send from **Host A** to **Host B**.

**Examples**

```bash
python main.py 10      # 10-byte message → 1 segment
python main.py 500     # 500-byte message → 1 segment (maximum single-segment size)
python main.py 1000    # 1000-byte message → 2 segments (500 + 500)
python main.py 1250    # 1250-byte message → 3 segments (500 + 500 + 250)
```

**Requirements:** Python 3.9 or later (no third-party packages needed).

---

## Network Topology

```
Host A (10.0.1.10)                         Host B (10.0.2.20)
  AA:AA:AA:AA:AA:AA  ──── Link L1 ────  Router R1  ──── Link L2 ────  DD:DD:DD:DD:DD:DD
                         IF1: 10.0.1.1               IF2: 10.0.2.1
                         BB:BB:BB:BB:BB:BB            CC:CC:CC:CC:CC:CC
```

- **Subnet 1:** `10.0.1.0/24` — Host A ↔ R1 Interface 1  
- **Subnet 2:** `10.0.2.0/24` — R1 Interface 2 ↔ Host B  

---

## File Structure

| File | Purpose |
|------|---------|
| `main.py` | Entry point.  Parses the command-line argument, calls `build_network()` to wire up devices, generates a payload, and invokes `host_a.send_message()`. |
| `protocol.py` | Header class definitions and helper functions for all three layers. |
| `devices.py` | `Host` and `Router` device classes implementing Layers 2, 3, and 4 logic. |
| `config.py` | All fixed constants: IP addresses, MAC addresses, subnet parameters, protocol values, port numbers, and segment-size limits. |
| `README.md` | This file. |

---

## Design Overview

### `config.py`
A single place for every network constant.  Changing the topology (e.g. different IP ranges) requires editing only this file.

### `protocol.py`

| Class | Layer | Key fields |
|-------|-------|------------|
| `Layer4Segment` | Transport (L4) | `src_port`, `dst_port`, `length`, `checksum`, `seg_type`, `seq_num`, `data` |
| `Layer3Packet`  | Network  (L3) | `src_ip`, `dst_ip`, `ttl`, `protocol`, `total_length`, `payload` |
| `Layer2Frame`   | Data Link (L2) | `dst_mac`, `src_mac`, `ether_type`, `payload` |

All classes provide `to_bytes()` / `from_bytes()` for serialisation.  `Layer4Segment` also exposes `compute_checksum()` and `verify_checksum()` (16-bit one's-complement, RFC 1071).

### `devices.py`

**`Host`** implements:
- **Application layer** — `send_message()` splits large data into ≤ 500-byte chunks and drives the rdt2.2 loop.
- **Layer 4** — `_layer4_send_data()` / `_layer4_send_ack()` / `_layer4_receive()` implement the full rdt2.2 alternating-bit protocol (sequence numbers 0 and 1).
- **Layer 3** — `_layer3_send()` / `_layer3_receive()` handle IP-like encapsulation and longest-prefix-match routing.
- **Layer 2** — `_layer2_send()` / `receive_frame()` handle frame creation, ARP-table MAC resolution, and source-MAC learning.

**`Router`** implements:
- **Layer 3** — `_layer3_receive()` decrements TTL (dropping the packet if it reaches 0), performs longest-prefix-match routing, and forwards to Layer 2.
- **Layer 2** — `receive_frame()` / `_layer2_forward()` handle per-interface MAC learning, ARP-table MAC resolution, frame creation, and forwarding.

### Simulation mechanism

The simulation is fully **synchronous**.  "Sending" a frame means calling `receive_frame()` on the connected device directly.  As a result, when `host_a._layer3_send()` returns, the entire round trip — DATA delivery to Host B, ACK creation, ACK routing back through R1, and ACK processing by Host A — has already completed.  This makes rdt2.2 straightforward: `_layer4_receive()` advances `send_seq` when the correct ACK arrives, and the next segment naturally uses the toggled value.

### Routing

Both `Host` and `Router` use **longest-prefix-match**.  The helper `_longest_prefix_match()` in `devices.py` iterates the routing table and selects the entry whose prefix length (number of set bits in the mask) is greatest.  A `next_hop` of `None` signals a directly connected network; the destination IP itself is used as the next-hop address, matching the Router R1 behaviour described in the specification.

---

## rdt2.2 Protocol Summary

| Event | Sender (Host A) | Receiver (Host B) |
|-------|-----------------|-------------------|
| Send DATA | `seq = send_seq` | — |
| Correct in-order DATA received | — | Deliver to app; send `ACK(seq)` |
| Duplicate / corrupted DATA | — | Re-send last ACK |
| Correct ACK received | `send_seq = 1 − send_seq`; proceed | — |
| Incorrect / duplicate ACK | Log retransmit event | — |

Sequence numbers alternate: **0 → 1 → 0 → 1 → …**
