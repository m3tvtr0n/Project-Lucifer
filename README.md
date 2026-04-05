# Project Lucifer: Advanced 802.11 Association & Captive Portal Framework

Project Lucifer is a research-grade 802.11 adversary simulation and Rogue BSS framework designed to analyze forced client steering and seamless auto-association to captive portals against modern OS supplicants (iOS 26.3+, macOS 26.3+, Windows 11).

> [!IMPORTANT]
> **Authorization required.** This tool actively transmits RF packets and executes Layer 2 Wi-Fi manipulation (Deauth, Auth Flooding, CSA, NAV). Only operate this framework against equipment you own or have explicit written authorization to test.

## Table of Contents

- [Overview](#overview)
- [The Unique Combination (Core Innovations)](#the-unique-combination-core-innovations)
- [Why It's Different](#why-its-different)
- [Modular Injection Architecture (The Python Modules)](#modular-injection-architecture-the-python-modules)
- [Prerequisites & Hardware Needs](#prerequisites--hardware-needs)
- [Interface Architecture](#interface-architecture)
- [Captive Portal Templates](captive-portal-templates)
- [Requirements & Installation](#requirements--installation)
- [Quick Start](#quick-start)

---

## 📖 Overview

Project Lucifer is a research-grade 802.11 adversary simulation and Rogue BSS framework designed to analyze forced client steering and seamless auto-association to captive portals against modern OS supplicants (iOS 26.3+, macOS 26.3+, Windows 11). It is specifically engineered to manipulate WPA2 and WPA3-SAE environments, bridging Layer 2 denial (targeting ESS mesh topologies and co-located virtual BSSIDs) with Layer 7 Captive Network Assistant (CNA) hijacking.

While legacy tools struggle against modern probe suppression and Protected Management Frames (PMF), Lucifer utilizes a synchronized, three-adapter architecture to execute a "pincer" attack. It combines adaptive dissociation (Deauth/CSA), PHY-level channel silencing, scan poisoning, and aggressive hostapd-mana karma beaconing to force target devices to seamlessly transition to a rogue captive portal without user interaction.
Disclaimer: This tool is strictly for authorized, local lab-based research, advanced penetration testing, and defense mechanism engineering.

## ⚡ The Unique Combination (Core Innovations)

Lucifer departs from traditional single-adapter scripts by separating the attack into simultaneous operational planes: Target Locking, Mesh Suppression, and Rogue AP Hosting, utilizing a 5-layer denial stack.

1. Adaptive Pincer Dissociation
 Instead of blindly broadcasting deauths on a single channel, Lucifer tracks the target client using BPF/tcpdump. If the client channel-hops, the "Target Monitor" follows them, while the "Suppress Monitor" continuously sweeps and suppresses all other mesh nodes and hardware siblings (Guest/IoT networks on the same physical AP).

2. PMF & Modern Defenses Bypass
 Lucifer actively checks the target BSSID for 802.11w (PMF) requirements. If PMF is enforced (dropping standard deauths), the script dynamically shifts to Channel Switch Announcements (CSA) and Auth Flooding to deny the real AP and steer the client to the rogue channel.

3. Hardware Sibling Identification
 Using BSSID byte-masking, the tool maps out hidden, guest, and 5GHz/2.4GHz sibling networks originating from the same physical router, suppressing the entire hardware stack rather than a single SSID.

4. PHY-Level Silencing & Scan Poisoning
 When clients are disconnected, they actively scan to reconnect. Lucifer silences the legitimate AP using NAV (Network Allocation Vector) manipulation, then injects perfectly cloned, spoofed Probe Responses. This poisons the client's internal scan candidate list, tricking it into believing the real AP has moved to the rogue channel.

5. "Loud" MANA Karma (Probe Asymmetry)
 Modern iOS devices suppress directed probes, making legacy karma attacks obsolete. Lucifer uses hostapd-mana in "loud" mode to capture probes from noisy devices (macOS/Windows) and broadcast them as beacons. This turns active probers into "seeders," tricking silent, passive-scanning iOS devices into auto-connecting to saved networks they never actually probed for.

## 🆚 Why It's Different

vs. Hak5 WiFi Pineapple

	•	Active vs. Passive: The Pineapple excels at passive PineAP beacon flooding but relies heavily on the environment to bring clients to it. Lucifer brings the Pineapple's "loud" karma capabilities to any Linux machine, but couples it with an extremely aggressive, multi-channel dissociation engine to force the client off their current infrastructure.

	•	Hardware Independence: Runs on standard, widely available hardware (e.g., 3x Alfa ACMs) without requiring proprietary Hak5 firmware.

vs. Airgeddon / Wifiphisher / Legacy Scripts

	•	Zero-Interaction Goal: Legacy scripts often deploy an open clone of a WPA2 network and wait for the user to manually open their Wi-Fi settings and click the fake AP. Lucifer's goal is automatic association. By combining MANA pool broadcasting with persistent, PMF-aware network denial, it triggers native OS auto-connect routines.

	•	Modern Supplicant Awareness: Legacy tools break when targets transition between 2.4/5GHz bands or mesh nodes. Lucifer's BSSID mapping and active client sensing prevent the target from escaping the dissociation wave.

## 🧩 Modular Injection Architecture (The Python Modules)

Lucifer relies on precision raw-socket injection to manipulate 802.11 frames at the bit level. These components are offloaded to dedicated Python scripts.
⚠️ DO NOT run these Python scripts manually. They are headless modules designed to be invoked, managed, and killed automatically by the main lucifer.sh target/suppress loops.

	•	lucifer_nav.py (NAV Silencing): Floods the target channel with spoofed CTS-to-self control frames. This manipulates the Network Allocation Vector (NAV) of all nearby radios, forcing the legitimate AP to defer its own transmissions at the PHY layer. Because control frames are ignored by 802.11w, this bypasses PMF.

	•	lucifer_probe.py (Scan Poisoning): Listens for client Probe Requests and immediately injects a cloned Probe Response (built from a PCAP of the real AP's beacon). It patches the DS Parameter Set IE to advertise the rogue AP's channel, steering the client into the trap.

	•	lucifer_csa.py (Channel Steering): Injects 802.11h Channel Switch Announcements, commanding associated clients to jump to the rogue frequency.

	•	lucifer_portal.py (Captive Engine): A multi-threaded, RFC-8908 compliant HTTP/DNS server that manages OS-specific captive portal triggers (Apple CNA, Windows NCSI, Android connectivity checks) and handles transparent NAT bridging post-capture.

## 🛠️ Prerequisites & Hardware Needs

To run this framework as intended, your environment requires:

	•	OS: Kali Linux, Parrot OS, or a heavily modified Debian/Ubuntu setup (macOS via UTM/VM is fully supported with USB passthrough).
	•	Hardware: 3x USB Wireless Adapters that support both Monitor Mode with Packet Injection and AP Mode (e.g., MediaTek MT7612U / Alfa AWUS036ACM).
	•	Dependencies:
	    •	    hostapd-mana (Crucial: standard hostapd will not work)
	    •	    mdk4 (For Auth Flooding / Multi-BSSID Deauth)
	    •	    airodump-ng suite & macchanger
	    •	    dnsmasq & python3
		•       scapy

## 📡 Interface Architecture

The framework’s multi-channel synchronization has been heavily tested and validated using three Alfa AWUS036ACM (MT7612U) 802.11ac adapters. To prevent USB endpoint exhaustion and TX power sag, the radios were deployed across a dedicated powered USB hub with isolated host controllers (dedicated buses). Running three active transmitters on a shared, unpowered USB bus will cause kernel-level driver crashes or silent packet drops. Although this tool has been designed to work with a VM linux environment, this setuo does consolidate the adapters into a unified bus. Using a bare metal linux is more desirable 

Lucifer requires you to assign three distinct roles to your physical adapters upon launch:

	1	Target Monitor: Locks onto the target BSSID and client channel, executing PMF-aware dissociation (CSA/Deauth/Auth Flood/NAV/Probe Inject).
	2	Suppress Monitor: Rapidly sweeps sibling channels (5GHz/2.4GHz/Mesh nodes) to deny alternative connection paths.
	3	Rogue AP: The hostapd-mana interface broadcasting the Evil Twin and hosting the captive portal/DNS infrastructure.

## 🎭 Captive Portal Templates

Lucifer dynamically injects the target's cloned SSID into your captive portal HTML.
 To add custom phishing pages:

	1	Create a new folder inside the portals/ directory.
	2	Copy the router.php file into that folder from an existing portal template.
	3	Place your index.html (and associated assets) inside.
	4	Use the string {{SSID}} anywhere in your HTML. Lucifer will automatically replace this with the target network's real name at runtime.

All captured credentials are automatically logged to the loot/ directory.

## 📥 Requirements & Installation

Lucifer requires a Linux environment with adapters capable of Monitor Mode and AP/Master Mode.

1. System Dependencies

Depending on your distribution, install the required network and wireless tools:

Kali Linux / Debian / Ubuntu:

```bash
sudo apt update

sudo apt install -y aircrack-ng mdk4 dnsmasq xterm iw tcpdump tshark macchanger python3-scapy
```

(Note: hostapd-mana is pre-packaged in Kali Linux. On standard Ubuntu/Debian, you will need to build hostapd-mana from source or use a specialized repository).

Arch Linux / BlackArch:

```bash
sudo pacman -S aircrack-ng dnsmasq xterm iw tcpdump wireshark-cli macchanger python-scapy
```

hostapd-mana and mdk4 available via BlackArch repo or AUR

2. Dependencies

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## 🚀 Quick Start
	1	Connect your 3 compatible USB wireless adapters to the host.

	2	Clone the repository and make the script executable:
git clone https://github.com/yourusername/lucifer.git

```bash
cd lucifer
```
```bash
chmod +x lucifer.sh
```
	3	Run the framework as root (required for raw packet injection and network namespace manipulation):
	
```bash	
sudo ./lucifer.sh
```
	4	Follow the interactive prompts to configure the attack state machine:

	•	Interface Assignment: You will be asked to assign your three adapters to their respective roles (Target Monitor, Suppress Monitor, and Rogue AP).
	•	Target Selection & Reconnaissance: The tool will launch a live scan. Let the script scan for a few minutes to ensure it finds and logs all active clients on the target Access Point. Press ENTER to stop the scan and enter the ID of your target network. Lucifer will automatically map its mesh nodes and siblings.
	•	Client Tracking: You can choose to lock onto a specific target client (enabling adaptive, surgical channel tracking), or leave the attack open to all clients on the AP (using weighted channel-hopping to deny the entire ESS) by selecting 0.
	•	Template Selection: Choose which HTML captive portal payload to deploy from the portals/ directory.
	•	Security Mode:
	•	[1] OPEN: Deploys a standard unencrypted portal. Highly effective for capturing new connections, but relies on OS fallback mechanics.
	•	[2] WPA2: Requires you to input the target's known PSK. Forces seamless Layer 2 roaming and auto-association for devices that already have the network saved.

