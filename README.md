Project Lucifer: Advanced 802.11 Association & Captive Portal Framework

📖 Overview


Project Lucifer is a research-grade Wi-Fi auditing and Evil Twin framework designed to study forced auto-association mechanics against modern operating systems (iOS 16+, macOS Ventura+, Windows 11).

While legacy tools struggle against modern probe suppression and Protected Management Frames (PMF), Lucifer utilizes a synchronized, three-adapter architecture to execute a "pincer" attack. It combines adaptive dissociation (Deauth/CSA/Auth Flooding) with aggressive hostapd-mana karma beaconing to force target devices to seamlessly transition to a rogue captive portal without user interaction.


Disclaimer: This tool is strictly for authorized, local lab-based research, advanced penetration testing, and defense mechanism engineering.



---

⚡ The Unique Combination (Core Innovations)


Lucifer departs from traditional single-adapter scripts by separating the attack into three simultaneous operational planes: Target Locking, Mesh Suppression, and Rogue AP Hosting.


1. Adaptive Pincer Dissociation

Instead of blindly broadcasting deauths on a single channel, Lucifer tracks the target client using BPF/tcpdump. If the client channel-hops, the "Target Monitor" follows them, while the "Suppress Monitor" continuously sweeps and suppresses all other mesh nodes and hardware siblings (Guest/IoT networks on the same physical AP).

2. PMF & Modern Defenses Bypass

Lucifer actively checks the target BSSID for 802.11w (PMF) requirements. If PMF is enforced (dropping standard deauths), the script dynamically shifts to Channel Switch Announcements (CSA) and Auth Flooding to deny the real AP and steer the client to the rogue channel.

3. Hardware Sibling Identification

Using BSSID byte-masking, the tool maps out hidden, guest, and 5GHz/2.4GHz sibling networks originating from the same physical router, suppressing the entire hardware stack rather than a single SSID.

4. "Loud" MANA Karma (Probe Asymmetry)

Modern iOS devices suppress directed probes, making legacy karma attacks obsolete. Lucifer uses hostapd-mana in "loud" mode to capture probes from noisy devices (macOS/Windows) and broadcast them as beacons. This turns active probers into "seeders," tricking silent, passive-scanning iOS devices into auto-connecting to saved networks they never actually probed for.


---

🆚 Why It's Different

vs. Hak5 WiFi Pineapple

- Active vs. Passive: The Pineapple excels at passive PineAP beacon flooding but relies heavily on the environment to bring clients to it. Lucifer brings the Pineapple's "loud" karma capabilities to any Linux machine, but couples it with an extremely aggressive, multi-channel dissociation engine to force the client off their current infrastructure.

- Hardware Independence: Runs on standard, widely available hardware (e.g., 3x Alfa ACMs) without requiring proprietary Hak5 firmware.

vs. Airgeddon / Wifiphisher / Legacy Scripts

- Zero-Interaction Goal: Legacy scripts often deploy an open clone of a WPA2 network and wait for the user to manually open their Wi-Fi settings and click the fake AP. Lucifer's goal is automatic association. By combining MANA pool broadcasting with persistent, PMF-aware network denial, it triggers native OS auto-connect routines.

- Modern Supplicant Awareness: Legacy tools break when targets transition between 2.4/5GHz bands or mesh nodes. Lucifer's BSSID mapping and active client sensing prevent the target from escaping the dissociation wave.


---

🛠️ Prerequisites & Hardware Needs


To run this framework as intended, your environment requires:


- OS: Kali Linux, Parrot OS, or a heavily modified Debian/Ubuntu setup (macOS via UTM/VM is fully supported with USB passthrough).

- Hardware: 3x USB Wireless Adapters that support both Monitor Mode with Packet Injection and AP Mode (e.g., MediaTek MT7612U / Alfa AWUS036ACM).

- Dependencies:
	- hostapd-mana (Crucial: standard hostapd will not work)

	- mdk4 (For Auth Flooding / Multi-BSSID Deauth)

	- airodump-ng suite & macchanger

	- dnsmasq & python3 (with scapy for custom CSA frame injection)


📡 Interface Architecture

Lucifer requires you to assign three distinct roles to your physical adapters upon launch:

	Target Monitor: Locks onto the target BSSID and client channel, executing PMF-aware dissociation (CSA/Deauth/Auth Flood).

	Suppress Monitor: Rapidly sweeps sibling channels (5GHz/2.4GHz/Mesh nodes) to deny alternative connection paths.

	Rogue AP: The `hostapd-mana` interface broadcasting the Evil Twin and hosting the captive portal/DNS infrastructure.


🎭 Captive Portal Templates

Lucifer dynamically injects the target's cloned SSID into your captive portal HTML. 
To add custom phishing pages:
1. Create a new folder inside the `portals/` directory.
2. Copy the router.php file into that folder from existing portal template.
3. Place your `index.html` (and associated assets) inside.
4. Use the string `{{SSID}}` anywhere in your HTML. Lucifer will automatically replace this with the target network's real name at runtime.

All captured credentials are automatically logged to the `loot/` directory.


Requirements & Installation

Lucifer requires a Linux environment with an adapter capable of Monitor Mode and AP/Master Mode.

1. System Dependencies
Depending on your distribution, install the required network and wireless tools:

Kali Linux / Debian / Ubuntu:
```bash
sudo apt update
sudo apt install -y aircrack-ng mdk4 dnsmasq xterm iw tcpdump tshark macchanger python3-scapy
```
(Note: `hostapd-mana` is pre-packaged in Kali Linux. On standard Ubuntu/Debian, you will need to build `hostapd-mana` from source or use a specialized repository).

Arch Linux / BlackArch:

```bash
sudo pacman -S aircrack-ng dnsmasq xterm iw tcpdump wireshark-cli macchanger python-scapy

hostapd-mana and mdk4 available via BlackArch repo or AUR
```

2. Python Dependencies
If your distribution did not include Scapy in the system package manager (e.g., `python3-scapy`), you can install it using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

🚀 Quick Start

1. Connect your 3 compatible USB wireless adapters to the host.
2. Clone the repository and make the script executable:
```bash
git clone https://github.com/yourusername/lucifer.git
cd lucifer
chmod +x lucifer.sh
```
3. Run the framework as root (required for raw packet injection and network namespace manipulation):
```bash
sudo ./lucifer.sh
```
4. Follow the interactive prompts to assign your interfaces, select a target network, and launch the captive portal.

