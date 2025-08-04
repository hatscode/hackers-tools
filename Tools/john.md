# John the Ripper (JtR) - Password Cracking Guide

*A comprehensive guide to password cracking using John the Ripper*

---
*Disclaimer: For authorized penetration testing and educational purposes only. Unauthorized use is illegal!*  

---

## Installation  
### Linux (Debian/Ubuntu)  
```bash
sudo apt update && sudo apt install john -y
```

### macOS (Use homebrew)  
```bash
brew install john
```

### Windows (WSL Recommended)  
```bash
wsl --install Ubuntu
sudo apt install john
```

- Here we're using debian kali linux

![image](https://github.com/user-attachments/assets/40749611-d5eb-4cd1-895d-60929b5c5208)
  

---

## Basic Usage  

### 1. Prepare Hashes  
  - John can crack hashes from /etc/shadow, Windows SAM dumps, ZIPs, RARs, and more.
  
  - Step 1: Prepare hashes
  - Save hashes in a file (hashes.txt). Example (MD5):

![image](https://github.com/user-attachments/assets/d2c8f429-3ee9-4cdf-94a3-9de22c7b85e5)


### 2. Dictionary Attack  
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### 3. Brute-Force (Incremental Mode)  
```bash
john --incremental hashes.txt
```

![image](https://github.com/user-attachments/assets/370f6675-01b3-42f9-84b3-723ff2d0a4f7)


### 4. Show Results  
```bash
john --show hashes.txt
```
*Output:*  
```
alex:chocolate
```

---

## Advanced Techniques

### Rules-Based Cracking  
Mangle wordlists for complex variations:  
```bash
john --wordlist=wordlist.txt --rules hashes.txt
```

### GPU Acceleration  
```bash
john --format=raw-md5 --device=1,2 hashes.txt
```
*Supports NVIDIA (`--device=1`) and AMD (`--device=2`).*

### Custom Formats  
Specify hash types (e.g., `md5crypt`, `sha512crypt`):  
```bash
john --format=sha512crypt hashes.txt
```

---

## Legal & Ethical Warning
### **Use responsibly!** Only test systems you own or have explicit permission to audit.**  
