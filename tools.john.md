<div align="center">
  <img src="https://media.giphy.com/media/L1R1tvI9svkIWwpVYr/giphy.gif" width="200" alt="Hacker GIF">
  
  [![Open Source Love](https://badges.frapsoft.com/os/v2/open-source.svg?v=103)](https://github.com/yourusername/)
  <a class="header-badge" target="_blank" href="https://discord.com/users/yourusername">
    <img src="https://img.shields.io/badge/Discord-7289DA?style=social&logo=discord&label=Join%20Me">
  </a> 
  [![Twitter Follow](https://img.shields.io/twitter/follow/yourusername?style=social)](https://twitter.com/yourusername)
  
  ⚡ *"Knowledge shared is knowledge squared"* ⚡
</div>

---

## John the Ripper (JtR) - Password Cracking Guide
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

---

## Basic Usage  

### 1. Prepare Hashes  
Save target hashes in a file (e.g., `hashes.txt`). Formats:  
- **MD5**: `user:5f4dcc3b5aa765d61d8327deb882cf99`  
- **SHA-256**: `admin:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8`  

### 2. Dictionary Attack  
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

### 3. Brute-Force (Incremental Mode)  
```bash
john --incremental hashes.txt
```

### 4. Show Results  
```bash
john --show hashes.txt
```
*Output:*  
```
user1:password123  
admin:qwerty
```

---

## ⚡ Advanced Techniques  

### 🔄 Rules-Based Cracking  
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

## ⚠️ Legal & Ethical Warning  
### **Use responsibly!** Only test systems you own or have explicit permission to audit.  
