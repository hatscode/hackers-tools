# **Learn Hashcat Fast: Hands-On Cracking Guide**  

Hashcat is the fastest password-cracking tool, supporting **GPU acceleration** and multiple attack modes. This guide skips the theory and jumps straight into practical cracking.  

---

## **1. Basic Hashcat Command**  
The core syntax:  
```bash
hashcat -m [hash_type] -a [attack_mode] [hash_or_file] [wordlist_or_mask]
```  

### **Key Flags**  
- `-m` → Hash type (e.g., `0` for MD5, `1000` for NTLM)  
- `-a` → Attack mode (`0` for wordlist, `3` for brute-force)  
- `-o` → Save cracked passwords to a file  
- `--show` → View previously cracked hashes  

---

## **2. Cracking Common Hashes (Cheat Sheet)**  

### **A. Crack MD5 Hash**  
```bash
hashcat -m 0 -a 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt
```  
- **If successful:** `e3e3ec5831ad5e7288241960e5d4fdb8:password123`  

### **B. Crack SHA1 Hash**  
```bash
hashcat -m 100 -a 0 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 rockyou.txt
```  

### **C. Crack NTLM (Windows Password)**  
```bash
hashcat -m 1000 -a 0 aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 rockyou.txt
```  

---

## **3. Attack Modes (Real-World Examples)**  

### **A. Wordlist Attack (`-a 0`)**  
```bash
hashcat -m 0 -a 0 target_hashes.txt rockyou.txt
```  

### **B. Wordlist + Rules (Smart Attack)**  
```bash
hashcat -m 0 -a 0 target_hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```  
- **What it does:** Tries `password → P@ssw0rd`, `hello → h3ll0!`, etc.  

### **C. Brute-Force Mask Attack (`-a 3`)**  
Crack an 8-digit PIN:  
```bash
hashcat -m 0 -a 3 5f4dcc3b5aa765d61d8327deb882cf99 ?d?d?d?d?d?d?d?d
```  
Crack "Password123!" (Uppercase + lowercase + digits + symbol):  
```bash
hashcat -m 0 -a 3 target_hash ?u?l?l?l?l?l?l?d?d?s
```  

---

## **4. Optimizing Your Attacks**  

### **A. Use GPU for Faster Cracking**  
```bash
hashcat -m 0 -a 0 -d 1 2c103f2c4ed1e59c0b4e2e01821770fa rockyou.txt  # -d 1 = Use GPU #1
```  

### **B. Resume an Interrupted Job**  
```bash
hashcat --restore
```  

### **C. Save Cracked Passwords**  
```bash
hashcat -m 0 -a 0 target_hash.txt rockyou.txt -o cracked.txt
```  

### **D. Check Already Cracked Hashes**  
```bash
hashcat --show cracked_hashes.txt
```  

---

## **5. Common Errors & Fixes**  

| Error | Solution |
|-------|----------|
| `No hashes loaded` | Check file path or hash format |
| `No devices found` | Install GPU drivers (`nvidia-smi` for NVIDIA) |
| `Token length exception` | Wrong hash format (e.g., extra spaces) |
| `Unsupported hash type` | Verify `-m` value (`hashid -m [hash]`) |

---

## **6. Real-World Lab**  

### **Step 1: Create a Test MD5 Hash**  
```bash
echo -n "hackme123" | md5sum | cut -d ' ' -f1 > target_hash.txt
```  
(Output: `5f4dcc3b5aa765d61d8327deb882cf99`)  

### **Step 2: Crack It with RockYou**  
```bash
hashcat -m 0 -a 0 target_hash.txt /usr/share/wordlists/rockyou.txt
```  
**Result:** `5f4dcc3b5aa765d61d8327deb882cf99:hackme123`  

---

## **Final Tips**  
✅ **Always check `hashcat --help` for advanced options**  
✅ **Use `-O` for faster cracking (optimized kernel)**  
✅ **Combine wordlists (`cat list1.txt list2.txt > combined.txt`)**  
✅ **For large attacks, use `--session [name]` to save progress**  

🔥 **Now go crack some hashes!** 🔥  

> **Legal Note:** Only test on systems you own or have permission to attack. Unauthorized cracking is illegal.
