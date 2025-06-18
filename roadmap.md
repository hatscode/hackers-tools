# **3-Month Pentesting Roadmap: Beginner to Intermediate/Advanced**  

This structured roadmap will take you from a beginner to a **junior/intermediate pentester** in **3 months**, covering networking, tools, exploitation, Active Directory, and real-world practice.  

---

## **📌 Month 1: Foundations & Basic Tools**  
**Goal:** Learn networking, Linux, basic security concepts, and essential tools.  

### **Week 1: Networking & Linux Basics**  
- **Networking:**  
  - Watch [NetworkChuck's Networking Course](https://youtu.be/qiQR5rTSshw)  
  - Learn **subnetting, TCP/IP, HTTP/HTTPS, DNS, DHCP**  
  - Practice with [Wireshark Docs](https://www.wireshark.org/docs/)  
- **Linux & Bash:**  
  - Complete [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) (Levels 0-15)  
  - Study [Linux Command Guide](https://linuxjourney.com/)  

### **Week 2: Security Fundamentals & Kali Setup**  
- **Security Basics:**  
  - Read [OWASP Top 10](https://owasp.org/www-project-top-ten/)  
  - Do [TryHackMe Pre-Security](https://tryhackme.com/path/outline/presecurity)  
- **Kali Linux:**  
  - Install Kali ([Guide](https://www.kali.org/docs/installation/))  
  - Explore [Kali Tools List](https://www.kali.org/tools/)  

### **Week 3: Scanning & Enumeration**  
- **Nmap Deep Dive:**  
  - Study [Nmap Cheat Sheet](https://www.stationx.net/nmap-cheat-sheet/)  
  - Read [Nmap Network Scanning (Book)](https://nmap.org/book/)  
  - Practice scanning on [Metasploitable 2](https://metasploit.help.rapid7.com/docs/metasploitable-2)  
- **Web App Basics:**  
  - Start [PortSwigger Labs](https://portswigger.net/web-security) (SQLi, XSS, CSRF)  

### **Week 4: Exploitation Basics**  
- **Password Cracking:**  
  - Learn [Hashcat Examples](https://hashcat.net/wiki/doku.php?id=example_hashes)  
  - Crack hashes using `rockyou.txt`  
- **Metasploit Intro:**  
  - Follow [Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)  
  - Exploit [VulnServer](https://github.com/stephenbradshaw/vulnserver)  

---

## **📌 Month 2: Intermediate Pentesting (Web, AD, PrivEsc)**  
**Goal:** Master web app pentesting, Active Directory, and privilege escalation.  

### **Week 5: Web App Pentesting**  
- **Burp Suite:**  
  - Complete [Burp Suite Academy](https://portswigger.net/web-security)  
  - Practice on [WebSec Academy](https://websecacademy.com/)  
- **Web Exploitation:**  
  - Do **5+ PortSwigger Labs** (SQLi, SSRF, IDOR)  

### **Week 6: Active Directory Basics**  
- **AD Fundamentals:**  
  - Read [Impacket Cheat Sheet](https://www.secureauth.com/labs/open-source-tools/impacket)  
  - Try [HTB Heist](https://www.hackthebox.com/achievement/machine/573859/377)  
- **BloodHound:**  
  - Learn [BloodHound Docs](https://bloodhound.readthedocs.io/)  
  - Simulate attacks with [AD Attack Simulation](https://github.com/BloodHoundAD/BloodHound)  

### **Week 7: Privilege Escalation**  
- **Linux PrivEsc:**  
  - Study [GTFOBins](https://gtfobins.github.io/)  
  - Use [LinPEAS](https://github.com/carlospolop/PEASS-ng)  
- **Windows PrivEsc:**  
  - Learn [WinPEAS](https://github.com/carlospolop/PEASS-ng)  
  - Practice on [HTB Legacy](https://www.hackthebox.com/home/machines/profile/1)  

### **Week 8: Buffer Overflows & Python Scripting**  
- **Buffer Overflows:**  
  - Follow [Buffer Overflow Guide](https://www.thegreycorner.com/p/beginning-stack-based-buffer.html)  
  - Try [HTB Gatekeeper](https://www.hackthebox.com/achievement/machine/1586/377)  
- **Python for Pentesting:**  
  - Study [Black Hat Python](https://nostarch.com/blackhatpython)  
  - Write a **simple port scanner** in Python  

---

## **📌 Month 3: Advanced Topics & Real-World Practice**  
**Goal:** CTFs, AD attacks, bug bounty basics, and certification prep.  

### **Week 9: Advanced AD Attacks**  
- **Kerberos Attacks:**  
  - Study [Kerberoasting Guide](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)  
  - Try [HTB Active](https://www.hackthebox.com/home/machines/profile/158)  
- **Pass-the-Hash & Golden Ticket:**  
  - Practice with [Impacket](https://github.com/SecureAuthCorp/impacket)  

### **Week 10: CTFs & VulnHub Machines**  
- **CTF Challenges:**  
  - Complete [TryHackMe Offensive Path](https://tryhackme.com/path/outline/offensivepentesting)  
  - Try [VulnHub Kioptrix](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)  
- **Medium HTB Machines:**  
  - Solve [TJ_Null’s HTB List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=0)  

### **Week 11: Bug Bounty & Reporting**  
- **Bug Hunting:**  
  - Read [HackerOne Reports](https://github.com/reddelexc/hackerone-reports)  
  - Hunt on [Bug Bounty Playbook](https://github.com/arkadiyt/bounty-targets-data)  
- **Report Writing:**  
  - Study [Sample Pentest Report](https://www.offensive-security.com/reports/sample-penetration-testing-report.pdf)  

### **Week 12: Final Challenges & Cert Prep**  
- **Final Exam:**  
  - Complete [HTB RastaLabs](https://www.hackthebox.com/home/labs/rastalabs)  
  - Try [VulnHub Final Exam](https://www.vulnhub.com/entry/finalexam-1,249/)  
- **Certification Prep:**  
  - Study [eJPT Syllabus](https://elearnsecurity.com/ejpt-certification/)  
  - Try [PNPT Resources](https://www.tryhackme.com/path/outline/pnpt)  

---

## **🎯 Final Goal:**  
By the end of **3 months**, you should:  
✅ Understand networking, Linux, and security fundamentals  
✅ Perform web app pentesting (Burp Suite, SQLi, XSS)  
✅ Exploit Active Directory (Kerberoasting, BloodHound)  
✅ Write basic Python scripts for pentesting  
✅ Solve **10+ HTB/VulnHub machines**  
✅ Be ready for **eJPT/PNPT certification**  

---

**🚀 Next Steps:**  
- Join **Discord pentesting communities** (HackTheBox, TryHackMe)  
- Contribute to **bug bounty programs** (HackerOne, Bugcrowd)  
- Keep practicing **HTB & VulnHub machines**  

Happy Hacking! 🔥💻  

**🔐 License:** [MIT](https://opensource.org/licenses/MIT) | **Author:** [alex](https://github.com/stilla1ex)
