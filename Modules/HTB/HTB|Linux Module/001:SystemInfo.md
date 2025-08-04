# HTB Linux Module - System Information

*Learning how to gather system information in Linux environments*

---

## Objective
- SSH into the server at `the machine ip` (ACADEMY-NIXFUND).
- Check [here](https://github.com/Iam4lex/HTB/blob/main/Modules/001:Getting%20started/001:sshtokali.md) on how to ssh.

---


### Find out the machine hardware name and submit it as the answer.
- Use `uname -m` to determine the machine's hardware name. For more options, refer to `uname --help`.
```bash
uname -m
uname --help
```
![image](https://github.com/user-attachments/assets/db1dcec4-ebcd-4020-b9f8-8b6abfe59099)  
**Answer**
```bash
x86_64
```

---

### What is the path to htb-student’s home directory?  
- To find *htb-student*’s home directory, the `pwd` (print working directory) command is used:  
```bash
pwd
```
Other alternative commands can be used as well.  
![image](https://github.com/user-attachments/assets/90c7bcf1-f190-4bbe-820a-7289bacfcfac)  
**Answer**
```bash
/home/htb-student
```

---

### What is the path to *htb-student*'s mail?  
- The `env` command displays the full paths of files and directories. It can also provide the mail path.  
```bash
env | grep MAIL
```
![image](https://github.com/user-attachments/assets/a18adce7-43c4-4f76-93a5-16d5c5d64b44)
**Answer**
```bash
/var/mail/htb-student
```

---

### Which shell is specified for the htb-student user?  
- The same command used previously (`env`) can reveal this information.  
```bash
env | grep SHELL
```
![image](https://github.com/user-attachments/assets/4e77f57f-6ea4-4970-bd98-703a0f64b988)

**Answer**
```bash
/bin/bash
```

---

### Which kernel version is installed on the system? (Format: 1.22.3)  
- Run `uname -r` to check the kernel version:  
```bash
uname -r
```
![image](https://github.com/user-attachments/assets/de49fcf2-f7f4-417e-88ea-54115104d64f)

**Answer**
```bash
4.15.0
```

---

### What is the name of the network interface with MTU set to 1500?  
- Use `ifconfig` to list all network interfaces. Look for the interface with MTU 1500:  
```bash
ip link show | grep -B 1 "mtu 1500"
```
![image](https://github.com/user-attachments/assets/ca4d184e-edeb-441a-be42-6116a1c5ba76)

**Answer**
```bash
ens192
```

---

*For questions or feedback about this module, please refer to the main repository documentation.*

