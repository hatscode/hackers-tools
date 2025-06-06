<div align="center"> 
  <a class="header-badge" target="_blank" href="https://www.linkedin.com/in/Iam4lex/">
  <img src="https://img.shields.io/badge/style--5eba00.svg?label=LinkedIn&logo=linkedin&style=social">
  </a>
  <a class="header-badge" target="_blank" href="https://twitter.com/Iam4lex">
  <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/Iam4lex?style=social"> 
  </a> 
</div>

---
<div align="center">
<h2>Working with Files and Directories (2)</h2>
</div>


### Objective
- SSH into the server at `the machine ip` (ACADEMY-NIXFUND).
- Check [here](https://github.com/Iam4lex/HTB/blob/main/Modules/001:Getting%20started/001:sshtokali.md) on how to ssh.

---

**What is the name of the config file that has been created after 2020-03-03 and is smaller than 28k but larger than 25k?**

Use the `find` command to locate files with the specified criteria
```bash
find / -type f -name "*.conf" -size +25k -size -28k -newermt 2020-03-03 -exec ls -la {} \; 2>/dev/null
```
**Answer**
```bash
00-mesa-defaults.conf
```

![image](https://github.com/user-attachments/assets/12fa3723-a081-40ed-8314-71ad80c12447)

Look for files with the `.conf` extension and verify the name matches `00-mesa-defaults.conf`.

---

**How many files exist on the system that have the ".bak" extension?**

Use the `find` command to list all `.bak` files
```bash
find / -type  f -name "*.bak" -exec ls -la {} \; 2>/dev/null
```
Count the files
   ```bash
   find / -type f -name "*.bak" 2>/dev/null | wc -l
   ```
**Answer**
```bash
4
```
   
![image](https://github.com/user-attachments/assets/a93e7755-f544-4aad-b0a0-a29e9b342554)

**Verify the count matches `4`.**

---

**Submit the full path of the "xxd" binary.**

Use the `which` command to find the binary location
```bash
which xxd
```

Alternatively, use `find` to locate the binary
```bash
find / -type f -name "xxd" 2>/dev/null
```

**Answer**
```bash
/usr/bin/xxd
```

![image](https://github.com/user-attachments/assets/16170bbc-8e1e-4a53-8f66-a0f16f8038e0)

Verify the path is `/usr/bin/xxd`

---

**Author**: Iam4lex  
**Connect with me**:  
- [X (Twitter)](https://x.com/Iam4lex)  
- [LinkedIn](https://www.linkedin.com/in/iam4lex/)  
- [Instagram](https://instagram.com/iqm4lex)

Let me know if you spot any corrections or mistakes. Feedback is always welcome!
