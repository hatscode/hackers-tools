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
<h2>Navigation</h2>
</div>


### Objective
- SSH into the server at `the machine ip` (ACADEMY-NIXFUND).
- Check [here](https://github.com/Iam4lex/HTB/blob/main/Modules/001:Getting%20started/001:sshtokali.md) on how to ssh.

---


**What is the name of the hidden "history" file in the htb-user's home directory?**

- Go to the htb-user's home directory using the following command
```bash
cd  ~
```

- Run the command to list all files, including hidden ones, to find the "history" file:
```bash
ls -la
```

- Look for a hidden file named `.bash_history` in the output.

**Answer**
```bash
.bash_history
```
![image](https://github.com/user-attachments/assets/836b60f0-cd5a-4675-afd7-fe22e33c954d)

---

**What is the index number of the "sudoers" file in the "/etc" directory?**

### Solution:
- To determine this, use the `ls` command with the `-i` (-i, --inode: print the index number of each file) option to show index numbers of files in the `/etc` directory:
```bash
ls -i /etc/sudoers
```
- The output will show the index number, inode, of the `sudoers` file.

**Answer:** 
```bash
147627
```
![image](https://github.com/user-attachments/assets/dd8df50f-98a6-4ce6-b9ca-fd84540295e1)

---

**Author**: Iam4lex  
**Connect with me**:  
- [X (Twitter)](https://x.com/Iam4lex)  
- [LinkedIn](https://www.linkedin.com/in/iam4lex/)  
- [Instagram](https://instagram.com/iqm4lex)

Let me know if you spot any corrections or mistakes. Feedback is always welcome!
