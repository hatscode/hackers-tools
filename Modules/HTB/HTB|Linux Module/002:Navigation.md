# HTB Linux Module - Navigation

*Mastering Linux filesystem navigation and directory traversal*

---

## Objective
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

*For questions or feedback about this module, please refer to the main repository documentation.*
