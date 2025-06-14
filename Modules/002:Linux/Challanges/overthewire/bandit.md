<h3 align="center">overthewire wargames</h3>

---  
### Bandit Level 0  - First, we need to ssh to the overthewire 

**Level Goal**  
The password for the next level is stored in a file called `readme` located in the home directory. Use this password to log into `bandit1` using SSH.  

Whenever you find a password for a level, use SSH (on port `2220`) to log into that level and continue the game.   
 
**Commands you may need to solve this level:**  
```bash 
  ls, cd, cat, file, du, find  
``` 

***Type the following commands***
```bash
  ssh bandit0@bandit.labs.overthewire.org -p 2220
```
***password is already provided [here](https://overthewire.org/wargames/bandit/bandit0.html)***
```bash
  bandit0
```

![image](https://github.com/user-attachments/assets/c8781de2-6d6a-4ffd-bf8c-2a86c2c521b5)

---

## Bandit Level 0 → Level 1

**Level Goal**
The password for the next level is stored in a file called readme located in the home directory. Use this password to log into bandit1 using SSH. Whenever you find a password for a level, use SSH (on port 2220) to log into that level and continue the game.

**Commands you may need to solve this level:**
```bash
  ls , cd , cat , file , du , find
```

- We will be using ``ls`` command to list the files in the current working directory, ``cat`` to view the content, ``cd`` to change the directory, ``file`` to determine the type of a file, ``du`` to check disk usage, and ``find`` to search for files within the directory structure
  
![image](https://github.com/user-attachments/assets/8fb248ae-fb7d-4768-9b7e-e77c71319aa6)

**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 1 → Level 2
**Level Goal**
The password for the next level is stored in a file called - located in the home directory

**Commands you may need to solve this level**
```bash
ls , cd , cat , file , du , find
```
use the ``ls`` command to print the working drectory.
```bash
ls
```

use the ``cat`` command to print the content of the file.
```bash
cat ./-
```

![image](https://github.com/user-attachments/assets/5ff93b73-bf4b-4a3e-9f50-f605f298aac2)


**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 2 → Level 3
**Level Goal**
The password for the next level is stored in a file called spaces in this filename located in the home directory

**Commands you may need to solve this level**
```bash
ls , cd , cat , file , du , find
```
use the ``ls`` command to print the working drectory.
```bash
ls
```

use the ``cat`` command to print the content of the file.
```bash
cat spaces\ in\ this\ filename
```

![image](https://github.com/user-attachments/assets/69ae015a-d3cf-444e-b716-bee51172c659)

**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 3 → Level 4
**Level Goal**
The password for the next level is stored in a hidden file in the inhere directory.

**Commands you may need to solve this level**
```bash
ls , cd , cat , file , du , find
```
use the ``ls`` command to print the working drectory.
```bash
ls
```

**Locate to inhere directory**
```bash
cd inhere
ls -la
```

use the ``cat`` command to print the content of the file ...Hiding-From-You.
```bash
cat ...Hiding-From-You
```

![image](https://github.com/user-attachments/assets/abc2213a-9011-482a-a754-38255bebe0cb)


**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 4 → Level 5

**Level Goal**  
The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the "reset" command.

**Commands you may need to solve this level**  
```bash
ls, cd, cat, file, du, find
```

### Solution

First, let's check the current directory contents:
```bash
ls
```

**Navigate to the inhere directory:**
```bash
cd inhere
ls
```

You'll see several files with hyphen-prefixed names. To find the human-readable one, we'll use the `file` command with `find`:

**Identify the human-readable file:**
```bash
find . -type f -exec file {} \; | grep ASCII
```

This will show you which file contains ASCII (human-readable) text. In this case, it's `-file07`.

**View the contents of the readable file:**
```bash
cat ./-file07
```

![image](https://github.com/user-attachments/assets/921ffecd-40f7-46a4-83b9-a89d2aac526f)

**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 5 → Level 6  

**Level Goal**  
The password for the next level is stored in a file somewhere under the `inhere` directory with the following properties:  
- **Human-readable**  
- **1033 bytes in size**  
- **Not executable**

**Commands you may need to solve this level**  
```bash
ls, cd, cat, file, du, find
```

### Solution  

**List the contents of the home directory:**  
```bash
ls
```

**Navigate into the `inhere` directory:**  
 ```bash
 cd inhere
 ls
 ```

**Find the correct file using `find` with specific filters:**  
   - `-type f` → Only search for files (not directories).  
   - `-readable` → Ensure the file is human-readable.  
   - `-size 1033c` → File size must be exactly **1033 bytes**.  
   - `! -executable` → File must **not** be executable.  

```bash
find . -type f -readable -size 1033c ! -executable
```

**Display the password by reading the file:**  
```bash
cat ./maybehere07/.file2
```

![image](https://github.com/user-attachments/assets/60d30c9f-acce-4b33-b7fa-569b6f49db51)

**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 6 → Level 7  

**Level Goal**  
The password for the next level is stored somewhere on the server and has the following properties:  
- **Owned by user `bandit7`**  
- **Owned by group `bandit6`**  
- **33 bytes in size**  

**Commands you may need to solve this level**  
```bash
ls, cd, cat, file, find, grep
```

### Solution  

**Check the home directory (empty in this case):**  
```bash
ls -la
```
Output:  
```
   total 20
   drwxr-xr-x  2 root root 4096 Apr 10 14:22 .
   drwxr-xr-x 70 root root 4096 Apr 10 14:24 ..
   -rw-r--r--  1 root root  220 Mar 31  2024 .bash_logout
   -rw-r--r--  1 root root 3771 Mar 31  2024 .bashrc
   -rw-r--r--  1 root root  807 Mar 31  2024 .profile
```
- No visible files here; we must search the entire server.

**Search system-wide for the file with the given criteria:**  
   - `-type f` → Regular files only.  
   - `-user bandit7` → Owned by user `bandit7`.  
   - `-group bandit6` → Owned by group `bandit6`.  
   - `-size 33c` → Exactly **33 bytes** in size.  
   - `2>/dev/null` → Suppress permission errors.  

```bash
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

**Retrieve the password by reading the file:**  
   ```bash
   cat /var/lib/dpkg/info/bandit7.password
   ```

![image](https://github.com/user-attachments/assets/1febf1fd-0484-4f31-b4c8-530fdcf36250)

**Now it's your turn — follow the steps to uncover the password yourself!**

---

## Bandit Level 7 → Level 8  

**Level Goal**  
The password for the next level is stored in the file **data.txt** next to the word **millionth**.  

**Commands you may need to solve this level**  
```bash
man, grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
```

---

### Solution  

**List the contents of the home directory:**  
```bash
ls
```
Output:  
```
data.txt
```

**Search for the password next to the word "millionth":**  
   - Use `grep` to filter lines containing "millionth".  
   - The password appears as the second field (separated by whitespace).
   - `grep` efficiently searches for patterns in files. Here, it isolates the line containing "millionth" and the password. 
```bash
cat data.txt | grep millionth
```

**Alternative (more precise):**  
```bash
grep -w "millionth" data.txt
```
(`-w` ensures an exact whole-word match).

**Alternative Approaches:**  
  - `awk '/millionth/ {print $2}' data.txt` → Uses `awk` to print the second field.  
  - `strings data.txt | grep millionth` →

![image](https://github.com/user-attachments/assets/03589e1a-bbf3-4bcd-b88d-605505f0474e)

**Now it’s your turn—find the password yourself!**  

---

## Bandit Level 8 → Level 9

**Level Goal**
The password for the next level is stored in the file data.txt and is the only line of text that occurs only once.

**Commands you may need to solve this level**
```bash
grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
```

### Solution

List the contents of the home directory:**
```bash
ls
```
Output:
```
data.txt
```

**Find the unique line in the file:**
   - First, sort the file contents (required for `uniq` to work properly)
   - Then use `uniq -u` to display only lines that appear exactly once

```bash
sort data.txt | uniq -u
```
   
### Explanation

- `sort data.txt`: Sorts all lines in the file alphabetically (required for `uniq` to detect duplicates correctly)
- `uniq -u`: Filters to show only lines that are unique (appear exactly once)
- The password is the only line in the entire file that isn't duplicated

![image](https://github.com/user-attachments/assets/aed6b547-960b-4af7-b562-74e4cbb076cd)

***Now it’s your turn—find the password yourself!*** [Piping and Redirection](https://ryanstutorials.net/linuxtutorial/piping.php)

---

## Bandit Level 9 → Level 10

**Level Goal**
The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several '=' characters.

**Commands you may need to solve this level**
```bash
grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
```

### Solution

**List the contents of the home directory:**
```bash
ls
```
Output:
```
data.txt
```

**Extract human-readable strings from the file:**
 ```bash
 strings data.txt
 ```
(This command displays all printable character sequences in the file)

**Filter for lines containing multiple '=' characters:**
```bash
strings data.txt | grep -E "={5,}"
```
   - `-E` enables extended regular expressions
   - `={5,}` matches 5 or more consecutive '=' characters
   - This reveals the password line among other false positives

Output:
```
   ========== the
   ========== password{k
   =========== is
   ========== xxxxxxxxxxxxxxxxxxxxxx
```

**Identify the password!**

### Additional Notes
- The file contains mostly binary data, so normal `cat` or `less` won't work well
- Alternative approach:
  ```bash
  strings data.txt | grep -E "^={5,}\s\w+"
  ```
  This looks for equals signs at the start of line followed by whitespace and word characters
- The password format is consistent with previous levels (32 random alphanumeric characters)

![image](https://github.com/user-attachments/assets/bcc2b2af-2d21-42c2-986d-06dc65367d8e)


---

## Bandit Level 10 → Level 11

**Level Goal**
The password for the next level is stored in the file data.txt, which contains base64 encoded data.

**Commands you may need to solve this level**
```bash
grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
```

### Solution

**List the contents of the home directory:**
```bash
ls
```
Output:
```
data.txt
```

**Decode the base64 encoded file:**
```bash
base64 -d data.txt
```
   - `-d` flag decodes the input
   - The command reveals the password in plaintext

Alternative approach using pipe:
```bash
cat data.txt | base64 -d
```

Output:
```
The password is xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Identify the password!**

![image](https://github.com/user-attachments/assets/a4ade22f-49e4-42a7-ba7e-aaf909a7f93d)

---

## Bandit Level 11 → Level 12

**Level Goal**
The password for the next level is stored in the file `data.txt`, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions (ROT13).

**Commands you may need to solve this level**
```bash
grep, sort, uniq, strings, base64, tr, tar, gzip, bzip2, xxd
```

### Solution

List the contents of the home directory:**
```bash
ls
```
Output:
```
data.txt
```

View the encoded password:**
```bash
cat data.txt
```
Sample output (encoded):
```
Gur cnffjbeq vf 7k16WNeHIi5YkIhWsfFIqoognUTyj9Q4
```

Decode the ROT13 cipher using `tr` command:**
```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Identify the password!**

![image](https://github.com/user-attachments/assets/207f96be-8d86-4122-a662-020abd094a09)

---
