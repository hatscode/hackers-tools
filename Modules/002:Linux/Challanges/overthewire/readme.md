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
***password***
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
  
![image](https://github.com/user-attachments/assets/979c1281-0eef-471f-88a4-e97dbc2cf9a3)


***Password to bandit1***
```bash
ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If
```

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

![image](https://github.com/user-attachments/assets/2b02c092-1d6d-40e5-9c41-e9ddeb82fa72)

***Password for bandit2***
```bash
263JGJPfgU6LtdEvgfWU1XP5yac29mFx
```

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

![image](https://github.com/user-attachments/assets/34321e76-6ad6-45c0-aeff-36cf730f2bfa)


***Password for bandit3***
```bash
MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx
```
