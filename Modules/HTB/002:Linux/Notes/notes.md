###  Linux Commands Explained
---

**man <tool>**
- Opens the manual pages for the specified tool.
- **Example**:
  ```bash
  man ls
  ```

**<tool> -h**
- Prints the help page of the tool.
- **Example**:
  ```bash
  ls -h
  ```

**apropos <keyword>**
- Searches through manual pages' descriptions for instances of a given keyword.
- **Example**:
  ```bash
  apropos network
  ```

**cat**
- Concatenates and prints files.
- **Example**:
  ```bash
  cat file.txt
  ```

**whoami**
- Displays the current username.
- **Example**:
  ```bash
  whoami
  ```

**id**
- Returns user identity.
- **Example**:
  ```bash
  id
  ```

**hostname**
- Sets or prints the name of the current host system.
- **Example**:
  ```bash
  hostname
  ```

**uname**
- Prints the operating system name.
- **Example**:
  ```bash
  uname -a
  ```

**pwd**
- Returns the current working directory name.
- **Example**:
  ```bash
  pwd
  ```

---

### Networking Commands

**ifconfig**
- Assigns or views an address to a network interface or configures network interface parameters.
- **Example**:
  ```bash
  ifconfig
  ```

**ip**
- Shows or manipulates routing, network devices, interfaces, and tunnels.
- **Example**:
  ```bash
  ip addr
  ```

**netstat**
- Shows network status.
- **Example**:
  ```bash
  netstat -an
  ```

**ss**
- Investigates sockets.
- **Example**:
  ```bash
  ss -tuln
  ```

---

### Process Management Commands

**ps**
- Shows process status.
- **Example**:
  ```bash
  ps aux
  ```

**who**
- Displays who is logged in.
- **Example**:
  ```bash
  who
  ```

**env**
- Prints the environment or sets and executes a command.
- **Example**:
  ```bash
  env
  ```

**kill**
- Sends a signal to a process.
- **Example**:
  ```bash
  kill 1234
  ```

**bg**
- Puts a process into the background.
- **Example**:
  ```bash
  bg %1
  ```

**jobs**
- Lists all processes running in the background.
- **Example**:
  ```bash
  jobs
  ```

**fg**
- Puts a process into the foreground.
- **Example**:
  ```bash
  fg %1
  ```

---

### File Management Commands

**ls**
- Lists directory contents.
- **Example**:
  ```bash
  ls -l
  ```

**cd**
- Changes the directory.
- **Example**:
  ```bash
  cd /home/user
  ```

**touch**
- Creates an empty file.
- **Example**:
  ```bash
  touch newfile.txt
  ```

**mkdir**
- Make a directory. The command mkdir has an option marked -p to add parent directories.

- **Example**:
  ```bash
  mkdir new_directory
  ```

**mv**
- Moves or renames files and directories.
- **Example**:
  ```bash
  mv file1.txt file2.txt
  ```

**cp**
- Copies files or directories.
- **Example**:
  ```bash
  cp file1.txt path/
  ```

**rm**
- Removes files or directories.
- **Example**:
  ```bash
  rm file.txt
  ```

---

### System Commands

**sudo**
- Executes a command as a different user.
- **Example**:
  ```bash
  sudo apt update
  ```

**su**
- Switches to another user account.
- **Example**:
  ```bash
  su - username
  ```

**passwd**
- Changes the user password.
- **Example**:
  ```bash
  passwd
  ```

---

### Package Management Commands

**dpkg**
- Installs, removes, and configures Debian-based packages. It stands for debian package manager.
- **Example**:
  ```bash
  dpkg -i package.deb
  ```

**apt**
- High-level package management command-line utility. It stands for advanced package tool.
- **Example**:
  ```bash
  apt install package_name
  ```

**snap**
- Manages snap packages.
- **Example**:
  ```bash
  snap install package_name
  ```

**pip**
- Standard package manager for Python.
- **Example**:
  ```bash
  pip install requests
  ```

**gem**
- Standard package manager for Ruby.
- **Example**:
  ```bash
  gem install rails
  ```

---

### Miscellaneous Commands

**curl**
- Transfers data from or to a server.
- **Example**:
  ```bash
  curl http://example.com
  ```

**wget**
- Downloads files from FTP or HTTP(s) servers.
- **Example**:
  ```bash
  wget http://example.com/file.zip
  ```

  **python3 -m http.server**
- Starts a Python3 web server on TCP port 8000.
- **Example**:
  ```bash
  python3 -m http.server 8080
  ```

---

This document outlines basic Linux commands with their purposes and examples. Use these commands to enhance your Linux system proficiency.
