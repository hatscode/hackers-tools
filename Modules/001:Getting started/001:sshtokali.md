<div align="center">
<h2>How to ssh</h2>
</div>


Hack The Box (HTB) is a popular platform for cybersecurity enthusiasts to practice penetration testing and ethical hacking. In this guide, we’ll walk through the process of connecting your HTB account to Kali Linux to start solving challenges.

### Prerequisites

Before starting, ensure you have the following:
- An active Hack The Box account.
- Kali Linux installed and updated.
- Basic knowledge of using the terminal in Kali Linux.

## Step 1: Create or Log into Your Hack The Box Account

1. Visit [Hack The Box](https://www.hackthebox.eu) and sign up for an account if you don’t have one.
2. Once signed in, you will need to locate your HTB VPN connection details. These are required to connect Kali Linux to the HTB network.
- Click on your username on the top right conner.
- Click on VPN settings

![image](https://github.com/user-attachments/assets/6e14c4d6-9212-4c79-8220-6dece62f3f8a)

- Scroll down to VPN servers.
- Select TCP and download the VPN connection file

![image](https://github.com/user-attachments/assets/6242c925-6427-4804-8d43-af6aa1954b5a)

## Step 2: Install OpenVPN on Kali Linux

You will need OpenVPN to connect to HTB. Most versions of Kali Linux come with OpenVPN pre-installed. If it’s not already installed, run the following commands to install it:

- Update kai linux
```bash
sudo apt update
```

- Install openvpn
```bash
sudo apt install openvpn
```

## Step 3: Connect to Hack The Box Using OpenVPN

- Navigate to the directory where the VPN configuration file was downloaded. For example:
```
cd ~/Downloads
```
- Start the VPN connection using OpenVPN:
```
sudo openvpn <your-vpn-config-file>.ovpn
```
- Replace "your-vpn-config-file" with the actual name of the file downloaded.

- Enter your root password when prompted.

![image](https://github.com/user-attachments/assets/43e58c18-526d-4a2f-8a5e-47397c4a7249)

## Step 4: Verify the Connection to Hack The Box
After connecting via OpenVPN, check your IP address to confirm you are connected to the HTB network:

```
ifconfig
```
The output should display an IP address associated with the HTB network at tun0.

Log in to your Hack The Box account, navigate to the Active Machines section, and select a machine to start practicing.
Click on the "Click here to spawn the target system!"

![image](https://github.com/user-attachments/assets/4b0db762-ca4e-4547-8244-12af8f7eb8c8)

When target spawning is done, you'll see something like this

![image](https://github.com/user-attachments/assets/90c6017b-39eb-4333-8661-88601fd0d54d)

Copy the ip address and open a new terminal. Type the following commands
```
ssh -v htb-student@ipaddress
```
Replace the ip address with the provided one in htb machine after spawning is done.
Type the password shown below

![image](https://github.com/user-attachments/assets/07fea90f-f52c-4938-a709-81d42fb52737)

You will see something like this when the connection is established

![image](https://github.com/user-attachments/assets/c06ceae2-c1d3-4190-965d-c48a9c04abd7)


## Step 5: Troubleshooting Common Issues
If you encounter issues connecting to HTB:

- Ensure that your internet connection is active and stable.
- Verify that the VPN configuration file is not corrupted by redownloading it.
- Check the OpenVPN logs for error messages:
```
sudo journalctl -xe
```
- Ensure that no other VPN connections are active during this session.
Conclusion
You are now connected to Hack The Box via Kali Linux! You can start exploring active machines, solving challenges, and honing your penetration testing skills. Happy hacking!

---

**Author**: Iam4lex  
**Connect with me**:  
- [X (Twitter)](https://x.com/stilla1ex)  

Let me know if there are any corrections or mistakes.
