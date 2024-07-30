import os
import sys
import subprocess
import time
sys.path.insert(1, f'{os.getcwd()}/src')
from changemode import ChangeMode # type: ignore
from ewil_twin_captive_portal_type1 import EwilTwin1 # type: ignore
from evil_twin_type2 import EvilTwin2 # type: ignore
from evil_twin_type3 import EvilTwin3 # type: ignore
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET

error_raise = 0
def banner():
    print(f"{RED}         Welcome to EthHacks Wireless Attacks Toolkit         {RESET}")
    print(f"""{RED}
     ______ _   _     _    _            _        
    |  ____| | | |   | |  | |          | |       
    | |__  | |_| |__ | |__| | __ _  ___| | _____ {RESET}{BLUE}
    |  __| | __| '_ \|  __  |/ _` |/ __| |/ / __|
    | |____| |_| | | | |  | | (_| | (__|   <\___ {RESET}{GREEN}
    |______|\__|_| |_|_|  |_|\__,_|\___|_|\_\___|
        {RESET}""")
    print("\n")
    print("----------------------------------------------------------------------------")


def help_function():
    print("\t\t\tHELP MENU")
    print(f"""
\n\t\t{RED}EthHacks Wireless Toolkit{RESET}

{GREEN}An open source Wireless Attacks Toolkit could be used to practice different types Wireless Attacks and provide awareness. It is created for educational purpose only.

- Language: Python 3

- Operating System type : Linux

- Tested On: Kali Linux 2024
{RESET}

{BLUE}--> Requirements:{RESET}

{GREEN}The Wireless-Toolkit folder contains  "requirements.txt" file. Its contains all the required python libraries for this tool.
Install them manualy by using:{RESET}

Bash Command: sudo pip3 install [library]

{GREEN}OR use the requirements.txt file and install as:{RESET}

Bash Command: sudo pip3 install -r requirements.txt


{BLUE}--> Features:{RESET}

* Change Mode of Wireless Adaptor:
{GREEN}It can be used to change the mode of Wireless adaptor from managed to monitor or monitor to managed accordingly.
{RESET}
* Evil Twin type 1:

{GREEN}Evil Twin attack type 1 against a target network will perform Deauthentication attack on target network and will create a Rogue Access Point that will redirect to captive portal when user try to connect. There will be a lot of option for different captive portal which are listed in captive portal portion. It will then capture all the usernames or password that different use to login to captive portal. It run continounsly and capture usernames and password until attack is closed by presses "CTRL+C" twice.

( Note: It is recommended to use 2 Wireless Adaptors, one for Rogue Access Point and Second for Deauthentication attack and capturing data.)
{RESET}
* Evil Twin type 2:

{GREEN}Evil Twin attack type 2 is used to capture the password of target network. After selecting the target network, It will capture the handshake file. It the start deauthentication attack on target network and will start the Rogue Access Point that will redirect all users that try to connect to captive portal. It will capture usernames and password and will try to verify the password of target network using handshake file and when correct password is found, attack will be closed and will show the correct password.

( Note: It is recommended to use 2 Wireless Adaptors, one for Rogue Access Point and Second for Deauthentication attack and capturing data.)
{RESET}
* Evil Twin type 3:

{GREEN}Evil Twin type 3 is to create a Rogue Access Point either of a target network by Deauthenticating the target point or just a random network. It will provide internet to user connected to rogue Access Point. It will capture data that user access or visit through this rogue Access Point. It can also created WPA2 encrypted Rogue Access Point.

( Note: It is recommended to use different Wireless Adaptors for Rogue Access Point, Deauthentication attack and providing internet.)
{RESET}
* Captive Portal:
{GREEN}
Captive Portal menu is used in Evil Twin type 1 and Evil Twin type 2.Captive Portal menu include 4 different method to setup the captive portal.
   1. Captive Portal of Login Page of Website using URL:
It requires the url of login page of target website to create the captive portal exactly similar to that login page. It will also ask for name, it could be random and is just to differentiate websites with different name in apache2 folder.

     Note: You must be connected to internet to create captive portal with url. Captive portal of some websites like FaceBook or Google could not be created using url. So, try using already created captive portal of famous websites.
   
   2. Captive Portal Of Wifi network:
If your target network is open network and have captive portal for authentication, then you can use this option. It will create captive portal look exactly similar to the captive portal of target network.
   
   3. Captive portal of famous websites:
It include login pages of 43 famous websites. By selecting one of these,it will create captive portal of that login page of website.
   
   4. Want to place your own portal files:
If you want to place captive portal created by you, then use this option. First place your captive portal files in a folder and place this folder in "/var/www/html" folder. It will list all folders present in "/var/www/hrml". Select your folder and it will create captive portal using it.  
{RESET}

{BLUE}--> Usage/Installation
{RESET}{GREEN}
After installing the requirements using "requirements.txt". Run the program using following command:
{RESET}

Bash Command: sudo python3 main.py


{GREEN}First program will try to install the required linux tools. It will try to install these using "apt" manager. It your linux don't have "apt" manager then try to install below listed tools manually as without these tools it will not work.

- Aircrack-ng
- Apache2
- Iptables
- Hostapd
- Dnsmasq
{RESET}
"""
    )





os.system("clear")
banner()
print("[!!] Checking for required tools and installing them: ------")

result = subprocess.run("aircrack-ng", shell=True, capture_output=True, text=True)
if "not found" in result.stderr and "aircrack-ng" in result.stderr:
    print("[-] Aircrack-ng is not installed. Installing aircrack-ng: Wait-----")
    result = subprocess.run("apt install aircrack-ng -y", shell=True, capture_output=True, text=True)
    result = subprocess.run("aircrack-ng", shell=True, capture_output=True, text=True)
    if "not found" in result.stderr and "aircrack-ng" in result.stderr:
        print("[-] Could not install Aircrack-ng: Install it manaully -----")
        error_raise += 1
    else:
        print("[+] Aircrack-ng is successfully installed!!!!")
else:
    print("[+] Aircrack-ng is already installed!!!!")

result = subprocess.run("dnsmasq --help", shell=True, capture_output=True, text=True)
if "not found" in result.stderr and "dnsmasq" in result.stderr:
    print("[-] Dnsmasq is not installed. Installing dnsmasq: -----")
    result = subprocess.run("apt install dnsmasq -y", shell=True, capture_output=True, text=True)
    result = subprocess.run("dnsmasq --help", shell=True, capture_output=True, text=True)
    if "not found" in result.stderr and "dnsmasq" in result.stderr:
        print("[-] Could not install dnsmasq: Install it manaully -----")
        error_raise += 1
    else:
        print("[+] Dnsmasq is successfully installed!!!!")
else:
    print("[+] Dnsmasq is already installed!!!!")

result = subprocess.run("hostapd -help", shell=True, capture_output=True, text=True)
if "not found" in result.stderr and "hostapd" in result.stderr:
    print("[-] Hostapd is not installed. Installing hostapd: -----")
    result = subprocess.run("apt install hostapd -y", shell=True, capture_output=True, text=True)
    result = subprocess.run("hostapd -help", shell=True, capture_output=True, text=True)
    if "not found" in result.stderr and "hostapd" in result.stderr:
        print("[-] Could not install hostapd: Install it manaully -----")
        error_raise += 1
    else:
        print("[+] Hostapd is successfully installed!!!!")
else:
    print("[+] Hostapd is already installed!!!!")

result = subprocess.run("iptables --help", shell=True, capture_output=True, text=True)
if "not found" in result.stderr and "iptables" in result.stderr:
    print("[-] Iptables is not installed. Installing iptables: -----")
    result = subprocess.run("apt install iptables -y", shell=True, capture_output=True, text=True)
    result = subprocess.run("iptables --help", shell=True, capture_output=True, text=True)
    if "not found" in result.stderr and "iptables" in result.stderr:
        print("[-] Could not install iptables: Install it manaully -----")
        error_raise += 1
    else:
        print("[+] Iptables is successfully installed!!!!")
else:
    print("[+] Iptables is already installed!!!!")

result = subprocess.run("apaches2 -help", shell=True, capture_output=True, text=True)
if "not found" in result.stderr and "apache2" in result.stderr:
    print("[-] Apache2 is not installed. Installing apache2: -----")
    result = subprocess.run("apt install apache2 -y", shell=True, capture_output=True, text=True)
    result = subprocess.run("apache2 -help", shell=True, capture_output=True, text=True)
    if "not found" in result.stderr and "apache2" in result.stderr:
        print("[-] Could not install apache2: Install it manaully -----")
        error_raise += 1
    else:
        print("[+] Apache2 is successfully installed!!!!")
else:
    print("[+] Apache2 is already installed!!!!")


print("[!!] Killing processess that could cause error and Flushing Iptables....")
result = subprocess.run("killall hostapd", shell=True, capture_output=True, text=True)
result = subprocess.run("killall dnsmasq", shell=True, capture_output=True, text=True)
result = subprocess.run("killall aireplay-ng", shell=True, capture_output=True, text=True)
result = subprocess.run("iptables --flush", shell=True, capture_output=True, text=True)
result = subprocess.run("iptables --table nat --flush", shell=True, capture_output=True, text=True)
result = subprocess.run("iptables --delete-chain", shell=True, capture_output=True, text=True)
result = subprocess.run("iptables --table nat --delete-chain", shell=True, capture_output=True, text=True)

time.sleep(2)
if error_raise == 0:
    ON = True

    while ON:
        os.system("clear")
        banner()
        print(f"{GREEN}0. Change Mode of Wireless Adapter")
        print("1. Evil twin with captive portal. Type 1  (DEAUTH Target + Rogue Access Point with Captive portal + Sniff Login Details)")
        print("2. Evil Twin. Type 2  (Capture Target WiFI Password using Captive Portal)")
        print("3. Evil Twin. Type 3  (Rogue Access Point with internet + Sniff Data)")
        print("4. Help")
        print("5. Exit")
        option = input(f"Select the option by typing corresponding index number: 0-3 --> {RESET}")
        if option == "5" or option == "exit" or option == "Exit":
            ON = False
        elif option == "0":
            changewirelessmode = ChangeMode()
            changewirelessmode.changemodes()
        elif option == "1":
            ewiltwin1 = EwilTwin1()
        elif option == "2":
            eviltwin2 = EvilTwin2()
        elif option == "3":
            eviltwin2 = EvilTwin3()
        elif option == "4" or option == "help" or option == "Help" or option == "HELP":        
            try:
                os.system("clear")
                help_function()
                check_exit = input("\n\nType 'y' or 'exit' to exit out of help menu --> " ).lower
                if check_exit == "y" or check_exit == "exit":
                    pass
            except KeyboardInterrupt:
                pass
            
else:
    print(f"\n\n [-] {str(error_raise)} no of tools that must be installed are not installed. Please Install these tool manually and then run this tool again.")


