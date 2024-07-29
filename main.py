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
        print("1. Evil twin with captive portal. Type 1")
        print("2. Evil Twin. Type 2")
        print("3. Evil Twin. Type 3")
        print("4. Exit")
        option = input(f"Select the option by typing corresponding index number: 0-3 --> {RESET}")
        if option == "4" or option == "exit" or option == "Exit":
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
else:
    print(f"\n\n [-] {str(error_raise)} no of tools that must be installed are not installed. Please Install these tool manually and then run this tool again.")
