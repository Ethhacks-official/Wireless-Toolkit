import subprocess
import os
from sources import Sources
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET

class ChangeMode:
    def __init__(self):
        None               
                    
    def changemodes(self):
        wireless_interface = Sources().selectadapter()
        mode = Sources().checkmode(wireless_interface)
        if mode == "Managed":
            change_mode = input(f"\n{GREEN}Your selected wireless adaptar is in managed mode. Do you want to change it to monitor mode: y/n --> {RESET}").lower()
            if change_mode == "y":
                self.changetomonitormode(wireless_interface)

        elif mode == "Monitor":
            change_mode = input(f"\n{GREEN}Your selected wireless adaptar is in monitor mode. Do you want to change it to managed mode: y/n --> {RESET}").lower()
            if change_mode == "y":
                self.changetomanagedmode(wireless_interface)

    def changetomanagedmode(self, wireless_interface):
        wireless_interface2_manufacturer = Sources().get_interface_menufacturer_name(wireless_interface)
        wireless_interface2_mac_address = Sources().get_dev_path(wireless_interface)
        ifindex = Sources().get_ifindex(wireless_interface)
        print(f"\n{BLUE}[-][-]Changing mode of {wireless_interface} to Managed mode...{RESET}")
        result = subprocess.run(f"ifconfig {wireless_interface} down", shell=True, capture_output=True, text=True)
        result = subprocess.run(f"airmon-ng stop {wireless_interface}", shell=True, capture_output=True, text=True)
        result = subprocess.run("service NetworkManager restart", shell=True, capture_output=True, text=True)
        list_of_interfaces = Sources().listinterfaces()
        os.system("clear")
        for interface in list_of_interfaces:
            if (wireless_interface2_mac_address == Sources().get_dev_path(interface) or ifindex == Sources().get_ifindex(interface)) and wireless_interface2_manufacturer == Sources().get_interface_menufacturer_name(interface) and Sources().checkmode(interface) == "Managed":
                wireless_interface = interface
        mode = Sources().checkmode(wireless_interface)
        if mode == "Managed":
            print(f"\n{BLUE}[+][+]Your wireless adapter mode is successfully changed to 'Managed'.{RESET}")
            return wireless_interface
        else:
            print(f"\n{RED}[-][-] Due to some issues, Your wireless adapter mode could not changed to 'Managed' using aircrack-ng tool. Trying different way !!.{RESET}")
            print(f"\n{BLUE}[-][-]Changing mode of {wireless_interface} to Managed mode...{RESET}")
            result = subprocess.run(f"ifconfig {wireless_interface} down", shell=True, capture_output=True, text=True)
            result = subprocess.run(f"iwconfig {wireless_interface} mode managed", shell=True, capture_output=True, text=True)
            result = subprocess.run(f"ifconfig {wireless_interface} up", shell=True, capture_output=True, text=True)
            for interface in list_of_interfaces:
                if (wireless_interface2_mac_address == Sources().get_dev_path(interface) or ifindex == Sources().get_ifindex(interface)) and wireless_interface2_manufacturer == Sources().get_interface_menufacturer_name(interface) and Sources().checkmode(interface) == "Managed":
                    wireless_interface = interface
            mode = Sources().checkmode(wireless_interface)
            if mode == "Managed":
                print(f"\n{BLUE}[+][+]Your wireless adapter mode is successfully changed to 'Managed'.{RESET}")
                return wireless_interface
            else:
                print(f"\n{RED}[-][-] Due to some issues, Your wireless adapter mode could not changed to 'Managed'. Trying Again !!.{RESET}")
                self.changetomanagedmode(wireless_interface)

    def changetomonitormode(self, wireless_interface):
        wireless_interface2_manufacturer = Sources().get_interface_menufacturer_name(wireless_interface)
        wireless_interface2_mac_address = Sources().get_dev_path(wireless_interface)
        ifindex = Sources().get_ifindex(wireless_interface)
        print(f"\n{BLUE}[-][-]Changing mode of {wireless_interface} to Monitor mode...{RESET}")
        result = subprocess.run(f"ifconfig {wireless_interface} down", shell=True, capture_output=True, text=True)
        result = subprocess.run("airmon-ng check kill", shell=True, capture_output=True, text=True)
        result = subprocess.run(f"airmon-ng start {wireless_interface}", shell=True, capture_output=True, text=True)
        result = subprocess.run("service NetworkManager restart", shell=True, capture_output=True, text=True)
        list_of_interfaces = Sources().listinterfaces()
        os.system("clear")
        for interface in list_of_interfaces:
            if (wireless_interface2_mac_address == Sources().get_dev_path(interface) or ifindex == Sources().get_ifindex(interface)) and wireless_interface2_manufacturer == Sources().get_interface_menufacturer_name(interface) and Sources().checkmode(interface) == "Monitor":
                wireless_interface = interface
        mode = Sources().checkmode(wireless_interface)
        if mode == "Monitor":
            print(f"\n{BLUE}[+][+]Your wireless adapter mode is successfully changed to 'Monitor'.{RESET}")
            return wireless_interface
        else:
            print(f"\n{RED}[-][-] Due to some issues, Your wireless adapter mode could not changed to 'Monitor' using aircrack-ng tool. Trying different way !!.{RESET}")
            print(f"\n{BLUE}[-][-]Changing mode of {wireless_interface} to Managed mode...{RESET}")
            result = subprocess.run(f"ifconfig {wireless_interface} down", shell=True, capture_output=True, text=True)
            result = subprocess.run(f"iwconfig {wireless_interface} mode monitor", shell=True, capture_output=True, text=True)
            result = subprocess.run(f"ifconfig {wireless_interface} up", shell=True, capture_output=True, text=True)
            for interface in list_of_interfaces:
                if (wireless_interface2_mac_address == Sources().get_dev_path(interface) or ifindex == Sources().get_ifindex(interface)) and wireless_interface2_manufacturer == Sources().get_interface_menufacturer_name(interface) and Sources().checkmode(interface) == "Monitor":
                    wireless_interface = interface
            mode = Sources().checkmode(wireless_interface)
            if mode == "Monitor":
                print(f"\n{BLUE}[+][+]Your wireless adapter mode is successfully changed to 'Monitor'.{RESET}")
                return wireless_interface
            else:
                print(f"\n{RED}[-][-] Due to some issues, Your wireless adapter mode could not changed to 'Monitor'. Trying Again !!.{RESET}")
                self.changetomonitormode(wireless_interface)


