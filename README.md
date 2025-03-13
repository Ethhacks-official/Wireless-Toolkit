
# EthHacks Wireless Toolkit

An open source Wireless Attacks Toolkit could be used to practice different types Wireless Attacks and provide awareness. It is created for educational purpose only.

- Language: Python 3

- Operating System type : Linux

- Tested On: Kali Linux 2024


## Requirements
The Wireless-Toolkit folder contains  "requirements.txt" file. Its contains all the required python libraries for this tool.
Install them manualy by using:
```bash
sudo pip3 install [library]
```
OR use the requirements.txt file and install as:
```bash
sudo pip3 install -r requirements.txt
```

## Features

- Change Mode of Wireless Adaptor:
It can be used to change the mode of Wireless adaptor from managed to monitor or monitor to managed accordingly.
- Change Mac Address of Wireless Adaptor:
It can be used to change the mac address of Wireless adaptor. It have two option either change mac address to new mac address provided by you or new mac address similar to mac address or bssid of target network. For second option, tool will list the surronding networks and after selecting the target network, it will convert the mac address of adapter to the mac address or bssid of selected target network.
- Evil Twin type 1:

Evil Twin attack type 1 against a target network will perform Deauthentication attack on target network and will create a Rogue Access Point that will redirect to captive portal when user try to connect. There will be a lot of option for different captive portal which are listed in captive portal portion. It will then capture all the usernames or password that different use to login to captive portal. It run continounsly and capture usernames and password until attack is closed by presses "CTRL+C" twice.

( Note: It is recommended to use 2 Wireless Adaptors, one for Rogue Access Point and Second for Deauthentication attack and capturing data.)
- Evil Twin type 2:

Evil Twin attack type 2 is used to capture the password of target network. After selecting the target network, It will capture the handshake file. It the start deauthentication attack on target network and will start the Rogue Access Point that will redirect all users that try to connect to captive portal. It will capture usernames and password and will try to verify the password of target network using handshake file and when correct password is found, attack will be closed and will show the correct password.

( Note: It is recommended to use 2 Wireless Adaptors, one for Rogue Access Point and Second for Deauthentication attack and capturing data.)
- Evil Twin type 3:

Evil Twin type 3 is to create a Rogue Access Point either of a target network by Deauthenticating the target point or just a random network. It will provide internet to user connected to rogue Access Point. It will capture data that user access or visit through this rogue Access Point. It can also created WPA2 encrypted Rogue Access Point.

( Note: It is recommended to use different Wireless Adaptors for Rogue Access Point, Deauthentication attack and providing internet.)
- Captive Portal:

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

## Usage/Installation

After installing the requirements using "requirements.txt". Run the program using following command:

```bash
sudo python3 main.py
```

First program will try to install the required linux tools. It will try to install these using "apt" manager. It your linux don't have "apt" manager then try to install below listed tools manually as without these tools it will not work.

- Aircrack-ng
- Apache2
- Iptables
- Hostapd
- Dnsmasq

    


## License

This project is licensed under the GNU LESSER GENERAL PUBLIC LICENSE Version 2.1 - see the [LICENSE] file for details.