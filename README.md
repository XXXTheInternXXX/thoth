# thoth
---
A script intended to be installed on a raspberryPi that will sweep the network for targets, run netdiscover to find other devices, and run an NMAP scan on systems to find open ports. The script also uses a "targets" file that it will take custom input from.

The intent of this script is to execute on boot and provide the user with an output of the scan. 

The install script in this repository will also install vulners which will assist in providing potential CVE's that can potentially work against targets servers. 

# Installation
---
Clone the GitHub repository and install in the /home/pi directory the install.sh script should handle the rest please make sure you run **sudo chmod +x install.sh** so the script runs.

# TO-DO
---
* Add capability to connect to an external C&C
* Add ability to detect services (SSH, Telnet, HTTP, HTTPS)
	* Nikto Scans
	* Brute Force
	* Connection verification
* Ability to post data in a better format instead of log file
* Add ability to detect scan failure and resume scans if the system is halted
* Potentially integrate tools like sn1per that handle what I'm trying to do much better
* Create a bind / reverse shell with an external server like a [LAN Turtle](https://shop.hak5.org/products/lan-turtle)