#!/bin/bash
# Installer for thoth 
echo "" 

#Verify root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo "Press ENTER to continue, CTRL+C to abort."
read INPUT
touch targets
echo "" 
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt autoclean -y
apt install nmap netdiscover git screen -y
apt update -y
apt upgrade -y
git clone https://github.com/vulnersCom/nmap-vulners.git
mv nmap-vulners/http-vulners-regex.nse /usr/share/nmap/scripts/
mv nmap-vulners/http-vulners-regex.json /usr/share/nmap/nselib/data/
mv nmap-vulners/http-vulners-paths.txt /usr/share/nmap/nselib/data/
mv nmap-vulners/vulners.nse /usr/share/nmap/scripts/
nmap --script-updatedb
cp /etc/rc.local /etc/rc.local.backup
cp /etc/rc.local /etc/rc.local.tmp
sed -i '/exit 0/d' /etc/rc.local
echo "cd /home/pi/thoth && sudo python3 /home/pi/thoth/thoth.py" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
echo "Making sure NIC is set to eth0"
cp /lib/udev/rules.d/73-usb-net-by-mac.rules /lib/udev/rules.d/73-usb-net-by-mac.rules.backup
sed -i 's/$env{ID_NET_NAME_MAC}/eth0/g' /lib/udev/rules.d/73-usb-net-by-mac.rules
echo "DONE"
reboot --
