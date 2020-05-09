# Thoth
import os
import time
import datetime
import logging
import sys
import socket
import subprocess
import requests
import json
try:
    import RPi.GPIO as gpio
    piEnv = True
except (ImportError, RuntimeError):
    piEnv = False

# Configure Logging 
logging.basicConfig(format='[%(asctime)s]-%(message)s]\n', datefmt='%m-%d-%Y %H:%M:%S')
hostFileTime = time.strftime("%m-%d-%Y %H:%M:%S")
now      = datetime.datetime.now()
scanTime = now.strftime('%m_%d_%Y') 
try: 
    logger = logging.getLogger('thothLog')
    hdlr = logging.FileHandler('thothLog.log')
    formatter = logging.Formatter('[%(asctime)s]-%(message)s]\n', datefmt='%m-%d-%Y %H:%M:%S')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)
except Exception as e:
	os.system('touch {0} thothLog.log'.format(getTime))
	logger.info("[-] AN ERROR OCCURED: " + str(e))
	logger.info("[+] New log file created")
	logger.info("[+]***RESTARTING***")
	os.system('python3 thoth.py')

# Every possible netmask, used as a reference set
netmasks     = ['255.255.255.252', '255.255.255.248', '255.255.255.240','255.255.255.224','255.255.255.192','255.255.255.128','255.255.255.0','255.255.254.0','255.255.252.0','255.255.248.0','255.255.240.0','255.255.224.0','255.255.192.0','255.255.128.0','255.255.0.0']

# Every possible CIDR notation, used as a reference set
cidrNotation = ['/30', '/29', '/28', '/27', '/26', '/25', '/24', '/23', '/22', '/21', '/20', '/19', '/18', '/17', '/16']

# Common DNS servers to check for connectivity
commonDns    = ['208.67.222.222','208.67.220.220','1.1.1.1','8.8.8.8','1.0.0.1','8.8.4.4','199.85.126.10','199.85.127.10','8.26.56.26','9.9.9.9','149.112.112.112','64.6.64.6','64.6.65.6']
commonSites  = ['google.com','youtube.com','facebook.com','baidu.com','reddit.com','live.com','office.com','microsoft.com']
ipServices   = ['https://ident.me','https://api.ipify.org/','https://api.myip.com','https://ipapi.co/json','https://api.my-ip.io/ip','https://ip.seeip.org/jsonip']

# The IP, Netmask, and CIDR of the localhost
deviceIp     = []
deviceMask   = []
deviceSubnet = []
devicePublic = []

# Special commands to run during this script, grab the netmask of the eth0 interface and the grep command to pull IPs
cmd     = """ifconfig eth0 | grep netmask | awk \'/netmask/ {print $4;}\'"""
grepCmd = """grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}'"""

# Make sure to run script as root
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script. (Netdiscover / NMAP)")

def asciiArt():
    print ("""
  ________          __  __  
 /_  __/ /_  ____  / /_/ /_ 
  / / / __ \/ __ \/ __/ __ \\
 / / / / / / /_/ / /_/ / / /
/_/ /_/ /_/\____/\__/_/ /_/""")

# Make sure device is booted, since this script will start on boot, this will give the device some time to simmer. 
def patience():
    try:
        logger.info("[+] Waiting 30 seconds before starting")
        time.sleep(30)
        pass
    except KeyboardInterrupt:
        logger.info("[-] Script stopped by user")
        exit()

# Making a  ping request to common DNS servers to test if we can ping out
def testPing():
    global goodDns
    internetz = False
    x = 0
    logger.info("[+] Testing connection to the Internet")
    while internetz == False and x != len(commonDns):
        try: 
            logger.info("[*] Pinging a public DNS: {0}".format(commonDns[x]))
            ping_response = os.system("ping -c 7 -W 3 {0}".format(commonDns[x]))
            if ping_response == 0 and x != len(commonDns):
                logger.info("[+] Connection received")
                goodDns = commonDns[x]
                internetz == True
                x = 13
                break
            elif ping_response != 0 and x != len(commonDns) - 1: 
                logger.info('[*] Testing a new server')
                x += 1
            else: 
                logger.info("[-] Network connection failed...")
                logger.info("[-] Sleeping for 5 seconds before restarting...")
                time.sleep(5)
                logger.info("[!] Restarting ")
                python = sys.executable
                os.execl(python, python, * sys.argv)
        except Exception as e:
            logger.error('[*] An error occurred ' + str(e))
            exit()

# Testing to see if we can resolve a hostname to an IP
def testDns():
    global dnsWorks
    dnsWorks = 0 # If 0 operate without internet, if 1 operate with internet 
    omega = 0
    logger.info("[+] Testing if our device can pull DNS records")
    while omega != len(commonSites):
        try:
            logger.info("[*] Attemtping to gain response from: {0}".format(commonSites[omega]))
            dnsResponse = socket.gethostbyname(commonSites[omega])
            logger.info ('[+] Attained the IP {0} from {1}'.format(dnsResponse,commonSites[omega]))
            dnsWorks = 1
            break
        except:
            logger.info('[-] Unable to obtain an IP for {0}'.format(commonSites[omega]))
            omega += 1
            pass

# Ping the good boy domain so we can get our NIC IP
def getIP():
    # Get the IP address of the NIC connected to the internet
    logger.info('[+] Attempting to get our NIC address')
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((goodDns, 80))
    deviceIp.append(s.getsockname()[0])
    logger.info('[+] Success. Our interface address is: {0}'.format(deviceIp[0]))
    s.close()

# Finding the network mask that was given to the device which will help in the future
def getNetMask(): 
    #Getting the network mask so the subnet can be identified
    deviceMaskResult = (subprocess.check_output(cmd, shell=True))
    deviceMask.append(deviceMaskResult.strip().decode('utf-8'))
    logger.info('[+] Our netmask is: {0}'.format(deviceMask[0]))

# Find if the netmask matches the indexes and then find the corresponding CIDR notation
def getSubnet():
    findNetmasks = netmasks.index((deviceMask[0]))
    if findNetmasks > -1:
        correctNotation = cidrNotation[findNetmasks]
        deviceSubnet.append(correctNotation)
        logger.info("[+] The subnet for our device is: {0}".format(deviceSubnet[0]))
    else:
        logger.error("[!] Subnet not found in list...")
        logger.info("[-] Sleeping for 5 seconds before restarting...")
        time.sleep(5)
        logger.info("[!] Restarting")
        python = sys.executable
        os.execl(python, python, * sys.argv)

# Gathering public IP data 
def whoAreWe():
    serviceChoice = 0
    if dnsWorks == 1:
        logger.info('[+] Attempting to gather public IP')
        while serviceChoice != len(ipServices):
            logger.info('[+] Listening for response from {0}'.format(ipServices[serviceChoice]))
            urlResponse = requests.get(ipServices[serviceChoice])
            if urlResponse != '<Response [200]>':
                logger.info('[+] Successfully connected to target server')
                siteResponse = str(urlResponse.content.strip().decode('utf-8'))
                if serviceChoice == 0 or serviceChoice == 1 or serviceChoice == 4:
                    logger.info('[+] Our public address is: {0}'.format(siteResponse))
                    devicePublic.append(siteResponse)
                    break
                else:
                    ip_json_data = json.loads(siteResponse)
                    siteResponse = ip_json_data
                    logger.info('[+] Our public address is: {0}'.format(ip_json_data['ip']))
                    devicePublic.append(ip_json_data['ip'])
                    break
            else: 
                logger.info('[-] Unable to connect to target server, trying new target in 3 seconds')
                time.sleep(3)
                serviceChoice += 1
    elif dnsWorks == 0:
        logger.info('[+] Skipping since there is no DNS connection')
    else:
        logger.error('[-] Something went very wrong here')

def beanCounter(fname):
    try:
        with open(fname) as f:
            for i, l in enumerate(f):
                pass
        return i + 1
    except UnboundLocalError:
        return 0
        pass

def scanLocalSubnet():
    logger.info('[+] Running the following command \'nmap -sn {0}{1} --exclude {2} -oG pingSweep\''.format(deviceIp[0],deviceSubnet[0],deviceIp[0]))
    os.system('nmap -sn {0}{1} --exclude {2} -oG pingSweep'.format(deviceIp[0],deviceSubnet[0],deviceIp[0]))
    logger.info('[+] Writing hosts that are up to a new file')
    os.system('cat pingSweep | grep -v {0} | {1} > dedupeMe'.format(deviceIp[0],grepCmd))
    logger.info('[+] Ping sweep detected {0} host(s) to scan'.format(beanCounter('dedupeMe')))
    
# Parse the list and remove duplicates 
def targetedAttack():
    xray = beanCounter('targets')
    if xray == 0:
        logger.info('[*] There are 0 specific host(s) in target file, continuing')
    elif xray != 0:
        logger.info('[*] There are {0} specific host(s) in target file'.format(xray))
        os.system('cat targets >> dedupeMe')
        logger.info('[+] Updated target list there are now {0} host(s) to scan'.format(beanCounter('dedupeMe')))
    else:
        logger.error('[-] Hope is lost')

# Active an active scan from netdiscover and find new hosts to scan
def unknownWorlds():
    logger.info('[+] Running netdiscover to find new devices')
    os.system('netdiscover -r 10.0.0.0/8,192.168.0.0/16,172.16.0.0/12 -P > ndResults')
    os.system("""cat ndResults | {0} | awk '!a[$0]++' >> dedupeMe""".format(grepCmd))
    logger.info('[+] Updated target list there are now {0} host(s) to scan'.format(beanCounter('dedupeMe')))

def goTime():
    # Start the scan
    os.system("""cat dedupeMe | awk '!a[$0]++' >> scanMe""".format(grepCmd))
    logger.info('[+] Removed duplicate targets from file there are now {0} host(s) to scan'.format(beanCounter('scanMe')))
    logger.info('[+] Running scan against the target list')
    os.system('sudo nmap -sV -A -O -iL scanMe -oN scanResults')

def scanFinish():
    # Since this is the raspberry pi we will flash the onboard LED. 
    logger.info("[!!!] THE GREEN LED WILL BLINK, THE SCANS ARE FINISHED [!!!]")
    os.system('modprobe ledtrig_heartbeat')
    os.system('echo heartbeat > /sys/class/leds/led0/trigger')

def packingUp():
    # Clean up messy files and put results into directory
    logger.info('[+] Loading files into a nice little folder')
    try:
        os.system('rm dedupeMe ; mkdir loot ; mkdir loot/{0} ; mkdir loot/{0}/RAW_DATA ; mv ndResults pingSweep scanMe targets thothLog.log loot/{0}/RAW_DATA/ ; mv scanResults loot/{0}/ ;touch targets'.format(scanTime))
    except: 
        pass
    logger.info('[+] Scan complete')

asciiArt()
patience()
testPing()
testDns()
getIP()
getNetMask()
getSubnet()
whoAreWe()
scanLocalSubnet()
targetedAttack()
unknownWorlds()
goTime()
if piEnv == True:
    logger.info('[+] Script is running on a pi, executing LED script')    
    scanFinish()
packingUp()