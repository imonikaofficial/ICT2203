from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt 
import os,time,datetime
def monitor_mode():
    global interface
    print( "Step 1: Choose an interface to put in 'monitor mode'.\n")
    empty = input ("Press enter to continue...\n")
    os.system('ifconfig')
    interface = input("Please enter the interface name you want to put in 'monitor mode': ")
    # Put the interface you have chosen  in 'monitor mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')
    os.system('airmon-ng start wlan0')
    # os.system('iwconfig') #check

### After defense, switch back the interface to 'managed mode'.
def managed_mode():
    print( "\n Step 3: Put the interface back in 'managed mode'. \n")
    empty = input ("Press Enter in order to put " + interface + " in 'managed mode' .........\n")
    # Put the choosen interface back in 'managed mode'
    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode managed')
    os.system('ifconfig ' + interface + ' up')
    os.system('airmon-ng stop wlan0mon')
    print("The interface: " + interface + ", is now in Managed Mode. \nYou can check it here : \n")
    os.system('iwconfig')


def deathentication_check():

    print("Step 3: Sniffing the packets and checking for deauthentication attack. \n")
    print("In case that will be sniffed 30 packets which contains deauthentication layer, you will alerted that there is attempt to do deathentication attack to the access point you choose. \n")
    empty = input ("Press Enter to continue...\n")
    print("Sniffing packets now ...")

    # Sniffing packets - search for the packets that are sent to the  choosen AP
    sniff(iface=interface, prn = detect_deauth_attack , stop_filter=stopfilter)

### sniff(..., prn = packet_handler, ...)
### The argument 'prn' allows us to pass a function that executes with each packet sniffed.
count = 0
def detect_deauth_attack(pkt):
    global count
	# Deauthentication  attack detecting function
    if pkt.haslayer(Dot11Deauth):
                count=count+1
		# Analyzing if packet contain Deauth layer
                time=datetime.datetime.today()
		# Generating timestamp
                a= '[' + str(count) + ']'  +  ' [ ' + str(time)+ ']'+  'Deauthentication Attack Detected Against Mac Address: ' + str(pkt.addr2).swapcase()
                print(a)
### Stop condition for sniffing the deauthentication packets
def stopfilter(x):
	# If there was attempt to do deathentication attack, we stop the packets sniffing and alerts the user about it
	if count==30:
		print( "WARNNING!! There is an attempt to do deathentication attack on your network. \n")
		return True
	else:
		return False



if __name__ == "__main__":

	if os.geteuid():
		sys.exit('Please run as root')

	### Step 1:  Choosing an interface to put in 'monitor mode'.
	monitor_mode()

	### Step 2: Sniffing the packets and checking for deauthentication attack.
	deathentication_check()

	### Step 3: Put the interface back in 'managed mode'.
	managed_mode()

