import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from threading import Thread
import sys
import os.path
import argparse
import netifaces as ni

# For a get request, TFTPReader class will listen and store the file
class TFTPReader:
	# Initializing fields
	def __init__(self, src, dst, sport, dport, filename):
		self.src = src
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(src=self.src, dst=self.dst)/UDP(sport=self.sport)
		self.block = 1
		self.filename = filename
		self.verbose = False
		with open(self.filename, "w") as f:
			f.write("")

	# End of file transmission
	def finish(self, pkt):
		# since scapy not recognizes recvd tftp, consider op, block (4 bytes) into raw load
		if Raw in pkt and len(pkt[Raw].load) != 516:
			return True
		return False

	# Filter on the packets to be recieved
	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and self.src == pkt[IP].dst and self.dst == pkt[IP].src and \
		pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

	# Save data into file
	def save_data(self, pkt):
		pkt[UDP].dport = 69
		pkt = pkt.__class__(str(pkt))
		if TFTP_DATA in pkt and pkt[TFTP_DATA].block == self.block and Raw in pkt:
			with open(self.filename, "a") as f:
				f.write(pkt[Raw].load)
			ack = self.basic_pkt
			ack[UDP].dport = pkt[UDP].sport
			ack_pkt = ack/TFTP(op=04)/TFTP_ACK(block=self.block)
			send(ack_pkt, verbose=self.verbose)
			self.block += 1
		elif TFTP_DATA in pkt and pkt[TFTP_DATA].block <= self.block:
			pass
		else:
			print "No such file"

	# Sniff the packets
	def listen(self):
		sniff(prn=self.save_data, lfilter=self.sniff_filter,  stop_filter=self.finish)


# Send file to the server
class TFTPWriter:
	# initialize variables
	def __init__(self, src, dst, sport, dport, filename):
		self.src = src
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(src=self.src, dst=self.dst)/UDP(dport=self.dport, sport=self.sport)
		self.block = 1
		self.filename = filename
		self.verbose = False
		with open(self.filename, "r") as f:
			data = f.read()
			self.data_list = [data[i:i+512] for i in range(0, len(data), 512)]

	# End of file transmission
	def finish(self, pkt):
		if self.block == len(self.data_list) + 1:
			return True
		return False

	# Filter on packets to be recieved
	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt[IP].src == self.dst and pkt[IP].dst == self.src and \
			pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

	# Send the file block by block
	def send_data(self):
		for i in range(1, len(self.data_list)+1):
			DATA = self.basic_pkt/TFTP(op=03)/TFTP_DATA(block=i)/Raw(load=self.data_list[i-1])
			send(DATA, verbose=self.verbose)
			# setup a timer 
			while self.block == i:
				pass

	# Recieve acknowledgement and increment successfully sent blocks
	def recv_ack(self, pkt):
		pkt[UDP].dport = 69
		pkt = pkt.__class__(str(pkt))
		if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.block:
			self.block += 1
		elif TFTP_ERROR in pkt:
			print pkt[TFTP_ERROR].errmsg
			sys.exit(0)
		else:
			pkt.dump()

	# Sniff packets
	def listen(self):
		sniff(prn=self.recv_ack, lfilter=self.sniff_filter,  stop_filter=self.finish)


# Main client class
class TFTPClient:
	# Initialize fields
	def __init__(self, src, dst, sport, dport):
		self.mode = "octet"
		self.src = src
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(src=self.src, dst=self.dst)/UDP(sport=self.sport, dport=self.dport)
		self.verbose = False

	# Interactive shell
	def interactive(self):
		inp = ""
		while "exit" not in inp:
			sys.stdout.write(">> ")
			inp = raw_input().split(' ')
			if len(inp) == 1:
				inp.append(None)
			self.run_command(inp[0], inp[1])
			print "Done"

	# Manages commands recieved from the terminal
	def run_command(self, command, filename=None):
		if command == 'get':
			RRQ = self.basic_pkt/TFTP(op=01)/TFTP_RRQ(filename=filename, mode=self.mode)
			read_obj = TFTPReader(self.src, self.dst, self.sport, self.dport, filename)
			read_thread = Thread(target=read_obj.listen)
			read_thread.start()
			send(RRQ, verbose=self.verbose)
			read_thread.join()						
		elif command == 'put':
			if not os.path.isfile(filename):
				print "No such file"
				return
			WRQ = self.basic_pkt/TFTP(op=02)/TFTP_RRQ(filename=filename, mode=self.mode)
			reply = None
			while not reply:
				reply = sr1(WRQ, timeout=2, verbose=self.verbose)
			reply[UDP].dport = 69
			reply = reply.__class__(str(reply))
			if TFTP_ERROR in reply:
				print reply[TFTP_ERROR].errormsg
				sys.exit(0)
			dport = reply[UDP].sport			
			write_obj = TFTPWriter(self.src, self.dst, self.sport, dport, filename)
			write_thread = Thread(target=write_obj.listen)
			write_thread.start()
			write_obj.send_data()
			write_thread.join()
		else:
			pass



if __name__ == '__main__':

	def manage_multiple(n):
		ports = []
		for i in range(n):
			p = random.randint(1024, 65535)
			while p in ports:
				p = random.randint(1024, 65535)
			ports.append(p)
		clients = []
		for i in range(n):
			c = TFTPClient(source_ip, dest_ip, ports[i], dest_port)
			clients.append(c)

		while True:
			sys.stdout.write(">> ")
			inp = raw_input().split(' ')
			if inp == 'exit':
				return
			if len(inp) == 1:
				inp.append(None)
			run_cmd_multiple(clients, n, inp)

	def run_cmd_multiple(clients, n, cmd):
		threads = []
		for i in range(n):
			t = Thread(target=clients[i].run_command, args=(cmd[0], cmd[1],))
			t.start()
			threads.append(t)
		for i in range(n):
			threads[i].join()	

	parser = argparse.ArgumentParser()
	parser.add_argument('-6', '--ipv6', help='Connect to a IPv6 TFTP server', action='store_true')
	parser.add_argument('-p', '--port', help='TFTP server port number', default=69, type=int, nargs=1, required=True)
	parser.add_argument('-i', '--ipaddr', help='TFTP server ip address', type=str, nargs=1, required=True)
	parser.add_argument('-si', '--source_ip', help='client ip address', nargs=1, type=str, required=False)
	parser.add_argument('-sp', '--source_port', help='client port', nargs=1, type=int, required=False)
	parser.add_argument('--iface', help='Interface of which the client should put the packets', nargs=1, type=str, required=False)
	parser.add_argument('-m', '--multiple', help='Open given number of connections to FTP server', nargs=1, type=int)
	args = parser.parse_args()

	if args.ipv6:
		IP = IPv6

	if not args.source_ip and not args.iface:
		print 'Either specify source ip and port or give interface to be used'
		sys.exit(0)

	if args.source_ip:
		if not args.source_port:
			print 'Source port not found'
			sys.exit(0)
		source_ip = args.source_ip[0]
		source_port = args.source_port[0]
	else:
		try:
			if not args.ipv6:
				source_ip = ni.ifaddresses(args.iface[0])[ni.AF_INET][0]['addr']
			else:
				source_ip = ni.ifaddresses(args.iface[0])[ni.AF_INET6][0]['addr'].split('%')[0]
			source_port = random.randint(1024, 65535)
		except:
			print 'Invalid interface name', args.iface[0]
			sys.exit(0)

	dest_ip = args.ipaddr[0]
	dest_port = args.port[0]

	print source_ip
	print dest_ip

	if args.multiple:
		n = args.multiple[0]
		manage_multiple(n)
	else:
		tftp = TFTPClient(source_ip, dest_ip, source_port, dest_port)
		tftp.interactive()