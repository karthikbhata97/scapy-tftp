import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from threading import Thread
import sys
import os.path
import argparse

# For a get request, TFTPReader class will listen and store the file
class TFTPReader:
	# Initializing fields
	def __init__(self, dst, sport, dport, filename):
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(dst=self.dst)/UDP(sport=self.sport)
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
		return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

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
		else:
			print "No such file"

	# Sniff the packets
	def listen(self):
		sniff(prn=self.save_data, lfilter=self.sniff_filter,  stop_filter=self.finish)


# Send file to the server
class TFTPWriter:
	# initialize variables
	def __init__(self, dst, sport, dport, filename):
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(dst=self.dst)/UDP(sport=self.sport)
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
		return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

	# Send the file block by block
	def send_data(self):
		data_pkt = self.basic_pkt
		data_pkt[UDP].dport = self.dport
		for i in range(1, len(self.data_list)+1):
			DATA = data_pkt/TFTP(op=03)/TFTP_DATA(block=i)/Raw(load=self.data_list[i-1])
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
	def __init__(self, dst, dport):
		self.mode = "octet"
		self.dst = dst
		self.dport = dport
		self.sport = random.randint(1024, 65535)
		self.basic_pkt = IP(dst=self.dst)/UDP(sport=self.sport, dport=self.dport)
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
			read_obj = TFTPReader(self.dst, self.sport, self.dport, filename)
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
			write_obj = TFTPWriter(self.dst, self.sport, dport, filename)
			write_thread = Thread(target=write_obj.listen)
			write_thread.start()
			write_obj.send_data()
			write_thread.join()
		else:
			pass



if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-6', '--ipv6', help='Connect to a IPv6 TFTP server', action='store_true')
	parser.add_argument('-p', '--port', help='TFTP server port number', default=69, type=int, nargs=1, required=True)
	parser.add_argument('-i', '--ipaddr', help='TFTP server ip address', type=str, nargs=1, required=True)
	args = parser.parse_args()
	if args.ipv6:
		IP = IPv6
	print args.ipaddr[0], args.port[0]
	tftp = TFTPClient(args.ipaddr[0], args.port[0])
	tftp.interactive()