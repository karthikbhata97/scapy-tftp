from scapy.all import *
from threading import Thread
import sys

class TFTPReader:
	def __init__(self, dst, sport, filename):
		self.dst = dst
		self.dport = None
		self.sport = sport
		self.basic_pkt = IP(dst=self.dst)/UDP(sport=self.sport)
		self.block = 1
		self.filename = filename
		self.verbose = False
		with open(self.filename, "w") as f:
			f.write("")

	def finish(self, pkt):
		# since scapy not recognizes recvd tftp, consider op, block (4 bytes) into raw load
		if Raw in pkt and len(pkt[Raw].load) != 516:
			return True
		return False

	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

	def save_data(self, pkt):
		pkt[UDP].dport = 69
		pkt = pkt.__class__(str(pkt))
		if TFTP_DATA in pkt and pkt[TFTP_DATA].block == self.block:
			with open(self.filename, "a") as f:
				f.write(pkt[Raw].load)
			ack = self.basic_pkt
			ack[UDP].dport = pkt[UDP].sport
			ack_pkt = ack/TFTP(op=04)/TFTP_ACK(block=self.block)
			send(ack_pkt, verbose=self.verbose)
			self.block += 1

	def listen(self):
		sniff(prn=self.save_data, lfilter=self.sniff_filter,  stop_filter=self.finish)


class TFTPWriter:
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

	def finish(self, pkt):
		if self.block == len(self.data_list) + 1:
			return True
		return False

	def sniff_filter(self, pkt):
		return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

	def send_data(self):
		data_pkt = self.basic_pkt
		data_pkt[UDP].dport = self.dport
		for i in range(1, len(self.data_list)+1):
			DATA = data_pkt/TFTP(op=03)/TFTP_DATA(block=i)/Raw(load=self.data_list[i-1])
			send(DATA, verbose=self.verbose)
			# setup a timer 
			while self.block == i:
				pass

	def recv_ack(self, pkt):
		pkt[UDP].dport = 69
		pkt = pkt.__class__(str(pkt))
		if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.block:
			self.block += 1

	def listen(self):
		sniff(prn=self.recv_ack, lfilter=self.sniff_filter,  stop_filter=self.finish)



class TFTPClient:
	def __init__(self, dst):
		self.mode = "octet"
		self.dst = dst
		self.dport = 69
		self.sport = random.randint(1024, 65535)
		self.basic_pkt = IP(dst=self.dst)/UDP(sport=self.sport, dport=self.dport)
		self.verbose = False

	def interactive(self):
		inp = None
		while True:
			sys.stdout.write(">> ")
			inp = raw_input().split(' ')
			if len(inp) == 1:
				inp.append(None)
			self.run_command(inp[0], inp[1])
			print "Done"

	def run_command(self, command, filename=None):
		if command == 'get':
			RRQ = self.basic_pkt/TFTP(op=01)/TFTP_RRQ(filename=filename, mode=self.mode)
			read_obj = TFTPReader(self.dst, self.sport, filename)
			read_thread = Thread(target=read_obj.listen)
			read_thread.start()
			send(RRQ, verbose=self.verbose)
			read_thread.join()						
		elif command == 'put':
			WRQ = self.basic_pkt/TFTP(op=02)/TFTP_RRQ(filename=filename, mode=self.mode)
			reply = None
			while not reply:
				reply = sr1(WRQ, timeout=2, verbose=self.verbose)
			dport = reply[UDP].sport
			write_obj = TFTPWriter(self.dst, self.sport, dport, filename)
			write_thread = Thread(target=write_obj.listen)
			write_thread.start()
			write_obj.send_data()
			write_thread.join()
		else:
			pass



tftp = TFTPClient(sys.argv[1])
# tftp.run_command('get', 'idk')
# tftp.run_command('put', 'idk.pcap')
tftp.interactive()