from scapy.all import *
from threading import Thread
import sys
import os.path

class TFTPReader:
	def __init__(self, src, dst, sport, dport, filename, mode):
		self.src = src
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(src=self.src, dst=self.dst)/UDP(sport=self.sport, dport=self.dport)
		self.block = 1
		self.filename = filename
		self.mode = mode
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

	def listen(self):
		sniff(prn=self.save_data, lfilter=self.sniff_filter,  stop_filter=self.finish)


class TFTPWriter:
	def __init__(self, src, dst, sport, dport, filename, mode):
		self.src = src
		self.dst = dst
		self.dport = dport
		self.sport = sport
		self.basic_pkt = IP(src=self.src,dst=self.dst)/UDP(sport=self.sport)
		self.block = 1
		self.filename = filename
		self.mode = mode
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
		pkt[UDP].dport = 69 # trick for scapy tp detect as TFTP
		pkt = pkt.__class__(str(pkt))
		if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.block:
			self.block += 1

	def listen(self):
		sniff(prn=self.recv_ack, lfilter=self.sniff_filter,  stop_filter=self.finish)



class TFTPServer:
	def __init__(self, sport):
		self.sport = sport
		self.verbose = False

	def read_handler(self, pkt, pdu):
		sp = random.randint(1024, 65535)
		dp = pkt[UDP].sport
		sip = pkt[IP].dst
		dip = pkt[IP].src
		filename = pdu[TFTP_RRQ].filename
		mode = pdu[TFTP_RRQ].mode
		writer_obj = TFTPWriter(sip, dip, sp, dp, filename, mode)
		write_thread = Thread(target=writer_obj.listen)
		write_thread.start()
		writer_obj.send_data()
		write_thread.join()

	def write_handler(self, pkt, pdu):
		sp = random.randint(1024, 65535)
		dp = pkt[UDP].sport
		sip = pkt[IP].dst
		dip = pkt[IP].src
		filename = pdu[TFTP_WRQ].filename
		mode = pdu[TFTP_WRQ].mode
		ack = IP(src=sip, dst=dip)/UDP(sport=sp, dport=dp)/TFTP(op=04)/TFTP_ACK(block=0)
		read_obj = TFTPReader(sip, dip, sp, dp, filename, mode)
		read_thread = Thread(target=read_obj.listen)
		read_thread.start()
		send(ack, verbose=self.verbose)
		read_thread.join()	

	def action(self, pkt):
		if self.sport == 69: #scapy default
			pdu = pkt[TFTP]
		else:
			pdu = TFTP().__class__(pkt[Raw].load)

		if TFTP_RRQ in pdu:
			self.read_handler(pkt, pdu)
		elif TFTP_WRQ in pdu:
			self.write_handler(pkt, pdu)
		else:
			pass


	def sniff_filter(self, pkt):
		if pkt.haslayer(UDP) and pkt[UDP].dport == self.sport:
			return True
		return False

	def listen(self):
		sniff(prn=self.action, lfilter=self.sniff_filter)



tftp = TFTPServer(int(sys.argv[1]))
tftp.listen()
# tftp.run_command('get', 'idk')
# tftp.run_command('put', 'idk.pcap')
