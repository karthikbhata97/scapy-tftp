import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *
from threading import Thread
import sys
import os.path
import argparse
import netifaces as ni


# Store file sent from the client
class TFTPReader:
    # Initialize fields
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

    # End of transmission of file
    def finish(self, pkt):
        # since scapy not recognizes recvd tftp, consider op, block (4 bytes) into raw load
        if Raw in pkt and len(pkt[Raw].load) != 516:
            return True
        return False

    # Filter on packets to be recieved
    def sniff_filter(self, pkt):
        return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

    # Store data into a file
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

    # Sniff packets
    def listen(self):
        sniff(prn=self.save_data, lfilter=self.sniff_filter,  stop_filter=self.finish)


# Send file to the client
class TFTPWriter:
    # Initialize fields
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

    # End of file transmission
    def finish(self, pkt):
        if self.block == len(self.data_list) + 1:
            return True
        return False

    # Filter on packets to be recieved
    def sniff_filter(self, pkt):
        return pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt[UDP].dport == self.sport

    # Send data to client
    def send_data(self):
        data_pkt = self.basic_pkt
        data_pkt[UDP].dport = self.dport
        for i in range(1, len(self.data_list)+1):
            DATA = data_pkt/TFTP(op=03)/TFTP_DATA(block=i)/Raw(load=self.data_list[i-1])
            send(DATA, verbose=self.verbose)
            # setup a timer 
            while self.block == i:
                pass

    # Recieve ack and increment the block successfully sent
    def recv_ack(self, pkt):
        pkt[UDP].dport = 69 # trick for scapy tp detect as TFTP
        pkt = pkt.__class__(str(pkt))
        if TFTP_ACK in pkt and pkt[TFTP_ACK].block == self.block:
            self.block += 1

    # Sniff packets
    def listen(self):
        sniff(prn=self.recv_ack, lfilter=self.sniff_filter,  stop_filter=self.finish)


# Main server class
class TFTPServer:
    # Initialize the fields
    def __init__(self, ipaddr, sport):
        self.src = ipaddr
        self.sport = sport
        self.verbose = False

    # Upon RRQ, it will create a thread for TFTPWriter
    def read_handler(self, pkt, pdu):

        sp = random.randint(1024, 65535)
        dp = pkt[UDP].sport

        sip = pkt[IP].dst
        dip = pkt[IP].src

        filename = pdu[TFTP_RRQ].filename
        mode = pdu[TFTP_RRQ].mode

        print "Read request from: {}:{}, for file {}".format(sip, sp, filename)

        writer_obj = TFTPWriter(sip, dip, sp, dp, filename, mode)
        write_thread = Thread(target=writer_obj.listen)
        write_thread.start()

        writer_obj.send_data()

        write_thread.join()

    # Upon WRQ it will create a thread for TFTPReader
    def write_handler(self, pkt, pdu):
        sp = random.randint(1024, 65535)
        dp = pkt[UDP].sport

        sip = pkt[IP].dst
        dip = pkt[IP].src
        
        filename = pdu[TFTP_WRQ].filename
        mode = pdu[TFTP_WRQ].mode
        
        ack = IP(src=sip, dst=dip)/UDP(sport=sp, dport=dp)/TFTP(op=04)/TFTP_ACK(block=0)
        
        print "Write request from: {}:{}, for file {}".format(sip, sp, filename)

        read_obj = TFTPReader(sip, dip, sp, dp, filename, mode)
        read_thread = Thread(target=read_obj.listen)
        read_thread.start()
        
        send(ack, verbose=self.verbose)
        
        read_thread.join()	

    # Parse recieved packet for command type
    def action(self, pkt):
        if self.sport == 69: #scapy default
            pdu = pkt[TFTP]
        else:
            pdu = TFTP().__class__(pkt[Raw].load)

        print "Recieved packet"
        if TFTP_RRQ in pdu:
            print "Opening read thread"
            read_thread = Thread(target=self.read_handler, args=(pkt, pdu))
            read_thread.start()
        elif TFTP_WRQ in pdu:
            print "Opening write thread"
            write_thread = Thread(target=self.write_handler, args=(pkt, pdu))
            write_thread.start()
        else:
            pass


    # Filter on packets to be recieved
    def sniff_filter(self, pkt):
        if pkt.haslayer(IP) and pkt.haslayer(UDP) and \
            pkt[IP].dst == self.src and \
            pkt[UDP].dport == self.sport:
            return True
        return False

    # Sniff packets
    def listen(self):
        sniff(prn=self.action, lfilter=self.sniff_filter)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-6', '--ipv6', help='Run tftp server on IPv6 mode', action='store_true')
    parser.add_argument('-p', '--port', nargs=1, help='Run tftp server given port. default: 69', type=int, default=69)
    parser.add_argument('-i', '--ipaddr', nargs=1, help='Run tftp server given IP.', type=str)
    parser.add_argument('--iface', nargs=1, help='Interface as source IP.', type=str)
    args = parser.parse_args()

    if args.ipv6:
        IP = IPv6
    if args.port:
        port = args.port[0]

    if args.iface:
        try:
            if not args.ipv6:
                ipaddr = ni.ifaddresses(args.iface[0])[ni.AF_INET][0]['addr']
            else:
                ipaddr = ni.ifaddresses(args.iface[0])[ni.AF_INET6][0]['addr'].split('%')[0]
        except:
            print 'Invalid interface name', args.iface[0]
            sys.exit(0)
    elif args.ipaddr:
        ipaddr = args.ipaddr[0]
    else:
        print('Specify Interface or IP address')
        sys.exit(0)

    print "{}:{}".format(ipaddr, port)
    tftp = TFTPServer(ipaddr, port)
    tftp.listen()

