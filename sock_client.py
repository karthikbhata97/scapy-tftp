import socket
from scapy.all import *
import sys
import os.path

class TFTPClient:
    def __init__(self, addr):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # create a UDP socket
        self.server = addr
        self.mode = "netascii"

    def file_append(self, filename, data):
        with open(filename, "a") as f:
            f.write(data)
        
    def interactive():
        pass
        
    def read_data(self, filename):
        with open(filename, "w") as f:
            f.write("")
        PDU = TFTP(op=01)/TFTP_RRQ(filename=filename, mode=self.mode)
        self.sock.sendto(str(PDU), self.server)
        blk = 1
        blksz = 512
        data = dict()
        while blksz == 512: # change to conditional later
            recv_PDU, addr = self.sock.recvfrom(1024) # 512 + 4 is enough
            recv_PDU = TFTP().__class__(recv_PDU)
            if TFTP_DATA in recv_PDU:
                if blk == recv_PDU[TFTP_DATA].block:
                    self.file_append(filename, recv_PDU[Raw].load)
                    blk += 1
                    blksz = len(recv_PDU[Raw].load)
                else:
                    data[recv_PDU[TFTP_DATA].block] = recv_PDU[Raw].load
            elif TFTP_ERROR in recv_PDU:
                print recv_PDU[TFTP_ERROR].errormsg
                return
            else:
                pass #error
            while blk in data:
                self.file_append(filename, data[blk])
                blk += 1


    def write_data(filename):
        pass
    
    def run(self, command):
        if command[0] == 'get':
            self.read_data(command[1])
        elif command[0] == 'put':
            self.write_data(command[1])
        else:
            pass
        
if __name__ == '__main__':
    addr = ("172.17.9.169",69)
    dude  = TFTPClient(addr)
    dude.run(('get', 'an0ne'))
