# TFTP client using scapy

### Requirements
* Scapy on Python2.7
* Update iptables to prevent sending RST
  ```
  bash update_iptables.sh
  ``` 

#### Python Dependencies:
	* netifaces

# TFTP client using scapy
usage:
```
sudo python2.7 client.py [-h] [-6] -p PORT -i IPADDR [-si SOURCE_IP] [-sp SOURCE_PORT] [--iface IFACE] [-m MULTIPLE]
```

eg: sudo python2.7 client.py -p 31337 -i 172.17.1.125 --iface eth0

Help:
```
Arguments:
  -h, --help            show this help message and exit
  
  -6, --ipv6            Connect to a IPv6 TFTP server
  
  -p PORT, --port PORT  TFTP server port number
  
  -i IPADDR, --ipaddr IPADDR
                        TFTP server ip address
  
  -si SOURCE_IP, --source_ip SOURCE_IP
                        client ip address
  
  -sp SOURCE_PORT, --source_port SOURCE_PORT
                        client port
  
  --iface IFACE         Interface of which the client should put the packets

  -m MULTIPLE, --multiple MULTIPLE
                        Open given number of connections to TFTP server
                        Commands are entered comma seperated command list in interactive input mode. `exit` to end.
                        Eg: >>> get one,get two
```

Use ```get``` and ```put``` to share  files between client and server.


# TFTP server using scapy

usage:
```
sudo python2.7 server.py [-h] [-6] [-p PORT] [-i IPADDR] [--iface IFACE]
```
eg: sudo python2.7 server.py -p 31337 --iface eth0

Help:
```
Arguments:
  -h, --help            show this help message and exit
 
  -6, --ipv6            Run tftp server on IPv6 mode
 
  -p PORT, --port PORT  Run tftp server given port. default: 69
 
  -i IPADDR, --ipaddr IPADDR
                        Run tftp server given IP.
 
  --iface IFACE         Interface as source IP.
```

