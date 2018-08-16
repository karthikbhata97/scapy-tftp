
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo iptables -A OUTPUT -p ICMP --icmp-type port-unreachable -j DROP
sudo /sbin/iptables-save 

sudo ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
sudo ip6tables -A OUTPUT -p ICMPv6 --icmpv6-type port-unreachable -j DROP
sudo /sbin/ip6tables-save

