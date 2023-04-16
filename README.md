# IPK 2023 Project 2
### Author: Daniel Blaško (xblask05)
<hr>

## Description
Packet sniffer program for TCP, UDP, ARP, ICMP4/6, IGMP, NDP and MLD packets, built in .NET 6.0.

## How to build and run
```
$ make
$ ./out/ipk-sniffer {-i | --interface <interface>} {-p <port>} (-t | --tcp) (-u | --udp) (--arp) (--icmp4) (--icmp6) (--igmp) (--mld) (--ndp) {-n <packetNum>}
```
(Needs sudo rights, argument order is interchangeable).
`$ make clean` to delete build files

*`-i | --interface <interface>` sets the the name of the interface from which the packets will be sniffed. If not specified, a list of all available interfaces will be printed and the program will terminate.
*`-p <port>` sets the port number, if not specified, the whole <0,65536> port band is used.
*`-t | --tcp` adds TCP packets to the packet filter.
*`-u | --udp` adds UDP packets to the packet filter.
*`--arp` adds ARP packets to the packet filter.
*`--icmp4` adds ICMP4 packets to the packet filter.
*`--icmp6` adds ICMP6 packets to the packet filter.
*`--igmp` adds IGMP packets to the packet filter.
*`--mld` adds MLD packets to the packet filter.
*`--ndp` adds IGMP packets to the packet filter.
*`-n <packetNum>` specifies the number of packets to be caught, defaults to 1 if not specified.



## Used NuGet packages
SharpPcap 5.4.0 (https://github.com/dotpcap/sharppcap)
