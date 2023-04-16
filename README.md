# IPK 2023 Project 2
### Author: Daniel Blaško (xblask05)
<hr>

##Description
Packet sniffer program for TCP, UDP, ARP, ICMP4/6, IGMP, NDP and MLD packets.

## How to build and run
```
$ make
$ ./out/ipk-sniffer {-i | --interface <interface>} {-p <port>} (-t | --tcp) (-u | --udp) (--arp) (--icmp4) (--icmp6) (--igmp) (--mld) (--ndp)
```
(Needs sudo rights, argument order is interchangeable)
`$ make clean` to delete build files

## Used NuGet packages
SharpPcap 5.4.0 (https://github.com/dotpcap/sharppcap)
