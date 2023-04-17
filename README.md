# IPK 2023 Project 2
### Author: Daniel Blaško (xblask05)
<hr>

## Description
Packet sniffer program for TCP, UDP, ARP, ICMP4/6, IGMP, NDP and MLD packets, built in .NET 6.0.

## How to build and run
```
$ make
$ ./out/ipk-sniffer [-i | --interface <interface>] {-p <port> [-t | --tcp][-u | --udp]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [--ndp] {-n <packetNum>} [--help]
```
(Needs root privileges to run correctly, argument order is interchangeable).
`$ make clean` to delete build files.

* `-i | --interface <interface>` sets the the name of the interface from which the packets will be sniffed. If not specified, a list of all available interfaces will be printed and the program will terminate.
* `-p <port>` sets the port number, if not specified, the whole <0,65536> port band is used.
* `-t | --tcp` adds TCP packets to the packet filter.
* `-u | --udp` adds UDP packets to the packet filter.
* `--arp` adds ARP packets to the packet filter.
* `--icmp4` adds ICMP4 packets to the packet filter.
* `--icmp6` adds ICMP6 packets to the packet filter.
* `--igmp` adds IGMP packets to the packet filter.
* `--mld` adds MLD packets to the packet filter.
* `--ndp` adds IGMP packets to the packet filter.
* `-n <packetNum>` specifies the number of packets to be caught, defaults to 1 if not specified.
* `--help` prints out Usage guide for the program

## Used NuGet packages
SharpPcap 5.4.0 (https://github.com/dotpcap/sharppcap)

## Implementation details
The program consists of two files, `argParce.cs`, the function of which is to parse input arguments and hand them over to `sniffer.cs`. If the interface has not been specified, this code prints out a list of all network interfaces and terminates. If the interface has been specified, a packet filter is created based on input arguments and the device is opened for packet sniffing. The `SharpPcap` NuGet functions `ParsePacket` parses the raw packet, which is then extracted by the `Extract` function based on the packet type. The packet header is printed out with the following data, if present in the packet: 
* timestamp
* src MAC
* dst MAC
* frame length
* src IP
* dst IP
* src port
* dst port\
After that, the packet payload is printed in HEX and ASCII. When a specified or default number of packets has been caught, the program ceases its function. 
The program's source code is object oriented and contains the two following classes with their respective attributes and methods: 
* class `ArgParser`:
    * Attributes:
        `Device`, `Port`, `Tcp`, `Udp`, `Arp`, `Icmp4`, `Icmp6`, `Ndp`, `Igmp`, `Mld`, `PacketNum`
    * Methods:
        `AnyTrue`, `ArgParser`
* class `Sniffer`:
    * Attributes:
        `_packetNum`, `_capturedNum`, `_captureDevice`
    * Methods:
        `Main`, `DeviceOnPacketArrival`, `FilterConstructor`, `PrintHeader`, `PrintData`, `FormattedMac`, `HandleCancelKeyPress`