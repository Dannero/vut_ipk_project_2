# IPK 2023 Project 2
### Author: Daniel Blaško (xblask05)
<hr>

## Description
Packet sniffer program for TCP, UDP, ARP, ICMP4/6, IGMP, NDP and MLD packets, built in .NET 6.0.

## How to build and run
```
$ make
$ ./ipk-sniffer [-i | --interface <interface>] {-p <port> [-t | --tcp][-u | --udp]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] [--ndp] {-n <packetNum>} [--help]
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
* `timestamp`    - Time stamp of the packet in RFC 3339 Format
* `src MAC`      - Physical address of the source device
* `dst MAC`      - Physical address of the destination device
* `frame length` - Length of packet in bytes
* `src IP`       - IP address of the source device
* `dst IP`       - IP address of the destination device
* `src port`     - Port of the source device
* `dst port`     - Port of the destination device

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

## Issues
* The packet time stamp is in the UTC+00:00 zone, not the local CEST+02:00 zone

## Testing Examples
OS: NixOS 22.11 (Reference testing machine)\
Platform: AMD64

## Sources
Vladimír Veselý, Project 2 - ZETA: Network sniffer [online]. Publisher: Brno University of Technology, Faculty of Information Technology, April 11th 2023. [cit. 2023-04-17]. Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%202/zeta

Chris Morgan, Ayoub Kaanich, Example3.BasicCap [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example3.BasicCap/Program.cs

Chris Morgan, Ayoub Kaanich, Example5.PcapFilter [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example5.PcapFilter/Program.cs

Chris Morgan, Ayoub Kaanich, Example12.PacketManipulation [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example12.PacketManipulation/Program.cs

Chris Morgan, PhyxionNl, Jan Pluskal, CapturingAndParsingPackets [online]. Publisher: Github, July 15th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/packetnet/blob/master/Examples/CapturingAndParsingPackets/Main.cs 
