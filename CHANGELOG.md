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

## Repository changelog
commit a3fdcf4862d726a540021da41b686fcea478a6ed
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 20:27:44 2023 +0200

    feat: Added LICENSE file

commit aacf4a82679a5036bd92ddbaf79bf24f09573929
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 20:23:23 2023 +0200

    fix: Ctrl C handling adjustment, Readme: Added sources

commit b966d0b0670778ec5b10f7b9606e78844300c7ce
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 20:05:02 2023 +0200

    feat: help printout added

commit 396e6e262ab8db6f6eff0bbe111640cd33b8dead
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 19:50:52 2023 +0200

    feat: Makefile update

commit e913184470cef0876565ef497667370b8774f686
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 19:50:09 2023 +0200

    fix: updated project structure and Makefile to comply with the assignment

commit cf60f94f8d81d3e8dc361df6792c34afb9956ec0
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 19:48:39 2023 +0200

    fix: Updated error handling and filter generating

commit 807badc723de44f50f4bd43aae902d86021512ac
Author: xblask05 <xblask05@noreply.%(DOMAIN)s>
Date:   Mon Apr 17 11:32:28 2023 +0200

    revert 2ef63975aced1b44deada9d2433579a9efe59f7d
    
    revert Remove before change to .NET 3.1 core app

commit 2ef63975aced1b44deada9d2433579a9efe59f7d
Author: xblask05 <xblask05@vutbr.cz>
Date:   Mon Apr 17 10:22:37 2023 +0200

    Remove before change to .NET 3.1 core app

commit 82c05664bd9c8023b19532ab551b88eb8d3a2927
Author: xblask05 <xblask05@vutbr.cz>
Date:   Sun Apr 16 20:00:21 2023 +0200

    feat: Added sniffer programs

commit 62c55ec7a72baaf18e4f49f65cd0f60ff1e8fbb0
Author: xblask05 <xblask05@stud.fit.vutbr.cz>
Date:   Sun Apr 16 19:59:13 2023 +0200

    first commit
