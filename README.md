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

### Test 1: Print out all interfaces
* Input: `./ipk-sniffer -i`
* Output: 
    ```
    enp0s3
    any
    lo

    nflog
    nfqueue
    ```
* Wireshark output:
    ```
    enp0s3
    any
    Loopback: lo
    bluetooth-monitor
    nflog
    nfqueue
    ```
* Note: The program prints the same number of interfaces, but prints the name of bluetooth-monitor as an empty string (bluetooth-monitor name was displayed normally while testing in Ubuntu 22.04)

### Test 2: Print one packet on enp0s3, no filter
* Input: `./ipk-sniffer -i enp0s3`
* Output:  
    ```
    timestamp: 2023-04-17T16:25:15.756+00:00
    src MAC: 08:00:27:56:aa:92
    dst MAC: 52:54:00:12:35:02
    frame length: 98 bytes
    src IP: 10.0.2.15
    dst IP: 142.251.37.110

    0x0000: 52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00  RT..5...'V....E.
    0x0010: 00 54 4b c7 40 00 40 01 2e 6a 0a 00 02 0f 8e fb  .TK.@.@..j......
    0x0020: 25 6e 08 00 54 c5 00 05 00 01 eb 72 3d 64 00 00  %n..T......r=d..
    0x0030: 00 00 b0 8a 0b 00 00 00 00 00 10 11 12 13 14 15  ................
    0x0040: 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25  .......... !"#$%
    0x0050: 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35  &'()*+,-./012345
    0x0060: 36 37                                            67
    ```

* Wireshark output:
    ```
    Frame 1: 98 bytes on wire (784 bits), 98 bytes captured (784 bits) on interface enp0s3, id 0
    Ethernet II, Src: PcsCompu_56:aa:92 (08:00:27:56:aa:92), Dst: RealtekU_12:35:02 (52:54:00:12:35:02)
    Internet Protocol Version 4, Src: 10.0.2.15, Dst: 142.251.37.110
    Internet Control Message Protocol

    0000   52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00   RT..5...'V....E.
    0010   00 54 4b c7 40 00 40 01 2e 6a 0a 00 02 0f 8e fb   .TK.@.@..j......
    0020   25 6e 08 00 54 c5 00 05 00 01 eb 72 3d 64 00 00   %n..T......r=d..
    0030   00 00 b0 8a 0b 00 00 00 00 00 10 11 12 13 14 15   ................
    0040   16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25   .......... !"#$%
    0050   26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35   &'()*+,-./012345
    0060   36 37                                             67
    ```

### Test 3: Print one packet on enp0s3, TCP filter
* Input: `./ipk-sniffer -i enp0s3 -t`
* Output:
    ```
    timestamp: 2023-04-17T16:31:15.238+00:00
    src MAC: 08:00:27:56:aa:92
    dst MAC: 52:54:00:12:35:02
    frame length: 54 bytes
    src IP: 10.0.2.15
    dst IP: 51.144.164.215
    src port: 38250
    dst port: 443

    0x0000: 52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00  RT..5...'V....E.
    0x0010: 00 28 4d be 40 00 40 06 08 9c 0a 00 02 0f 33 90  .(M.@.@.......3.
    0x0020: a4 d7 95 6a 01 bb b8 ca 1c 80 0b 96 e6 8f 50 10  ...j..........P.
    0x0030: f5 3c e4 90 00 00                                .<....
    ```

* Wireshark output: 
    ```
    Frame 21: 54 bytes on wire (432 bits), 54 bytes captured (432 bits) on interface enp0s3, id 0
    Ethernet II, Src: PcsCompu_56:aa:92 (08:00:27:56:aa:92), Dst: RealtekU_12:35:02 (52:54:00:12:35:02)
    Internet Protocol Version 4, Src: 10.0.2.15, Dst: 51.144.164.215
    Transmission Control Protocol, Src Port: 38250, Dst Port: 443, Seq: 1, Ack: 1, Len: 0

    0000   52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00   RT..5...'V....E.
    0010   00 28 4d be 40 00 40 06 08 9c 0a 00 02 0f 33 90   .(M.@.@.......3.
    0020   a4 d7 95 6a 01 bb b8 ca 1c 80 0b 96 e6 8f 50 10   ...j..........P.
    0030   f5 3c e4 90 00 00                                 .<....
    ```

### Test 4: Print two packets on enp0s3, TCP and ARP filter
* Input: `./ipk-sniffer -i enp0s3 -t --arp`
* Output:
    ```
    timestamp: 2023-04-17T16:46:29.659+00:00
    src MAC: 08:00:27:56:aa:92
    dst MAC: 52:54:00:12:35:02
    frame length: 74 bytes
    src IP: 10.0.2.15
    dst IP: 104.208.16.88
    src port: 35804
    dst port: 443

    0x0000: 52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00  RT..5...'V....E.
    0x0010: 00 3c 94 8a 40 00 40 06 20 fb 0a 00 02 0f 68 d0  .<..@.@. .....h.
    0x0020: 10 58 8b dc 01 bb d1 5a 54 e7 00 00 00 00 a0 02  .X.....ZT.......
    0x0030: fa f0 85 65 00 00 02 04 05 b4 04 02 08 0a 8f 2b  ...e...........+
    0x0040: 38 ad 00 00 00 00 01 03 03 07                    8.........

    timestamp: 2023-04-17T16:46:29.788+00:00
    src MAC: 52:54:00:12:35:02
    dst MAC: 08:00:27:56:aa:92
    frame length: 58 bytes
    src IP: 104.208.16.88
    dst IP: 10.0.2.15
    src port: 443
    dst port: 35804

    0x0000: 08 00 27 56 aa 92 52 54 00 12 35 02 08 00 45 00  ..'V..RT..5...E.
    0x0010: 00 2c 1a e9 00 00 40 06 da ac 68 d0 10 58 0a 00  .,....@...h..X..
    0x0020: 02 0f 01 bb 8b dc 12 e1 fc 01 d1 5a 54 e8 60 12  ...........ZT.`.
    0x0030: ff ff 50 22 00 00 02 04 05 b4                    ..P"......
    ```

* Wireshark output: 
    ```
    Frame 11: 74 bytes on wire (592 bits), 74 bytes captured (592 bits) on interface enp0s3, id 0
    Ethernet II, Src: PcsCompu_56:aa:92 (08:00:27:56:aa:92), Dst: RealtekU_12:35:02 (52:54:00:12:35:02)
    Internet Protocol Version 4, Src: 10.0.2.15, Dst: 104.208.16.88
    Transmission Control Protocol, Src Port: 35804, Dst Port: 443, Seq: 0, Len: 0

    0000   52 54 00 12 35 02 08 00 27 56 aa 92 08 00 45 00   RT..5...'V....E.
    0010   00 3c 94 8a 40 00 40 06 20 fb 0a 00 02 0f 68 d0   .<..@.@. .....h.
    0020   10 58 8b dc 01 bb d1 5a 54 e7 00 00 00 00 a0 02   .X.....ZT.......
    0030   fa f0 85 65 00 00 02 04 05 b4 04 02 08 0a 8f 2b   ...e...........+
    0040   38 ad 00 00 00 00 01 03 03 07                     8.........

    Frame 12: 58 bytes on wire (464 bits), 58 bytes captured (464 bits) on interface enp0s3, id 0
    Ethernet II, Src: RealtekU_12:35:02 (52:54:00:12:35:02), Dst: PcsCompu_56:aa:92 (08:00:27:56:aa:92)
    Internet Protocol Version 4, Src: 104.208.16.88, Dst: 10.0.2.15
    Transmission Control Protocol, Src Port: 443, Dst Port: 35804, Seq: 0, Ack: 1, Len: 0

    0000   08 00 27 56 aa 92 52 54 00 12 35 02 08 00 45 00   ..'V..RT..5...E.
    0010   00 2c 1a e9 00 00 40 06 da ac 68 d0 10 58 0a 00   .,....@...h..X..
    0020   02 0f 01 bb 8b dc 12 e1 fc 01 d1 5a 54 e8 60 12   ...........ZT.`.
    0030   ff ff 50 22 00 00 02 04 05 b4                     ..P"......
    ```

### Test 5: Incorrect port number specified
* Input: `./ipk-sniffer -i enp0s3 --tcp -p -1`
* Output: `ERROR: specified port not in range <0,65536>`

### Test 6: Incorrect Packet count specified
* Input: `./ipk-sniffer -i enp0s3 -n arg`
* Output: `ERROR: specified packet count is not an integer`

### Test 7: Filter arguments specified with no interface specified
* Input: `./ipk-sniffer --tcp`
* Output: `ERROR: Filter parameters specified with no interface specified`

### Test 8: Nonexistent interface specified
* Input: `./ipk-sniffer -i wrong-interface`
* Output: `ERROR: Nonexistent interface specified`

## Sources
Vladimír Veselý, Project 2 - ZETA: Network sniffer [online]. Publisher: Brno University of Technology, Faculty of Information Technology, April 11th 2023. [cit. 2023-04-17]. Available at: https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%202/zeta

Chris Morgan, Ayoub Kaanich, Example3.BasicCap [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example3.BasicCap/Program.cs

Chris Morgan, Ayoub Kaanich, Example5.PcapFilter [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example5.PcapFilter/Program.cs

Chris Morgan, Ayoub Kaanich, Example12.PacketManipulation [online]. Publisher: Github, May 8th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/sharppcap/blob/master/Examples/Example12.PacketManipulation/Program.cs

Chris Morgan, PhyxionNl, Jan Pluskal, CapturingAndParsingPackets [online]. Publisher: Github, July 15th 2021. [cit. 2023-04-17]. Available at: https://github.com/dotpcap/packetnet/blob/master/Examples/CapturingAndParsingPackets/Main.cs 
