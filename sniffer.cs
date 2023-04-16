using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;


namespace ipk_sniffer
{
    public class Sniffer
    {
        private static int _packetNum = 1; //Number of packets specified in arguments
        private static int _capturedNum; //Current number of captured packets
        private static ICaptureDevice _captureDevice;
        
        private static void Main(string[] args)
        {
            //Call argument parser
            var arguments = new ArgParser(args);
            var devices = CaptureDeviceList.Instance;
            //Assign defined number of packets to be captured to a variable
            _packetNum = arguments.PacketNum;
            //No devices
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            //Print Devices//
            //Device not specified in -i/--interface argument
            //Exit program after device printout
            if (arguments.Device == null)
            {
                //Error if interface not specified but other parameters specified
                if (arguments.AnyTrue())
                {
                    Console.WriteLine("Filter parameters specified with no interface specified");
                    //EXIT
                }
                //Print devices
                foreach (var device in devices.OfType<LibPcapLiveDevice>())
                {
                    Console.WriteLine($"{device.Interface.Name}");
                }
                //EXIT Program
                return;
            }
            //Device is specified in arguments
            int i = 0;
            int deviceIndex = -1;
            if (arguments.Device != null)
            {
                foreach (var device in devices.OfType<LibPcapLiveDevice>())
                {
                    if (arguments.Device == device.Name)
                    {
                        deviceIndex = i;
                    }
                    i++;
                }
                if (deviceIndex == -1)
                {
                    Console.WriteLine("ERROR: Nonexistent interface specified");
                    Environment.Exit(-1);
                }
            }
            //Ctrl C handling
            //Reference: https://github.com/dotpcap/packetnet/blob/master/Examples/CapturingAndParsingPackets/Main.cs 
            Console.CancelKeyPress += HandleCancelKeyPress;
            

            //Reference: SharpPcap Github repository
            //https://github.com/dotpcap/sharppcap/blob/master/Examples/Example5.PcapFilter/Program.cs
            //Timeout for packet capturing
            int readTimeoutMilliseconds = 1000;
            _captureDevice = devices[deviceIndex];
            _captureDevice.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            _captureDevice.Filter = FilterConstructor(arguments);
            _captureDevice.OnPacketArrival += device_OnPacketArrival;
            _captureDevice.StartCapture();
        }
        
        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var rawPacket = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            var timeStamp = e.Packet.Timeval.Date.ToString("yyyy-MM-dd'T'HH\\:mm\\:ss.fffzzz");
            var frameLength = e.Packet.Data.Length;

            //Transport data read
            
            var transportPacket = rawPacket.Extract<TransportPacket>();
            if (transportPacket != null)
            {
                var ethernetPacket = rawPacket.Extract<EthernetPacket>();
                var ipPacket = (IPPacket)transportPacket.ParentPacket;
                PrintHeader(timeStamp, FormattedMac(ethernetPacket.SourceHardwareAddress), FormattedMac(ethernetPacket.DestinationHardwareAddress),
                    frameLength, ipPacket.SourceAddress, ipPacket.DestinationAddress, transportPacket.SourcePort,
                    transportPacket.DestinationPort);
            }
            //ARP data read
            var arpPacket = rawPacket.Extract<ArpPacket>();
            if (arpPacket != null)
            {
                PrintHeader(timeStamp, FormattedMac(arpPacket.SenderHardwareAddress), FormattedMac(arpPacket.TargetHardwareAddress), frameLength, 
                    arpPacket.SenderProtocolAddress, arpPacket.TargetProtocolAddress);
            }
            
            //ICMP/IGMP data read
            var icmp4Packet = rawPacket.Extract<IcmpV4Packet>();
            var icmp6Packet = rawPacket.Extract<IcmpV6Packet>();
            var igmpPacket = rawPacket.Extract<IgmpV2Packet>();
            if (icmp4Packet != null || icmp6Packet != null || igmpPacket != null)
            {
                var ethernetPacket = rawPacket.Extract<EthernetPacket>();
                var ipPacket = rawPacket.Extract<IPPacket>();
                PrintHeader(timeStamp, FormattedMac(ethernetPacket.SourceHardwareAddress), FormattedMac(ethernetPacket.DestinationHardwareAddress),
                    frameLength, ipPacket.SourceAddress, ipPacket.DestinationAddress);
            }
            
            //Print packet data in HEX
            PrintData(rawPacket.BytesSegment.Bytes);
            
            //Reached defined number of captured packets
            _capturedNum += 1;
            if (_capturedNum == _packetNum)
            {
                _captureDevice.StopCapture();
                _captureDevice.Close();
                Environment.Exit(0);
            }

        }
        
        //Construct filter based on given arguments
        private static string FilterConstructor(ArgParser arguments)
        {
            string filter = "";
            if (arguments.Tcp)
            {
                if (arguments.Port != null)
                {
                    filter += $"(ip or ip6 and tcp and {arguments.Port}) or ";
                }
                else
                {
                    filter += "(ip or ip6 and tcp) or ";
                }
            }

            if (arguments.Udp)
            {
                if (arguments.Port != null)
                {
                    filter += $"(ip or ip6 and udp and {arguments.Port}) or ";
                }
                else
                {
                    filter += "(ip or ip6 and udp) or ";
                }
            }

            if (arguments.Arp)
            {
                filter += "(arp) or ";
            }

            if (arguments.Ndp)
            {
                filter += "(ndp) or ";
            }

            if (arguments.Mld)
            {
                filter += "(mld) or ";
            }

            if (arguments.Igmp)
            {
                filter += "(igmp) or ";
            }

            if (arguments.Icmp4)
            {
                filter += "(icmp) or ";
            }

            if (arguments.Icmp6)
            {
                filter += "(icmp6) or ";
            }

            //Remove the redundant " or " from the filter
            if (filter != "")
            {
                filter = filter.Substring(0, (filter.Length - 4));
            }
            return filter;
        }
        
        private static void PrintHeader(string timeStamp, string srcMac, string dstMac, int frameLength,
            IPAddress srcIp, IPAddress dstIp, int srcPort = -1, int dstPort = -1)
        {
            Console.WriteLine($"timestamp: {timeStamp}");
            Console.WriteLine($"src MAC: {srcMac}");
            Console.WriteLine($"dst MAC: {dstMac}");
            Console.WriteLine($"frame length: {frameLength} bytes");
            Console.WriteLine($"src IP: {srcIp}");
            Console.WriteLine($"dst IP: {dstIp}");
            //Only print ports if specified
            if (srcPort != -1)
            {
                Console.WriteLine($"src port: {srcPort}");
            }
            if (dstPort != -1)
            {
                Console.WriteLine($"dst port: {dstPort}"); 
            }
            
        }

        //Prints the payload of the packet in bytes (Offset + 16 bytes a line in HEX)
        private static void PrintData(byte[] bytes)
        {
            int countTo16 = 0;
            string hexBytes = "";
            string asciiBytes = "";
            for (int i = 0; i < bytes.Length; i++)
            {
                if (countTo16 == 0)
                {
                    Console.Write($"0x{i:X4}: "); //Print byte offset
                }

                hexBytes += $"{bytes[i]:X2} ";
                if (bytes[i] < 32 || bytes[i] > 126)
                {
                    asciiBytes += "."; //Non-printable char
                }
                else
                {
                    asciiBytes += $"{(char)bytes[i]}";
                }
                countTo16++;
                if (countTo16 == 16 || i == bytes.Length-1)
                {
                    countTo16 = 0;
                    Console.Write($"{hexBytes} {asciiBytes}\n");
                    hexBytes = "";
                    asciiBytes = "";
                }
            }
        }

        static string FormattedMac(PhysicalAddress mac)
        {
            string macString = "";
            for (int i = 0; i < mac.ToString().Length; i++)
            {
                if (i % 2 == 0 && i != 0)
                {
                    macString += ":";
                }
                macString += mac.ToString()[i];
            }

            return macString;
        }

        //Stop capturing packets when Ctrl+C is pressed
        static void HandleCancelKeyPress(object? sender, ConsoleCancelEventArgs e)
        {
            _captureDevice.StopCapture();
            _captureDevice.Close();
            Console.WriteLine("Packet sniffing aborted");
            Environment.Exit(0);
        }
    }
    
}