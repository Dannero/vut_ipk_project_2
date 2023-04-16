using System;
using System.Linq;

namespace ipk_sniffer
{
    public class ArgParser
    {
        public string? Device;
        public int? Port;
        public bool Tcp;
        public bool Udp;
        public bool Arp;
        public bool Icmp4;
        public bool Icmp6;
        public bool Ndp;
        public bool Igmp;
        public bool Mld;
        public int PacketNum = 1;

        public bool AnyTrue()
        {
            return new[] { Tcp, Udp, Arp, Icmp4, Icmp6, Ndp, Igmp, Mld }.Any(v => v);
        }

        public ArgParser(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                //HELP PRINTOUT
                if (args[i] == "--help")
                {
                    Console.WriteLine("Usage:");
                    Console.WriteLine("./ipk-sniffer {-i | --interface <interface>} {-p <port>} (-t | --tcp) (-u | --udp) (--arp) (--icmp4) (--icmp6) (--igmp) (--mld) (--ndp) {-n <packetNum>}");
                    Console.WriteLine("-i | --interface <interface> sets the the name of the interface from which the packets will be sniffed. If not specified, a list of all available interfaces will be printed and the program");
                    Console.WriteLine("-p <port>                    sets the port number, if not specified, the whole <0,65536> port band is used.");
                    Console.WriteLine("-t | --tcp                   adds TCP packets to the packet filter.");
                    Console.WriteLine("-u | --udp                   adds UDP packets to the packet filter.");
                    Console.WriteLine("--arp                        adds ARP packets to the packet filter.");
                    Console.WriteLine("--icmp4                      adds ICMP4 packets to the packet filter.");
                    Console.WriteLine("--icmp6                      adds ICMP6 packets to the packet filter.");
                    Console.WriteLine("--igmp                       adds IGMP packets to the packet filter.");
                    Console.WriteLine("--mld                        adds MLD packets to the packet filter.");
                    Console.WriteLine("--ndp                        adds NDP packets to the packet filter.");
                    Console.WriteLine("-n <packetNum>               specifies the number of packets to be caught, defaults to 1 if not specified.");
                    Environment.Exit(0);
                }
                //INTERFACE
                if (args[i] == "-i" || args[i] == "--interface")
                {
                    //Interface specified
                    if ((i + 1) < args.Length && args[i + 1][0] != '-')
                    {
                        this.Device = args[i + 1];
                    }
                }

                //TCP
                if (args[i] == "-t" || args[i] == "--tcp")
                {
                    this.Tcp = true;
                }

                //UDP
                if (args[i] == "-u" || args[i] == "--udp")
                {
                    this.Udp = true;
                }

                //Port 
                if (args[i] == "-p")
                {
                    try
                    {
                        this.Port = Int32.Parse(args[i + 1]);
                    }
                    catch (FormatException)
                    {
                        Console.WriteLine("ERROR: specified port is not an integer");
                        //EXIT
                    }

                    //Invalid port number
                    if (this.Port is < 0 or > 65536)
                    {
                        Console.WriteLine("ERROR: specified port not in range <0,65536>");
                        //EXIT
                    }
                }

                //ARP
                if (args[i] == "--arp")
                {
                    this.Arp = true;
                }

                //ICMP4
                if (args[i] == "--icmp4")
                {
                    this.Icmp4 = true;
                }

                //ICMP6
                if (args[i] == "--icmp6")
                {
                    this.Icmp6 = true;
                }

                //IGMP
                if (args[i] == "--igmp")
                {
                    this.Igmp = true;
                }

                //NDP
                if (args[i] == "--ndp")
                {
                    this.Ndp = true;
                }

                //MLD
                if (args[i] == "--mld")
                {
                    this.Mld = true;
                }

                //Number of packets
                if (args[i] == "-n")
                {
                    try
                    {
                        this.PacketNum = Int32.Parse(args[i + 1]);
                    }
                    catch (FormatException)
                    {
                        Console.WriteLine("ERROR: specified number is not an integer");
                        Environment.Exit(1);
                    }
                }
            }
        }
    }
}