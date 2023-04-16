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