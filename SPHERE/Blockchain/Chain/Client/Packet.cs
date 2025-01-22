using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Blockchain.Client
{


    public class Packet
    {

        public PacketHeader Header;
        public string Content;
        public string Signature;


        public class PacketHeader
        {
            public string NodeId { get; set; }
            public string IPAddress { get; set; }
            public string Port { get; set; }
            public string PublicKey { get; set; }
            public string Packet_Type { get; set; }
        }


        

    }
}
