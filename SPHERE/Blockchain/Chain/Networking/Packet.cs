using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SPHERE.Networking.PacketBuilder;

namespace SPHERE.Networking
{ 

    /// <summary>
    /// A packet is just what it says it is created by a node to be sent by the client to another node. 
    /// The signature is made with the nodes private signature. 
    /// the reciever can use this and the included node ID and public key to verify the signature. 
    /// 
    /// </summary>
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


        public Packet BuildPacketContent(string content)
        {
            Packet packet = new Packet();
            packet.Content = content;
            packet.Header = Header;
            
            return new Packet();
        }

        public static PacketType ParsePacketType(string type)
        {
            Enum.TryParse(type, out PacketType parsedEnum);
            return parsedEnum;
        }

    }
}
