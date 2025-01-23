using SPHERE.Blockchain.Client;
using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SPHERE.Blockchain.Client.Packet;


namespace SPHERE.Client
{

    /// <summary>
    /// Used to build a packet by the node to send to the client for sending.  
    /// 
    /// There are a few typs of packets and they are converted into an opcode for the TCP transport. 
    /// 
    /// </summary>
    public class PacketBuilder
    {
        public enum PacketType
        {
            Bootstrap,
            Get,
            Put,
            Ping,
            Update,
            Sync,
        }

        private readonly Dictionary<PacketType, int> PacketTypes = new Dictionary<PacketType, int>
        {
            { PacketType.Bootstrap,1},
            { PacketType.Get,2 },
            { PacketType.Ping,4 },
            { PacketType.Update,5},
            { PacketType.Sync,6},
        };

        MemoryStream _ms;

        public PacketBuilder()
        {
            _ms = new MemoryStream();
        }

        public void WriteOpCode(PacketType packetType)
        {
            _ms.WriteByte(byte.Parse(packetType.ToString()));
        }

        public void WriteMessage(string message)
        {
            var messageLength = message.Length;

            _ms.Write(BitConverter.GetBytes(messageLength), 0, 4);
            _ms.Write(Encoding.ASCII.GetBytes(message), 0, messageLength);

        }

        public Byte[] GetPacketBytes()
        {

            return _ms.ToArray();
        }

        public static Packet BuildPacket(Node sendingNode, string message, string packetType)
        {
            PacketHeader header = new PacketHeader
            {

                NodeId = sendingNode.Header.NodeId,
                IPAddress = sendingNode.Header.NodeIP,
                Port = sendingNode.Header.NodePort.ToString(),
                PublicKey = sendingNode.Header.PublicSignatureKey,
                Packet_Type = packetType.ToString(),
            };

            Packet packet = new Packet
            {
                Header = header,
                Content = message,
                Signature = SignatureGenerator.CreateBlockSignature(sendingNode.Header.NodeId)
            };

            return packet;
        }

        public byte[] SerializePacket(Packet packet)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryWriter writer = new BinaryWriter(ms);

                // Write Opcode
                if (packet.Header.Packet_Type!=null)
                {
                    writer.Write(byte.Parse(packet.Header.Packet_Type.ToString()));
                }
                else
                {
                    throw new ArgumentException($"Unknown Packet_Type: {packet.Header.Packet_Type}");
                }

                // Write Header
                writer.Write(packet.Header.NodeId);
                writer.Write(packet.Header.IPAddress);
                writer.Write(packet.Header.Port);
                writer.Write(packet.Header.PublicKey);

                // Write Content
                writer.Write(packet.Content);

                // Write Signature
                writer.Write(packet.Signature);
                
                return ms.ToArray();
            }
        }


    }



}
