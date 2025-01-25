
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SPHERE.Blockchain;
using SPHERE.Configure;
using static SPHERE.Networking.Packet;
using static SPHERE.Networking.PacketBuilder;

namespace SPHERE.Networking
{

    /// <summary>
    /// Used to build a packet by the node to send to the client for sending.  
    /// 
    /// There are a few typs of packets and they are converted into an opcode for the TCP transport. 
    /// 
    /// </summary>
    public class PacketBuilder
    {
        public  enum PacketType
        {
            BootstrapRequest,
            BootstrapResponse,
            GetRequest,
            GetResponse,
            PutRequest,
            PutResponse,
            PingRequest,
            PingResponse,
            PeerUpdateRequest,
            PeerUpdateResponse,
            SyncDHTRequest,
            SyncDHTResponse,
        }

        private static readonly Dictionary<PacketType, int> PacketTypes = new Dictionary<PacketType, int>
        {
            { PacketType.BootstrapRequest,1},
            { PacketType.BootstrapResponse,2},
            { PacketType.GetRequest,3 },
            { PacketType.GetResponse,4},
            { PacketType.PutRequest,5},
            { PacketType.PutResponse,6},
            { PacketType.PingRequest,7 },
            { PacketType.PingResponse,8},
            { PacketType.SyncDHTRequest,9},
            { PacketType.SyncDHTResponse,10},
            { PacketType.PeerUpdateRequest,11},
            { PacketType.PeerUpdateResponse,12},

        };

        public static Packet BuildPacket(Node sendingNode, string message, PacketType packetType, int timeToLive)
        {
            PacketHeader header = new PacketHeader
            {

                NodeId = sendingNode.Peer.NodeId,
                IPAddress = sendingNode.Peer.NodeIP,
                Port = sendingNode.Peer.NodePort.ToString(),
                PublicSignatureKey = sendingNode.Peer.PublicSignatureKey,
                Packet_Type = packetType.ToString(),
                TTL=timeToLive.ToString(),
            };

            Packet packet = new Packet
            {
                Header = header,
                Content = message,
                Signature = SignatureGenerator.CreateBlockSignature(sendingNode.Peer.NodeId)
            };

            return packet;
        }

        public static byte[] SerializePacket(Packet packet)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryWriter writer = new BinaryWriter(ms);

                // Write Opcode
                if (!string.IsNullOrEmpty(packet.Header.Packet_Type))
                {
                    string packettype = packet.Header.Packet_Type;

                    // Try to parse the string into an enum
                    if (Enum.TryParse(packettype, true, out PacketType packetType))
                    {
                        // Safely check if the enum exists in the dictionary
                        if (PacketTypes.TryGetValue(packetType, out int intValue))
                        {
                            // Cast the int to byte and write to the BinaryWriter
                            byte opcode = (byte)intValue;
                            writer.Write(opcode);
                        }
                        else
                        {
                            throw new ArgumentException($"Packet type '{packetType}' not found in PacketTypes dictionary.");
                        }
                    }
                    else
                    {
                        throw new ArgumentException($"Invalid Packet_Type string: '{packettype}'.");
                    }
                }
                else
                {
                    throw new ArgumentException("Packet.Header.Packet_Type is null or empty.");
                }

                // Write Header
                writer.Write(packet.Header.NodeId);
                writer.Write(packet.Header.IPAddress);
                writer.Write(packet.Header.Port);
                writer.Write(packet.Header.PublicSignatureKey);
                writer.Write(packet.Header.PublicEncryptKey);

                // Write Content
                writer.Write(packet.Content);

                // Write Signature
                writer.Write(packet.Signature);
                
                return ms.ToArray();
            }
        }

        public static Packet DeserializePacket(byte[] data)
        {
            if (data == null || data.Length == 0)
            {
                throw new ArgumentException("Data cannot be null or empty.", nameof(data));
            }

            using (MemoryStream ms = new MemoryStream(data))
            using (BinaryReader reader = new BinaryReader(ms))
            {
                try
                {
                    // Create a new Packet object
                    Packet packet = new Packet();
                    packet.Header = new PacketHeader();

                    // Read Opcode
                    byte opcode = reader.ReadByte();
                    if (!PacketTypes.ContainsValue(opcode))
                    {
                        throw new ArgumentException($"Invalid opcode: {opcode}");
                    }

                    // Find the corresponding PacketType enum value
                    PacketType packetType = PacketTypes.FirstOrDefault(x => x.Value == opcode).Key;
                    packet.Header.Packet_Type = packetType.ToString();

                    // Read Header
                    packet.Header.NodeId = reader.ReadString();
                    packet.Header.IPAddress = reader.ReadString();
                    packet.Header.Port = reader.ReadInt32().ToString();
                    packet.Header.PublicSignatureKey = reader.ReadString();
                    packet.Header.PublicEncryptKey = reader.ReadString();

                    // Read Content
                    packet.Content = reader.ReadString();

                    // Read Signature
                    packet.Signature = reader.ReadString();

                    return packet;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error deserializing packet: {ex.Message}");
                    throw;
                }
            }
        }

    }

}
