using System.Net.Sockets;
using System.Text;
using static SPHERE.Networking.PacketBuilder;
using SPHERE.Blockchain;

namespace SPHERE.Networking
{
    /// <summary>
    /// The PacketReader is used to read incoming Packets. 
    /// 
    /// At the moment it is jsut reading a message this is missing its fucntionality as it is next to finish. 
    /// 
    /// The packet reader will convert the steam back into a serilized pack once that happens it can use the packet type to process the packet accourdingly.
    /// 
    /// </summary>
    public  class PacketReader: BinaryReader
    {
            private NetworkStream _stream;
            public PacketReader(NetworkStream stream) : base(stream)
            {

                _stream = stream;

            }

            public async Task<string>  ReadMessage()
            {
                Byte[] buffer;
                var length = ReadInt32();
                buffer = new Byte[length];
                _stream.Read(buffer, 0, length);

                var message = Encoding.ASCII.GetString(buffer);

                return message;
            }

        public async Task ProcessIncomingPacket(Node node, byte[] packetData)
        {
            try
            {
                Packet packet = PacketBuilder.DeserializePacket(packetData);

                PacketType type = Packet.ParsePacketType(packet.Header.Packet_Type);

                switch (type)
                {
                    case PacketType.BootstrapRequest:
                        await node.SendBootstrapResponse(packet);
                        break;

                    case PacketType.BootstrapResponse:
                        await node.ProcessBootstrapResponse(packet);
                        break;

                    case PacketType.PeerUpdateRequest:
                        await node.RespondToPingAsync(packet);
                        break;

                    default:
                        Console.WriteLine($"Unknown packet type: {packet.Header.Packet_Type}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing packet: {ex.Message}");
            }
        }


    }
}
