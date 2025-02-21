using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json.Serialization;
using static SPHERE.PacketLib.Packet.PacketBuilder;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SPHERE.PacketLib
{
    /// <summary>
    /// A packet is just what it says it is created by a node to be sent by the client to another node. 
    /// The signature is made with the nodes private signature. 
    /// the receiver can use this and the included node ID and public key to verify the signature. 
    /// 
    /// </summary>
    public class Packet
    {
        public Packet() { }

        static Packet()
        {
            if (Assembly.GetCallingAssembly() != Assembly.GetExecutingAssembly())
            {
                throw new UnauthorizedAccessException("Unauthorized access detected!");
            }
           
        }

        [JsonPropertyName("Header")]
        public PacketHeader Header;
        [JsonPropertyName("Content")]
        public string Content;
        [JsonPropertyName("Signature")]
        public string Signature;


        public class PacketHeader
        {
            [JsonPropertyName("NodeId")]
            public string NodeId { get; set; }
            [JsonPropertyName("Node_Type")]
            public string Node_Type { get; set; }
            [JsonPropertyName("IPAddress")]
            public string IPAddress { get; set; }
            [JsonPropertyName("Port")]
            public string Port { get; set; }
            [JsonPropertyName("PublicSignatureKey")]
            public byte[] PublicSignatureKey { get; set; }
            [JsonPropertyName("PublicEncryptKey")]
            public byte[] PublicEncryptKey { get; set; }
            [JsonPropertyName("Packet_Type")]
            public string Packet_Type { get; set; }
            [JsonPropertyName("TTL")]
            public string TTL { get; set; }
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
            Enum.TryParse(type, out PacketBuilder.PacketType parsedEnum);
            return parsedEnum;
        }

        /// <summary>
        /// Used to build a packet by the node to send to the client for sending.  
        /// 
        /// There are a few types of packets and they are converted into an opcode for the TCP transport. 
        /// 
        /// </summary>
        public class PacketBuilder
        {

            public enum PacketType
            {
                BootstrapRequest,
                BootstrapResponse,
                GetRequest,
                GetResponse,
                PutRequest,
                PutResponse,
                Ping,
                Pong,
                PeerUpdate,
                SyncDHTRequest,
                SyncDHTResponse,
                BrodcastConnection,
                PushTokenIssued,
                PushTokenPing,
                PushTokenPong,
                PingPal,
                PongPal,
                ReputationRequest,
                ReputationResponse,
                ReputationUpdate,
            }

            public static readonly Dictionary<PacketType, int> PacketTypes = new Dictionary<PacketType, int>
            {
            { PacketType.BootstrapRequest,1},
            { PacketType.BootstrapResponse,2},
            { PacketType.GetRequest,3 },
            { PacketType.GetResponse,4},
            { PacketType.PutRequest,5},
            { PacketType.PutResponse,6},
            { PacketType.Ping,7 },
            { PacketType.Pong,8},
            { PacketType.SyncDHTRequest,9},
            { PacketType.SyncDHTResponse,10},
            { PacketType.PeerUpdate,11},
            { PacketType.BrodcastConnection,12},
            { PacketType.PushTokenIssued,13},
            { PacketType.PushTokenPing,14},
            { PacketType.PushTokenPong,15},
            { PacketType.PingPal,16},
            { PacketType.PongPal,17},
            { PacketType.ReputationRequest,18},
            { PacketType.ReputationResponse,19},
            { PacketType.ReputationUpdate,20},
            };

            public static PacketHeader BuildPacketHeader(PacketType packetType, string nodeId, string nodeType, byte[] publicSignatureKey, byte[] publicEncryptKey, int port, string iPAddress, int tTL)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                try
                {

                    PacketHeader header = new PacketHeader
                    {

                        NodeId = nodeId,
                        Node_Type = nodeType,
                        IPAddress = iPAddress,
                        Port = port.ToString(),
                        PublicSignatureKey = publicSignatureKey,
                        PublicEncryptKey = publicEncryptKey,
                        Packet_Type = packetType.ToString(),
                        TTL = tTL.ToString(),
                    };
                    return header;
                }
                catch (Exception ex)
                {
                    throw new Exception("BuildPacketHeader: Could Not Create Header.");
                }


            }



            public static Packet BuildPacket(PacketHeader header, string message)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                Packet packet = new Packet
                {
                    Header = header,
                    Content = message,
                    Signature = "TestSignature",
                };

                return packet;
            }

            public static byte[] SerializePacket(Packet packet)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                Func<Packet, byte[]> secureMethod = SerializePacketInternal;
                return secureMethod(packet);
            }


            private static byte[] SerializePacketInternal(Packet packet)
            {

                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                if (packet == null)
                    throw new ArgumentNullException(nameof(packet), "SerializePacket: Packet cannot be null.");

                if (packet.Header == null)
                    throw new ArgumentNullException(nameof(packet.Header), "SerializePacket: Packet header cannot be null.");

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
                                throw new ArgumentException($"SerializePacket: Packet type '{packetType}' not found in PacketTypes dictionary.");
                            }
                        }
                        else
                        {
                            throw new ArgumentException($"SerializePacket: Invalid Packet_Type string: '{packettype}'.");
                        }
                    }
                    else
                    {
                        throw new ArgumentException("SerializePacket: Packet.Header.Packet_Type is null or empty.");
                    }

                    // Write Header
                    if (string.IsNullOrEmpty(packet.Header.NodeId))
                        throw new ArgumentNullException(nameof(packet.Header.NodeId), "NodeId cannot be null or empty.");
                    writer.Write(packet.Header.NodeId);

                    if (string.IsNullOrEmpty(packet.Header.Node_Type))
                        throw new ArgumentNullException(nameof(packet.Header.Node_Type), "NodeId cannot be null or empty.");
                    writer.Write(packet.Header.Node_Type);

                    if (string.IsNullOrEmpty(packet.Header.IPAddress))
                        throw new ArgumentNullException(nameof(packet.Header.IPAddress), "IPAddress cannot be null or empty.");
                    writer.Write(packet.Header.IPAddress);



                    if (string.IsNullOrEmpty(packet.Header.Port))
                        throw new ArgumentNullException(nameof(packet.Header.Port), "Port cannot be null or empty.");
                    writer.Write(int.Parse(packet.Header.Port));


                    if (string.IsNullOrEmpty(Convert.ToBase64String(packet.Header.PublicSignatureKey)))
                        throw new ArgumentNullException(nameof(packet.Header.PublicSignatureKey), "PublicSignatureKey cannot be null or empty.");
                    writer.Write(packet.Header.PublicSignatureKey.Length);
                    writer.Write(packet.Header.PublicSignatureKey);


                    if (string.IsNullOrEmpty(Convert.ToBase64String(packet.Header.PublicEncryptKey)))
                        throw new ArgumentNullException(nameof(packet.Header.PublicEncryptKey), "PublicEncryptKey cannot be null or empty.");
                    writer.Write(packet.Header.PublicEncryptKey.Length);
                    writer.Write(packet.Header.PublicEncryptKey);


                    if (string.IsNullOrEmpty(packet.Header.TTL))
                        throw new ArgumentNullException(nameof(packet.Header.TTL), "TTL cannot be null or empty.");
                    writer.Write(int.Parse(packet.Header.TTL));


                    // Write Content
                    if (string.IsNullOrEmpty(packet.Content))
                        throw new ArgumentNullException(nameof(packet.Content), "Content cannot be null or empty.");
                    writer.Write(packet.Content);


                    // Write Signature
                    if (string.IsNullOrEmpty(packet.Signature))
                        throw new ArgumentNullException(nameof(packet.Signature), "Signature cannot be null or empty.");
                    byte[] signatureBytes = Encoding.UTF8.GetBytes(packet.Signature);
                    writer.Write(signatureBytes.Length);
                    writer.Write(signatureBytes);



                    return ms.ToArray();
                }
            }
            public static Packet DeserializePacket(byte[] data)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                Func<byte[], Packet> secureMethod = DeserializePacketInternal;
                return secureMethod(data);

            }


            private static Packet DeserializePacketInternal(byte[] data)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                if (data == null || data.Length == 0)
                {
                    Console.WriteLine("Debug-DeserializePacket: Input data is null or empty.");
                    throw new ArgumentException("Data cannot be null or empty.", nameof(data));
                }


                using (MemoryStream ms = new MemoryStream(data))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    try
                    {
                        Packet packet = new Packet();
                        packet.Header = new PacketHeader();

                        // ✅ Read Opcode
                        byte opcode = reader.ReadByte();
                        if (!PacketTypes.ContainsValue(opcode))
                            throw new ArgumentException($"DeserializePacket: Invalid opcode: {opcode}");

                        packet.Header.Packet_Type = PacketTypes.FirstOrDefault(x => x.Value == opcode).Key.ToString();

                        // ✅ Read Header
                        packet.Header.NodeId = reader.ReadString();
                        packet.Header.Node_Type = reader.ReadString();
                        packet.Header.IPAddress = reader.ReadString();
                        packet.Header.Port = reader.ReadInt32().ToString();

                        int sigKeyLength = reader.ReadInt32();
                        packet.Header.PublicSignatureKey = reader.ReadBytes(sigKeyLength);

                        int encKeyLength = reader.ReadInt32();
                        packet.Header.PublicEncryptKey = reader.ReadBytes(encKeyLength);

                        packet.Header.TTL = reader.ReadInt32().ToString();

                        // ✅ Read Content
                        packet.Content = reader.ReadString();

                        // ✅ Read Signature Length + Signature
                        int signatureLength = reader.ReadInt32();
                        byte[] signatureBytes = reader.ReadBytes(signatureLength);
                        packet.Signature = Encoding.UTF8.GetString(signatureBytes);


                        return packet;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"DeserializePacket: Error deserializing packet: {ex.Message}");
                        throw;
                    }



                }
            }
        }

        /// <summary>
        /// The PacketReader is used to read incoming Packets. 
        /// 
        /// At the moment it is just reading a message this is missing its functionality as it is next to finish. 
        /// 
        /// The packet reader will convert the steam back into a serialized pack once that happens it can use the packet type to process the packet accordingly.
        /// 
        /// </summary>
        public class PacketReader : BinaryReader
        {
            private readonly NetworkStream _stream;

            public PacketReader(NetworkStream stream) : base(stream)
            {
                _stream = stream;
            }


            public async Task<(byte[] encryptedData, byte[] sendersKey, byte[] signature)> ReadMessage()
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                try
                {
                    byte[] lengthPrefix = new byte[4];

                    // Read total message length
                    await ReadExactlyAsync(_stream, lengthPrefix, 4);
                    int messageLength = BitConverter.ToInt32(lengthPrefix, 0);

                    // Console.WriteLine($"Debug-ReadMessage: Declared Message Length: {messageLength} bytes");

                    if (messageLength <= 4 || messageLength > 10_000_000)
                    {
                        Console.WriteLine($"Debug-ReadMessage: Invalid message length received: {messageLength}");
                        return (null, null, null);
                    }

                    // Read the remaining packet
                    int remainingPacketSize = messageLength - 4;
                    byte[] fullPacket = new byte[remainingPacketSize];
                    await ReadExactlyAsync(_stream, fullPacket, remainingPacketSize);

                    //Console.WriteLine($"Debug-ReadMessage: Fully Received Packet - {remainingPacketSize} bytes");

                    //Parse the packet to extract data
                    return ParsePacket(fullPacket);
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Error-ReadMessage: Connection closed before full message received. {ex.Message}");
                    return (null, null, null);
                }
            }


            private (byte[] encryptedData, byte[] sendersKey, byte[] signature) ParsePacket(byte[] fullPacket)
            {

                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                try
                {
                    if (fullPacket.Length < 12) // Must be at least 4 bytes (key length) + 4 bytes (signature length) + 4 bytes (some data)
                    {
                        Console.WriteLine($"Debug-ParsePacket: Packet too small ({fullPacket.Length} bytes) to be valid.");
                        return (null, null, null);
                    }

                    // Read sender’s public key length (bytes 0-3)
                    int keyLength = BitConverter.ToInt32(fullPacket, 0);


                    if (keyLength <= 0 || keyLength > fullPacket.Length - 8) // Must leave room for signature length
                    {
                        Console.WriteLine($"Debug-ParsePacket: Invalid sender public key length: {keyLength}");
                        return (null, null, null);
                    }

                    // Extract sender’s public key (bytes 4 → 4+keyLength)
                    byte[] sendersKey = new byte[keyLength];
                    Buffer.BlockCopy(fullPacket, 4, sendersKey, 0, keyLength);

                    // Read signature length (immediately after sender’s key)
                    int signatureLengthOffset = 4 + keyLength;
                    int signatureLength = BitConverter.ToInt32(fullPacket, signatureLengthOffset);


                    if (signatureLength <= 0 || signatureLength > fullPacket.Length - signatureLengthOffset - 4)
                    {
                        Console.WriteLine($"Debug-ParsePacket: Invalid signature length: {signatureLength}");
                        return (null, null, null);
                    }

                    // Extract signature (bytes after signature length prefix)
                    int signatureOffset = signatureLengthOffset + 4;
                    byte[] signature = new byte[signatureLength];
                    Buffer.BlockCopy(fullPacket, signatureOffset, signature, 0, signatureLength);


                    int encryptedMessageStart = signatureOffset + signatureLength;
                    int encryptedMessageLength = fullPacket.Length - encryptedMessageStart;

                    if (encryptedMessageLength <= 0)
                    {
                        Console.WriteLine($"Debug-ParsePacket: Invalid encrypted message length: {encryptedMessageLength}");
                        return (null, null, null);
                    }

                    if (encryptedMessageStart >= fullPacket.Length)
                    {
                        Console.WriteLine($"Debug-ParsePacket: Encrypted message start ({encryptedMessageStart}) is out of bounds!");
                        return (null, null, null);
                    }

                    if (encryptedMessageLength + 4 == fullPacket.Length)
                    {
                        Console.WriteLine("Detected misalignment, adjusting by -4...");
                        encryptedMessageLength -= 4;
                    }

                    byte[] encryptedData = new byte[encryptedMessageLength];


                    Buffer.BlockCopy(fullPacket, encryptedMessageStart, encryptedData, 0, encryptedMessageLength);



                    return (encryptedData, sendersKey, signature);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($" Error-ParsePacket: {ex.Message}");
                    return (null, null, null);
                }
            }



            private static async Task<bool> ReadExactlyAsync(NetworkStream stream, byte[] buffer, int size)
            {
                if (Debugger.IsAttached || Debugger.IsLogging())
                {
                    Environment.FailFast("Debugger detected! Exiting...");
                }

                int totalBytesRead = 0;

                try
                {
                    while (totalBytesRead < size)
                    {
                        int bytesRead = await stream.ReadAsync(buffer, totalBytesRead, size - totalBytesRead);

                        if (bytesRead == 0)
                        {
                            Console.WriteLine($"Warning-ReadExactlyAsync: Stream closed early. Read {totalBytesRead}/{size} bytes.");
                            return false;
                        }

                        totalBytesRead += bytesRead;
                    }


                    return true;
                }
                catch (IOException ioEx)
                {
                    Console.WriteLine($"Warning-ReadExactlyAsync: IO Exception during read: {ioEx.Message}");
                    return false;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error-ReadExactlyAsync: Unexpected error: {ex.Message}");
                    return false;
                }
            }
        }

    }
}


