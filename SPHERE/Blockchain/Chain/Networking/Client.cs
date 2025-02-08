using System.Net;
using System.Net.Sockets;
using System.Text;
using static SPHERE.Blockchain.Node;
using SPHERE.PacketLib;
using SPHERE.Blockchain;
using static SPHERE.PacketLib.Packet;
using SPHERE.Configure;

using SPHERE.Security;
using System.Collections;
using System.Text.RegularExpressions;
using SPHERE.TestingLib;


namespace SPHERE.Networking
{
    /// <summary>
    /// The client is a standard TCP/IP listener. 
    /// We use STUN (Session Traversal Utilities for NAT) to get a port and Ip for the listener to allow the client to connect and listen to the outside world without portfowarding.
    /// 
    /// Sent Packets are sent dynamically so no other work is needed,
    /// 
    /// The client will get packets from the Node and send them to the requested address
    /// Or the client listener will get Packets from other Nodes and send them to the Packet reader to be processed. 
    /// 
    /// Use Case to start a listener.
    /// Client client = new Client();
    /// await Client.StartClientListenerWithSTUNAsync(client)
    /// This will create a new client and listener.  
    /// 
    /// If you need to start a listener for a client already on a node it would be the same thing just dont start a new client feed in node.client.
    /// 
    /// A Node needs to have a client and listener started up before it can Bootstrap or talk to other Nodes.  
    /// A client can send out comms from any port dynamically but can only listen on the IP and port discovered with STUN
    /// 
    /// !!!!
    /// When a client is started or restarted, a NODE NEEDS TO SEND ITS NEW CONTACT INFO TO PEERS, So they can redirect traffic to the node correctly
    /// !!!
    /// 
    /// </summary>
    public class Client 
    {


        private const int StartPort = 5000;                     // Start of the port range
        private const int EndPort = 6000;                       // End of the port range
        public TcpClient client;
        public TcpListener Listener;
        public Packet.PacketBuilder packetBuilder;
        public Packet.PacketReader packetReader;

        public IPAddress clientIP;
        public int clientListenerPort = 0;                             //Port for listening to incoming messages Should be static and provided to other clinets 
        public int clientCommunicationPort;


        public static async Task<bool> SendPacketToPeerAsync(string ip, int port, byte[] encryptedData)
        {
            try
            {
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

                if (isTesting)
                {

                    byte[] sendersKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeEncryptionKey);
                    using TcpClient client = new TcpClient();
                    await client.ConnectAsync(ip, port);
                    using NetworkStream stream = client.GetStream();

                    Console.WriteLine($"Debug-SendPacketToPeerAsync: Encrypted Data Length: {encryptedData.Length}");
                    Console.WriteLine($"Debug-SendPacketToPeerAsync: Sender's Public Key Length: {sendersKey.Length} bytes");
                    //Console.WriteLine($"Debug: Encrypted Data Length: {Convert.ToBase64String(encryptedData)}");
                    Console.WriteLine($"Debug-SendPacketToPeerAsync: Sender's Public Key Length: {Convert.ToBase64String(sendersKey)} bytes");

                    // ✅ Compute full packet size
                    int totalPacketLength = 4 + 4 + sendersKey.Length + encryptedData.Length;
                    byte[] lengthPrefix = BitConverter.GetBytes(totalPacketLength);
                    byte[] keyLengthPrefix = BitConverter.GetBytes(sendersKey.Length);

                    // ✅ Create final packet
                    byte[] finalPacket = new byte[lengthPrefix.Length + keyLengthPrefix.Length + sendersKey.Length + encryptedData.Length];

                    Buffer.BlockCopy(lengthPrefix, 0, finalPacket, 0, lengthPrefix.Length);
                    Buffer.BlockCopy(keyLengthPrefix, 0, finalPacket, lengthPrefix.Length, keyLengthPrefix.Length);
                    Buffer.BlockCopy(sendersKey, 0, finalPacket, lengthPrefix.Length + keyLengthPrefix.Length, sendersKey.Length);
                    Buffer.BlockCopy(encryptedData, 0, finalPacket, lengthPrefix.Length + keyLengthPrefix.Length + sendersKey.Length, encryptedData.Length);

                    // ✅ Log before sending
                    Console.WriteLine($"Debug-SendPacketToPeerAsync: Sending Final Packet of {finalPacket.Length} bytes to {ip}:{port}");

                    // ✅ Ensure all bytes are sent before closing connection
                    await stream.WriteAsync(finalPacket, 0, finalPacket.Length);
                    await stream.FlushAsync();

                    // ✅ Log success
                    Console.WriteLine($"Debug-SendPacketToPeerAsync: Successfully sent {finalPacket.Length} bytes.");

                    return true;
                }
                else
                {
                    byte[] sendersKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey);
                    using TcpClient client = new TcpClient();
                    await client.ConnectAsync(ip, port);
                    using NetworkStream stream = client.GetStream();

                    Console.WriteLine($"Debug: Encrypted Data Length: {encryptedData.Length}");
                    Console.WriteLine($"Debug: Sender's Public Key Length: {sendersKey.Length} bytes");
                    Console.WriteLine($"Debug: Encrypted Data Length: {Convert.ToBase64String(encryptedData)}");
                    Console.WriteLine($"Debug: Sender's Public Key Length: {Convert.ToBase64String(sendersKey)} bytes");

                    // ✅ Compute full packet size
                    int totalPacketLength = 4 + 4 + sendersKey.Length + encryptedData.Length;
                    byte[] lengthPrefix = BitConverter.GetBytes(totalPacketLength);
                    byte[] keyLengthPrefix = BitConverter.GetBytes(sendersKey.Length);

                    // ✅ Create final packet
                    byte[] finalPacket = new byte[lengthPrefix.Length + keyLengthPrefix.Length + sendersKey.Length + encryptedData.Length];

                    Buffer.BlockCopy(lengthPrefix, 0, finalPacket, 0, lengthPrefix.Length);
                    Buffer.BlockCopy(keyLengthPrefix, 0, finalPacket, lengthPrefix.Length, keyLengthPrefix.Length);
                    Buffer.BlockCopy(sendersKey, 0, finalPacket, lengthPrefix.Length + keyLengthPrefix.Length, sendersKey.Length);
                    Buffer.BlockCopy(encryptedData, 0, finalPacket, lengthPrefix.Length + keyLengthPrefix.Length + sendersKey.Length, encryptedData.Length);

                    // ✅ Log before sending
                    Console.WriteLine($"✅ Debug: Sending Final Packet of {finalPacket.Length} bytes to {ip}:{port}");

                    // ✅ Ensure all bytes are sent before closing connection
                    await stream.WriteAsync(finalPacket, 0, finalPacket.Length);
                    await stream.FlushAsync();

                    // ✅ Log success
                    Console.WriteLine($"✅ Debug: Successfully sent {finalPacket.Length} bytes.");

                    return true;

                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-SendPacketToPeerAsync: {ex.Message}");
                return false;
            }
        }

        private static async Task SendFullyAsync(NetworkStream stream, byte[] data)
        {
            int totalSent = 0;
            while (totalSent < data.Length)
            {
                await stream.WriteAsync(data.AsMemory(totalSent, data.Length - totalSent));
                totalSent = data.Length; 
            }
            await stream.FlushAsync();
        }


        public static void SetListenerPort(Client client, int port)
        {
            client.clientListenerPort = port;

        }

        public static void SetListenerIP(Client client, IPAddress iPAddress)
        {
            client.clientIP = iPAddress;

        }

        public void SetListenerPortWithSTUN(Client client)
        {
            var stun = new STUN();
            var (PublicIP, PublicPort) = stun.GetPublicEndpoint();
            client.clientIP = PublicIP;
            client.clientListenerPort = PublicPort;
        }

        public static int FindAvailablePort()
        {
            for (int port = StartPort; port <= EndPort; port++)
            {
                if (IsPortAvailableAsync(port))
                {
                    return port;
                }


            }
            throw new Exception("No available ports found in the specified range.");
        }

        private static bool IsPortAvailableAsync(int port)
        {

            try
            {
                using (var listener = new TcpListener(IPAddress.Any, port))
                {
                    listener.Start();
                    listener.Stop();
                    return true;
                }
            }
            catch (SocketException)
            {
                return false;
            }

        }

        public async Task StartClientListenerAsync(Node node, Client client)
        {
            try
            {
                // Ensure we have a valid listener port
                if (client.clientListenerPort == 0)
                {
                    client.clientListenerPort = FindAvailablePort();
                }
                client.Listener = new TcpListener(client.clientIP, client.clientListenerPort);
                client.Listener.Start();
                Console.WriteLine($"Async server is listening on port {client.clientListenerPort}");

                while (true)
                {
                    try
                    {
                        client.client = await client.Listener.AcceptTcpClientAsync();
                        Console.WriteLine($"Connection established with {client.client.Client.RemoteEndPoint}");

                        _ = HandleClientAsync(node, client.client);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Server error: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting listener: {ex.Message}");
                return;
            }
        }

        public  async Task StartClientListenerWithSTUNAsync(Node node, Client client)
        {
            try
            {
                // DllLoader.LoadAllEmbeddedDlls();
                var stun = new STUN();
                var (PublicIP, PublicPort) = stun.GetPublicEndpoint();

                if (PublicIP == null || PublicPort == 0)
                {
                    Console.WriteLine("StartClientListenerWithSTUNAsync: Failed to retrieve public endpoint. Trying once more.");
                    var (PublicIP1, PublicPort1) = stun.GetPublicEndpoint();
                    if (PublicIP1 == null || PublicPort1 == 0)
                    {
                        Console.WriteLine("StartClientListenerWithSTUNAsync: Failed to retrieve public endpoint again. Exiting.");
                        return;
                    }

                }

                client.clientListenerPort = PublicPort;
                client.clientIP = PublicIP;
                client.Listener = new TcpListener(client.clientIP, client.clientListenerPort);
                client.Listener.Start();
                Console.WriteLine($"StartClientListenerWithSTUNAsync: Async server is listening on port {client.clientListenerPort}");


                while (true)
                {
                    try
                    {
                        client.client = await client.Listener.AcceptTcpClientAsync();
                        Console.WriteLine($"StartClientListenerWithSTUNAsync: Connection established with {client.client.Client.RemoteEndPoint}");

                        _ = HandleClientAsync(node, client.client);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"StartClientListenerWithSTUNAsync: Server error: {ex.Message}");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"StartClientListenerWithSTUNAsync: Error starting listener: {ex.Message}");
                return;
            }
        }


        // Synchronous method to start the client listener using STUN
        public  void StartClientListenerWithSTUNSync(Node node, Client client)
        {
            try
            {
                // Step 1: Retrieve public IP and port using STUN
                var stun = new STUN();
                var (PublicIP, PublicPort) = stun.GetPublicEndpoint();

                if (PublicIP == null || PublicPort == 0)
                {
                    Console.WriteLine("Failed to retrieve public endpoint. Exiting.");
                    throw new Exception("STUN failed to retrieve public endpoint.");
                }

                client.clientListenerPort = PublicPort;
                client.clientIP = PublicIP;
                client.Listener = new TcpListener(client.clientIP, client.clientListenerPort);

                // Step 2: Start the listener
                client.Listener.Start();
                Console.WriteLine($"Server is listening on {client.clientIP}:{client.clientListenerPort}");

                while (true)
                {
                    // Step 3: Accept a new client connection
                    TcpClient incomingClient = client.Listener.AcceptTcpClient();
                    Console.WriteLine($"New client connected from {((IPEndPoint)incomingClient.Client.RemoteEndPoint).Address}");

                    // Step 4: Handle the client in a separate task
                    _ = Task.Run(() => HandleClientAsync(node, incomingClient));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error starting client listener: {ex.Message}");
            }
        }


        private async Task HandleClientAsync(Node node, TcpClient client)
        {
            try
            {
                using NetworkStream stream = client.GetStream();
                using Packet.PacketReader reader = new Packet.PacketReader(stream);

                while (client.Connected)
                {
                    try
                    {
                        // Correct: Read and unpack the message tuple
                        var (encryptedMessage, senderPublicEncryptionKey) = await reader.ReadMessage();

                        // Ensure values are valid before processing
                        if (encryptedMessage == null || senderPublicEncryptionKey == null)
                        {
                            Console.WriteLine("Error-HandleClientAsync: Received an invalid packet. Closing connection.");
                            break; 
                        }

                        int receivedPacketSize = senderPublicEncryptionKey.Length + encryptedMessage.Length + 4;
                        Console.WriteLine($"Debug: Total received packet size (Reconstructed): {receivedPacketSize} bytes");
                        Console.WriteLine($"Debug-HandleClientAsync: Extracted Sender's Public Key Length: {senderPublicEncryptionKey.Length} bytes");
                        Console.WriteLine($"Debug-HandleClientAsync: Sender Public Key (Base64): {Convert.ToBase64String(senderPublicEncryptionKey)}");
                        Console.WriteLine($"Debug-HandleClientAsync: Extracted Encrypted Message Length: {encryptedMessage.Length} bytes");
                        // Console.WriteLine($"Debug: Encrypted Message (Base64): {Convert.ToBase64String(encryptedMessage)}");

                        // Check for unexpected key length mismatches
                        if (senderPublicEncryptionKey.Length != 72 && senderPublicEncryptionKey.Length != 91)
                        {
                            Console.WriteLine($"Error-HandleClientAsync: Unexpected sender public key length! Expected 72 or 91, got {senderPublicEncryptionKey.Length}");
                        }

                        // Process message 
                        ProcessIncomingPacket(node, encryptedMessage, senderPublicEncryptionKey);
                    }
                    catch (EndOfStreamException eosEx)
                    {
                      
                        Console.WriteLine($"Info-HandleClientAsync: Stream ended normally: {eosEx.Message}");
                        break;
                    }
                    catch (IOException ioEx)
                    {
                        Console.WriteLine($"Info-HandleClientAsync: Connection closed by peer: {ioEx.Message}");
                        break;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error-HandleClientAsync: Unexpected error processing packet: {ex.Message}");
                        break;
                    }

                }
            }
            catch (EndOfStreamException eosEx)
            {
               
                Console.WriteLine($"Info-HandleClientAsync: Stream ended normally: {eosEx.Message}");
             
            }
            catch (IOException ioEx)
            {
                
                Console.WriteLine($"Info-HandleClientAsync: Connection closed by peer: {ioEx.Message}");
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-HandleClientAsync: Unexpected error processing packet: {ex.Message}");
            
            }
            finally
            {
                client.Close();
            }
        }

        bool IsBase64String(string input)
        {
            input = input.Trim();
            return (input.Length % 4 == 0) && Regex.IsMatch(input, @"^[a-zA-Z0-9\+/]*={0,2}$", RegexOptions.None);
        }

        public async Task ProcessIncomingPacket(Node node, byte[] packetData, byte[] senderPublicEncryptKey)
        {
            Console.WriteLine($"Debug-ProcessIncomingPacket: Processing Incoming Encrypted.");
            try
            {
                Packet packet = new Packet();
                packet.Header = new PacketHeader();
                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
                if (isTesting)
                {
                    byte[] recipientsPublicKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey);
                    Console.WriteLine($"Debug-ProcessIncomingPacket: Getting Test Key from Test Environment.");
                 
                    
                    //byte[] privateKeyBytes = Convert.FromBase64String(recipientsPublicKey);
                    Console.WriteLine($"Debug-ProcessIncomingPacket: Test Key: {recipientsPublicKey}");

                    // ✅ Decrypt using both the sender’s public key & recipient’s private key
                    byte[] decryptedData = Encryption.DecryptPacketWithPrivateKey(packetData, senderPublicEncryptKey);

                    Console.WriteLine($"Debug-ProcessIncomingPacket: Deserializing Test Packet.");
                    packet = PacketBuilder.DeserializePacket(decryptedData);
                }
                else
                {
                    string sendersPublicEncryptKey = Convert.ToBase64String(senderPublicEncryptKey);
                    Console.WriteLine($"Debug-ProcessIncomingPacket: Getting Stored Key from Container.");
                    byte[] decryptedData = Encryption.DecryptPacketWithPrivateKey(packetData,
                        senderPublicEncryptKey);

                    Console.WriteLine($"Debug-ProcessIncomingPacket: Deserializing Packet.");
                    packet = PacketBuilder.DeserializePacket(decryptedData);
                }

                PacketBuilder.PacketType type = ParsePacketType(packet.Header.Packet_Type);

                switch (type)
                {
                    case PacketBuilder.PacketType.BootstrapRequest:
                        await node.SendBootstrapResponse(packet);
                        break;

                    case PacketBuilder.PacketType.BootstrapResponse:
                        await node.ProcessBootstrapResponse(packet);
                        break;

                    case PacketBuilder.PacketType.PeerUpdateRequest:
                        await node.RespondToPingAsync(packet);
                        break;

                    default:
                        Console.WriteLine($"ProcessIncomingPacket:Unknown packet type: {packet.Header.Packet_Type}");
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ProcessIncomingPacket: Error processing packet: {ex.Message}");
            }
        }

    }
    /// <summary>
    /// The STUN server is used to get an IP and port that is open for listening for traffic without needing pinholes or portforwarding. 
    /// It needs to be ran evertime a listener is started. It reaches out to a list of known STUN servers and then parses the response it gets to get a valid usable IP an port.
    /// 
    /// The implimentation here is limited and needs TURN to also be included for somesituations. This as it sits is a basic prototyped temporary implementation.
    /// 
    /// Futureistlly everynode should have the ability to act as a stun server or atleast full Nodes. The app can use the provided ip and port for bootstraping, to first send a STUN request.
    /// It will then get its IP and port back, set up its listener, then send its bootstrap request and wait to get its peers and the Chain or shards.
    /// 
    /// </summary>
    public class STUN
    {
        private readonly Dictionary<string, int> stunServers = new Dictionary<string, int>
        {
            { "stun.l.google.com", 19302 },
            { "stun1.l.google.com", 19302 },
            { "stun2.l.google.com", 19302 },
            { "stun3.l.google.com", 19302 },
            { "stun4.l.google.com", 19302 },
            { "stun.stunprotocol.org", 3478 },
            { "stun.voiparound.com", 3478 },
            { "stun.voipbuster.com", 3478 },
            { "stun.voipstunt.com", 3478 },
            { "stun.counterpath.net", 3478 },
            { "stun.ekiga.net", 3478 },
            { "stun.sipgate.net", 3478 },
            { "stun.ideasip.com", 3478 },
            { "stun.voxgratia.org", 3478 },
            { "stun.xten.com", 3478 }
        };

        public (IPAddress PublicIP, int PublicPort) GetPublicEndpoint()
        {
            foreach (var server in stunServers)
            {
                try
                {
                    Console.WriteLine($"Trying STUN server: {server.Key}:{server.Value}");
                    var result = QueryStunServer(server.Key, server.Value);
                    if (result.PublicIP != null)
                    {
                        Console.WriteLine($"Success with {server.Key}:{server.Value}");
                        return result;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"STUN server {server.Key}:{server.Value} failed: {ex.Message}");
                }
            }

            // If none succeed
            Console.WriteLine("All STUN servers failed.");
            return (null, 0);
        }

        private (IPAddress PublicIP, int PublicPort) QueryStunServer(string stunServer, int stunPort)
        {
            try
            {
                // STUN Binding Request magic cookie (RFC 5389)
                byte[] stunRequest = new byte[20];
                stunRequest[0] = 0x00; // Message Type: Binding Request
                stunRequest[1] = 0x01;
                stunRequest[2] = 0x00; // Message Length
                stunRequest[3] = 0x00;
                // Magic Cookie
                stunRequest[4] = 0x21;
                stunRequest[5] = 0x12;
                stunRequest[6] = 0xA4;
                stunRequest[7] = 0x42;
                // Transaction ID (12 bytes)
                new Random().NextBytes(stunRequest[8..20]);

                using (UdpClient udpClient = new UdpClient())
                {
                    // Connect to STUN server
                    udpClient.Connect(stunServer, stunPort);

                    // Send STUN Binding Request
                    udpClient.Send(stunRequest, stunRequest.Length);

                    // Receive response
                    var remoteEndpoint = new IPEndPoint(IPAddress.Any, 0);
                    byte[] response = udpClient.Receive(ref remoteEndpoint);

                    if (response.Length >= 20 && response[0] == 0x01 && response[1] == 0x01)
                    {
                        // Parse XOR-MAPPED-ADDRESS attribute (offset varies based on attributes)
                        int offset = 20; // Start parsing attributes after the header
                        while (offset < response.Length - 4)
                        {
                            short attributeType = (short)((response[offset] << 8) | response[offset + 1]);
                            short attributeLength = (short)((response[offset + 2] << 8) | response[offset + 3]);

                            if (attributeType == 0x0020) // XOR-MAPPED-ADDRESS
                            {
                                int family = response[offset + 5];
                                if (family == 0x01) // IPv4
                                {
                                    // Decode XOR-MAPPED-ADDRESS
                                    int port = ((response[offset + 6] << 8) | response[offset + 7]) ^ 0x2112;
                                    byte[] ipBytes = new byte[4];
                                    for (int i = 0; i < 4; i++)
                                    {
                                        ipBytes[i] = (byte)(response[offset + 8 + i] ^ stunRequest[4 + i]);
                                    }
                                    IPAddress publicIP = new IPAddress(ipBytes);
                                    return (publicIP, port);
                                }
                            }
                            offset += 4 + attributeLength; // Move to the next attribute
                        }
                    }

                    throw new Exception("Failed to retrieve public IP and port.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error querying STUN server {stunServer}:{stunPort} - {ex.Message}");
                throw;
            }
        }

    }


}

