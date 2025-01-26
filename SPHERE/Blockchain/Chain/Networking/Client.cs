using System.Net;
using System.Net.Sockets;
using System.Text;
using static SPHERE.Blockchain.Node;
using SPHERE.PacketLib;
using SPHERE.Blockchain;
using static SPHERE.PacketLib.Packet;
using SPHERE.Configure;


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

        public IPAddress clientIP ;
        public int clientListenerPort=0;                             //Port for listening to incoming messages Should be static and provided to other clinets 
        public int clientCommunicationPort;



        public static async Task<bool> SendPacketToPeerAsync(string ip, int port, byte[] encryptedData, string signature)
        {
            // Combine the signature and encrypted data
            byte[] combinedData = CombineEncryptedDataAndSignature(encryptedData, Encoding.UTF8.GetBytes(signature));

            try
            {
                using TcpClient client = new TcpClient();
                await client.ConnectAsync(ip, port);

                using NetworkStream stream = client.GetStream();

                // Send the packet
                await stream.WriteAsync(combinedData, 0, combinedData.Length);
                return true; // Indicate success
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                return false; // Indicate failure
            }
        }

        
        private static byte[] CombineEncryptedDataAndSignature(byte[] encryptedData, byte[] signature)
        {
            // Create a byte array to hold the signature length, signature, and encrypted data
            byte[] result = new byte[4 + signature.Length + encryptedData.Length];

            // Add the signature length as a 4-byte prefix
            BitConverter.GetBytes(signature.Length).CopyTo(result, 0);

            // Add the signature
            Buffer.BlockCopy(signature, 0, result, 4, signature.Length);

            // Add the encrypted data
            Buffer.BlockCopy(encryptedData, 0, result, 4 + signature.Length, encryptedData.Length);

            return result;
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
            client.clientIP= PublicIP; 
            client.clientListenerPort = PublicPort;
        }

        public static int FindAvailablePort()
        {
            for (int port = StartPort; port <= EndPort; port++)
            {
                if ( IsPortAvailableAsync(port))
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

        public static async Task StartClientListenerAsync(Client client)
        {
            DllLoader.LoadAllEmbeddedDlls();
            if (client.clientListenerPort==0)
            {
                client.clientListenerPort = FindAvailablePort();

            }
            
            client.Listener = new TcpListener(IPAddress.Any, client.clientListenerPort);
            client.Listener.Start();
            Console.WriteLine($"Async server is listening on port {client.clientListenerPort}");

            while (true)
            {
                try
                {
                    client.client = await client.Listener.AcceptTcpClientAsync();
                    Console.WriteLine($"Connection established with {client.client.Client.RemoteEndPoint}");

                    _ = HandleClientAsync(client.client); 
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Server error: {ex.Message}");
                }
            }
        }

        public static async Task StartClientListenerWithSTUNAsync(Client client)
        {
            try
            {
                DllLoader.LoadAllEmbeddedDlls();
                var stun = new STUN();
                var (PublicIP, PublicPort) = stun.GetPublicEndpoint();

                if (PublicIP == null || PublicPort == 0)
                {
                    Console.WriteLine("Failed to retrieve public endpoint. Trying once more.");
                    var (PublicIP1, PublicPort1) = stun.GetPublicEndpoint();
                    if (PublicIP1 == null || PublicPort1 == 0)
                    {
                        Console.WriteLine("Failed to retrieve public endpoint again. Exiting.");
                        return;
                    }

                }

                client.clientListenerPort = PublicPort;
                client.clientIP = PublicIP;
                client.Listener = new TcpListener(client.clientIP, client.clientListenerPort);
                client.Listener.Start();
                Console.WriteLine($"Async server is listening on port {client.clientListenerPort}");


                while (true)
                {
                    try
                    {
                        client.client = await client.Listener.AcceptTcpClientAsync();
                        Console.WriteLine($"Connection established with {client.client.Client.RemoteEndPoint}");

                        _ = HandleClientAsync(client.client);
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


        // Synchronous method to start the client listener using STUN
        public static void StartClientListenerWithSTUNSync(Client client)
        {
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
            client.Listener.Start();
            Console.WriteLine($"Server is listening on port {client.clientListenerPort}");
        }

        private static async Task HandleClientAsync(TcpClient client)
        {
            try
            {
                using NetworkStream stream = client.GetStream();
                using Packet.PacketReader reader = new Packet.PacketReader(stream);

                while (client.Connected)
                {
                    // Read the incoming message using the PacketReader
                    string message = await reader.ReadMessage();
                    Console.WriteLine($"Received message: {message}");


                    // message needs to be sent to node processed encrypted. 

                    //(Missing Fucntionality) will add. 
                  
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Client handling error: {ex.Message}");
            }
            finally
            {
                client.Close();
            }
        }

        public async Task ProcessIncomingPacket(Node node, byte[] packetData)
        {
            try
            {
                Packet packet = PacketBuilder.DeserializePacket(packetData);

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

