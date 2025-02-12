using System.Net.Mail;
using System.Reflection;
using System.Text;
using System.Text.Json;
using SPHERE.Configure;
using SPHERE.Networking;
using SPHERE.PacketLib;
using SPHERE.Security;



using System.Xml.Linq;
using System;
using static SPHERE.PacketLib.Packet.PacketBuilder;
using System.Net;
using System.Collections.Concurrent;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// A Node is the heart and soul of a decenteralized network.
    /// A Node is responsible for mantaining either a whole copy of the blockchain or its shard. 
    /// ( in the begining the whole thing as its going to be small and even a single node online can re populate the network.)
    /// 
    /// --Node responsibilities-- 
    /// (Again: The node is the back end of the application.)  
    /// 
    /// It will coordinate with the TCP client to send and get packets.
    /// It will validate incoming packets and process the requests. (Get Block, Put Block, Edit Block, Validate Block)
    /// 
    /// * A Node will also be responsible for bootstraping new nodes with peers and copy of the chain. 
    /// * This is done by recieving a valid nodes connection info and public key from either the internet, another user or any source.
    /// * on first run to start a node you will need to provide that info as a user. 
    /// 
    /// Block validation will likely result in verifying a block and passing it on unless it is recieved with a set of verified jumps already. 
    /// 
    /// Nodes will be responsible for relaying requests to its peers to ensure all changes are populated through the chain. 
    /// 
    /// --Node Security--
    /// 
    /// Nodes do not directly have access to stored keys, but have the ability to use the keys to sign packets. 
    /// This leaves nodes thenselves from the application side safe. But nodes control the chain. A bad node or application acting maliciously as a node could be risky. 
    /// However, because Block edits can only be done with a signature from the original node that created the block and blocks can not be deleted, just edited, then a malicious node 
    /// or app could only edit the single block or blocks it created Leaving the rest of the chain tamper free.
    ///
    /// 
    /// </summary>
    public enum NodeType
    {
        Full,           //Stores the full DHT has most athority on chain discrepancies
        Power,          //Stores a Larger amount of the chain (Super Shards) or whole thing if the size is small.
        Mini,           //Stores a standard shard or whole thing if the size is small.
        Leech,          // Does not store or support the chain in any way other than to look up info in the chain and return it.  (Verification servers, and entities that dont need to store blocks, or are high risk for attacks)

    }
    public class Node 
    {



        public static readonly object stateLock = new object();
        public const string DefaultPreviousHash = "UNKNOWN";
        public RoutingTable RoutingTable { get; set; }
        public ConcurrentDictionary<string, DateTime> seenPackets = new();
        private readonly TimeSpan cacheLifetime = TimeSpan.FromMinutes(5);
        public bool isBootstrapped = false;
        public Peer Peer;
        public Client Client;
        public DHT DHT;
        public readonly int MaxPeers = 25;
        public bool Test_Mode = false;


        //This is used to Create the Node or Load one if it exists. 

        public static Node CreateNode(Client client, NodeType nodeType)
        {


            //create a node.
            Node node = new Node();

            //Create a client for the node using STUN. 

            // Thread-safe key generation
            lock (stateLock)
            {
                //Check to see if Keys exist.
                if (!ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicNodeSignatureKey) || !ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicNodeEncryptionKey))
                {
                    KeyGenerator.GenerateNodeKeyPairs();
                }
            }

            try
            {

                // Initialize PeerHeader
                Peer peer = new Peer
                {
                    Node_Type = nodeType,
                    NodeId = ServiceAccountManager.GenerateKademliaId(),
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = DefaultPreviousHash, // Placeholder value
                    PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeSignatureKey),
                    PublicEncryptKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey),
                };

                // Assign header to node
                node.Peer = peer;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }


            // Initialize DHT Peers and Routing Table.
            node.DHT = new DHT();
            //node.Peers = new Dictionary<string, Peer>();
            node.RoutingTable = new RoutingTable();
            

            try
            {
                // Load DHT state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("DHT")))
                {
                    node.DHT.LoadState();
                }
                else
                {
                    Console.WriteLine("DHT state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading DHT state: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.DHT = new DHT(); // Reinitialize
            }

            try
            {
                // Load RoutingTable state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("RT")))
                {
                    node.RoutingTable.LoadRoutingTable();
                }
                else
                {
                   
                    Console.WriteLine("Routing Table state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading RoutingTable state: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.RoutingTable = new RoutingTable(); // Reinitialize
            }
            node.RoutingTable.node = node;
            return node;
        }

        //This is used to Create the Node or Load one if it exists. 
        public static Node CreateNodeWithClientListenerUsingSTUN(NodeType nodeType)
        {


            //create a node.
            Node node = new Node();

            //Create a client get listeners using STUN. 
           
            Client client = new Client();
            

            // Thread-safe key generation
            lock (stateLock)
            {
                //Check to see if Keys exist.
                if (!ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicNodeSignatureKey) || !ServiceAccountManager.KeyContainerExists(KeyGenerator.KeyType.PublicNodeEncryptionKey))
                {
                    KeyGenerator.GenerateNodeKeyPairs();
                }
            }
            client.StartClientListenerWithSTUNSync(node, client);
            node.Client = client;
            try
            {

                // Initialize PeerHeader
                Peer peer = new Peer
                {
                    Node_Type = nodeType,
                    NodeId = ServiceAccountManager.GenerateKademliaId(),
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = DefaultPreviousHash, // Placeholder value
                    PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeSignatureKey),
                    PublicEncryptKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey),
                };

                // Assign header to node
                node.Peer = peer;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }

            // Initialize DHT
            node.DHT = new DHT();

            try
            {
                // Load DHT state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("DHT")))
                {
                    node.DHT.LoadState();
                }
                else
                {
                    Console.WriteLine("DHT state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading DHT state: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.DHT = new DHT(); // Reinitialize
            }

            try
            {
                // Load RoutingTable state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("RT")))
                {
                    node.RoutingTable.LoadRoutingTable();
                }
                else
                {
                    Console.WriteLine("Routing Table state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading RoutingTable state: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.RoutingTable = new RoutingTable(); // Reinitialize
            }

            return node;
        }

        //Sends a Bootstrap Request You will need to be provided the IP, Port and public communication Key of the Host. (It can be provided by any othter node on request. But is only good till they go off and back online and thier ip and port reset.
        public async Task SendBootstrapRequest(string iPAddress, int port, byte[] recipientsPublicEncryptKey)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug-SendBootstrapRequest: Starting Bootstrap Request...");

                Console.WriteLine($"Debug-SendBootstrapRequest: Using RecipientPublicEncrypt Key: {recipientsPublicEncryptKey}");
                // Validate inputs
                if (node == null)
                {
                    Console.WriteLine("Debug: Node is null.");
                    throw new ArgumentNullException(nameof(node), "Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(iPAddress))
                {
                    Console.WriteLine("Debug: Invalid IP address input.");
                    throw new ArgumentException("IP address cannot be null or empty.", nameof(iPAddress));
                }

                if (port <= 0 || port > 65535)
                {
                    Console.WriteLine($"Debug: Invalid port: {port}.");
                    throw new ArgumentOutOfRangeException(nameof(port), "Port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientsPublicEncryptKey)))
                {
                    Console.WriteLine("Debug: Recipient's public communication key is null or empty.");
                    throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientsPublicEncryptKey));
                }

                Console.WriteLine($"Debug-SendBootstrapRequest: Inputs validated. IP: {iPAddress}, Port: {port}, PublicEncryptKey: {recipientsPublicEncryptKey}");

                // Use RetryAsync to retry the operation on failure
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-SendBootstrapRequest: Building bootstrap request packet...");
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BootstrapRequest,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        75
                    );

                    Packet packet = BuildPacket(header, PacketType.BootstrapRequest.ToString());
                    Console.WriteLine($"Debug-SendBootstrapRequest: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    Console.WriteLine("Debug-SendBootstrapRequest: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    Console.WriteLine($"Debug-SendBootstrapRequest: Packet serialized. Data Length: {data.Length} bytes");

                    bool success = new bool();
                    if (Test_Mode)
                    {
                        Console.WriteLine("Debug-SendBootstrapRequest: Encrypting packet...");
                        // Encrypt the packet using the recipient's public communication key
                        Console.WriteLine("Debug-SendBootstrapRequest: Encrypting packet...");
                        byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(data, recipientsPublicEncryptKey);
                        Console.WriteLine($"Debug-SendBootstrapRequest: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");


                        // Send the encrypted data and signature to the recipient
                        Console.WriteLine($"Debug-SendBootstrapRequest: Sending packet to {iPAddress}:{port}...");
                        success = await Client.SendPacketToPeerAsync(iPAddress, port, encryptedData);
                    }
                    else
                    {

                        // Encrypt the packet using the recipient's public communication key
                        Console.WriteLine("Debug-SendBootstrapRequest: Encrypting packet...");
                        byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(data, recipientsPublicEncryptKey); 
                        Console.WriteLine($"Debug-SendBootstrapRequest: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");

                    

                        // Send the encrypted data and signature to the recipient
                        Console.WriteLine($"Debug-SendBootstrapRequest: Sending packet to {iPAddress}:{port}...");
                         success = await Client.SendPacketToPeerAsync(iPAddress, port, encryptedData);
                    }


                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-SendBootstrapRequest: Failed to send bootstrap request to {iPAddress}:{port}");
                        throw new Exception($"SendBootstrapRequest: Failed to send bootstrap request to {iPAddress}:{port}.");
                    }

                    // Log successful bootstrap request
                    Console.WriteLine($"Debug-SendBootstrapRequest: Bootstrap request successfully sent to {iPAddress}:{port}");

                    Console.WriteLine("Debug-SendBootstrapRequest: Bootstrap Request process completed.");
                    return success; 
                });

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-SendBootstrapRequest: {ex.Message}");
                Console.WriteLine($"SendBootstrapRequest: Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Process Bootstrap Response
        public async Task ProcessBootstrapResponse(Packet packet)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug-ProcessBootstrapResponse: Starting to process bootstrap response...");

                // Verify Node isn't already Bootstrapped, prevents re-bootstrapping by accident
                if (node.isBootstrapped)
                {
                    Console.WriteLine("Debug-ProcessBootstrapResponse: Node is already bootstrapped. Ignoring the response.");
                    return;
                }

                // Validate the packet and extract the header details
                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Debug-ProcessBootstrapResponse: Invalid packet or missing header.");
                    return;
                }

                Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing packet from Node ID: {packet.Header.NodeId}, IP: {packet.Header.IPAddress}, Port: {packet.Header.Port}");

                // Extract details from the packet header
                byte[] senderPublicEncrptyKey = packet.Header.PublicEncryptKey;
                string signature = packet.Signature;

                // Deserialize the response payload
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                BootstrapResponsePayload responsePayload = JsonSerializer.Deserialize<BootstrapResponsePayload>(packet.Content, options);




                Console.WriteLine($"Debug-ProcessBootstrapResponse: Packet signature: {signature}.");


                bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";
                if (isTesting)
                {

                    // Verify the signature
                    byte[] packetArray = SerializePacket(packet);
                        Console.WriteLine("Debug-ProcessBootstrapResponse: Verifying packet signature...");

 
                        if (responsePayload == null)
                        {
                            Console.WriteLine("Debug-ProcessBootstrapResponse: Failed to deserialize bootstrap response payload.");
                            return;
                        }
                        Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response payload deserialized successfully.");

                        // Process the peer list
                        if (responsePayload.Peers != null)
                        {
                            Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.Peers.Count} peers...");
                            lock (RoutingTable) // Ensure thread-safe access to the RoutingTable
                            {
                                foreach (var peer in responsePayload.Peers)
                                {
                                    // Create a Peer object for each entry
                                    var newPeer = new Peer
                                    {
                                        NodeId = peer.NodeId,
                                        NodeIP = peer.NodeIP,
                                        NodePort = peer.NodePort,
                                        PublicSignatureKey = peer.PublicSignatureKey,
                                        PublicEncryptKey = peer.PublicEncryptKey
                                    };

                                    // Add the peer to the RoutingTable (will handle duplicates automatically)
                                    RoutingTable.AddPeer(newPeer);
                                    Console.WriteLine($"Debug-ProcessBootstrapResponse: Added or updated peer {peer.NodeId} in the routing table.");
                                }
                            }
                        }

                        // Process the DHT state (if included)
                        if (responsePayload.DHT != null)
                        {
                            Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.DHT.Count} DHT blocks...");
                            lock (stateLock) // Ensure thread-safe access to the DHT
                            {
                                foreach (var block in responsePayload.DHT)
                                {
                                    // Validate the block before adding it
                                    if (DHT.IsBlockValid(block))
                                    {
                                        node.DHT.AddBlock(block);
                                        Console.WriteLine($"Debug-ProcessBootstrapResponse: Added DHT block: {block.Header.BlockId}");
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Debug-ProcessBootstrapResponse: Invalid block {block.Header.BlockId}. Skipping.");
                                    }
                                }
                            }
                        }

                        Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response processed successfully.");
                    }
                    else
                    {
               
                        if (responsePayload == null)
                        {
                            Console.WriteLine("Debug-ProcessBootstrapResponse: Failed to deserialize bootstrap response payload.");
                            return;
                        }
                        Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response payload deserialized successfully.");

                        // Process the peer list
                        if (responsePayload.Peers != null)
                        {
                            Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.Peers.Count} peers...");
                            lock (RoutingTable) // Ensure thread-safe access to the RoutingTable
                            {
                                foreach (var peer in responsePayload.Peers)
                                {
                                    // Create a Peer object for each entry
                                    var newPeer = new Peer
                                    {
                                        NodeId = peer.NodeId,
                                        NodeIP = peer.NodeIP,
                                        NodePort = peer.NodePort,
                                        PublicSignatureKey = peer.PublicSignatureKey,
                                        PublicEncryptKey = peer.PublicEncryptKey
                                    };

                                    // Add the peer to the RoutingTable (will handle duplicates automatically)
                                    RoutingTable.AddPeer(newPeer);
                                    //Console.WriteLine($"Debug-ProcessBootstrapResponse: Added or updated peer {peer.NodeId} in the routing table.");
                                }
                            }
                        }

                        // Process the DHT state (if included)
                        if (responsePayload.DHT != null)
                        {
                            Console.WriteLine($"Debug-ProcessBootstrapResponse: Processing {responsePayload.DHT.Count} DHT blocks...");
                            lock (stateLock) // Ensure thread-safe access to the DHT
                            {
                                foreach (var block in responsePayload.DHT)
                                {

                                        node.DHT.AddBlock(block);
                                        //Console.WriteLine($"Debug-ProcessBootstrapResponse: Added DHT block: {block.Header.BlockId}");
                          
                                }
                            }
                        }

                        Console.WriteLine("Debug-ProcessBootstrapResponse: Bootstrap response processed successfully.");


                    }

                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-ProcessBootstrapResponse: {ex.Message}");
                Console.WriteLine($"ProcessBootstrapResponse: Debug Trace: {ex.StackTrace}");
            }
        }

        // Sends a response to a request to Bootstrap.  Sends a peer list and copy of DHT (Or shards at some point)
        public async Task SendBootstrapResponse(Packet packet)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug-SendBootstrapResponse: Starting to send bootstrap response...");

                // Extract recipient details from the packet
                string recipientsID = packet.Header.NodeId;
                string recipientIPAddress = packet.Header.IPAddress;
                int recipientPort = int.Parse(packet.Header.Port);
                byte[] recipientPublicEncryptKey = packet.Header.PublicEncryptKey;

                Console.WriteLine($"Debug-SendBootstrapResponse: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    Console.WriteLine($"Debug-SendBootstrapResponse: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientPublicEncryptKey)))
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Recipient's public encryption key is invalid.");
                    throw new ArgumentException("Recipient's public encryption key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                Console.WriteLine("Debug-SendBootstrapResponse: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-SendBootstrapResponse: Preparing peer list for response...");
                    List<Peer> peerList;

                    lock (node.RoutingTable)
                    {
                        if (!string.IsNullOrWhiteSpace(recipientsID))
                        {
                            peerList = node.RoutingTable.GetClosestPeers(recipientsID, 20); // Adjust '20' as needed
                            Console.WriteLine($"Debug-SendBootstrapResponse: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                        }
                        else
                        {
                            peerList = node.RoutingTable.GetAllPeers();
                            Console.WriteLine($"Debug-SendBootstrapResponse: Retrieved all peers. Total: {peerList.Count}");
                        }
                    }

                    // Prepare a lightweight peer list for the response payload
                    var responsePeerList = peerList.Select(peer => Peer.CreatePeer(
                        peer.Node_Type,  // Assuming `Node_Type` is part of Peer
                        peer.NodeId,
                        peer.NodeIP,
                        peer.NodePort,
                        peer.PreviousNodesHash,  
                        peer.PublicSignatureKey,
                        peer.PublicEncryptKey
                    )).ToList();

                    Console.WriteLine($"Debug-SendBootstrapResponse: Peer list prepared. Count: {responsePeerList.Count}");

                    // Include DHT state (if necessary)
                    Console.WriteLine("Debug-SendBootstrapResponse: Retrieving DHT state...");
                    var dhtState = node.DHT.GetCurrentState();
                    Console.WriteLine($"Debug-SendBootstrapResponse: Retrieved DHT state. Block count: {dhtState.Count}");

                    //build packet header
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BootstrapResponse,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        1
                     
                     );

                    // Build the response payload
                    BootstrapResponsePayload responsePayload = new BootstrapResponsePayload
                    {
                        Peers = responsePeerList,
                        DHT = dhtState
                    };
               

                    Packet responsePacket = Packet.PacketBuilder.BuildPacket(header, JsonSerializer.Serialize(responsePayload));

                    Console.WriteLine("Debug-SendBootstrapResponse: Serializing response payload...");
                    byte[] responseData = Packet.PacketBuilder.SerializePacket(responsePacket);
                    Console.WriteLine($"Debug-SendBootstrapResponse: Serialized response payload. Size: {responseData.Length} bytes");
                    bool success = new bool();

                    // Encrypt the response data using the recipient's public communication key
                    Console.WriteLine("Debug-SendBootstrapResponse: Encrypting response data...");


                    if (Test_Mode)
                    {
                        byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(responseData, recipientPublicEncryptKey);
                        Console.WriteLine("Debug-SendBootstrapResponse: Encrypting Disabled for internal testing");
                        string responseSignature = "TestSignature";
                        Console.WriteLine("Debug-SendBootstrapResponse: Signature Disabled for internal testing");

                        // Send the encrypted response data and signature to the recipient
                        Console.WriteLine($"Debug-SendBootstrapResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                        success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData);
                    }
                    else
                    {

                        byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(responseData, recipientPublicEncryptKey);
                        Console.WriteLine($"Debug-SendBootstrapResponse: Encrypted response data. Encrypted size: {encryptedResponseData.Length} bytes");

                        // Generate a signature for the encrypted data using the node's private key
                        Console.WriteLine("Debug-SendBootstrapResponse: Generating signature for response...");
                        Console.WriteLine("Debug-SendBootstrapResponse: Signing disabled for testing....");
                        byte[] responseSignature = SignatureGenerator.SignByteArray(encryptedResponseData);
                        Console.WriteLine($"Debug: Signature generated. Length: {responseSignature.Length} characters");

                        // Send the encrypted response data and signature to the recipient
                        Console.WriteLine($"Debug-SendBootstrapResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                        success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData);
                    }

                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-SendBootstrapResponse: Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"SendBootstrapResponse: Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    Console.WriteLine("Debug-SendBootstrapResponse: Updating trust score for recipient...");
                    lock (node.RoutingTable)
                    {
                        var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);
                        if (peer != null)
                        {
                            peer.UpdateTrustScore(peer, +5); // Reward 5 points
                            Console.WriteLine($"Debug-SendBootstrapResponse: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.TrustScore}");
                        }
                        else
                        {
                            Console.WriteLine("Debug-SendBootstrapResponse: Recipient peer not found in the routing table.");
                        }
                    }

                    // Log successful bootstrap response
                    Console.WriteLine($"Debug-SendBootstrapResponse: Bootstrap response successfully sent to {recipientIPAddress}:{recipientPort}.");
                    return success; // Explicitly return success
                });

                Console.WriteLine("Debug-SendBootstrapResponse: Bootstrap response process completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-SendBootstrapResponse: {ex.Message}");
                Console.WriteLine($"SendBootstrapResponse: Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Resets the Bootstrap Status to allow a corupted node to "Reset" it's peers and DHT.
        public static void ResetBootstrapStatus(Node node)
        {
            node.isBootstrapped = false;
        }

        //Once the Node has a Routing Table it can get the Previous Hash and update the Previous Hash
        public void UpdateNodePerviousHash(Node node, string previousHash)
        {
            node.Peer.PreviousNodesHash = previousHash;
        }

        // Updates the Endpoint info of a Peer.
        public void UpdatePeerEndpoint(string peerID, string newIP, int newPort)
        {
            if (string.IsNullOrEmpty(peerID))
            {
                throw new ArgumentException("Peer ID cannot be null or empty.", nameof(peerID));
            }

            if (string.IsNullOrEmpty(newIP))
            {
                throw new ArgumentException("New IP cannot be null or empty.", nameof(newIP));
            }

            if (newPort <= 0 || newPort > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(newPort), "Port must be a valid number between 1 and 65535.");
            }

            lock (stateLock) // Ensure thread safety when accessing and modifying the Peers dictionary
            {
                Peer peer = RoutingTable.GetPeerByID(peerID);
                if (peer == null)
                {
                    throw new KeyNotFoundException($"Peer with ID {peerID} not found.");
                }

                // Update the peer's endpoint
                peer.NodeIP = newIP;
                peer.NodePort = newPort;

                Console.WriteLine($"Updated endpoint for peer {peerID}: {newIP}:{newPort}");
            }
        }

        // Send response to a Ping request.
        public async Task RespondToPingAsync(Packet packet)
        {
            Node node = this;
            try
            {
                // Validate the incoming packet
                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Invalid ping request packet.");
                    return;
                }

                string senderIPAddress = packet.Header.IPAddress;
                int senderPort = int.Parse(packet.Header.Port);
                byte[] senderPublicSignatureKey = packet.Header.PublicSignatureKey;
                byte[] senderPublicEncryptKey = packet.Header.PublicEncryptKey;

                if (string.IsNullOrWhiteSpace(senderIPAddress) || string.IsNullOrWhiteSpace(Convert.ToBase64String(senderPublicSignatureKey)))
                {
                    Console.WriteLine("Invalid ping request header details.");
                    return;
                }

                // Validate and potentially add the sender to the routing table
                lock (RoutingTable)
                {
                    // Create a new peer object
                    Peer newPeer = new Peer
                    {
                        NodeIP = senderIPAddress,
                        NodePort = senderPort,
                        PublicSignatureKey = senderPublicSignatureKey,
                        PublicEncryptKey = senderPublicEncryptKey,
                        NodeId = packet.Header.NodeId,
                        TrustScore = 0 // Initial trust score
                    };

                    // Add the peer to the RoutingTable (handles duplicates and updates)
                    RoutingTable.AddPeer(newPeer);
                    Console.WriteLine($"Added or updated peer {newPeer.NodeId} in the routing table.");
                }

                // Build the ping response packet
                Packet responsePacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = this.Peer.NodeId,
                        IPAddress = Client.clientIP.ToString(),
                        Port = Client.clientListenerPort.ToString(),
                        PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeSignatureKey),
                        PublicEncryptKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicNodeEncryptionKey),
                        Packet_Type = "Pong",
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("Pong")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("Pong")))
                };

                // Serialize and send the response packet
                byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(
                    Encoding.UTF8.GetBytes(responsePacket.Content),
                    node.Peer.PublicEncryptKey
               
                );

                bool success = await Client.SendPacketToPeerAsync(senderIPAddress, senderPort, encryptedResponseData);

                if (success)
                {
                    Console.WriteLine($"Successfully sent PingResponse to {senderIPAddress}:{senderPort}");
                }
                else
                {
                    Console.WriteLine($"Failed to send PingResponse to {senderIPAddress}:{senderPort}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error responding to ping: {ex.Message}");
            }
        }

        //Cleans up the Cashe that stores recent messages preventing processing the same message twice
        private async Task StartCacheCleanup()
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromMinutes(1));  // Run cleanup every minute

                lock (seenPackets)  // Ensure thread safety
                {
                    DateTime now = DateTime.UtcNow;
                    var expiredKeys = seenPackets.Where(kvp => now - kvp.Value > cacheLifetime)
                                                 .Select(kvp => kvp.Key)
                                                 .ToList();

                    foreach (var key in expiredKeys)
                    {
                        seenPackets.TryRemove(key, out _);
                    }
                }
            }
        }

        // Pings the Peerlist Staggard.
        public async Task StartStaggeredPingAsync()
        {
            while (true) // Keep the pinging process running
            {
                // Step 1: Collect all peers from the routing table
                List<Peer> allPeers;
                lock (RoutingTable)
                {
                    allPeers = RoutingTable.GetAllPeers(); // Retrieve all peers from the routing table
                }

                if (allPeers == null || allPeers.Count == 0)
                {
                    Console.WriteLine("No peers available to ping.");
                    await Task.Delay(TimeSpan.FromHours(1)); // Wait for an hour before checking again
                    continue;
                }

                Console.WriteLine("Starting staggered hourly pings to peers...");

                // Step 2: Calculate the staggered interval in milliseconds
                int staggeredInterval = (int)(TimeSpan.FromHours(1).TotalMilliseconds / allPeers.Count);

                // Step 3: Ping each peer asynchronously with a staggered delay
                foreach (var peer in allPeers)
                {
                    // Ping each peer
                    _ = SafeTask(async () =>
                    {
                        bool isAlive = await PingPeerAsync(this, peer);
                        if (isAlive)
                        {
                            Console.WriteLine($"Peer {peer.NodeId} responded successfully.");
                        }
                        else
                        {
                            Console.WriteLine($"Peer {peer.NodeId} did not respond. Marking as inactive.");
                            lock (RoutingTable)
                            {
                                RoutingTable.RemovePeer(peer.NodeId); // Remove the peer if unreachable
                            }
                        }
                    });

                    // Wait for the staggered interval before pinging the next peer
                    await Task.Delay(staggeredInterval);
                }

                // Wait for the next hour before starting the next round of pings
                await Task.Delay(TimeSpan.FromHours(1));
            }
        }

        //Brodcast the Nodes Conncetion to the Network
        public async Task BrodcastConnectionToNetwork()
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug-BrodcastConnectionToNetwork: Starting Brodcast Network Connectiont...");


                // Use RetryAsync to retry the operation on failure
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Brodcast  Network Connection packet...");
                    Packet.PacketHeader header = BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BrodcastConnection,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        50
                    );

                    Packet packet = Packet.PacketBuilder.BuildPacket(header, PacketType.BrodcastConnection.ToString());
                    Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet serialized. Data Length: {data.Length} bytes");

                    bool allSuccessful = true;

                    List<Peer> peers = node.RoutingTable.GetAllPeers();

                        foreach(var peer in peers)
                        {
                            Console.WriteLine("Debug-BrodcastConnectionToNetwork: Encrypting packet...");
                            // Encrypt the packet using the recipient's public communication key
                            Console.WriteLine("Debug-BrodcastConnectionToNetwokr: Encrypting packet...");
                            byte[] encryptedData = Encryption.EncryptPacketWithPublicKey(data, peer.PublicEncryptKey);
                            Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");


                            // Send the encrypted data and signature to the recipient
                            Console.WriteLine($"Debug-BrodcastConnectionToNetwokr: Sending packet to NODE: {peer.NodeId.Substring(0, 6)} at {peer.NodeIP}:{peer.NodePort}...");
                            bool success = await Client.SendPacketToPeerAsync(peer.NodeIP, peer.NodePort, encryptedData);

                            // If the send operation fails, throw an exception to trigger a retry
                            if (!success)
                            {
                                Console.WriteLine($"Debug-BrodcastConnectionToNetworkt: Failed to send Brodcast of network connection to {peer.NodeIP}:{peer.NodePort}");
                                allSuccessful = false;
                        }
                            Console.WriteLine($"Debug-BrodcastConnectionToNetwork: Brodcast of network connection successfully sent to {peer.NodeIP}:{peer.NodePort}");
                        }


                    if (!allSuccessful)
                    {
                        throw new Exception("BrodcastConnectionToNetwork: Some peers failed to receive the broadcast.");
                    }

                    // Log successful bootstrap request

                    Console.WriteLine("Debug-BrodcastConnectionToNetwork: Bootstrap Request process completed.");
                    return allSuccessful;
                });

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-BrodcastConnectionToNetwork: {ex.Message}");
                Console.WriteLine($"BrodcastConnectionToNetwork: Debug Trace: {ex.StackTrace}");
                throw;
            }

        }

        //Send Peer List to requesting peer
        public async Task PeerListResponse(Packet packet)
        {

            Node node = this;
           
            try
            {
                Console.WriteLine("Debug-PeerListResponse: Starting to send bootstrap response...");
                Peer peer = Peer.CreatePeer(
                    Enum.Parse<NodeType>(packet.Header.Node_Type),
                    packet.Header.NodeId,
                    packet.Header.IPAddress,
                    int.Parse(packet.Header.Port),
                    "Unknown",
                    packet.Header.PublicSignatureKey,
                    packet.Header.PublicEncryptKey);

                if (!node.RoutingTable.GetAllPeers().Contains(peer) || peer.NodeId!=node.Peer.NodeId)
                {
                    node.RoutingTable.AddPeer(peer);
                }

                // Extract recipient details from the packet
                string recipientsID = packet.Header.NodeId;
                string recipientIPAddress = packet.Header.IPAddress;
                int recipientPort = int.Parse(packet.Header.Port);
                byte[] recipientPublicEncryptKey = packet.Header.PublicEncryptKey;

                Console.WriteLine($"Debug-PeerListResponse: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    Console.WriteLine("Debug-PeerListResponse: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    Console.WriteLine("Debug-PeerListResponse: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    Console.WriteLine("Debug-PeerListResponse: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    Console.WriteLine($"Debug-PeerListResponse: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(Convert.ToBase64String(recipientPublicEncryptKey)))
                {
                    Console.WriteLine("Debug-PeerListResponse: Recipient's public encryption key is invalid.");
                    throw new ArgumentException("Recipient's public encryption key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                Console.WriteLine("Debug-PeerListResponse: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug-PeerListResponse: Preparing peer list for response...");
                    List<Peer> peerList;

                    lock (node.RoutingTable)
                    {
                        if (!string.IsNullOrWhiteSpace(recipientsID))
                        {
                            peerList = node.RoutingTable.GetClosestPeers(recipientsID, 20); // Adjust '20' as needed
                            Console.WriteLine($"Debug-PeerListResponse: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                        }
                        else
                        {
                            peerList = node.RoutingTable.GetAllPeers();
                            Console.WriteLine($"Debug-PeerListResponse: Retrieved all peers. Total: {peerList.Count}");
                        }
                    }

                    //// Prepare a lightweight peer list for the response payload
                    //List<Peer> responsePeerList = peerList.Select(peer => Peer.CreatePeer(
                    //    peer.Node_Type,  // Assuming `Node_Type` is part of Peer
                    //    peer.NodeId,
                    //    peer.NodeIP,
                    //    peer.NodePort,
                    //    peer.PreviousNodesHash,
                    //    peer.PublicSignatureKey,
                    //    peer.PublicEncryptKey
                    //)).ToList();

                    Console.WriteLine($"Debug-PeerListResponse: Peer list prepared. Count: {peerList.Count}");


                    //build packet header
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.PeerUpdate,
                        node.Peer.NodeId,
                        node.Peer.Node_Type.ToString(),
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        1

                     );



                    Packet responsePacket = Packet.PacketBuilder.BuildPacket(header, JsonSerializer.Serialize(peerList));

                    Console.WriteLine("Debug-PeerListResponse: Serializing response payload...");
                    byte[] responseData = Packet.PacketBuilder.SerializePacket(responsePacket);
                    Console.WriteLine($"Debug-PeerListResponse: Serialized response payload. Size: {responseData.Length} bytes");
                    bool success = new bool();

                    // Encrypt the response data using the recipient's public communication key
                    Console.WriteLine("Debug-PeerListResponse: Encrypting response data...");


              
                    byte[] encryptedResponseData = Encryption.EncryptPacketWithPublicKey(responseData, recipientPublicEncryptKey);

                    // Send the encrypted response data and signature to the recipient
                    Console.WriteLine($"Debug-PeerListResponse: Sending response to {recipientIPAddress}:{recipientPort}...");
                    success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData);
                    


                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug-PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"PeerListResponse: Failed to send Peer List Response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    Console.WriteLine("Debug-PeerListResponse: Updating trust score for recipient...");
                    lock (node.RoutingTable)
                    {
                        var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);
                        if (peer != null)
                        {
                            peer.UpdateTrustScore(peer, +5); // Reward 5 points
                            Console.WriteLine($"Debug-PeerListResponse: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.TrustScore}");
                        }
                        else
                        {
                            Console.WriteLine("Debug-PeerListResponse: Recipient peer not found in the routing table.");
                        }
                    }

                    // Log successful bootstrap response
                    Console.WriteLine($"Debug-PeerListResponse: Peer List Responsesuccessfully sent to {recipientIPAddress}:{recipientPort}.");

                    await node.Client.RebroadcastToPeerList(node, packet);
                    return success; // Explicitly return success

                });

                Console.WriteLine("Debug-PeerListResponse: Peer List Response process completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error-PeerListResponse: {ex.Message}");
                Console.WriteLine($"PeerListResponse: Debug Trace: {ex.StackTrace}");
                throw;
            }


        }

        //Process PeerList Response
        public async Task ProcessPeerListResponse(Packet packet)
        {
            Console.WriteLine($"Debug-ProcessPeerListResponse: Processing response from {packet.Header.NodeId}...");

            List<Peer> peers = JsonSerializer.Deserialize<List<Peer>>(packet.Content);

            Node node = this;
                

                if (peers != null)
                {
                    Console.WriteLine($"Debug-ProcessPeerListResponse: Received {peers.Count} peers.");

                    lock (RoutingTable) // Ensure thread-safe access
                    {
                        foreach (var peer in peers)
                        {
                            if (node.RoutingTable.GetAllPeers().Contains(peer))
                            {
                                Console.WriteLine($"Debug-ProcessPeerListResponse: Skipping duplicate peer {peer.NodeId}.");
                                continue;
                            }

                            if (peer.NodeId == node.Peer.NodeId)
                            {
                                Console.WriteLine($"ERROR: babyNode ({node.Peer.NodeId}) is receiving itself in a peer list. Sender: {packet.Header.NodeId}");
                                continue;
                            }

                            node.RoutingTable.AddPeer(peer);
                        }
                    }
                }
        }

        //Ping a single peer. Returns True or false based on successful ping. 
        public static async Task<bool> PingPeerAsync(Node node,Peer peer)
        {
            try
            {
                // Send a small ping packet to the peer
                Packet pingPacket = new Packet
                {
                    Header = new Packet.PacketHeader
                    {
                        NodeId = node.Peer.NodeId,
                        IPAddress = node.Peer.NodeIP,
                        Port = node.Peer.NodePort.ToString(),
                        PublicSignatureKey = node.Peer.PublicSignatureKey,
                        PublicEncryptKey= node.Peer.PublicEncryptKey,
                        Packet_Type = "Ping",
                        TTL = "1"
                    },
                    Content = Convert.ToBase64String(Encoding.UTF8.GetBytes("PingRequest")),
                    Signature = Convert.ToBase64String(SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("PingRequest")))
                };

                // Send the ping and wait for a response
                bool success = await Client.SendPacketToPeerAsync(
                    peer.NodeIP,
                    peer.NodePort,
                    Encoding.UTF8.GetBytes(pingPacket.Content)
                    

                );

                return success; // Return true if the ping was successful
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error pinging peer {peer.NodeId}: {ex.Message}");
                return false; // Return false if there was an error
            }
        }

        // This is used to allow for retries on sending out messages to other nodes.
        private async Task<T> RetryAsync<T>(Func<Task<T>> action, int maxRetries = 3, int delayMilliseconds = 1000)
        {
            for (int i = 0; i < maxRetries; i++)
            {
                try
                {
                    return await action(); // Attempt the action
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Attempt {i + 1} failed: {ex.Message}");
                    if (i == maxRetries - 1)
                        throw; // Re-throw on final attempt

                    await Task.Delay(delayMilliseconds * (int)Math.Pow(2, i)); // Exponential backoff
                }
            }

            throw new Exception("RetryAsync failed after all attempts."); // Should never reach here
        }

        //same thing here, This is used to assist in retyoing and queueing the tasks.. 
        private async Task SafeTask(Func<Task> action)
        {
            try
            {
                await action();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Task error: {ex.Message}");
            }
        }
    }

    // This is used to manage the BootStrap Payloads.
    public class BootstrapResponsePayload
    {
        public List<Peer> Peers { get; set; }
        public List<Block> DHT { get; set; } // Use a List<Block> to handle multiple blocks
    }
 
}

