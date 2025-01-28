using System.Net.Mail;
using System.Reflection;
using System.Text;
using System.Text.Json;
using SharedLibraries;
using SPHERE.Configure;
using SPHERE.Networking;
using SPHERE.PacketLib;
using SPHERE.Security;
using SharedLibraries;
using SPHERE.TestingLib;

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
       // public Dictionary<string, Peer> Peers = new Dictionary<string, Peer>();
        public RoutingTable RoutingTable { get; set; }
        public bool isBootstrapped = false;
        public Peer Peer;
        public Client Client;
        public DHT DHT;
        public readonly int MaxPeers = 25;


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
            IKeyProvider keyProvider = new Testing();
            Client client = new Client(keyProvider);
            

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
        public async Task SendBootstrapRequest(string iPAddress, int port, string recipientsPublicEncryptKey)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug: Starting Bootstrap Request...");

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

                if (string.IsNullOrWhiteSpace(recipientsPublicEncryptKey))
                {
                    Console.WriteLine("Debug: Recipient's public communication key is null or empty.");
                    throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientsPublicEncryptKey));
                }

                Console.WriteLine($"Debug: Inputs validated. IP: {iPAddress}, Port: {port}, PublicComKey: {recipientsPublicEncryptKey}");

                // Use RetryAsync to retry the operation on failure
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug: Building bootstrap request packet...");
                    Packet.PacketHeader header = Packet.PacketBuilder.BuildPacketHeader(
                        Packet.PacketBuilder.PacketType.BootstrapRequest,
                        node.Peer.NodeId,
                        node.Peer.PublicSignatureKey,
                        node.Peer.PublicEncryptKey,
                        node.Client.clientListenerPort,
                        node.Client.clientIP.ToString(),
                        75
                    );

                    Packet packet = Packet.PacketBuilder.BuildPacket(header, "BootstrapRequest");
                    Console.WriteLine($"Debug: Packet built with NodeId: {node.Peer.NodeId}, IP: {node.Client.clientIP}, Port: {node.Client.clientListenerPort}");

                    // Serialize the packet into a byte array
                    Console.WriteLine("Debug: Serializing packet...");
                    byte[] data = Packet.PacketBuilder.SerializePacket(packet);
                    Console.WriteLine($"Debug: Packet serialized. Data Length: {data.Length} bytes");

                    // Encrypt the packet using the recipient's public communication key
                    Console.WriteLine("Debug: Encrypting packet...");
                    byte[] encryptedData = Encryption.EncryptWithPersonalKey(data, recipientsPublicEncryptKey);
                    Console.WriteLine($"Debug: Packet encrypted. Encrypted Data Length: {encryptedData.Length} bytes");

                    // Generate a signature for the encrypted data using the node's private key
                    Console.WriteLine("Debug: Generating signature...");
                    string signature = SignatureGenerator.SignByteArray(encryptedData);
                    Console.WriteLine($"Debug: Signature generated. Signature Length: {signature.Length} characters");

                    // Send the encrypted data and signature to the recipient
                    Console.WriteLine($"Debug: Sending packet to {iPAddress}:{port}...");
                    bool success = await Client.SendPacketToPeerAsync(iPAddress, port, encryptedData, signature);

                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug: Failed to send bootstrap request to {iPAddress}:{port}");
                        throw new Exception($"Failed to send bootstrap request to {iPAddress}:{port}.");
                    }

                    // Log successful bootstrap request
                    Console.WriteLine($"Debug: Bootstrap request successfully sent to {iPAddress}:{port}");

                    return success; // Explicitly return the success status
                });

                Console.WriteLine("Debug: Bootstrap Request process completed.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Process Bootstrap Response
        public async Task ProcessBootstrapResponse(Packet packet)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug: Starting to process bootstrap response...");

                // Verify Node isn't already Bootstrapped, prevents re-bootstrapping by accident
                if (node.isBootstrapped)
                {
                    Console.WriteLine("Debug: Node is already bootstrapped. Ignoring the response.");
                    return;
                }

                // Validate the packet and extract the header details
                if (packet == null || packet.Header == null)
                {
                    Console.WriteLine("Debug: Invalid packet or missing header.");
                    return;
                }

                Console.WriteLine($"Debug: Processing packet from Node ID: {packet.Header.NodeId}, IP: {packet.Header.IPAddress}, Port: {packet.Header.Port}");

                // Extract details from the packet header
                string senderPublicKey = packet.Header.PublicSignatureKey;
                string signature = packet.Signature;
                byte[] encryptedData = Convert.FromBase64String(packet.Content);

                Console.WriteLine($"Debug: Packet signature: {signature}. Content size: {encryptedData.Length} bytes");

                // Verify the signature
                Console.WriteLine("Debug: Verifying packet signature...");
                bool isSignatureValid = SignatureGenerator.VerifyByteArray(encryptedData, signature, senderPublicKey);
                if (!isSignatureValid)
                {
                    Console.WriteLine("Debug: Invalid signature. Response has been tampered with.");
                    return;
                }
                Console.WriteLine("Debug: Signature verification passed.");

                // Decrypt the data
                Console.WriteLine("Debug: Decrypting packet data...");
                byte[] decryptedData = Encryption.DecryptWithPrivateKey(
                    encryptedData,
                    ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateNodeEncryptionKey)
                );
                Console.WriteLine($"Debug: Decryption successful. Decrypted data size: {decryptedData.Length} bytes");

                // Deserialize the response payload
                Console.WriteLine("Debug: Deserializing bootstrap response payload...");
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var responsePayload = JsonSerializer.Deserialize<BootstrapResponsePayload>(decryptedData, options);

                if (responsePayload == null)
                {
                    Console.WriteLine("Debug: Failed to deserialize bootstrap response payload.");
                    return;
                }
                Console.WriteLine("Debug: Bootstrap response payload deserialized successfully.");

                // Process the peer list
                if (responsePayload.Peers != null)
                {
                    Console.WriteLine($"Debug: Processing {responsePayload.Peers.Count} peers...");
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
                            Console.WriteLine($"Debug: Added or updated peer {peer.NodeId} in the routing table.");
                        }
                    }
                }

                // Process the DHT state (if included)
                if (responsePayload.DHT != null)
                {
                    Console.WriteLine($"Debug: Processing {responsePayload.DHT.Count} DHT blocks...");
                    lock (stateLock) // Ensure thread-safe access to the DHT
                    {
                        foreach (var block in responsePayload.DHT)
                        {
                            // Validate the block before adding it
                            if (DHT.IsBlockValid(block))
                            {
                                node.DHT.AddBlock(block);
                                Console.WriteLine($"Debug: Added DHT block: {block.Header.BlockId}");
                            }
                            else
                            {
                                Console.WriteLine($"Debug: Invalid block {block.Header.BlockId}. Skipping.");
                            }
                        }
                    }
                }

                Console.WriteLine("Debug: Bootstrap response processed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Debug Trace: {ex.StackTrace}");
            }
        }

        // Sends a response to a request to Bootstrap.  Sends a peer list and copy of DHT (Or shards at some point)
        public async Task SendBootstrapResponse(Packet packet)
        {
            Node node = this;

            try
            {
                Console.WriteLine("Debug: Starting to send bootstrap response...");

                // Extract recipient details from the packet
                string recipientsID = packet.Header.NodeId;
                string recipientIPAddress = packet.Header.IPAddress;
                int recipientPort = int.Parse(packet.Header.Port);
                string recipientPublicEncryptKey = packet.Header.PublicSignatureKey;

                Console.WriteLine($"Debug: Recipient details - NodeId: {recipientsID}, IP: {recipientIPAddress}, Port: {recipientPort}, PublicComKey: {recipientPublicEncryptKey}");

                // Validate inputs
                if (packet == null)
                {
                    Console.WriteLine("Debug: Packet is null.");
                    throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
                }

                if (node == null)
                {
                    Console.WriteLine("Debug: Node is null.");
                    throw new ArgumentNullException(nameof(node), "The Node cannot be null.");
                }

                if (string.IsNullOrWhiteSpace(recipientIPAddress))
                {
                    Console.WriteLine("Debug: Recipient IP address is invalid.");
                    throw new ArgumentException("Packet's IP address cannot be null or empty.", nameof(recipientIPAddress));
                }

                if (recipientPort <= 0 || recipientPort > 65535)
                {
                    Console.WriteLine($"Debug: Invalid recipient port: {recipientPort}");
                    throw new ArgumentOutOfRangeException(nameof(recipientPort), "Packet port must be a valid number between 1 and 65535.");
                }

                if (string.IsNullOrWhiteSpace(recipientPublicEncryptKey))
                {
                    Console.WriteLine("Debug: Recipient's public communication key is invalid.");
                    throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientPublicEncryptKey));
                }

                Console.WriteLine("Debug: Inputs validated successfully.");

                // Use RetryAsync to ensure the response is sent
                await RetryAsync<bool>(async () =>
                {
                    Console.WriteLine("Debug: Preparing peer list for response...");
                    List<Peer> peerList;

                    lock (node.RoutingTable)
                    {
                        if (!string.IsNullOrWhiteSpace(recipientsID))
                        {
                            peerList = node.RoutingTable.GetClosestPeers(recipientsID, 20); // Adjust '20' as needed
                            Console.WriteLine($"Debug: Retrieved {peerList.Count} closest peers for NodeId {recipientsID}.");
                        }
                        else
                        {
                            peerList = node.RoutingTable.GetAllPeers();
                            Console.WriteLine($"Debug: Retrieved all peers. Total: {peerList.Count}");
                        }
                    }

                    // Prepare a lightweight peer list for the response payload
                    var responsePeerList = peerList.Select(peer => new
                    {
                        peer.NodeId,
                        peer.NodeIP,
                        peer.NodePort,
                        peer.PublicSignatureKey,
                        peer.PublicEncryptKey
                    }).ToList();
                    Console.WriteLine($"Debug: Peer list prepared. Count: {responsePeerList.Count}");

                    // Include DHT state (if necessary)
                    Console.WriteLine("Debug: Retrieving DHT state...");
                    var dhtState = node.DHT.GetCurrentState();
                    Console.WriteLine($"Debug: Retrieved DHT state. Block count: {dhtState.Count}");

                    // Build the response payload
                    var responsePayload = new
                    {
                        MessageType = "BootstrapResponse",
                        Peers = responsePeerList,
                        DHT = dhtState
                    };

                    Console.WriteLine("Debug: Serializing response payload...");
                    byte[] responseData = JsonSerializer.SerializeToUtf8Bytes(responsePayload);
                    Console.WriteLine($"Debug: Serialized response payload. Size: {responseData.Length} bytes");

                    // Encrypt the response data using the recipient's public communication key
                    Console.WriteLine("Debug: Encrypting response data...");
                    byte[] encryptedResponseData = Encryption.EncryptWithPersonalKey(responseData, recipientPublicEncryptKey);
                    Console.WriteLine($"Debug: Encrypted response data. Encrypted size: {encryptedResponseData.Length} bytes");

                    // Generate a signature for the encrypted data using the node's private key
                    Console.WriteLine("Debug: Generating signature for response...");
                    string responseSignature = SignatureGenerator.SignByteArray(encryptedResponseData);
                    Console.WriteLine($"Debug: Signature generated. Length: {responseSignature.Length} characters");

                    // Send the encrypted response data and signature to the recipient
                    Console.WriteLine($"Debug: Sending response to {recipientIPAddress}:{recipientPort}...");
                    bool success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData, responseSignature);

                    // If the send operation fails, throw an exception to trigger a retry
                    if (!success)
                    {
                        Console.WriteLine($"Debug: Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}");
                        throw new Exception($"Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}.");
                    }

                    // Reward the recipient with a trust score for a valid request
                    Console.WriteLine("Debug: Updating trust score for recipient...");
                    lock (node.RoutingTable)
                    {
                        var peer = node.RoutingTable.GetPeerByIPAddress(recipientIPAddress);
                        if (peer != null)
                        {
                            peer.UpdateTrustScore(peer, +5); // Reward 5 points
                            Console.WriteLine($"Debug: Trust score updated for peer {peer.NodeId}. New Trust Score: {peer.TrustScore}");
                        }
                        else
                        {
                            Console.WriteLine("Debug: Recipient peer not found in the routing table.");
                        }
                    }

                    // Log successful bootstrap response
                    Console.WriteLine($"Debug: Bootstrap response successfully sent to {recipientIPAddress}:{recipientPort}.");
                    return success; // Explicitly return success
                });

                Console.WriteLine("Debug: Bootstrap response process completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Console.WriteLine($"Debug Trace: {ex.StackTrace}");
                throw;
            }
        }

        //Resets the Bootstrap Status to allow a corupted node to "Reset" it's peers and DHT.
        public static void ResetBootstrapStatus(Node node)
        {
            node.isBootstrapped = false;
        }

        //Build Routing Table from DHT. (Not yet made.)

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
                string senderPublicSignatureKey = packet.Header.PublicSignatureKey;
                string senderPublicEncryptKey = packet.Header.PublicEncryptKey;

                if (string.IsNullOrWhiteSpace(senderIPAddress) || string.IsNullOrWhiteSpace(senderPublicSignatureKey))
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
                    Signature = SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("Pong"))
                };

                // Serialize and send the response packet
                byte[] encryptedResponseData = Encryption.EncryptWithPersonalKey(
                    Encoding.UTF8.GetBytes(responsePacket.Content),
                    senderPublicEncryptKey
                );

                bool success = await Client.SendPacketToPeerAsync(senderIPAddress, senderPort, encryptedResponseData, responsePacket.Signature);

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
                    Signature = SignatureGenerator.SignByteArray(Encoding.UTF8.GetBytes("PingRequest"))
                };

                // Send the ping and wait for a response
                bool success = await Client.SendPacketToPeerAsync(
                    peer.NodeIP,
                    peer.NodePort,
                    Encoding.UTF8.GetBytes(pingPacket.Content),
                    pingPacket.Signature
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
        public List<Peer.PeerInfo> Peers { get; set; }
        public List<Block> DHT { get; set; } // Use a List<Block> to handle multiple blocks
    }
 
}

