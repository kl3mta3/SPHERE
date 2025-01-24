using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml.Linq;
using SPHERE.Configure;
using SPHERE.Networking;
using static System.Runtime.InteropServices.JavaScript.JSType;


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
        private static readonly object stateLock = new object();
        private const string DefaultPreviousHash = "UNKNOWN";
        public readonly Dictionary<string, Peer> Peers = new Dictionary<string, Peer>();
        private bool isBootstrapped = false;
        public Peer Peer;
        private Client Client;
        private DHT DHT;
        private readonly int MaxPeers = 25;

        public static Node CreateNode(Client client, NodeType nodeType)
        {
            Node node = new Node();

            // Thread-safe key generation
            lock (stateLock)
            {
                //Check to see if Keys exist.
                if (!ServiceAccountManager.KeyContainerExists("PUBNODSIGK") || !ServiceAccountManager.KeyContainerExists("PUBNODENCK"))
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
                    NodeId = AppIdentifier.GetOrCreateDHTNodeID(),
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = DefaultPreviousHash, // Placeholder value
                    PublicSignatureKey = ServiceAccountManager.RetrieveKeyFromContainer("PUBNODSIGK"),
                    PublicEncryptKey = ServiceAccountManager.RetrieveKeyFromContainer("PUBNODENCK"),
                };

                // Assign header to node
                node.Peer = peer;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }

            // Initialize client and DHT
            node.Client = client;
            node.DHT = new DHT();

            try
            {
                // Load DHT state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath()))
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

            return node;
        }

        public void AddPeerToPeers(Peer peer)
        {
            if (peer == null)
            {
                throw new ArgumentNullException(nameof(peer), "Peer cannot be null.");
            }

            lock (stateLock) // Ensures thread safety
            {
                if (!Peers.ContainsKey(peer.NodeId)) // Optional: Prevent duplicate keys
                {
                    Peers.Add(peer.NodeId, peer);
                    Console.WriteLine($"Peer {peer.NodeId} added successfully.");
                }
                else
                {
                    Console.WriteLine($"Peer {peer.NodeId} already exists.");
                }
            }
        }
        
        public void RemovePeerFromPeers(Node node)
        {
            Peers.Remove(node.Peer.NodeId);
        }

        public Peer GetPeer(string nodeId)
        {
            if (string.IsNullOrEmpty(nodeId))
            {
                throw new ArgumentException("Node ID cannot be null or empty.", nameof(nodeId));
            }

            lock (stateLock) // Ensures thread-safe access to the Peers dictionary
            {
                return Peers.ContainsKey(nodeId) ? Peers[nodeId] : null;
            }
        }

        public void UpdateNodePerviousHash(Node node, string previousHash)
        {
            node.Peer.PreviousNodesHash = previousHash;
        }

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
                Peer peer = GetPeer(peerID);
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

        public async Task BroadcastEndpointToPeers(Node node)
        {
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node), "Node cannot be null.");
            }

            var tasks = new List<Task>();

            // Build and serialize the packet with a TTL of 75
            Packet packet = PacketBuilder.BuildPacket(node, "Update My EndPoint Info", PacketBuilder.PacketType.PeerUpdate, 75);
            byte[] data = PacketBuilder.SerializePacket(packet);

            lock (Peers)
            {
                foreach (var peer in Peers.Values)
                {
                    string key = peer.PublicSignatureKey;

                    if (string.IsNullOrEmpty(key))
                    {
                        Console.WriteLine($"Skipping peer with missing or invalid PublicSignatureKey.");
                        continue;
                    }

                    // Encrypt and sign the packet
                    byte[] secureData = Encryption.EncryptWithPersonalKey(data, key);
                    string signature = SignatureGenerator.SignByteArray(secureData);

                    // Add a task to send the packet and update the trust score on success
                    tasks.Add(SafeTask(async () =>
                    {
                        bool success = await RetryAsync(() => Client.SendPacketToPeerAsync(
                            node.Client.clientIP.ToString(),
                            node.Client.clientListenerPort,
                            secureData,
                            signature
                        ));

                        if (success)
                        {
                            // Only update trust score if the packet was successfully delivered
                            lock (stateLock)
                            {
                                peer.UpdateTrustScore(peer, +2);
                            }
                        }
                    }));
                }
            }

            // Wait for all tasks to complete
            try
            {
                await Task.WhenAll(tasks);
            }
            catch (Exception ex)
            {
                // Handle any exceptions that were thrown
                Console.WriteLine($"Error during broadcast: {ex.Message}");
            }
        }

        public void EvaluateAndReplacePeer(Peer newPeer)
        {
            lock (Peers)
            {
                if (Peers.Values.Count < MaxPeers)
                {
                    Peers[newPeer.NodeId] = newPeer;
                    Console.WriteLine($"Added new peer: {newPeer.NodeId}");
                    return;
                }

                // Find the weakest peer
                Peer weakestPeer = Peers.Values
                    .OrderBy(peer => peer.CalculateProximity(peer))
                    .ThenBy(peer => peer.TrustScore)
                    .FirstOrDefault();

                if (weakestPeer != null &&
                    (newPeer.CalculateProximity(newPeer) > weakestPeer.CalculateProximity(weakestPeer) ||
                    newPeer.TrustScore > weakestPeer.TrustScore))
                {
                    Peers.Remove(weakestPeer.NodeId);
                    Peers[newPeer.NodeId] = newPeer;
                    Console.WriteLine($"Replaced peer {weakestPeer.NodeId} with {newPeer.NodeId}");
                }
            }
        }
        public async Task ProcessBootstrapResponse(Node node, byte[] encryptedData,string signature,string senderPublicKey)
        {
            try
            {
                // Verify Node isnt already Bootstrapped, Prevents reBootstrapping By accident.
                if(node.isBootstrapped=true)
                {
                    Console.WriteLine("Node is already Bootstrapped. Ignoring the response.");
                    return;
                }

                // Verify the signature
                bool isSignatureValid = SignatureGenerator.VerifyByteArray(encryptedData, signature, senderPublicKey);
                if (!isSignatureValid)
                {
                    Console.WriteLine("Invalid signature. Response has been tampered with.");
                    return;
                }

                // Decrypt the data
                byte[] decryptedData = Encryption.DecryptWithPrivateKey(encryptedData, ServiceAccountManager.RetrieveKeyFromContainer("PRINODENCK"));

                // Deserialize the response payload
                var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                var responsePayload = JsonSerializer.Deserialize<BootstrapResponsePayload>(decryptedData, options);

                if (responsePayload == null)
                {
                    Console.WriteLine("Failed to deserialize bootstrap response payload.");
                    return;
                }

                // Process the peer list
                if (responsePayload.Peers != null)
                {
                    lock (stateLock) // Ensure thread-safe access to the Peers collection
                    {
                        foreach (var peer in responsePayload.Peers)
                        {
                            if (!Peers.ContainsKey(peer.NodeId))
                            {
                                var newPeer = new Peer
                                {
                                    NodeId = peer.NodeId,
                                    NodeIP = peer.NodeIP,
                                    NodePort = peer.NodePort,
                                    PublicSignatureKey = peer.PublicSignatureKey,
                                    PublicEncryptKey = peer.PublicEncryptKey
                                };

                                AddPeerToPeers(newPeer);
                                Console.WriteLine($"Added new peer: {peer.NodeId} ({peer.NodeIP}:{peer.NodePort})");
                            }
                            else
                            {
                                Console.WriteLine($"Peer {peer.NodeId} already exists. Skipping.");
                            }
                        }
                    }
                }

                // Process the DHT state (if included)
                if (responsePayload.DHT != null)
                {
                    lock (stateLock) // Ensure thread-safe access to the DHT
                    {
                        foreach (var block in responsePayload.DHT)
                        {
                            // Validate the block before adding it
                            if (DHT.IsBlockValid(block))
                            {
                                node.DHT.AddBlock(block);
                                Console.WriteLine($"Added DHT block: {block.Header.BlockId}");
                            }
                            else
                            {
                                Console.WriteLine($"Invalid block {block.Header.BlockId}. Skipping.");
                            }
                        }
                    }
                }

                Console.WriteLine("Bootstrap response processed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error processing bootstrap response: {ex.Message}");
            }
        }

        public async Task SendBootstrapResponse(Node node, string recipientIPAddress, int recipientPort, string recipientPublicComKey, bool includeDHT = false)
        {
            // Validate inputs
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node), "Node cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(recipientIPAddress))
            {
                throw new ArgumentException("Recipient IP address cannot be null or empty.", nameof(recipientIPAddress));
            }

            if (recipientPort <= 0 || recipientPort > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(recipientPort), "Port must be a valid number between 1 and 65535.");
            }

            if (string.IsNullOrWhiteSpace(recipientPublicComKey))
            {
                throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientPublicComKey));
            }

            // Use RetryAsync to ensure the response is sent
            await RetryAsync<bool>(async () =>
            {
                // Step 1: Build the bootstrap response packet
                var peerList = Peers.Values.Select(peer => new
                {
                    peer.NodeId,
                    peer.NodeIP,
                    peer.NodePort,
                    peer.PublicSignatureKey,
                    peer.PublicEncryptKey
                }).ToList();

                // Optionally include DHT state
                var dhtState = includeDHT ? node.DHT.GetCurrentState() : null;

                var responsePayload = new
                {
                    MessageType = "BootstrapResponse",
                    Peers = peerList,
                    DHT = dhtState
                };

                // Serialize the response payload into a byte array
                byte[] responseData = JsonSerializer.SerializeToUtf8Bytes(responsePayload);

                // Encrypt the response data using the recipient's public communication key
                byte[] encryptedResponseData = Encryption.EncryptWithPersonalKey(responseData, recipientPublicComKey);

                // Generate a signature for the encrypted data using the node's private key
                string responseSignature = SignatureGenerator.SignByteArray(encryptedResponseData);

                // Send the encrypted response data and signature to the recipient
                bool success = await Client.SendPacketToPeerAsync(recipientIPAddress, recipientPort, encryptedResponseData, responseSignature);

                // If the send operation fails, throw an exception to trigger a retry
                if (!success)
                {
                    throw new Exception($"Failed to send bootstrap response to {recipientIPAddress}:{recipientPort}.");
                }

                // Reward the recipient with trust score for a valid request
                var peer = GetPeerByIPAddress(recipientIPAddress);
                if (peer != null)
                {
                    peer.UpdateTrustScore(peer, +5); // Reward 5 points
                }

                // Log successful bootstrap response
                Console.WriteLine($"Bootstrap response successfully sent to {recipientIPAddress}:{recipientPort}.");
                return success; // Explicitly return success
            });
        }

        public async Task SendBootstrapRequest(Node node, string iPAddress, int port, string recipientsPublicComKey)
        {
            // Validate inputs
            if (node == null)
            {
                throw new ArgumentNullException(nameof(node), "Node cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(iPAddress))
            {
                throw new ArgumentException("IP address cannot be null or empty.", nameof(iPAddress));
            }

            if (port <= 0 || port > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(port), "Port must be a valid number between 1 and 65535.");
            }

            if (string.IsNullOrWhiteSpace(recipientsPublicComKey))
            {
                throw new ArgumentException("Recipient's public communication key cannot be null or empty.", nameof(recipientsPublicComKey));
            }

            // Use RetryAsync to retry the operation on failure
            await RetryAsync<bool>(async () =>
            {
                // Build the bootstrap request packet
                Packet packet = PacketBuilder.BuildPacket(node, "BootstrapRequest", PacketBuilder.PacketType.BootstrapRequest, 75);

                // Serialize the packet into a byte array
                byte[] data = PacketBuilder.SerializePacket(packet);

                // Encrypt the packet using the recipient's public communication key
                byte[] encryptedData = Encryption.EncryptWithPersonalKey(data, recipientsPublicComKey);

                // Generate a signature for the encrypted data using the node's private key
                string signature = SignatureGenerator.SignByteArray(encryptedData);

                // Send the encrypted data and signature to the recipient
                bool success = await Client.SendPacketToPeerAsync(iPAddress, port, encryptedData, signature);

                // If the send operation fails, throw an exception to trigger a retry
                if (!success)
                {
                    throw new Exception($"Failed to send bootstrap request to {iPAddress}:{port}.");
                }

                // Log successful bootstrap request
                Console.WriteLine($"Bootstrap request successfully sent to {iPAddress}:{port}.");

                return success; // Explicitly return the success status
            });
        }

        public static void ResetBootstrapStatus(Node node)
        {
            node.isBootstrapped = false;
        }

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

        public  Peer GetPeerByIPAddress(string ipAddress)
        {
            lock (stateLock)
            {
                return Peers.Values.FirstOrDefault(peer => peer.NodeIP == ipAddress);
            }
        }

        //public async Task SendPacketToPeerAsync(string ip, int port, byte[] encryptedData, string signature)
        //{
        //    await RetryAsync(async () =>
        //    {
        //        try
        //        {
        //            await Client.SendPacketToPeerAsync(ip, port, encryptedData, signature);
        //            Console.WriteLine($"Packet successfully sent to {ip}:{port}.");

        //            // Reward the recipient
        //            var peer = GetPeerByIPAddress(ip);
        //            if (peer != null)
        //            {
        //                peer.UpdateTrustScore(peer, +3); // Reward 3 points for successful communication
        //            }
        //        }
        //        catch (Exception ex)
        //        {
        //            Console.WriteLine($"Failed to send packet to {ip}:{port}: {ex.Message}");

        //            // Penalize the recipient
        //            var peer = GetPeerByIPAddress(ip);
        //            if (peer != null)
        //            {
        //                peer.UpdateTrustScore(peer, -5); // Penalize 5 points for failure
        //            }
        //        }
        //    });
        //}


    }

    public class BootstrapResponsePayload
    {
        public List<Peer.PeerInfo> Peers { get; set; }
        public List<Block> DHT { get; set; } // Use a List<Block> to handle multiple blocks
    }
 
}

