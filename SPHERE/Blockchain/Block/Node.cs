﻿// Ignore Spelling: DHT

using System.Net.Mail;
using System.Reflection;
using System.Text;
using System.Text.Json;
using SPHERE.Configure;
using SPHERE.Configure.Logging;
using SPHERE.Networking;
using SPHERE.Security;
using System.Xml.Linq;
using System;
using System.Net;
using System.Collections.Concurrent;
using System.Runtime.ConstrainedExecution;
using System.Linq.Expressions;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using System.Numerics;
using System.Net.Sockets;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// A Node is the heart and soul of a decenteralized network.
    /// A Node is responsible for mantaining either a whole copy of the blockchain or its shard. 
    /// ( in the beginning the whole thing as its going to be small and even a single node online can re populate the network.)
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
        Full,           //Stores the full DHT has most authority on chain discrepancies
        Power,          //Stores a Larger amount of the chain (Super Shards) or whole thing if the size is small.
        Mini,           //Stores a standard shard or whole thing if the size is small.
        Leech,          // Does not store or support the chain in any way other than to look up info in the chain and return it.  (Verification servers, and entities that dont need to store blocks, or are high risk for attacks)

    }

    public class Node
    {
        internal static readonly object stateLock = new object();
        internal const string DefaultPreviousHash = "UNKNOWN";
        public RoutingTable RoutingTable { get; set; } = new();

        internal ConcurrentDictionary<string, DateTime> seenPackets = new();
        internal ConcurrentDictionary<string, DateTime> requestedBlocks = new();
        internal ConcurrentDictionary<string, DateTime> issuedTokens = new();
        internal ConcurrentDictionary<string, Reputation.RepPacketEntry> seenRepPackets = new();

        internal PrivateKeyManager KeyManager = new PrivateKeyManager();
        internal TokenManager TokenManager = new TokenManager();
        internal NetworkManager NetworkManager = new NetworkManager();
        internal ScheduledTaskManager ScheduledTasks = new ScheduledTaskManager();

        public TimeSpan cacheLifetime { get; internal set; } = TimeSpan.FromMinutes(5);
        public bool isBootstrapped { get; internal set; } = false;
        public Peer Peer { get; set;} = new();

        public Client Client { get; set;} = new();

        public DHT ContactDHT { get; set; } = new();
        public DHT ReputationDHT { get; set; } = new();
        public DHT TransactionDHT { get; set; } = new();

        internal CleanupTasks AutomaticFunctions = new();

        public Node()
        {
            // Start background cleanup & maintenance tasks automatically
            ScheduledTasks.AutoStartCleanUpTasks(this);

            SystemLogger.Log("Node initialized - background tasks started.");
        }

        //This is used to Create the Node or Load one if it exists.
        public static Node CreateNode(Client client, NodeType nodeType)
        {


            //create a node.
            Node node = new Node();
            string nodeId = GenerateKademliaId();
            //Create a client for the node using STUN. 

            try
            {
                node.KeyManager.SetNodeEncryptionFilePath(node);
                NodeKeyStorageFile keyFile = node.KeyManager.LoadKeyFile();
                //Check to see if Keys exist.
                if (keyFile==null)
                {
                    KeyGenerator.GenerateNodeKeyPairs(node);
                }
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error- CreateNode: Error checking for Node Key File. Reason: {ex.Message}");
            }

            try
            {

                // Initialize PeerHeader
                Peer peer = new Peer
                {
                    Node_Type = nodeType,
                    NodeId = nodeId,
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = DefaultPreviousHash, // Placeholder value
                    PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                    PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                };

                // Assign header to node
                node.Peer = peer;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }


            // Initialize DHT Peers and Routing Table.
            node.ContactDHT = new DHT();
            //node.Peers = new Dictionary<string, Peer>();
            node.RoutingTable = new RoutingTable();


            try
            {
                // Load DHT state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("DHT")))
                {
                    node.ContactDHT.LoadState();
                }
                else
                {
                    SystemLogger.Log("DHT state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error loading DHT state: {ex.Message}");
                SystemLogger.Log("Starting with a fresh state.");
                node.ContactDHT = new DHT(); // Reinitialize
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

                    SystemLogger.Log("Routing Table state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error loading RoutingTable state: {ex.Message}");
                SystemLogger.Log("Starting with a fresh state.");
                node.RoutingTable = new RoutingTable(); // Reinitialize
            }
            node.RoutingTable.node = node;
            return node;
        }

        //This is used to Create the Node and Listener or Load one if it exists. 
        public static Node CreateNodeWithClientListenerUsingSTUN(NodeType nodeType)
        {


            //create a node.
            Node node = new Node();
            node.Peer.NodeId = Node.GenerateKademliaId();
            node.KeyManager = new();
            node.KeyManager.SetNodeEncryptionFilePath(node);
            //Create a client get listeners using STUN. 

            Client client = new Client();


            // Thread-safe key generation
            lock (stateLock)
            {
                try
                {
                    Console.WriteLine("Generating Test Keys...");
                    KeyGenerator.GenerateNodeKeyPairs(node);

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error-CreateTestNodeWithFakeSTUNAsync: Generating Key pairs. Reason: {ex.Message}");
                    throw;
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
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = DefaultPreviousHash, // Placeholder value
                    PublicSignatureKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeSignatureKey),
                    PublicEncryptKey = node.KeyManager.UseKeyInStorageContainer(node, KeyGenerator.KeyType.PublicNodeEncryptionKey),
                };

                // Assign header to node
                node.Peer = peer;
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }

            // Initialize DHT
            node.ContactDHT = new DHT();

            try
            {
                // Load DHT state (internal locking already handled by LoadState)
                if (File.Exists(DHT.GetAppDataPath("DHT")))
                {
                    node.ContactDHT.LoadState();
                }
                else
                {
                    SystemLogger.Log("DHT state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error loading DHT state: {ex.Message}");
                SystemLogger.Log("Starting with a fresh state.");
                node.ContactDHT = new DHT(); // Reinitialize
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
                    SystemLogger.Log("Routing Table state file not found. Starting with a fresh state.");
                }


            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error loading RoutingTable state: {ex.Message}");
                SystemLogger.Log("Starting with a fresh state.");
                node.RoutingTable = new RoutingTable(); // Reinitialize
            }

            return node;
        }

        //Once the Node has a Routing Table it can get the Previous Hash and update the Previous Hash
        public void UpdateNodePreviousHash(Node node, string previousHash)
        {
            node.Peer.PreviousNodesHash = previousHash;
        }

        public static Task<(string ip, string port, string publicEncryptSignature)> DisplayNodesBootStrapInfo(Node node)
        {
            
            SystemLogger.Log("Node Information:");
            try 
            { 

                if (node.RoutingTable.GetAllPeers().Count>0)
                {
                    Peer peer = node.RoutingTable
                                     .GetAllPeers()
                                     .OrderBy(peer => peer.Reputation)
                                     .FirstOrDefault();
                    if (peer == null)
                    {
                        Random random = new Random();
                        int index = random.Next(node.RoutingTable.GetAllPeers().Count);
                        peer = node.RoutingTable.GetAllPeers()[index];
                    }

                    return Task.FromResult((peer.NodeIP, peer.NodePort.ToString(), Convert.ToBase64String(peer.PublicEncryptKey)));
                }

                return Task.FromResult((node.Peer.NodeIP, node.Peer.NodePort.ToString(), Convert.ToBase64String(node.Peer.PublicEncryptKey)));
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error displaying node information: {ex.Message}");
                throw;
            }
        }

        public async Task<bool>RequestPutBlockWithToken(Node node, Block block)
        {
            try
            {
                if (node == null || node.Peer ==null)
                {
                    SystemLogger.Log("Error-RequestPutBlockWithToken: Node has no peer information.");
                    return false;
                }
                if (block == null)
                {
                    SystemLogger.Log("Error-RequestPutBlockWithToken: Block is null.");
                    return false;
                }
                if (node.TokenManager.GetTokenBalance() == 0)
                {
                    SystemLogger.Log("Error-RequestPutBlockWithToken: Node has no tokens.");
                    return false;
                }

                TokenManager.PushToken token = node.TokenManager.GetToken(node.TokenManager.GetTokenBalance().ToString());

                bool success = await NetworkManager.RequestPutWithToken(node, block, token);
                if (success)
                {
                    return success;
                }
                else 
                {
                    SystemLogger.Log("Error-RequestPutBlockWithToken: Failed to request block.");
                    return false;
                }

                
            }
            catch (Exception ex)
            {
                SystemLogger.Log($"Error requesting block: {ex.Message}");
                return false;
            }
        }

        //Generate Node and Block Id's
        internal static string GenerateKademliaId()
        {
            byte[] randomBytes = new byte[32]; // 256 bits = 32 bytes

            // Use the modern RandomNumberGenerator.Fill method
            System.Security.Cryptography.RandomNumberGenerator.Fill(randomBytes);

            // Convert the random bytes to a 64-character string
            return BitConverter.ToString(randomBytes).Replace("-", "").ToLower();
        }

    }

    // This is used to manage the BootStrap Payloads.
    public class BootstrapResponsePayload
    {
        [JsonPropertyName("Peers")]
        public required List<Peer> Peers { get; set; }

        [JsonPropertyName("DHT")]
        public required List<Block> DHT { get; set; } 
    }

    public class BlockResponsePayload
    {
        [JsonPropertyName("Type")]
        public required string Type { get; set; }

        [JsonPropertyName("Blocks")]
        public required List<Block> Blocks { get; set; }
    }

    public class PutRequestPayload
    {
        [JsonPropertyName("Block")]
        public required Block Block { get; set; }

        [JsonPropertyName("Token")]
        public required TokenManager.PushToken Token{ get; set; }
    }
   
}

