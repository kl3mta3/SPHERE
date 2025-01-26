using SPHERE.Security;
using SPHERE.PacketLib;
using SPHERE.Configure;
using SPHERE.Blockchain;
using static SPHERE.PacketLib.Packet;
using SPHERE.Networking;
using System.Net;
using System.DirectoryServices.AccountManagement;


namespace SPHERE.Testing
{
    public class Testing
    {
       

        //Test Symmetric Keys
        private static readonly string testLocalSymmetricKey = "6gCSoEHtslA0RlQD703wX0A781di8l/1tMc0WL9KM1k=";
        private static readonly string testSemiPublicKey = "1T6bxk6qVKJTMuIobq7SW/96WQvqgqOWwiqAEfoQYrw=";
        private static readonly Password testExportPassword = Password.CreatePasswordFromString("TestPassword1234!!");

        //Test Personal Keys
        private static readonly string testPublicPersonalSignatureKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaLURRVlxbGUASmUvDJ0FkFEWWjA4fhvmmg13DqQF9UdvvFVHGCkik39m7ixqh/hyjrIjuHZJr5Xq2evGP518lw==";
        private static readonly string testPrivatePersonalSignatureKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgk+guZjxfqtHeq/eof8SAG7DXKiDPMXNXif9qVQgrMPahRANCAARotRFFWXFsZQBKZS8MnQWQURZaMDh+G+aaDXcOpAX1R2+8VUcYKSKTf2buLGqH+HKOsiO4dkmvlerZ68Y/nXyX";
        private static readonly string testPublicPersonalEncryptionKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqH4KpEu5mcWyUKF26ETny/as/ChBVOwvEeJ585FdkbU0KI5kD6h3iGRAFi0YABp78E96T8FpL1qKmaFxb0Yrbw==";
        private static readonly string testPrivatePersonalEncryptionKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgl7THVjJIywus5kRZlCy7L2pTCUmDcqOOZWVX/xim1EqhRANCAASofgqkS7mZxbJQoXboROfL9qz8KEFU7C8R4nnzkV2RtTQojmQPqHeIZEAWLRgAGnvwT3pPwWkvWoqZoXFvRitv";
        
        //Test Node Keys
        private static readonly string testPublicNodeSignatureKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEd6KIr88ecHuZMbDHFUnjces81By4rH53+aIm6/JcfDb2+gbPPI5GsH7/IZfGhCG1G06elRiQ6rO2vA7VSzNw==";
        private static readonly string testPrivateNodeSignatureKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmdC5bn0GgguiRT85fONO+yENHvzcwaeVLVTjw/4gammhRANCAAR3ooivzx5we5kxsMcVSeNx6zzUHLgfisfnf5oibr8lx8Nvb6Bs88jkawfv8hl8aEIbUbTp6VGJDqs7a8DtVLM3";
        private static readonly string testPublicNodeEncryptionKey = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHxQ496XmElv+h9eMn10Jc9iBIyj9+4mNZAOjEp57hC+hRANCAAT01oQ1Z7ZrXgXsxhkx/4Bjo8fK5y6mqPDJBu+YuvXDE/IdgwM02rLmqikWgAIwGvYOJZhM7O/Zl9X3rw33GT7f";
        private static readonly string testPrivateNodeEncryptionKey = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9NaENWe2a14F7MYZMf+AY6PHyucupqjwyQbvmLr1wxPyHYMDNNqy5qopFoACMBr2DiWYTOzv2ZfV968N9xk+3w==";

        // Client Test Setting
        private static readonly string testClientIP = "127.0.0.1";
        private static readonly int testClientListenerPort = 564321;

        public static Packet BuildTestPacket(PacketBuilder.PacketType packetType, string message)
        {
            Packet.PacketHeader header = PacketBuilder.BuildPacketHeader(packetType, 9999.ToString(), "TestpublicSignatureKey", 6969, "127.0.0.1", 75);

            Packet packet = new Packet
            {
                Header = header,
                Content = message,
                Signature = header.PublicSignatureKey,
            };

            return packet;

        }

        //This is used to Create the Node or Load one if it exists. 
        public static Node CreateTestNodeWithFakeSTUNAsync( NodeType nodeType)
        {
            DllLoader.LoadAllEmbeddedDlls();
            Node node = new Node();
            Client client = new Client();
            client.clientListenerPort = testClientListenerPort;
            client.clientIP = IPAddress.Parse(testClientIP);


            try
            {

                // Initialize PeerHeader
                Peer peer = new Peer
                {
                    Node_Type = nodeType,
                    NodeId = AppIdentifier.GetOrCreateDHTNodeID(),
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = Node.DefaultPreviousHash, 
                    PublicSignatureKey = testPublicNodeSignatureKey,
                    PublicEncryptKey = testPublicNodeEncryptionKey,
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
            node.Peers = GenerateFakePeers(node.MaxPeers);
            

            try
            {
                // Load DHT state (internal locking already handled by LoadState)

                PopulateDHTWithFakeBlocks(node.DHT, node.Peers, node.MaxPeers);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Populating DHT With Fake Blocks: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.DHT = new DHT(); // Reinitialize
            }

            try
            {
                // Load RoutingTable Test state 
                node.RoutingTable = PopulateRoutingTable(node.Peers);



            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading RoutingTable state: {ex.Message}");
                Console.WriteLine("Starting with a fresh state.");
                node.RoutingTable = new RoutingTable(); // Reinitialize
            }

            return node;
        }

        //Populate a DHT with fake blocks from a peer list.
        public static void PopulateDHTWithFakeBlocks(DHT dht, Dictionary<string, Peer> peerList, int numberOfBlocks)
        {
            Random random = new Random();

            foreach (var peer in peerList.Values)
            {
                if (numberOfBlocks <= 0) break;

                Block block = new Block
                {
                    Header = new Block.BlockHeader
                    {
                        BlockId = peer.NodeId, // Use Peer NodeId as BlockId
                        PreviousHash = "PreviousHashExample",
                        BlockCreationTime = DateTime.UtcNow,
                        LastUpdateTime = DateTime.UtcNow,
                        EncryptionAlgorithm = "AES256",
                        KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                        PublicSignatureKey = peer.PublicSignatureKey,
                        BlockHash = Guid.NewGuid().ToString() // Example BlockHash
                    },
                    EncryptedContact = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    EncryptedLocalSymmetricKey = Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                };

                dht.AddBlock(block);
                numberOfBlocks--;
            }

            Console.WriteLine("DHT populated with fake blocks.");
        }
    
        // Method to generate a dictionary of fake peers
        public static Dictionary<string, Peer> GenerateFakePeers(int numberOfPeers)
        {
            Dictionary<string, Peer> peerDict = new Dictionary<string, Peer>();
            Random random = new Random();

            for (int i = 1; i <= numberOfPeers; i++)
            {
                string nodeId = Guid.NewGuid().ToString();
                string nodeIP = $"127.0.0.{i}"; // Internal IPs like 127.0.0.x
                int nodePort = random.Next(5000, 6000); // Random port between 5000 and 6000

                Peer fakePeer = Peer.CreatePeerHeader(
                    nodeType: NodeType.Mini, // Example NodeType
                    nodeID: nodeId,
                    nodeIP: nodeIP,
                    nodePort: nodePort,
                    previousHash: "PreviousHashExample",
                    publicSignatureKey: Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                    publicEncryptKey: Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                );

                peerDict[nodeId] = fakePeer;
            }

            return peerDict;
        }


       

        // Method to create a test routing table by selecting a subset of peers
        public static RoutingTable PopulateRoutingTable(Dictionary<string, Peer> peerList)
        {
            RoutingTable routingTable = new RoutingTable();

            foreach (var peer in peerList.Values)
            {
                routingTable.AddPeer(peer);
            }

            return routingTable;
        }



    }
}
