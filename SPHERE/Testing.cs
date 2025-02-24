// Ignore Spelling: keytype

using SPHERE.Security;
using SPHERE.Configure.Logging;
using SPHERE.Blockchain;
using SPHERE.Networking;
using System.Net;
using System.DirectoryServices.AccountManagement;
using System.Security.Cryptography;
using static SPHERE.Blockchain.Contact;
using System;
using System.Xml.Linq;
using static SPHERE.Networking.Packet;



namespace SPHERE.TestingLib
{
    public static class Testing
    {

        public static Node Node { get; set; }

        //Test Symmetric Keys

        private static readonly string testLocalSymmetricKey = "6gCSoEHtslA0RlQD703wX0A781di8l/1tMc0WL9KM1k=";
        private static readonly string testLocalEncryptedSymmetricKey = "nXgYPudd2MJVL8OO/klDwzUNgQkxCvSzo8E/3LGB2a9gx9zkGItI8hGMUBnlDv1vjTomkjp786yHiDm71wccg==";
        private static readonly string testSemiPublicKey = "1T6bxk6qVKJTMuIobq7SW/96WQvqgqOWwiqAEfoQYrw=";

        // Client Test Setting
        private static readonly string testClientIP = "127.0.0.1";
        private static readonly int testClientListenerPort = 0;

        //Test Service Account info
        private static readonly string ServiceAccountName = "TestServiceAccount";
        private static readonly string testCNGCertificate = "TestCNGCertificate";

        internal static Packet BuildTestPacket(PacketBuilder.PacketType packetType, string message, byte[] publicSigKey, byte[] publicEncKey)
        {
            PacketHeader header = PacketBuilder.BuildPacketHeader(packetType, 9999.ToString(), "Full", publicSigKey, publicEncKey, 6969, "127.0.0.1", 75);

            Packet packet = new Packet
            {
                Header = header,
                Content = message,
                Signature = "TestSignature",
            };

            return packet;

        }

        //This is used to Create the Node and populate a fake DHT and RT
        public static  Node CreateTestNodeWithFakeSTUNAsync(NodeType nodeType)
        {

            Node testNode = new Node();

            try
            {
                Console.WriteLine($"Debug: Starting Create Client ");
                Client client = new Client();
                client.clientListenerPort = testClientListenerPort;
                client.clientIP = IPAddress.Parse(testClientIP);
                Console.WriteLine($"Debug: Starting Create TestNode ");

                try
                {
                    Console.WriteLine("Checking if CNG Keys Exist...");
                    if (!DoesCngKeyExist(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey) ||
                        !DoesCngKeyExist(KeyGenerator.KeyType.PublicTestNodeEncryptionKey) ||
                        !DoesCngKeyExist(KeyGenerator.KeyType.PrivateTestNodeSignatureKey) ||
                        !DoesCngKeyExist(KeyGenerator.KeyType.PublicTestNodeSignatureKey))
                    {
                        Console.WriteLine("CNG Keys Missing. Generating Test Keys...");
                        GenerateTestNodeKeyPairs();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Checking or Generating CNG Keys: {ex.Message}");
                    throw;
                }

                try
                {
                    Console.WriteLine("Retrieving Keys from Storage...");
                    byte[] publicSigKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeSignatureKey);
                    byte[] privateSigKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey);
                    byte[] publicEncKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeEncryptionKey);
                    byte[] privateEncKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey);

                    string sigKeyBase64 = Convert.ToBase64String(publicSigKey);
                    string encKeyBase64 = Convert.ToBase64String(publicEncKey);


                    Console.WriteLine($"Signature Public Key: {sigKeyBase64}");

                    Console.WriteLine($"Encryption Public Key: {encKeyBase64}");

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Retrieving Keys: {ex.Message}");
                    throw;
                }

                try
                {
                    Console.WriteLine("Generating Random Node Port...");
                    Random random = new Random();
                    int nodePort = random.Next(5000, 6000);
                    if (nodePort < 5000 || nodePort > 6000)
                    {
                        Console.WriteLine($"Warning: Generated NodePort {nodePort} is outside expected range.");
                    }
                    client.clientListenerPort = nodePort;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Generating NodePort: {ex.Message}");
                    throw;
                }

                try
                {
                    Console.WriteLine("Initializing Peer Header...");
                    Peer peer = new Peer
                    {
                        Node_Type = nodeType,
                        NodeId = ServiceAccountManager.GenerateKademliaId(),
                        NodeIP = client.clientIP.ToString(),
                        NodePort = client.clientListenerPort,
                        PreviousNodesHash = Node.DefaultPreviousHash,
                        PublicSignatureKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeSignatureKey),
                        PublicEncryptKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeEncryptionKey),
                    };
                    testNode.Peer = peer;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Creating Peer Header: {ex.Message}");
                    throw;
                }

                try
                {
                    Console.WriteLine("Initializing DHT and Routing Table...");
                    testNode.Client = client;
                    List<Peer> fakePeers = GenerateFakePeers(25);
                    testNode.ContactDHT = new DHT();

                    try
                    {
                        PopulateTestDHTWithFakeBlocks( testNode.Peer.NodeId, testNode.ContactDHT, fakePeers, testNode.RoutingTable.replicationFactor);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error Populating DHT: {ex.Message}");
                        Console.WriteLine("Resetting to Fresh DHT...");
                        testNode.ContactDHT = new DHT();
                    }

                    try
                    {
                        testNode.RoutingTable = PopulateTestRoutingTable(fakePeers);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error Loading RoutingTable: {ex.Message}");
                        Console.WriteLine("Resetting to Fresh RoutingTable...");
                        testNode.RoutingTable = new RoutingTable();
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Initializing DHT or Routing Table: {ex.Message}");
                    throw;
                }

                try
                {
                    Console.WriteLine("Assigning Node ID and Storing in NodeManager...");

                    NodeManager.AddNodeToNodes(testNode);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Assigning Node ID: {ex.Message}");
                    throw;
                }

                Console.WriteLine("Node Created Successfully!");
                return testNode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Fatal Error Creating Test Node: {ex.Message}");
                throw;
            }
        }

        public static bool DoesCngKeyExist(KeyGenerator.KeyType keytype)
        {
            string keyName = keytype.ToString();

            try
            {
                return CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error checking CNG key existence: {ex.Message}");
                return false;
            }
        }

        //This is used to Create the Node With an Empty RT and DHT
        public  static Node CreateTestNodeWithNoDHTorRoutingTable(NodeType nodeType)
        {


            Node testNode = new Node();


            Client client = new Client();
            client.clientListenerPort = testClientListenerPort;
            client.clientIP = IPAddress.Parse(testClientIP);

            if (!DoesCngKeyExist(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey) || !DoesCngKeyExist(KeyGenerator.KeyType.PublicTestNodeEncryptionKey) || !DoesCngKeyExist(KeyGenerator.KeyType.PrivateTestNodeSignatureKey) || !DoesCngKeyExist(KeyGenerator.KeyType.PublicTestNodeSignatureKey))
            {
                GenerateTestNodeKeyPairs();
            }

            byte[] publicSigKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeSignatureKey);
            byte[] priveateSigKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeSignatureKey);

            byte[] publicEncKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PublicTestNodeEncryptionKey);
            byte[] privateEncKey = ServiceAccountManager.UseKeyInStorageContainer(KeyGenerator.KeyType.PrivateTestNodeEncryptionKey);

            Random random = new Random();
            // Generate NodePort
            int nodePort = random.Next(5000, 6000);
            if (nodePort < 5000 || nodePort > 6000)
            {
                Console.WriteLine($"Error: Generating NodePort {nodePort}. ");
            }
            client.clientListenerPort = nodePort;
            try
            {

                // Initialize PeerHeader
                Peer peer = new Peer
                {
                    Node_Type = nodeType,
                    NodeId = ServiceAccountManager.GenerateKademliaId(),
                    NodeIP = client.clientIP.ToString(),
                    NodePort = client.clientListenerPort,
                    PreviousNodesHash = Node.DefaultPreviousHash,
                    PublicSignatureKey = publicSigKey,
                    PublicEncryptKey = publicEncKey,
                };

                // Assign header to node
                testNode.Peer = peer;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error retrieving or creating keys: {ex.Message}");
                throw;
            }

            // Initialize client and DHT
            testNode.Client = client;
            testNode.ContactDHT = new DHT();
            List<Peer> fakePeers = GenerateFakePeers(25);

            try
            {



                Console.WriteLine("Starting with a fresh state.");
                testNode.ContactDHT = new DHT(); // Reinitialize

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Starting Fresh DHT: {ex.Message}");
            }

            try
            {

                Console.WriteLine("Starting with a fresh state.");
                testNode.RoutingTable = new RoutingTable(); // Reinitialize



            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error Starting RoutingTable: {ex.Message}");
            }


            NodeManager.AddNodeToNodes(testNode);
            return testNode;
        }

        //Populate a DHT with fake blocks from a peer list.
        public static void PopulateTestDHTWithFakeBlocks(string nodeId, DHT dht, List<Peer> peerList, int numberOfBlocks)
        {
            // Check if the DHT object is null
            if (dht == null)
            {
                Console.WriteLine("Error: The DHT object is null.");
                throw new ArgumentNullException(nameof(dht), "DHT cannot be null.");
            }

            // Check if the Peer list is null
            if (peerList == null)
            {
                Console.WriteLine("Error: The Peer list is null.");
                throw new ArgumentNullException(nameof(peerList), "Peer list cannot be null.");
            }

            // Check if the Peer list is empty
            if (peerList.Count == 0)
            {
                Console.WriteLine("Error: The Peer list is empty.");
                throw new ArgumentException("Peer list cannot be empty.", nameof(peerList));
            }

            // Check if the number of blocks is valid
            if (numberOfBlocks <= 0)
            {
                Console.WriteLine("Error: Number of blocks must be greater than 0.");
                throw new ArgumentOutOfRangeException(nameof(numberOfBlocks), "Number of blocks must be greater than 0.");
            }

            Random random = new Random();

            foreach (var peer in peerList)
            {

                if (peer == null)
                {
                    Console.WriteLine("Warning: A null peer was found in the Peer list. Skipping this peer.");
                    continue;
                }

                if (numberOfBlocks <= 0) break;

                try
                {
                   
                    // Create a new block
                    Block block = new Block
                    {
                        Header = new Block.BlockHeader
                        {
                            BlockId = peer.NodeId ?? "UnknownNodeId",
                            BlockType = Block.BlockType.Contact.ToString(),
                            BlockVersion = "1.0",
                            PreviousHash = "PreviousHashExample",
                            BlockCreationTime = DateTime.UtcNow,
                            LastUpdateTime = DateTime.UtcNow,
                            EncryptionAlgorithm = "AES256",
                            KeyUsagePolicies = "MESSAGE_ENCRYPTION_ONLY",
                            PublicSignatureKey = peer.PublicSignatureKey,
                            PublicEncryptionKey = peer.PublicEncryptKey,
                            CreatorNodeId = peer.NodeId ?? "UnknownNodeId",


                        },
                        EncryptedContact = Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
                        EncryptedLocalSymmetricKey = Guid.NewGuid().ToByteArray()
                    };
                   
                    block.Header.BlockHash = block.Header.CalculateBlockHash();

                    if(block.Header == null)
                    {
                        Console.WriteLine("Error: Block Header is null.");
                        return;
                    }

                    if (block==null)
                    {
                        Console.WriteLine("Error: Block is null.");
                        return;
                    }

                    // Add the block to the DHT
                    dht.AddBlock(block);
                   
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error while creating or adding a block for peer {peer.NodeId ?? "UnknownPeer"}: {ex.Message}");
                }

                numberOfBlocks--;
            }

            Console.WriteLine("DHT populated with fake blocks.");
        }

        // Method to generate a list of fake peers for RoutingTable population
        public static List<Peer> GenerateFakePeers(int numberOfPeers)
        {
            // Check if the input is valid
            if (numberOfPeers <= 0)
            {
                Console.WriteLine("Warning: Number of peers must be greater than 0.");
                return new List<Peer>();
            }

            List<Peer> peerList = new List<Peer>();
            Random random = new Random();

            Console.WriteLine($"Generating {numberOfPeers} fake peers...");

            for (int i = 1; i <= numberOfPeers; i++)
            {
                try
                {
                    // Generate NodeId
                    string nodeId = ServiceAccountManager.GenerateKademliaId();
                    if (string.IsNullOrWhiteSpace(nodeId))
                    {
                        Console.WriteLine($"Warning: Generated NodeId is null or empty for peer {i}.");
                    }

                    // Generate NodeIP
                    string nodeIP = $"127.0.0.{i}";
                    if (string.IsNullOrWhiteSpace(nodeIP))
                    {
                        Console.WriteLine($"Warning: Generated NodeIP is null or empty for peer {i}.");
                    }

                    // Generate NodePort
                    int nodePort = random.Next(5000, 6000);
                    if (nodePort < 5000 || nodePort > 6000)
                    {
                        Console.WriteLine($"Warning: Generated NodePort {nodePort} is out of expected range for peer {i}.");
                    }

                    // Create a new Peer

                    Peer fakePeer = Peer.CreatePeer(
                        nodeType: NodeType.Full, // Example NodeType
                        nodeID: nodeId,
                        nodeIP: nodeIP,
                        nodePort: nodePort,
                        previousHash: "PreviousHashExample",

                        publicSignatureKey: Guid.NewGuid().ToByteArray(),
                        publicEncryptKey: Guid.NewGuid().ToByteArray());

                    // Validate the created Peer
                    if (fakePeer == null)
                    {
                        Console.WriteLine($"Error: Failed to create Peer {i}.");
                        continue; // Skip adding this peer
                    }

                    // Add the peer to the list
                    peerList.Add(fakePeer);
                    //Console.WriteLine($"Peer {i} created: NodeId={nodeId}, NodeIP={nodeIP}, NodePort={nodePort}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error while creating peer {i}: {ex.Message}");
                }
            }

            // Final confirmation of peer generation
            Console.WriteLine($"Generated {peerList.Count}/{numberOfPeers} fake peers successfully.");

            return peerList;
        }

        // Method to create a test routing table by selecting a subset of peers
        public static RoutingTable PopulateTestRoutingTable(List<Peer> peerList)
        {
            // Check if the Peer list is null
            if (peerList == null)
            {
                Console.WriteLine("Error: The Peer list is null. Cannot populate the routing table.");
                throw new ArgumentNullException(nameof(peerList), "Peer list cannot be null.");
            }

            // Check if the Peer list is empty
            if (peerList.Count == 0)
            {
                Console.WriteLine("Warning: The Peer list is empty. The routing table will remain empty.");
                return new RoutingTable();
            }

            RoutingTable routingTable = new RoutingTable();

            Console.WriteLine("Populating the routing table with peers...");

            foreach (var peer in peerList)
            {
                try
                {
                    // Check if the current peer is null
                    if (peer == null)
                    {
                        Console.WriteLine("Warning: A null peer was found in the Peer list. Skipping this peer.");
                        continue;
                    }


                    // Add the peer to the routing table
                    try
                    {
                        if (peer == null)
                        {
                            Console.WriteLine("Warning: A null peer was found in the Peer list. Skipping this peer.");
                            continue;
                        }

                        // Validate NodeId for hexadecimal format
                        if (!RoutingTable.IsHexString(peer.NodeId))
                        {
                            Console.WriteLine($"Error: Peer.NodeId '{peer.NodeId}' is not a valid hexadecimal string. Skipping this peer.");
                            continue;
                        }

                        //Console.WriteLine($"Adding Peer: NodeId={peer.NodeId}, NodeIP={peer.NodeIP}, NodePort={peer.NodePort}");
                        routingTable.AddPeer(peer);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error while adding peer to routing table: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                    // Log any errors that occur while adding a peer
                    Console.WriteLine($"Error while adding peer to routing table: {ex.Message}");
                }
            }

            Console.WriteLine($"Successfully populated the routing table with {peerList.Count} peers.");
            return routingTable;
        }

        public static void StoreTestSignaturePrivateKey(byte[] keyBlob)
        {
            try
            {
                string keyName = KeyGenerator.KeyType.PrivateTestNodeSignatureKey.ToString();
                var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

                if (CngKey.Exists(keyName, provider))
                {
                    Console.WriteLine($"Private signature key '{keyName}' already exists. Skipping storage.");
                    return;
                }

                // 🔥 Create a persistent private key in CNG storage
                var creationParams = new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyUsage = CngKeyUsages.Signing, // ✅ Ensures this key is used for signing
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                };

                using var newCngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParams);
                newCngKey.SetProperty(new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None));

                Console.WriteLine($"Private signature key '{keyName}' stored permanently in CNG.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing private signature key: {ex.Message}");
            }
        }

        public static void StoreTestSignaturePublicKey(byte[] keyBlob)
        {
            try
            {
                string keyName = KeyGenerator.KeyType.PublicTestNodeSignatureKey.ToString();
                var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

                if (CngKey.Exists(keyName, provider))
                {
                    Console.WriteLine($"Public signature key '{keyName}' already exists. Skipping storage.");
                    return;
                }

                // 🔥 Create a persistent public key in CNG storage
                var creationParams = new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyUsage = CngKeyUsages.Signing // ✅ Ensures this key is used for signatures
                };

                using var newCngKey = CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creationParams);
                newCngKey.SetProperty(new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None));

                Console.WriteLine($"Public signature key '{keyName}' stored permanently in CNG.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing public signature key: {ex.Message}");
            }
        }

        public static void StoreEncryptionPrivateKey(byte[] keyBlob)
        {
            try
            {
                string keyName = KeyGenerator.KeyType.PrivateTestNodeEncryptionKey.ToString();
                var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

                if (CngKey.Exists(keyName, provider))
                {
                    Console.WriteLine($"Private encryption key '{keyName}' already exists. Skipping storage.");
                    return;
                }

                // 🔥 Create a persistent key in CNG storage
                var creationParams = new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyUsage = CngKeyUsages.KeyAgreement, // ✅ Ensure it's used for ECDH key exchange
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport
                };

                using var newCngKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, creationParams);
                newCngKey.SetProperty(new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None));

                Console.WriteLine($"Private encryption key '{keyName}' stored permanently in CNG.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing private encryption key: {ex.Message}");
            }
        }

        public static void StoreEncryptionPublicKey(byte[] keyBlob)
        {
            try
            {
                string keyName = KeyGenerator.KeyType.PublicTestNodeEncryptionKey.ToString();
                var provider = CngProvider.MicrosoftSoftwareKeyStorageProvider;

                // 🔥 Use SubjectPublicKeyInfo format to avoid import issues
                var format = CngKeyBlobFormat.GenericPublicBlob;

                if (CngKey.Exists(keyName, provider))
                {
                    Console.WriteLine($"Public encryption key '{keyName}' already exists. Skipping storage.");
                    return;
                }

                // 🔥 Create a persistent public key in CNG storage
                var creationParams = new CngKeyCreationParameters
                {
                    Provider = provider,
                    KeyUsage = CngKeyUsages.KeyAgreement
                };

                using var newCngKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, creationParams);
                newCngKey.SetProperty(new CngProperty("Length", BitConverter.GetBytes(256), CngPropertyOptions.None));

                Console.WriteLine($"Public encryption key '{keyName}' stored permanently in CNG.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error storing public encryption key: {ex.Message}");
            }
        }

        public static void GenerateTestNodeKeyPairs()
        {
            Console.WriteLine(" Starting key pair generation...");

            // ----- Signature Keys (ECDSA) -----
            string sigPrivateKeyName = KeyGenerator.KeyType.PrivateTestNodeSignatureKey.ToString();
            string sigPublicKeyName = KeyGenerator.KeyType.PublicTestNodeSignatureKey.ToString();

            byte[] privateSigKeyBlob = null;
            byte[] publicSigKeyBlob = null;

            if (CngKey.Exists(sigPrivateKeyName))
            {
                Console.WriteLine($" Using existing signature key: {sigPrivateKeyName}");
                using var sigKey = CngKey.Open(sigPrivateKeyName);
                privateSigKeyBlob = sigKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                //publicSigKeyBlob = sigKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                Console.WriteLine($" Creating new exportable signature key: {sigPrivateKeyName}");
                var sigCreationParams = new CngKeyCreationParameters
                {
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport,  // Allow export in test mode
                    KeyUsage = CngKeyUsages.Signing,

                };

                using var sigKey = CngKey.Create(CngAlgorithm.ECDsaP256, sigPrivateKeyName, sigCreationParams);
                privateSigKeyBlob = sigKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);


              

            }

            if (CngKey.Exists(sigPublicKeyName))
            {
                Console.WriteLine($" Using existing signature key: {sigPublicKeyName}");
                using var sigKey = CngKey.Open(sigPublicKeyName);
                //privateSigKeyBlob = sigKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                publicSigKeyBlob = sigKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                Console.WriteLine($" Creating new exportable signature key: {sigPrivateKeyName}");
                var sigCreationParams = new CngKeyCreationParameters
                {
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport,  // Allow export in test mode
                    KeyUsage = CngKeyUsages.Signing,

                };

                using var sigKey = CngKey.Create(CngAlgorithm.ECDsaP256, sigPublicKeyName, sigCreationParams);
               // privateSigKeyBlob = sigKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);


                publicSigKeyBlob = sigKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }

            // ----- Encryption Keys (ECDH) -----
            string encPrivateKeyName = KeyGenerator.KeyType.PrivateTestNodeEncryptionKey.ToString();
            string encPublicKeyName = KeyGenerator.KeyType.PublicTestNodeEncryptionKey.ToString();

            byte[] privateEncKeyBlob = null;
            byte[] publicEncKeyBlob = null;


            if (CngKey.Exists(encPrivateKeyName))
            {
                Console.WriteLine($"🔑 Using existing encryption key: {encPrivateKeyName}");
                using var encKey = CngKey.Open(encPrivateKeyName);
                privateEncKeyBlob = encKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
               // publicEncKeyBlob = encKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                Console.WriteLine($"🔑 Creating new exportable encryption key: {encPrivateKeyName}");
                var encCreationParams = new CngKeyCreationParameters
                {
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport, // Allow export in test mode
                    KeyUsage = CngKeyUsages.KeyAgreement | CngKeyUsages.Decryption,

                };

                using var encKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, encPrivateKeyName, encCreationParams);
                privateEncKeyBlob = encKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
               // publicEncKeyBlob = encKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }

            if (CngKey.Exists(encPublicKeyName))
            {
                Console.WriteLine($"🔑 Using existing encryption key: {encPublicKeyName}");
                using var encKey = CngKey.Open(encPublicKeyName);
               // privateEncKeyBlob = encKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                publicEncKeyBlob = encKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }
            else
            {
                Console.WriteLine($"🔑 Creating new exportable encryption key: {encPublicKeyName}");
                var encCreationParams = new CngKeyCreationParameters
                {
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    ExportPolicy = CngExportPolicies.AllowPlaintextExport, // Allow export in test mode
                    KeyUsage = CngKeyUsages.KeyAgreement | CngKeyUsages.Decryption,

                };

                using var encKey = CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, encPublicKeyName, encCreationParams);
               // privateEncKeyBlob = encKey.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
                publicEncKeyBlob = encKey.Export(CngKeyBlobFormat.EccPublicBlob);
            }



            // ----- Store the Keys -----
            Console.WriteLine(" Storing the keys...");
            StoreTestSignaturePrivateKey(privateSigKeyBlob);
            StoreTestSignaturePublicKey( publicSigKeyBlob);
            StoreEncryptionPrivateKey( privateEncKeyBlob);
            StoreEncryptionPublicKey(publicEncKeyBlob);

            Console.WriteLine(" Test node key pairs verified and stored (with exportable private keys)!");
        }

        public static void DeleteTestKeys()
        {
            Console.WriteLine(" Checking for test keys to delete...");

            foreach (KeyGenerator.KeyType keyType in Enum.GetValues(typeof(KeyGenerator.KeyType)))
            {
                string keyName = keyType.ToString();

                if (keyName.Contains("Test", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        if (CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                        {
                            Console.WriteLine($" Deleting test key: {keyName}");
                            using (var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                            {
                                key.Delete();
                            }

                            if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                            {

                                Console.WriteLine($" Test key '{keyName}' deleted successfully.");
                            }
                            else
                            {

                                Console.WriteLine($" Test key '{keyName}' deletion failed it still exists.");
                            }
                        }
                        else
                        {
                            Console.WriteLine($" Test key '{keyName}' does not exist, skipping...");
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($" Error deleting test key '{keyName}': {ex.Message}");
                    }
                }
            }

            Console.WriteLine(" Finished deleting test keys.");
        }

        // This is used to allow for retries on sending out messages to other nodes.
        private static async Task<T> TestRetryAsync<T>(Func<Task<T>> action, int maxRetries = 3, int delayMilliseconds = 1000)
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

        public static byte[] TestUseKeyInStorageContainer(KeyGenerator.KeyType keytype)
        {
            string keyName = keytype.ToString();
            switch ($"test{keyName}")
            {
                case nameof(testLocalSymmetricKey):
                    return Convert.FromBase64String(testLocalSymmetricKey);
                case nameof(testSemiPublicKey):
                    return Convert.FromBase64String(testSemiPublicKey);
                default:
                    throw new ArgumentException($"Key '{keyName}' not found.", nameof(keyName));
            }
        }

        public static  Contact TestCreateNewContact(string displayName, string name, string blockId, string? avatarURL, string? description, Password privateKeyPassword)
        {

            var semiPublicKey = testSemiPublicKey;
            var localSymmetricKey = testLocalSymmetricKey;

            var encryptedLocalSymmetricKey = testLocalEncryptedSymmetricKey;

            var GNCCert = testCNGCertificate;

            ContactKeys keys = new ContactKeys
            {
                PublicPersonalEncryptionKey = TestUseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalEncryptionKey),
                PublicPersonalSignatureKey = TestUseKeyInStorageContainer(KeyGenerator.KeyType.PublicPersonalSignatureKey),
                SemiPublicKey = TestUseKeyInStorageContainer(KeyGenerator.KeyType.SemiPublicKey),
                LocalSymmetricKey = TestUseKeyInStorageContainer(KeyGenerator.KeyType.LocalSymmetricKey)
            };

            ContactMetaData metaData = new ContactMetaData
            {
                DisplayName = displayName,
                Name = name,
                AvatarURLHash = avatarURL,
                Description = description,

            };

            Contact contact = new Contact
            {
                MetaData = metaData,
                Keys = keys,

            };
            return contact;
        }

        public  class NodeManager
        {

            public static List<Node> Nodes = new List<Node>();

            public static void CreateFakeNodeTest(int nodeToMake)
            {

               
                Console.WriteLine("Setting test Variable True.");
                Environment.SetEnvironmentVariable("SPHERE_TEST_MODE", "true");
                string testModeEnv = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE");
                Console.WriteLine($"SPHERE_TEST_MODE= {testModeEnv}.");
                for (int i = 0; i < nodeToMake; i++)
                {
                    try
                    {
                        Console.WriteLine("Creating a test node with a fake STUN...");

                        // Create a test node
                        Console.WriteLine("Starting testing.CreateTestNodeWithFakeSTUNAsync.");
                        Node testNode = CreateTestNodeWithFakeSTUNAsync(NodeType.Full);

                        Console.WriteLine("\n=== Node Created ===");
                        Console.WriteLine($"Node ID: {testNode.Peer.NodeId}");
                        Console.WriteLine($"Node IP: {testNode.Peer.NodeIP}");
                        Console.WriteLine($"Node Port: {testNode.Peer.NodePort}");
                        Console.WriteLine($"Node Type: {testNode.Peer.Node_Type}");
                        Console.WriteLine($"Public Signature Key: {testNode.Peer.PublicSignatureKey}");
                        Console.WriteLine($"Public Encryption Key: {testNode.Peer.PublicEncryptKey}");

                        Console.WriteLine("\n=== Routing Table ===");

                        int totalPeers = testNode.RoutingTable.GetAllPeers().Count();
                        Console.WriteLine($"\nRouting Table Contains {totalPeers}..");
                        Console.WriteLine($"First 5 Peers...");
                        int totalPeersCountDown = 5;
                        foreach (var peer in testNode.RoutingTable.GetAllPeers())
                        {
                            if (totalPeersCountDown > 0)
                            {
                                Console.WriteLine($"Peer ID: {peer.NodeId}, IP: {peer.NodeIP}, Port: {peer.NodePort}, Trust Score: {peer.Reputation}");
                                totalPeersCountDown--;
                            }
                            else
                            {
                                break;
                            }
                        }

                        Console.WriteLine("\n=== DHT Blocks ===");
                        int totalBlocks = testNode.ContactDHT.GetTotalBlockCount();
                        Console.WriteLine($"\nDHT Contains {totalBlocks}..");
                        Console.WriteLine($"First 5 Blocks...");
                        int totalBlocksCountDown = 5;
                        foreach (var block in testNode.ContactDHT.GetCurrentState())
                        {
                            if (totalBlocksCountDown > 0)
                            {
                                Console.WriteLine($"Block ID: {block.Header.BlockId}, Created: {block.Header.BlockCreationTime}, Updated: {block.Header.LastUpdateTime}");
                                totalBlocksCountDown--;
                            }
                            else
                            {
                                break;
                            }
                        }

                        Console.WriteLine("\nTest node creation completed successfully.");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: {ex.Message}");

                        if (ex.InnerException != null)
                        {
                            Console.WriteLine($"Inner Exception: {ex.InnerException.Message}");
                            Console.WriteLine(ex.InnerException.StackTrace);
                        }
                    }

                }
                Console.ReadLine(); // Keep the console open
            }

            public static async Task TestBootstrap()
            {
                Node hostNode = new Node();
               
                try
                {
                    Environment.SetEnvironmentVariable("SPHERE_TEST_MODE", "true");
                    string testModeEnv = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE");
                    Console.WriteLine($"SPHERE_TEST_MODE= {testModeEnv}.");

                    try
                    {
                        //Create a Full Fake Node DHT and RT and assign as HOST
                        CreateFakeNodeTest(1);
                        hostNode = GetFirstNode();
                        Console.WriteLine($"Starting hostNode Listener at {hostNode.Client.clientIP}:{hostNode.Client.clientListenerPort}");
                        hostNode.Client.StartClientListenerAsync(hostNode, hostNode.Client);
                        Console.WriteLine($"hostNode Created Successfully");
                        Console.WriteLine($"hostNode DHT size is  {hostNode.ContactDHT.GetTotalBlockCount()}");
                        Console.WriteLine($"hostNode Routing Table size is {hostNode.RoutingTable.GetAllPeers().Count()}");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: Creating hostNode. {ex.Message}");
                        throw new Exception();
                    }
                    Node babyNode = new Node();
                    try
                    {
                        // Create a babyNode with no Rt or DHT.   
                        babyNode = CreateTestNodeWithNoDHTorRoutingTable(NodeType.Full);
                        Console.WriteLine($"babyNode Created Successfully");
                        Console.WriteLine($"Starting babyNode Listener at {babyNode.Client.clientIP}:{babyNode.Client.clientListenerPort}");
                        babyNode.Client.StartClientListenerAsync(babyNode, babyNode.Client);
                        Console.WriteLine($"babyNode DHT Starting size is  {babyNode.ContactDHT.GetTotalBlockCount()}");
                        Console.WriteLine($"babyNode Routing Table Starting size is {babyNode.RoutingTable.GetAllPeers().Count()}");

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: Creating babyNode. {ex.Message}");
                        throw new Exception();
                    }
                    try
                    {
                        // Send the Boot Strap. 
                        Console.WriteLine($"Attempting to send Bootstrap Request to {hostNode.Client.clientIP.ToString()}:{hostNode.Client.clientListenerPort} with key of {Convert.ToBase64String(hostNode.Peer.PublicEncryptKey)}.");

                        await Bootstrap.SendBootstrapRequest(babyNode, hostNode.Client.clientIP.ToString(), hostNode.Client.clientListenerPort, hostNode.Peer.PublicEncryptKey);

                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error: Failed to send BootStrapRequest");
                    }

                     await Task.Delay(300); // A slight delay to allow async operations to settle (optional)
                    Console.WriteLine($"babyNode has processed the BootStrap.");
                    Console.WriteLine($"babyNode finished the test with a DHT of size: {babyNode.ContactDHT.GetTotalBlockCount()}");
                    Console.WriteLine($"babyNode finished the test with a Routing Table of size: {babyNode.RoutingTable.GetAllPeers().Count()}");
                    Console.WriteLine($"TEST Complete: babyNode Successfully Bootstrapped");

                }
                catch (Exception ex)
                {


                    Console.WriteLine($"Failed To TestBootStrap Process: {ex.Message}");
                }
                Console.ReadLine();
            }

            public static async Task TestBroadcastToPeers()
            {
                Environment.SetEnvironmentVariable("SPHERE_TEST_MODE", "true");
                string testModeEnv = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE");
                Console.WriteLine($"Debug-TestBrodcastToPeers: SPHERE_TEST_MODE = {testModeEnv}");

                List<Node> hostNodes = new List<Node>();

                Node hostNode1 = new Node();
                Node hostNode2 = new Node();
                Node hostNode3 = new Node();
                Node hostNode4 = new Node();
                Node babyNode = new Node();

                try
                {
                    Console.WriteLine("Debug-TestBrodcastToPeers: Initializing test environment...");

                    // Reset and create test nodes
                    Nodes.Clear();
                    CreateFakeNodeTest(5);

                    hostNode1 = Nodes[0];
                    hostNodes.Add(hostNode1);
                    hostNode2 = Nodes[1];
                    hostNodes.Add(hostNode2);
                    hostNode3 = Nodes[2];
                    hostNodes.Add(hostNode3);
                    hostNode4 = Nodes[3];
                    hostNodes.Add(hostNode4);

                    Console.WriteLine("Debug-TestBrodcastToPeers: Nodes created successfully!");

                    // Clearing routing tables to prevent stale data
                    Console.WriteLine("Debug-TestBrodcastToPeers: Clearing routing tables...");
                    hostNode1.RoutingTable.ClearRoutingTable();
                    hostNode2.RoutingTable.ClearRoutingTable();
                    hostNode3.RoutingTable.ClearRoutingTable();
                    hostNode4.RoutingTable.ClearRoutingTable();
                    Console.WriteLine("Debug-TestBrodcastToPeers: Routing tables cleared.");

                    // Adding initial peer connections
                    Console.WriteLine("Debug-TestBrodcastToPeers: Adding peers to routing tables...");
                    Console.WriteLine("\n");
                    hostNode1.RoutingTable.AddPeer(hostNode2.Peer);
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode1 Has Added peer: {hostNode2.Peer.NodeId}");

                    hostNode2.RoutingTable.AddPeer(hostNode1.Peer);
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode2 Has Added peer: {hostNode1.Peer.NodeId}");

                    hostNode3.RoutingTable.AddPeer(hostNode2.Peer);
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode3 Has Added peer: {hostNode2.Peer.NodeId}");

                    hostNode4.RoutingTable.AddPeer(hostNode3.Peer);
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode4 Has Added peer: {hostNode3.Peer.NodeId}");

                    // Print routing table sizes before broadcast
                    Console.WriteLine("Debug-TestBrodcastToPeers: Routing Table Sizes BEFORE Broadcast:\n");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode1 now has {hostNode1.RoutingTable.GetAllPeers().Count} peers.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode2 now has {hostNode2.RoutingTable.GetAllPeers().Count} peers.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode3 now has {hostNode3.RoutingTable.GetAllPeers().Count} peers.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode4 now has {hostNode4.RoutingTable.GetAllPeers().Count} peers.");

                    // Create a baby node and add a connection
                    Console.WriteLine("Debug-TestBrodcastToPeers: Creating babyNode...");
                    babyNode = Nodes[4];
                    babyNode.RoutingTable.ClearRoutingTable();
                    babyNode.RoutingTable.AddPeer(hostNode4.Peer);


                    foreach (var node in hostNodes)
                    {
                        node.Client.StartClientListenerAsync(node, node.Client);
                    }
                    babyNode.Client.StartClientListenerAsync(babyNode, babyNode.Client);


                    // Broadcasting network connection
                    Console.WriteLine("Debug-TestBrodcastToPeers: babyNode Broadcasting Connection to Network...");
                    await babyNode.NetworkManager.BroadcastConnectionToNetwork(babyNode);
                    Console.WriteLine("Debug-TestBrodcastToPeers: babyNode Broadcast completed.");

                    // Print routing table sizes AFTER broadcast
                    // 🕒 Wait for peer propagation
                    await Task.Delay(TimeSpan.FromSeconds(2)); // Adjust delay if needed

                    // Print routing table sizes AFTER broadcast
                    Console.WriteLine("Debug-TestBrodcastToPeers: Routing Table Sizes AFTER Broadcast:");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: babyNode ends test with {babyNode.RoutingTable.GetAllPeers().Count} peers should be 4.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode1 ends test with {hostNode1.RoutingTable.GetAllPeers().Count} peers should be 2.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode2 ends test with {hostNode2.RoutingTable.GetAllPeers().Count} peers should be 2.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode3 ends test with {hostNode3.RoutingTable.GetAllPeers().Count} peers should be 2.");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: hostNode4 ends test with {hostNode4.RoutingTable.GetAllPeers().Count} peers should be 2.");

                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Debug-TestBrodcastToPeers: [ERROR] {ex.Message}");
                    Console.WriteLine($"Debug-TestBrodcastToPeers: [ERROR] Stack Trace: {ex.StackTrace}");
                    throw;
                }
                Console.ReadLine();
            }

            public static void AddNodeToNodes(Node node)
            {
                Nodes.Add(node);
            }

            public static Node GetTestNodeByID(int id)
            {

                if (id < 0 || id >= Nodes.Count)
                {
                    throw new ArgumentOutOfRangeException(nameof(id), "Index is out of range.");
                }

                return Nodes[id];
            }

            public static Node GetFirstNode()
            {

                return Nodes[0];
            }

        }

    }
}

