
using SPHERE.Configure;
using SPHERE.Networking;
using System.Text.Json;
using SPHERE.Security;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// The Distributed Hash Table.
    /// 
    /// The DHT is the Blockchain it is the nodes record of the chain, either all or its shard(Piece).
    /// 
    /// it is a Dictonary of Blocks with a key of their ID.
    /// 
    /// Blocks can be added to the DHT and edited, That is all. 
    /// 
    /// It exists exactly the same in all forms across all devices whether they have a shard or the whole Chain.
    /// </summary>
    public class DHT
    {
        private static readonly object stateLock = new object(); // For thread safety

        private readonly Dictionary<string, Block> _blocks = new();

        public RoutingTable RoutingTable { get; set; }

        public void AddBlock(Block block)
        {
            if (block == null || block.Header == null)
            {
                throw new ArgumentNullException(nameof(block), "Block or Block Header cannot be null.");
            }

            lock (stateLock) // Ensures thread-safe access to the _blocks dictionary
            {
                _blocks[block.Header.BlockId] = block;
            }
        }

        public Block GetBlock(string blockID)
        {
            if (string.IsNullOrEmpty(blockID))
            {
                throw new ArgumentException("Block ID cannot be null or empty.", nameof(blockID));
            }

            lock (stateLock) // Ensure thread-safe access to _blocks
            {
                return _blocks.TryGetValue(blockID, out var block) ? block : null;
            }
        }

        public void ReplaceBlock(string blockID, string encryptedContact, string signature)
        {
            if (string.IsNullOrEmpty(blockID))
            {
                throw new ArgumentException("Block ID cannot be null or empty.", nameof(blockID));
            }

            lock (stateLock) // Ensure thread-safe access to _blocks
            {
                // Retrieve the block
                Block block = GetBlock(blockID);
                if (block == null)
                {
                    Console.WriteLine($"Block with ID {blockID} not found. Replacement aborted.");
                    return;
                }

                // Verify the signature before replacing the block data
                if (SignatureGenerator.VerifyBlockSignature(blockID, signature, block.Header.PublicSignatureKey))
                {
                    // Update the block
                    block.EncryptedContact = encryptedContact;
                    block.Header.LastUpdateTime = DateTime.UtcNow;

                    Console.WriteLine($"Block {blockID} replaced successfully.");
                }
                else
                {
                    Console.WriteLine($"Signature verification failed for block {blockID}. Replacement aborted.");
                }
            }
        }
        public int GetTotalBlockCount()
        {
            lock (stateLock) // Ensure thread safety
            {
                return _blocks.Count;
            }
        }

        public static string GetAppDataPath(string fileName)
        {
            string appDataDir;
            appDataDir = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            return Path.Combine(appDataDir, $"{AppIdentifier.GetOrCreateServiceName()}{fileName}.state");
        }

        /// <summary>
        /// Retrieves the current DHT state.
        /// </summary>
        /// <param name="limit">Optional limit to the number of blocks to include in the response.</param>
        /// <returns>A dictionary representing the current DHT state.</returns>
        public List<Block> GetCurrentState(int limit = 0)
        {
            lock (stateLock) // Ensure thread safety
            {
                // If a limit is specified and valid, return a limited number of blocks
                if (limit > 0 && limit < _blocks.Count)
                {
                    return _blocks.Values.Take(limit).ToList();
                }

                // Return the full DHT state as a list of blocks
                return _blocks.Values.ToList();
            }
        }


        public bool IsBlockValid(Block block)
        {
            // Check for null or malformed data
            if (block == null || block.Header == null)
            {
                Console.WriteLine("Block or block header is null.");
                return false;
            }

            // Validate the block hash
            string calculatedHash = block.Header.CalculateBlockHash();
            if (calculatedHash != block.Header.BlockHash)
            {
                Console.WriteLine($"Invalid block hash for BlockId {block.Header.BlockId}. Expected {calculatedHash}, got {block.Header.BlockHash}.");
                return false;
            }

            // Optionally validate encryption algorithm, signature, or other policies
            if (block.Header.EncryptionAlgorithm != "AES256" && block.Header.EncryptionAlgorithm != "RSA2048")
            {
                Console.WriteLine($"Unsupported encryption algorithm: {block.Header.EncryptionAlgorithm}");
                return false;
            }

            return true;
        }

        public void SaveState()
        {
            lock (stateLock) // Ensure thread safety
            {
                try
                {
                    string filePath = GetAppDataPath("DHT");

                    // Ensure the directory exists
                    string directoryPath = Path.GetDirectoryName(filePath);
                    if (!Directory.Exists(directoryPath))
                    {
                        Directory.CreateDirectory(directoryPath);
                    }

                    // Serialize the state to JSON
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    string json = JsonSerializer.Serialize(_blocks, options);

                    // Write to the file with exclusive access
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    using (StreamWriter writer = new StreamWriter(fileStream))
                    {
                        writer.Write(json);
                    }

                    Console.WriteLine("DHT state saved successfully.");
                }
                catch (IOException ioEx)
                {
                    Console.WriteLine($"I/O error while saving DHT state: {ioEx.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to save DHT state: {ex.Message}");
                }
            }
        }

        // Load DHT state from a file
        public void LoadState()
        {
            lock (stateLock) // Ensure thread safety
            {
                try
                {
                    string filePath = GetAppDataPath("DHT");

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("DHT state file not found. Starting with an empty state.");
                        return;
                    }

                    // Open the file with a lock to prevent concurrent access
                    using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                    using (StreamReader reader = new StreamReader(fileStream))
                    {
                        string json = reader.ReadToEnd();
                        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                        var loadedBlocks = JsonSerializer.Deserialize<Dictionary<string, Block>>(json, options);

                        if (loadedBlocks != null)
                        {
                            _blocks.Clear();
                            foreach (var block in loadedBlocks)
                            {
                                _blocks[block.Key] = block.Value;
                            }

                            Console.WriteLine("DHT state loaded successfully.");
                        }
                        else
                        {
                            Console.WriteLine("No data found in the DHT state file. Starting with an empty state.");
                        }
                    }
                }
                catch (IOException ioEx)
                {
                    Console.WriteLine($"I/O error while loading DHT state: {ioEx.Message}");
                }
                catch (JsonException jsonEx)
                {
                    Console.WriteLine($"JSON error while loading DHT state: {jsonEx.Message}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to load DHT state: {ex.Message}");
                }
            }
        }

        //
        public void UpdateRoutingTable(IEnumerable<Peer> bootstrapPeers)
        {
            lock (stateLock)
            {
                foreach (var peer in bootstrapPeers)
                {
                    RoutingTable.AddPeer(peer); // Use the RoutingTable class to handle this
                }
            }
        }

        public List<Peer> SelectPeersForRoutingTable(IEnumerable<Peer> candidatePeers)
        {
            return candidatePeers
                .OrderBy(peer => peer.CalculateProximity(peer)) // Sort by proximity or a custom metric
                .Take(10) // Limit the number of peers
                .ToList();
        }

        public void RebuildRoutingTable()
        {
            lock (stateLock)
            {
                // Get all peers from the routing table
                List<Peer> allPeers = RoutingTable.GetAllPeers();

                // Clear the current routing table
                RoutingTable.ClearRoutingTable();

                // Re-add peers to the routing table, sorted by TrustScore and proximity
                foreach (var peer in allPeers
                    .OrderByDescending(peer => peer.TrustScore)
                    .ThenBy(peer => peer.CalculateProximity(peer)))
                {
                    RoutingTable.AddPeer(peer);
                }
            }
        }



    }

}
