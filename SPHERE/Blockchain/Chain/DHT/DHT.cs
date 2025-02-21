
using SPHERE.Configure;
using SPHERE.Configure.Logging;
using SPHERE.Networking;
using System.Text.Json;
using SPHERE.Security;
using System.Collections.Concurrent;
using System.Numerics;

namespace SPHERE.Blockchain
{
    /// <summary>
    /// The Distributed Hash Table.
    /// 
    /// The DHT is the Blockchain it is the nodes record of the chain, either all or its shard(Piece).
    /// 
    /// it is a Dictionary of Blocks with a key of their ID.
    /// 
    /// Blocks can be added to the DHT and edited, That is all. 
    /// 
    /// It exists exactly the same in all forms across all devices whether they have a shard or the whole Chain.
    /// </summary>
    public class DHT
    {
        private static readonly object stateLock = new object(); // For thread safety

        private readonly ConcurrentDictionary<string, Block> _blocks = new();

        public void AddBlock(Block block)
        {
            
                if (block == null || block.Header == null)
                {
                    throw new ArgumentNullException(nameof(block), "Block or Block Header cannot be null.");
                }

                lock (stateLock) // Ensures thread-safe access to the _blocks dictionary
                {
                    if (!_blocks.ContainsKey(block.Header.BlockId))
                    {
                        _blocks[block.Header.BlockId] = block;
                        return;
                    }
                   
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
                    if (_blocks.TryGetValue(blockID, out Block block))
                    {
                        return block;
                    }
                    else
                    {
                    SystemLogger.Log($"Block {blockID} not found in local DHT.");
                    DHTManagement.IncrementFailedLookups(this);
                    return null;
                }
               
                }
            
        }

        public void RemoveBlock(string blockID)
        {
            if (string.IsNullOrEmpty(blockID))
            {
                throw new ArgumentException("Block ID cannot be null or empty.", nameof(blockID));
            }

            lock (stateLock) // Ensure thread-safe access to _blocks
            {
                try
                {
                    _blocks.Remove(blockID, out _);
                    SystemLogger.Log($"Block {blockID} removed successfully.");
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Failed to remove block {blockID}: {ex.Message}");
                }
               
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
                    SystemLogger.Log($"Block with ID {blockID} not found. Replacement aborted.");
                    return;
                }

                // Verify the signature before replacing the block data
                if (SignatureGenerator.VerifyBlockSignature(blockID, signature, block.Header.PublicSignatureKey))
                {
                    // Update the block
                    block.EncryptedContact = encryptedContact;
                    block.Header.LastUpdateTime = DateTime.UtcNow;

                    SystemLogger.Log($"Block {blockID} replaced successfully.");
                }
                else
                {
                    SystemLogger.Log($"Signature verification failed for block {blockID}. Replacement aborted.");
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

        public void ClearState()
        {
            lock (stateLock) // Ensure thread safety
            {
                _blocks.Clear();
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


        public bool ShouldStoreBlock(Node node, string blockId, int replicationFactor = 20)
        {
            // Compute our distance from the block.
            BigInteger ourDistance = RoutingTable.CalculateXorDistance(node.Peer.NodeId, blockId);

            // Get the k (replicationFactor) closest peers for this block.
            List<Peer> closestPeers = node.RoutingTable.GetClosestPeers(blockId, replicationFactor);

            // Check if our node is among those peers.
            bool weAreClosest = closestPeers.Any(peer => peer.NodeId == node.Peer.NodeId);

            // Optionally, also check if our storage is underloaded.
            bool underloaded = DHTManagement.IsUnderloaded(node, node.ContactDHT); // or ReputationDHT etc.

            return weAreClosest || underloaded;
        }

        public bool IsBlockValid(Block block)
        {
            // Check for null or malformed data
            if (block == null || block.Header == null)
            {
                SystemLogger.Log("Block or block header is null.");
                return false;
            }

            // Validate the block hash
            string calculatedHash = block.Header.CalculateBlockHash();
            if (calculatedHash != block.Header.BlockHash)
            {
                SystemLogger.Log($"Invalid block hash for BlockId {block.Header.BlockId}. Expected {calculatedHash}, got {block.Header.BlockHash}.");
                return false;
            }

            // Optionally validate encryption algorithm, signature, or other policies
            if (block.Header.EncryptionAlgorithm != "AES256" && block.Header.EncryptionAlgorithm != "RSA2048")
            {
                SystemLogger.Log($"Unsupported encryption algorithm: {block.Header.EncryptionAlgorithm}");
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

                    SystemLogger.Log("DHT state saved successfully.");
                }
                catch (IOException ioEx)
                {
                    SystemLogger.Log($"I/O error while saving DHT state: {ioEx.Message}");
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Failed to save DHT state: {ex.Message}");
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
                        SystemLogger.Log("DHT state file not found. Starting with an empty state.");
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

                            SystemLogger.Log("DHT state loaded successfully.");
                        }
                        else
                        {
                            SystemLogger.Log("No data found in the DHT state file. Starting with an empty state.");
                        }
                    }
                }
                catch (IOException ioEx)
                {
                    SystemLogger.Log($"I/O error while loading DHT state: {ioEx.Message}");
                }
                catch (JsonException jsonEx)
                {
                    SystemLogger.Log($"JSON error while loading DHT state: {jsonEx.Message}");
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Failed to load DHT state: {ex.Message}");
                }
            }
        }   


    }

}
