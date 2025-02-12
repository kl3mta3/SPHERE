using SPHERE.Blockchain;
using SPHERE.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text.Json;

public class RoutingTable
{
    private readonly List<Bucket> _buckets;
    private readonly int _bucketSize;
    private readonly object _lock = new();
    public Node node { get; set; }

    public RoutingTable(int bucketSize = 20)
    {
        _buckets = new List<Bucket>(Enumerable.Range(0, 256).Select(_ => new Bucket { node=node})); // 256 buckets for a 256-bit ID space
        _bucketSize = bucketSize;
    }

    public void AddPeer(Peer peer)
    {
        lock (_lock)
        {
            try
            { 
                int bucketIndex = GetBucketIndex(peer.NodeId);
          
                _buckets[bucketIndex].AddPeer(peer, _bucketSize);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in AddPeer: {ex.Message}");
                throw;
            }
        }
    }

    public List<Peer> GetAllPeers()
    {
        lock (_lock)
        {
            return _buckets.SelectMany(bucket => bucket.Peers).ToList();
        }
    }

    public Peer GetPeerByIPAddress(string ipAddress)
    {
        lock (_lock)
        {
            return _buckets.SelectMany(bucket => bucket.Peers)
                           .FirstOrDefault(peer => peer.NodeIP == ipAddress);
        }
    }

    public void RemovePeer(string nodeId)
    {
        lock (_lock)
        {
            int bucketIndex = GetBucketIndex(nodeId);
            _buckets[bucketIndex].RemovePeer(nodeId);
        }
    }

    public Peer GetPeerByID(string nodeId)
    {
        lock (_lock)
        {
            int bucketIndex = GetBucketIndex(nodeId);
            return _buckets[bucketIndex].GetPeer(nodeId);
        }
    }

    public List<Peer> GetClosestPeers(string targetId, int count)
    {
        lock (_lock)
        {
            return _buckets
                .SelectMany(bucket => bucket.Peers)
                .OrderBy(peer => CalculateXorDistance(peer.NodeId, targetId))
                .Take(count)
                .ToList();
        }
    }

    public static bool IsHexString(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return false;

        foreach (char c in input)
        {
            if (!Uri.IsHexDigit(c))
                return false;
        }

        return true;
    }

    private int GetBucketIndex(string nodeId)
    {

        // Validate that the input is not null or empty
        if (string.IsNullOrWhiteSpace(nodeId))
        {
            throw new ArgumentNullException(nameof(nodeId), "NodeId cannot be null or empty.");
        }

        // Validate that the input is a valid hexadecimal string
        if (!IsHexString(nodeId))
        {
            throw new FormatException($"NodeId '{nodeId}' is not a valid hexadecimal string.");
        }
        string localNodeId = "0000000000000000000000000000000000000000000000000000000000000000"; // Example local node ID (256 bits in hex)
        BigInteger distance = CalculateXorDistance(localNodeId, nodeId);

        if (distance.IsZero)
            throw new InvalidOperationException("Cannot calculate bucket index for the local node ID.");

        return 255 - (int)Math.Log2((double)distance);
    }

    private static BigInteger CalculateXorDistance(string localNodeId, string nodeId)
    {
        if (string.IsNullOrWhiteSpace(localNodeId) || string.IsNullOrWhiteSpace(nodeId))
        {
            throw new ArgumentNullException("Both localNodeId and nodeId must be non-null and non-empty.");
        }

        if (localNodeId.Length != nodeId.Length)
        {
            throw new ArgumentException("localNodeId and nodeId must have the same length.");
        }

        byte[] localNodeBytes = HexStringToByteArray(localNodeId);
        byte[] nodeBytes = HexStringToByteArray(nodeId);

        BigInteger xorDistance = new BigInteger(localNodeBytes) ^ new BigInteger(nodeBytes);

        if (xorDistance.Sign < 0)
        {
            xorDistance = BigInteger.Abs(xorDistance); // Ensure non-negative result
        }

        return xorDistance;
    }

    private static byte[] HexStringToByteArray(string hex)
    {
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException("Hex string must have an even length.");
        }

        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
    public void DisplayTable()
    {
        lock (_lock)
        {
            Console.WriteLine("Routing Table:");
            for (int i = 0; i < _buckets.Count; i++)
            {
                Console.WriteLine($"Bucket {i}:");
                foreach (var peer in _buckets[i].Peers)
                {
                    Console.WriteLine($"- {peer.NodeId}: {peer.NodeIP}:{peer.NodePort}");
                }
            }
        }
    }

    public void SaveRoutingTable()
    {
        lock (_lock)
        {
            try
            {
                string filePath = DHT.GetAppDataPath("RT");

                string directoryPath = Path.GetDirectoryName(filePath);
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }

                var options = new JsonSerializerOptions { WriteIndented = true };
                string json = JsonSerializer.Serialize(_buckets, options);

                using (FileStream fileStream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (StreamWriter writer = new StreamWriter(fileStream))
                {
                    writer.Write(json);
                }

                Console.WriteLine("RoutingTable state saved successfully.");
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"I/O error while saving RoutingTable state: {ioEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to save RoutingTable state: {ex.Message}");
            }
        }
    }

    public void ClearRoutingTable()
    {
        lock (_lock)
        {
            foreach (var bucket in _buckets)
            {
                bucket.Peers.Clear();
            }
        }
    }

    public void LoadRoutingTable()
    {
        lock (_lock)
        {
            try
            {
                string filePath = DHT.GetAppDataPath("RT");

                if (!File.Exists(filePath))
                {
                    Console.WriteLine("RoutingTable state file not found. Starting with an empty table.");
                    return;
                }

                using (FileStream fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.None))
                using (StreamReader reader = new StreamReader(fileStream))
                {
                    string json = reader.ReadToEnd();
                    var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
                    var loadedBuckets = JsonSerializer.Deserialize<List<Bucket>>(json, options);

                    if (loadedBuckets != null)
                    {
                        _buckets.Clear();
                        foreach (var bucket in loadedBuckets)
                        {
                            _buckets.Add(bucket);
                        }

                        Console.WriteLine("RoutingTable state loaded successfully.");
                    }
                    else
                    {
                        Console.WriteLine("No data found in the RoutingTable state file. Starting with an empty table.");
                    }
                }
            }
            catch (IOException ioEx)
            {
                Console.WriteLine($"I/O error while loading RoutingTable state: {ioEx.Message}");
            }
            catch (JsonException jsonEx)
            {
                Console.WriteLine($"JSON error while loading RoutingTable state: {jsonEx.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to load RoutingTable state: {ex.Message}");
            }
        }
    }

    private class Bucket
    {
        public List<Peer> Peers { get; }
        public Node node { get; set; }
        public Bucket()
        {
            Peers = new List<Peer>();
        }

        public async Task AddPeer(Peer peer, int maxSize)
        {
            var existingPeer = Peers.FirstOrDefault(p => p.NodeId == peer.NodeId);
            if (existingPeer != null)
            {
                // Move the existing peer to the end of the list (LRU logic)
                Peers.Remove(existingPeer);
                Peers.Add(peer);
                return;
            }

            if (Peers.Count >= maxSize)
            {
                // Identify the peer with the lowest trust score
                Peer leastTrustedPeer = Peers.OrderBy(p => p.TrustScore).First();

                // Optionally ping the least trusted peer to confirm it's alive

                bool isAlive = await Node.PingPeerAsync(this.node, peer);
                if (isAlive)
                {
              
                    Peers.Remove(leastTrustedPeer);
                    Console.WriteLine($"Removed least trusted and unresponsive peer: {leastTrustedPeer.NodeId}");
                }
                else if (peer.TrustScore > leastTrustedPeer.TrustScore)
                {
                    // Replace the least trusted peer if the new peer has a higher trust score
                    Peers.Remove(leastTrustedPeer);
                    Console.WriteLine($"Removed least trusted peer: {leastTrustedPeer.NodeId} to add {peer.NodeId}");
                }
                else
                {
                    Console.WriteLine($"Peer {peer.NodeId} was not added due to lower trust score.");
                    return;
                }
            }

            Peers.Add(peer);
        }

        public void RemovePeer(string nodeId)
        {
            Peers.RemoveAll(p => p.NodeId == nodeId);
        }

        public Peer GetPeer(string nodeId)
        {
            return Peers.FirstOrDefault(p => p.NodeId == nodeId);
        }
    }
}