using SPHERE.Networking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Blockchain
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.NetworkInformation;
    using System.Text.Json;

    namespace SPHERE.Blockchain
    {
        /// <summary>
        /// The RoutingTable class implements a Kademlia-style Distributed Hash Table (DHT) for managing network peers.
        /// It organizes peers into buckets based on XOR distance from the local node, allowing efficient peer discovery and routing.
        /// 
        /// Key Features:
        /// - Buckets: Groups peers by XOR distance for efficient lookup.
        /// - Closest Peer Lookup: Finds peers closest to a given node ID.
        /// - Bucket Maintenance: Enforces a maximum bucket size and ensures active connections.
        /// - XOR Distance Calculation: Determines the proximity between peers using XOR metrics.
        /// 
        /// Usage:
        /// - Use AddPeer() to add a peer to the appropriate bucket.
        /// - Use RemovePeer() to remove a peer by its Node ID.
        /// - Use GetClosestPeers() to find the closest peers to a target Node ID.
        /// - Call DisplayTable() to log the current state of the routing table.
        /// 
        /// Example:
        /// var routingTable = new RoutingTable();
        /// var peer = Peer.CreatePeerHeader(...);
        /// routingTable.AddPeer(peer);
        /// var closestPeers = routingTable.GetClosestPeers(targetId, count);
        /// 
        ///</summary>
        /// Below is a use case example for the Routing Table
        /*  public class Program
            {
                public static void Main()
                {
                    var routingTable = new RoutingTable();

                    // Example peers
                    var peer1 = Peer.CreatePeerHeader(NodeType.FullNode, "001", "192.168.1.1", 8001, "hash1", "pubSig1", "pubEnc1");
                    var peer2 = Peer.CreatePeerHeader(NodeType.LightNode, "002", "192.168.1.2", 8002, "hash2", "pubSig2", "pubEnc2");
                    var peer3 = Peer.CreatePeerHeader(NodeType.FullNode, "003", "192.168.1.3", 8003, "hash3", "pubSig3", "pubEnc3");

                    // Add peers
                    routingTable.AddPeer(peer1);
                    routingTable.AddPeer(peer2);
                    routingTable.AddPeer(peer3);
 
                    // Display table
                    routingTable.DisplayTable();

                    // Get closest peers
                    var closestPeers = routingTable.GetClosestPeers("002", 2);
                    Console.WriteLine("Closest peers:");
                    foreach (var peer in closestPeers)
                    {
                        Console.WriteLine($"- {peer.NodeId}: {peer.NodeIP}:{peer.NodePort}");
                    }

                    // Remove a peer
                    routingTable.RemovePeer("002");

                    // Display table again
                    routingTable.DisplayTable();

        */

    }
    public class RoutingTable
        {
            private readonly List<Bucket> _buckets;
            private readonly int _bucketSize;
            private readonly object _lock = new();

            public RoutingTable(int bucketSize = 20)
            {
                _buckets = new List<Bucket>(Enumerable.Range(0, 160).Select(_ => new Bucket()));
                _bucketSize = bucketSize;
            }

            public void AddPeer(Peer peer)
            {
                lock (_lock)
                {
                    int bucketIndex = GetBucketIndex(peer.NodeId);
                    var bucket = _buckets[bucketIndex];
                    bucket.AddPeer(peer, _bucketSize);
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

            public Peer GetPeer(string nodeId)
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

            private int GetBucketIndex(string nodeId)
            {
                // Assuming the local node ID is 160 bits for Kademlia, adjust accordingly
                string localNodeId = "00000000000000000000000000000000"; // Example local node ID
                int distance = CalculateXorDistance(localNodeId, nodeId);
                return 159 - (int)Math.Log2(distance);
            }

            private static int CalculateXorDistance(string id1, string id2)
            {
                byte[] id1Bytes = Convert.FromHexString(id1);
                byte[] id2Bytes = Convert.FromHexString(id2);

                int distance = 0;
                for (int i = 0; i < id1Bytes.Length; i++)
                {
                    distance = (distance << 8) + (id1Bytes[i] ^ id2Bytes[i]);
                }

                return distance;
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
            lock (_lock) // Ensure thread-safe access to the RoutingTable
            {
                try
                {
                    string filePath = DHT.GetAppDataPath("RT");

                    // Ensure the directory exists
                    string directoryPath = Path.GetDirectoryName(filePath);
                    if (!Directory.Exists(directoryPath))
                    {
                        Directory.CreateDirectory(directoryPath);
                    }

                    // Serialize the routing table to JSON
                    var options = new JsonSerializerOptions { WriteIndented = true };
                    string json = JsonSerializer.Serialize(_buckets, options);

                    // Write to the file with exclusive access
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

        public void LoadRoutingTable()
        {
            lock (_lock) // Ensure thread-safe access to the RoutingTable
            {
                try
                {
                    string filePath = DHT.GetAppDataPath("RT");

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("RoutingTable state file not found. Starting with an empty table.");
                        return;
                    }

                    // Open the file and deserialize it into the routing table
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

                public Bucket()
                {
                    Peers = new List<Peer>();
                }

                public void AddPeer(Peer peer, int maxSize)
                {
                    if (Peers.Count >= maxSize)
                    {
                        Console.WriteLine($"Bucket is full. Cannot add peer {peer.NodeId}.");
                        return;
                    }

                    if (!Peers.Any(p => p.NodeId == peer.NodeId))
                    {
                        Peers.Add(peer);
                    }
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

}


