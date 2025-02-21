using SPHERE.Blockchain;
using SPHERE.Configure;
using SPHERE.PacketLib;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text;
using System.Xml.Linq;


namespace SPHERE.Networking
{
    /// <summary>
    /// The Peer Header is the INFO a node needs to be a peer. its everything that makes a node a node except for its client and copy of the chain.
    /// 
    /// We store this in a dict as list or peers. 
    /// 
    /// </summary>
    public class Peer
    {
        private static readonly object stateLock = new object();

        public string NodeId { get; set; }
        public NodeType Node_Type { get; set; } = new();
        public string NodeIP { get; set; } 
        public int NodePort { get; set; } = new();
        public string PreviousNodesHash { get; set; }
        public byte[] PublicSignatureKey { get; set; } 
        public byte[] PublicEncryptKey { get; set; }
        public  double Reputation {  get; set; } = new();

        public DateTime LastSeen { get; set; } =new();
        public DateTime FirstSeen { get; set; } = new();

        public static Peer CreatePeer(NodeType nodeType, string nodeID, string nodeIP, int nodePort, string? previousHash, byte[] publicSignatureKey, byte[] publicEncryptKey)
        {
            DateTime now = DateTime.UtcNow;
            Peer peer = new Peer
            {
                Node_Type = nodeType,
                NodeId = nodeID,
                NodeIP = nodeIP,
                NodePort = nodePort,
                PublicSignatureKey = publicSignatureKey,
                PublicEncryptKey = publicEncryptKey,
                Reputation=0,
                FirstSeen = now,
                LastSeen =now,
            };
            if (!String.IsNullOrWhiteSpace(previousHash))
            {
                peer.PreviousNodesHash = previousHash;
            }

            return peer;
        }

        public static Peer CreatePeerFromPacket(PacketLib.Packet packet)
        {
            NodeType nodeType = (NodeType)Enum.Parse(typeof(NodeType), packet.Header.Node_Type);
            DateTime now = DateTime.UtcNow;
            Peer peer = new Peer
            {
                Node_Type = nodeType,
                NodeId = packet.Header.NodeId,
                NodeIP = packet.Header.IPAddress,
                NodePort = int.Parse(packet.Header.Port),
                PublicSignatureKey = packet.Header.PublicSignatureKey,
                PublicEncryptKey = packet.Header.PublicEncryptKey,
                PreviousNodesHash = "UNKNOWN",
                Reputation = 0,
                FirstSeen = now,
                LastSeen = now,
            };

            return peer;
        }

        //We adjust the trust score of a peer. 
       

        //Validate a peer.
        public static bool ValidatePeer(Peer peer)
        {
            if (peer == null)
                return false;

            return !string.IsNullOrWhiteSpace(peer.NodeId) &&
                   !string.IsNullOrWhiteSpace(peer.NodeIP) &&
                   peer.NodePort > 0 &&
                   peer.PublicSignatureKey != null && peer.PublicSignatureKey.Length > 0 &&
                   peer.PublicEncryptKey != null && peer.PublicEncryptKey.Length > 0;
        }

        //Calculate the distance between the node an a peer.
        public double CalculateProximity(Peer peer)
        {
            // Example weights
            double latencyWeight = 0.6;
            double trustScoreWeight = 0.4;

            int latency = CalculateLatency(peer); 
            double trustScore = peer.Reputation; 

            // Normalize and combine
            return (latencyWeight * NormalizeLatency(latency)) +
                   (trustScoreWeight * NormalizeTrust(trustScore));
        }

        //Normalize Latency
        private double NormalizeLatency(int latency)
        {
            const int MaxLatency = 1000; 
            return Math.Min((double)latency / MaxLatency, 1.0); 
        }

        //Normalize Trustscore
        private double NormalizeTrust(double trustScore)
        {
            const int MaxTrustScore = 100; 
            return (double)trustScore / MaxTrustScore; // Normalize to [0, 1]
        }

        //CalculateLatency
        public int CalculateLatency(Peer peer)
        {
            try
            {
                // Perform a ping to the peer's IP address
                using (var ping = new Ping())
                {
                    var reply = ping.Send(peer.NodeIP, 1000); // Timeout after 1 second
                    return reply.Status == IPStatus.Success ? (int)reply.RoundtripTime : int.MaxValue;
                }
            }
            catch
            {
                // If ping fails, assign a high value (peer is far or unreachable)
                return int.MaxValue;
            }
        }

        //Update the endpoint of a peer.
        public void UpdatePeerEndpoint(Node node, string peerID, string newIP, int newPort)
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
                Peer peer = node.RoutingTable.GetPeerByID(peerID);
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

        //Process PeerList Response.
        public async Task ProcessPeerListResponse(Node node, Packet packet)
        {

            Console.WriteLine($"ProcessPeerListResponse: Processing response from {packet.Header.NodeId}...");
            List<Peer> peers = JsonSerializer.Deserialize<List<Peer>>(packet.Content);
            Peer senderPeer = node.RoutingTable.GetPeerByID(packet.Header.NodeId);
            if (senderPeer == null)
            {
                Console.WriteLine($"Warning: Sender {packet.Header.NodeId} is not in routing table. Ignoring response.");
                return;
            }

            if (peers == null || peers.Count == 0)
            {
                Console.WriteLine($"Warning: Received an empty or null peer list from {packet.Header.NodeId}.");
                node.NetworkManager.BroadcastReputationUpdate(node, senderPeer, Blockchain.Reputation.ReputationReason.GetContactFailed);
                 // Penalize peers that send empty responses
                return;
            }
            int validPeerCount = 0;
            int duplicateCount = 0;

            int invalidPeerCount = 0;

            const int TrustIncreasePerValidPeer = 2;  // Reward for each valid peer
            const int TrustDecreaseForDuplicates = -2; // Penalty for sending duplicates
            const int TrustPenaltyForInvalidData = -5; // Severe penalty for bad data

            try
            {

                if (peers != null)
                {
                    foreach (var peer in peers)
                    {
                        if (node.RoutingTable.GetAllPeers().Contains(peer))
                        {
                            Console.WriteLine($"Warning: ProcessPeerListResponse: Skipping duplicate peer {peer.NodeId}.");
                            duplicateCount++;

                            continue;
                        }

                        bool isPeerValid = false;
                        try
                        {
                            isPeerValid = Peer.ValidatePeer(peer);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error in ProcessPeerListResponse: {ex.Message}");
                        }


                        if (peer.NodeId == node.Peer.NodeId || peer.NodeId == senderPeer.NodeId || !isPeerValid)
                        {
                            Console.WriteLine($"ERROR: Node ({node.Peer.NodeId}) received a bad peer from Sender: {packet.Header.NodeId}");
                            invalidPeerCount++;
                            continue;
                        }

                        validPeerCount++;

                        node.RoutingTable.AddPeer(peer);
                    }

                    int trustChange = (validPeerCount * TrustIncreasePerValidPeer) + (duplicateCount * TrustDecreaseForDuplicates) + (invalidPeerCount * TrustPenaltyForInvalidData);

                    if (trustChange != 0)
                    {
                        node.NetworkManager.BroadcastReputationUpdate(node, senderPeer, Blockchain.Reputation.ReputationReason.GetContactFailed);
                    }
                }
            }
            catch (Exception ex)
            {

                Console.WriteLine($"Error in ProcessPeerListResponse: {ex.Message}");

            }
        }

    }
}
