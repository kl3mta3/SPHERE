using SPHERE.Blockchain;
using System.Net.NetworkInformation;


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
        public NodeType Node_Type { get; set; }
        public string NodeIP { get; set; }
        public int NodePort { get; set; }
        public string PreviousNodesHash { get; set; }
        public byte[] PublicSignatureKey { get; set; }
        public byte[] PublicEncryptKey { get; set; }
        public  int TrustScore {  get; set; }       

        public static Peer CreatePeer(NodeType nodeType, string nodeID, string nodeIP, int nodePort, string? previousHash, byte[] publicSignatureKey, byte[] publicEncryptKey)
        {

            Peer peer = new Peer
            {
                Node_Type = nodeType,
                NodeId = nodeID,
                NodeIP = nodeIP,
                NodePort = nodePort,
                PublicSignatureKey = publicSignatureKey,
                PublicEncryptKey = publicEncryptKey,
                TrustScore=0
            };
            if (!String.IsNullOrWhiteSpace(previousHash))
            {
                peer.PreviousNodesHash = previousHash;
            }

            return peer;
        }

        //We adjust the trust score of a peer. 
        public void UpdateTrustScore( Peer targetPeer, int change)
        {
            lock (stateLock)
            {
                if (this.NodeId == targetPeer.NodeId)
                {
                    Console.WriteLine("Error: A node cannot update its own trust score.");
                    return;
                }

                int newScore = Math.Clamp(targetPeer.TrustScore + change, 0, 100);
                targetPeer.TrustScore = newScore;

                Console.WriteLine($"Updated trust score for {targetPeer.NodeId} by {this.NodeId}: {targetPeer.TrustScore}");
            }
        }

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

            int latency = CalculateLatency(peer); // Use Option 1
            int trustScore = peer.TrustScore; // Use Option 3

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
        private double NormalizeTrust(int trustScore)
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
        
    }
}
