using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

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

        public NodeType Node_Type { get; set; }
        public string NodeId { get; set; }
        public string NodeIP { get; set; }
        public int NodePort { get; set; }
        public string PreviousNodesHash { get; set; }
        public string PublicSignatureKey { get; set; }
        public string PublicEncryptKey { get; set; }
        public int TrustScore {  get; set; } 

        public static Peer CreatePeerHeader(NodeType nodeType, string nodeID, string nodeIP, int nodePort, string previousHash, string publicSignatureKey, string publicEncryptKey)
        {

            Peer header = new Peer
            {
                Node_Type = nodeType,
                NodeId = nodeID,
                NodeIP = nodeIP,
                NodePort = nodePort,
                PreviousNodesHash = previousHash,
                PublicSignatureKey = publicSignatureKey,
                PublicEncryptKey = publicEncryptKey,
                TrustScore=0
            };


            return header;
        }

        public class PeerInfo
        {
            public string NodeId { get; set; }
            public string NodeIP { get; set; }
            public int NodePort { get; set; }
            public string PublicSignatureKey { get; set; }
            public string PublicEncryptKey { get; set; }
        }
        public void UpdateTrustScore(Peer peer, int change)
        {
            lock (stateLock)
            {
                int newScore = Math.Clamp((int)peer.TrustScore + change, 0, 100);
                peer.TrustScore = newScore;

                Console.WriteLine($"Updated trust score for {peer.NodeId}: {peer.TrustScore}");
            }
        }
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

        private double NormalizeLatency(int latency)
        {
            const int MaxLatency = 1000; // Define a maximum reasonable latency
            return Math.Min((double)latency / MaxLatency, 1.0); // Normalize to [0, 1]
        }

        private double NormalizeTrust(int trustScore)
        {
            const int MaxTrustScore = 100; // Example max trust score
            return (double)trustScore / MaxTrustScore; // Normalize to [0, 1]
        }
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
