using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Linq;
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
        public NodeType Node_Type { get; set; }
        public string NodeId { get; set; }
        public string NodeIP { get; set; }
        public int NodePort { get; set; }
        public string PreviousNodesHash { get; set; }
        public string PublicSignatureKey { get; set; }
        public string PublicEncryptKey { get; set; }

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
    }
}
