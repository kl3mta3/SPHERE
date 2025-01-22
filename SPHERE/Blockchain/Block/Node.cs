using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;


namespace SPHERE.Blockchain
{
    public class Node
    {
        private readonly Dictionary<string, Node> Peers = new Dictionary<string, Node>();
        public NodeHeader Header;
        private DHT chain;



        public void AddNodeToPeers(Node node)
        {
            Peers.Add(node.Header.NodeId, node);
        }

        public void RemoveNodeFromPeers(Node node)
        {
            Peers.Remove(node.Header.NodeId);
        }

        public Node GetNode(string nodeId)
        {
            return Peers.ContainsKey(nodeId) ? Peers[Header.NodeId] : null;
        }

    }

    public class NodeHeader
    {

        public string NodeId { get; set; }
        public string NodeIP { get; set; }
        public int NodePort { get; set; }
        public string PreviousNodesHash { get; set; }
        public string PublicSignatureKey {  get; set; }


    }
}

